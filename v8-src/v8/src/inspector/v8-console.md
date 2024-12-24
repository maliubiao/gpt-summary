Response: Let's break down the thought process to analyze this C++ code and provide a good summary and JavaScript examples.

1. **Understand the Goal:** The primary goal is to understand the functionality of `v8-console.cc` within the V8 inspector context and connect it to JavaScript's `console` API.

2. **Initial Skim and Keyword Spotting:**  Quickly read through the code, looking for recognizable keywords and patterns. Words like `Console`, `Debug`, `Error`, `Log`, `Warn`, `Group`, `Time`, `Profile`, `Assert`, etc., immediately stand out and strongly suggest a connection to the JavaScript `console` object. The `#include` statements also give clues about dependencies (e.g., `v8-inspector.h`, `v8-context.h`).

3. **Identify the Core Class:** The `V8Console` class is clearly the central piece. Its methods (`Debug`, `Error`, `Log`, etc.) mirror the methods of the JavaScript `console` object.

4. **Analyze Key Methods:**  Focus on the implementation of these core methods. Notice the pattern:
   - They receive `v8::debug::ConsoleCallArguments` (the arguments passed to `console.*` in JavaScript) and `v8::debug::ConsoleContext`.
   - They create a `ConsoleHelper` object.
   - They call `reportCall` or a similar `reportCall*` variant on the `ConsoleHelper`.

5. **Delve into `ConsoleHelper`:** This class seems crucial for handling the actual reporting logic. Analyze its members and methods:
   - `m_info`:  Holds the arguments passed to the console function.
   - `m_consoleContext`: Information about the context where the console call happened.
   - `m_inspector`:  A pointer to the main `V8InspectorImpl`, suggesting interaction with the inspector framework.
   - `reportCall`:  The core method for sending console messages. Notice how it constructs a `V8ConsoleMessage` and adds it to a storage. Pay attention to how it handles stack traces.
   - Methods like `firstArgToString`, `firstArgToBoolean`, etc., are utilities for extracting information from the arguments.

6. **Trace the Message Flow:**  Follow how a JavaScript `console.log()` call would translate to actions in this C++ code:
   - JavaScript `console.log("hello")` is executed.
   - V8's internal debugging hooks recognize this.
   - The `V8Console::Log` method is called in C++, with "hello" as an argument.
   - A `ConsoleHelper` is created.
   - `reportCall` in `ConsoleHelper` creates a `V8ConsoleMessage` with the log level and the "hello" string.
   - The message is stored and potentially sent to the connected debugger/inspector.

7. **Connect to JavaScript Examples:** Now that the C++ side is clearer, think about how the different `console` methods are used in JavaScript and how they relate to the C++ implementations. For example:
   - `console.log()` directly maps to `V8Console::Log`.
   - `console.warn()` maps to `V8Console::Warn`.
   - `console.group()` and `console.groupEnd()` map to `V8Console::Group` and `V8Console::GroupEnd`.
   - `console.time()` and `console.timeEnd()` relate to the `time` and `timeEnd` methods in `V8Console` and the `ConsoleHelper`'s logic for tracking timers.

8. **Identify Additional Functionality:**  Notice other interesting methods and features:
   - `Profile` and `ProfileEnd`:  Relate to profiling JavaScript code.
   - `Assert`:  Triggers a debugger breakpoint if the condition is false.
   - `Count` and `CountReset`:  Keep track of how many times a label has been logged.
   - `TimeLog`: Logs the elapsed time for a timer.
   - `Clear`: Clears the console.
   - The `createTask` and `runTask` functions suggest support for asynchronous task tracking in the debugger.
   - Methods like `debugFunctionCallback`, `monitorFunctionCallback`, `inspectCallback`, `copyCallback`, and `queryObjectsCallback` show the integration with debugger features like breakpoints and object inspection.
   - The `CommandLineAPIScope` class manages the injection of console-like functions into the JavaScript global scope during debugging.

9. **Structure the Summary:** Organize the findings into logical sections:
   - **Core Functionality:**  Focus on the main purpose of the file – implementing the `console` API for the debugger.
   - **Key Components:** Explain the roles of `V8Console` and `ConsoleHelper`.
   - **JavaScript Integration:**  Provide clear JavaScript examples for the different `console` methods and explain how they connect to the C++ code.
   - **Additional Features:**  Summarize the more advanced debugging features supported by this file.

10. **Refine and Clarify:** Review the summary for clarity and accuracy. Ensure the JavaScript examples are correct and illustrate the concepts effectively. Use precise language to describe the C++ components and their interactions. For example, instead of just saying "it reports calls," specify that it creates `V8ConsoleMessage` objects.

By following these steps, we can dissect the C++ code, understand its purpose within the V8 inspector, and effectively communicate its functionality and relationship to the JavaScript `console` API.
这个C++源代码文件 `v8-console.cc` 的主要功能是**实现 V8 JavaScript 引擎中 `console` 对象的方法，以便在调试环境中使用**。 它负责捕获和处理 JavaScript 代码中调用的各种 `console` 方法（例如 `console.log`, `console.error`, `console.time` 等），并将这些信息传递给调试器或开发者工具。

以下是更详细的归纳：

**核心功能:**

* **实现 `console` API:**  文件中的 `V8Console` 类提供了与 JavaScript `console` 对象上的方法对应的 C++ 方法 (例如 `Debug`, `Error`, `Log`, `Warn`, `Dir`, `Table`, `Time`, `Profile` 等)。
* **消息格式化和报告:**  当 JavaScript 代码调用 `console` 的方法时，V8 引擎会调用 `V8Console` 中相应的方法。这些方法会使用 `ConsoleHelper` 类来处理参数，创建 `V8ConsoleMessage` 对象，并将其添加到消息存储中。
* **集成调试器:**  `V8Console` 与 V8 的调试器 (`V8DebuggerAgentImpl`) 紧密集成。它可以：
    * 在 `console.assert` 失败时中断程序执行。
    * 支持 `debug(function)` 和 `undebug(function)` 来设置和移除函数断点。
    * 支持 `monitor(function)` 和 `unmonitor(function)` 来在函数调用时记录日志。
    * 将 `console` 输出发送到连接的调试器或开发者工具。
* **性能分析支持:**  通过 `console.profile()` 和 `console.profileEnd()` 方法，可以触发 V8 的性能分析器 (`V8ProfilerAgentImpl`)。
* **计时器支持:**  `console.time()` 和 `console.timeEnd()` 的实现依赖于 `V8ConsoleMessageStorage` 来跟踪计时器。
* **计数器支持:**  `console.count()` 和 `console.countReset()` 使用 `V8ConsoleMessageStorage` 来记录和重置计数器。
* **异步任务跟踪:** 引入了 `console.createTask()` 和相关的 API 来支持异步任务的创建和跟踪，这对于调试异步代码很有用。
* **`inspect()` 功能:**  `console.inspect()` 允许开发者在调试器中检查对象。
* **命令行 API 模拟:**  创建了一个 `CommandLineAPIScope` 类，用于在调试上下文中模拟一些常用的命令行 API 函数 (例如 `$0`, `$_`, `keys`, `values` 等)。
* **内存信息:**  提供了 `console.memory` 属性来访问内存使用信息。

**与 JavaScript 的关系和示例:**

这个 C++ 文件直接实现了 JavaScript 中 `console` 对象的行为。当你在 JavaScript 代码中使用 `console` 的方法时，V8 引擎会调用这个文件中相应的 C++ 代码。

**JavaScript 示例:**

```javascript
// console.log 用于输出普通日志信息
console.log("Hello, world!");

// console.error 用于输出错误信息，通常在开发者工具中会以不同的颜色显示
console.error("An error occurred!");

// console.warn 用于输出警告信息
console.warn("This is a warning.");

// console.debug 通常在更详细的调试模式下使用
console.debug("Debugging information.");

// console.info 用于输出提示信息
console.info("This is some information.");

// console.assert 用于断言某个条件是否为真，如果为假则会输出错误并可能中断执行
console.assert(1 + 1 === 2, "Math is broken!");

// console.dir 用于以对象的形式显示指定对象的属性
const myObject = { a: 1, b: "hello", c: [1, 2, 3] };
console.dir(myObject);

// console.table 用于以表格的形式显示数组或对象
const users = [{ name: "Alice", age: 30 }, { name: "Bob", age: 25 }];
console.table(users);

// console.time 和 console.timeEnd 用于测量代码执行时间
console.time("myTimer");
for (let i = 0; i < 100000; i++) {
  // 一些耗时的操作
}
console.timeEnd("myTimer");

// console.group 和 console.groupEnd 用于对控制台输出进行分组
console.group("My Group");
console.log("Message in group");
console.groupEnd();

// console.count 用于记录特定标签被调用的次数
console.count("myLabel");
console.count("myLabel");
console.count("anotherLabel");
console.countReset("myLabel"); // 重置 myLabel 的计数器
console.count("myLabel");

// console.trace 用于输出当前执行的堆栈跟踪信息
function a() {
  b();
}
function b() {
  console.trace();
}
a();

// console.profile 和 console.profileEnd 用于启动和结束性能分析器
console.profile("My Profile");
// 一些需要分析性能的代码
console.profileEnd("My Profile");

// console.clear 用于清空控制台
console.clear();

// console.inspect 用于在调试器中检查对象
const data = { x: 10, y: 20 };
console.inspect(data);

// 异步任务 API (需要 V8 支持)
const task = console.createTask("MyAsyncOperation");
setTimeout(() => {
  console.log("Async operation started");
  task.run(() => {
    console.log("Async operation finished");
  });
}, 1000);

// 访问内存信息
console.log(console.memory);

// 模拟命令行 API 的使用 (在调试环境中)
console.log($_); // 上一次表达式的计算结果
console.log($0); // 最近检查的 DOM 节点或 JavaScript 对象
```

**总结:**

`v8-console.cc` 是 V8 引擎中连接 JavaScript 的 `console` 对象和底层调试机制的关键组件。它使得开发者能够在调试过程中方便地输出信息、分析性能、设置断点以及检查对象，极大地提高了 JavaScript 开发的效率。 它的实现细节涉及到 V8 内部的结构和与调试器的交互。

Prompt: 
```
这是目录为v8/src/inspector/v8-console.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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
  DCHECK_GT(V8InspectorSessionImpl::kInspectedObjectBufferSize, num);
  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), m_inspector);
  if (V8InspectorSessionImpl* session = helper.session(sessionId)) {
    V8InspectorSession::Inspectable* object = session->inspectedObject(num);
    v8::Isolate* isolate = info.GetIsolate();
    if (object)
      info.GetReturnValue().Set(object->get(isolate->GetCurrentContext()));
    else
      info.GetReturnValue().Set(v8::Undefined(isolate));
  }
}

void V8Console::installMemoryGetter(v8::Local<v8::Context> context,
                                    v8::Local<v8::Object> console) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::External> data = v8::External::New(isolate, this);
  console->SetAccessorProperty(
      toV8StringInternalized(isolate, "memory"),
      v8::Function::New(
          context, &V8Console::call<&V8Console::memoryGetterCallback>, data, 0,
          v8::ConstructorBehavior::kThrow, v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked(),
      v8::Function::New(context,
                        &V8Console::call<&V8Console::memorySetterCallback>,
                        data, 0, v8::ConstructorBehavior::kThrow)
          .ToLocalChecked(),
      static_cast<v8::PropertyAttribute>(v8::None));
}

void V8Console::installAsyncStackTaggingAPI(v8::Local<v8::Context> context,
                                            v8::Local<v8::Object> console) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::External> data = v8::External::New(isolate, this);

  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);

  createBoundFunctionProperty(context, console, data, "createTask",
                              &V8Console::call<&V8Console::createTask>);
}

v8::Local<v8::Object> V8Console::createCommandLineAPI(
    v8::Local<v8::Context> context, int sessionId) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);

  v8::Local<v8::Object> commandLineAPI = v8::Object::New(isolate);
  bool success = commandLineAPI->SetPrototypeV2(context, v8::Null(isolate))
                     .FromMaybe(false);
  DCHECK(success);
  USE(success);

  v8::Local<v8::ArrayBuffer> data =
      v8::ArrayBuffer::New(isolate, sizeof(CommandLineAPIData));
  *static_cast<CommandLineAPIData*>(data->GetBackingStore()->Data()) =
      CommandLineAPIData(this, sessionId);
  createBoundFunctionProperty(context, commandLineAPI, data, "dir",
                              &V8Console::call<&V8Console::Dir>);
  createBoundFunctionProperty(context, commandLineAPI, data, "dirxml",
                              &V8Console::call<&V8Console::DirXml>);
  createBoundFunctionProperty(context, commandLineAPI, data, "profile",
                              &V8Console::call<&V8Console::Profile>);
  createBoundFunctionProperty(context, commandLineAPI, data, "profileEnd",
                              &V8Console::call<&V8Console::ProfileEnd>);
  createBoundFunctionProperty(context, commandLineAPI, data, "clear",
                              &V8Console::call<&V8Console::Clear>);
  createBoundFunctionProperty(context, commandLineAPI, data, "table",
                              &V8Console::call<&V8Console::Table>);

  createBoundFunctionProperty(context, commandLineAPI, data, "keys",
                              &V8Console::call<&V8Console::keysCallback>,
                              v8::SideEffectType::kHasNoSideEffect);
  createBoundFunctionProperty(context, commandLineAPI, data, "values",
                              &V8Console::call<&V8Console::valuesCallback>,
                              v8::SideEffectType::kHasNoSideEffect);
  createBoundFunctionProperty(
      context, commandLineAPI, data, "debug",
      &V8Console::call<&V8Console::debugFunctionCallback>);
  createBoundFunctionProperty(
      context, commandLineAPI, data, "undebug",
      &V8Console::call<&V8Console::undebugFunctionCallback>);
  createBoundFunctionProperty(
      context, commandLineAPI, data, "monitor",
      &V8Console::call<&V8Console::monitorFunctionCallback>);
  createBoundFunctionProperty(
      context, commandLineAPI, data, "unmonitor",
      &V8Console::call<&V8Console::unmonitorFunctionCallback>);
  createBoundFunctionProperty(context, commandLineAPI, data, "inspect",
                              &V8Console::call<&V8Console::inspectCallback>);
  createBoundFunctionProperty(context, commandLineAPI, data, "copy",
                              &V8Console::call<&V8Console::copyCallback>);
  createBoundFunctionProperty(
      context, commandLineAPI, data, "queryObjects",
      &V8Console::call<&V8Console::queryObjectsCallback>);
  createBoundFunctionProperty(
      context, commandLineAPI, data, "$_",
      &V8Console::call<&V8Console::lastEvaluationResultCallback>,
      v8::SideEffectType::kHasNoSideEffect);
  createBoundFunctionProperty(context, commandLineAPI, data, "$0",
                              &V8Console::call<&V8Console::inspectedObject0>,
                              v8::SideEffectType::kHasNoSideEffect);
  createBoundFunctionProperty(context, commandLineAPI, data, "$1",
                              &V8Console::call<&V8Console::inspectedObject1>,
                              v8::SideEffectType::kHasNoSideEffect);
  createBoundFunctionProperty(context, commandLineAPI, data, "$2",
                              &V8Console::call<&V8Console::inspectedObject2>,
                              v8::SideEffectType::kHasNoSideEffect);
  createBoundFunctionProperty(context, commandLineAPI, data, "$3",
                              &V8Console::call<&V8Console::inspectedObject3>,
                              v8::SideEffectType::kHasNoSideEffect);
  createBoundFunctionProperty(context, commandLineAPI, data, "$4",
                              &V8Console::call<&V8Console::inspectedObject4>,
                              v8::SideEffectType::kHasNoSideEffect);

  m_inspector->client()->installAdditionalCommandLineAPI(context,
                                                         commandLineAPI);
  return commandLineAPI;
}

static bool isCommandLineAPIGetter(const String16& name) {
  if (name.length() != 2) return false;
  // $0 ... $4, $_
  return name[0] == '$' &&
         ((name[1] >= '0' && name[1] <= '4') || name[1] == '_');
}

void V8Console::CommandLineAPIScope::accessorGetterCallback(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CommandLineAPIScope* scope = *static_cast<CommandLineAPIScope**>(
      info.Data().As<v8::ArrayBuffer>()->GetBackingStore()->Data());
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  if (scope == nullptr) {
    USE(info.HolderV2()->Delete(context, name).FromMaybe(false));
    return;
  }

  v8::Local<v8::Value> value;
  if (!scope->commandLineAPI()->Get(context, name).ToLocal(&value)) return;
  if (isCommandLineAPIGetter(
          toProtocolStringWithTypeCheck(info.GetIsolate(), name))) {
    DCHECK(value->IsFunction());
    v8::MicrotasksScope microtasks(context,
                                   v8::MicrotasksScope::kDoNotRunMicrotasks);
    if (value.As<v8::Function>()
            ->Call(context, scope->commandLineAPI(), 0, nullptr)
            .ToLocal(&value))
      info.GetReturnValue().Set(value);
  } else {
    info.GetReturnValue().Set(value);
  }
}

void V8Console::CommandLineAPIScope::accessorSetterCallback(
    v8::Local<v8::Name> name, v8::Local<v8::Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  CommandLineAPIScope* scope = *static_cast<CommandLineAPIScope**>(
      info.Data().As<v8::ArrayBuffer>()->GetBackingStore()->Data());
  if (scope == nullptr) return;
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  if (!info.HolderV2()->Delete(context, name).FromMaybe(false)) return;
  if (!info.HolderV2()
           ->CreateDataProperty(context, name, value)
           .FromMaybe(false))
    return;

  v8::Local<v8::PrimitiveArray> methods = scope->installedMethods();
  for (int i = 0; i < methods->Length(); ++i) {
    v8::Local<v8::Value> methodName = methods->Get(scope->m_isolate, i);
    if (methodName.IsEmpty() || !methodName->IsName()) continue;
    if (!name->StrictEquals(methodName)) continue;
    methods->Set(scope->m_isolate, i, v8::Undefined(scope->m_isolate));
    break;
  }
}

namespace {

// "get"-ting these functions from the global proxy is considered a side-effect.
// Otherwise, malicious sites could stash references to these functions through
// previews / ValueMirror and use them across origin isolation.
DEFINE_LAZY_LEAKY_OBJECT_GETTER(std::set<std::string_view>,
                                UnsafeCommandLineAPIFns,
                                std::initializer_list<std::string_view>{
                                    "debug", "undebug", "monitor", "unmonitor",
                                    "inspect", "copy", "queryObjects"})

bool IsUnsafeCommandLineAPIFn(v8::Local<v8::Value> name, v8::Isolate* isolate) {
  std::string nameStr = toProtocolStringWithTypeCheck(isolate, name).utf8();
  return UnsafeCommandLineAPIFns()->count(nameStr) > 0;
}

}  // namespace

V8Console::CommandLineAPIScope::CommandLineAPIScope(
    v8::Local<v8::Context> context, v8::Local<v8::Object> commandLineAPI,
    v8::Local<v8::Object> global)
    : m_isolate(context->GetIsolate()),
      m_context(m_isolate, context),
      m_commandLineAPI(m_isolate, commandLineAPI),
      m_global(m_isolate, global) {
  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::Local<v8::Array> names;
  if (!commandLineAPI->GetOwnPropertyNames(context).ToLocal(&names)) return;
  m_installedMethods.Reset(m_isolate,
                           v8::PrimitiveArray::New(m_isolate, names->Length()));

  m_thisReference = v8::Global<v8::ArrayBuffer>(
      m_isolate, v8::ArrayBuffer::New(context->GetIsolate(),
                                      sizeof(CommandLineAPIScope*)));
  *static_cast<CommandLineAPIScope**>(
      thisReference()->GetBackingStore()->Data()) = this;
  v8::Local<v8::PrimitiveArray> methods = installedMethods();
  for (uint32_t i = 0; i < names->Length(); ++i) {
    v8::Local<v8::Value> name;
    if (!names->Get(context, i).ToLocal(&name) || !name->IsName()) continue;
    if (global->Has(context, name).FromMaybe(true)) continue;

    const v8::SideEffectType get_accessor_side_effect_type =
        IsUnsafeCommandLineAPIFn(name, context->GetIsolate())
            ? v8::SideEffectType::kHasSideEffect
            : v8::SideEffectType::kHasNoSideEffect;
    if (!global
             ->SetNativeDataProperty(
                 context, name.As<v8::Name>(),
                 CommandLineAPIScope::accessorGetterCallback,
                 CommandLineAPIScope::accessorSetterCallback, thisReference(),
                 v8::DontEnum, get_accessor_side_effect_type)
             .FromMaybe(false)) {
      continue;
    }
    methods->Set(m_isolate, i, name.As<v8::Name>());
  }
}

V8Console::CommandLineAPIScope::~CommandLineAPIScope() {
  if (m_isolate->IsExecutionTerminating()) return;
  v8::MicrotasksScope microtasksScope(context(),
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  *static_cast<CommandLineAPIScope**>(
      thisReference()->GetBackingStore()->Data()) = nullptr;
  v8::Local<v8::PrimitiveArray> names = installedMethods();
  for (int i = 0; i < names->Length(); ++i) {
    v8::Local<v8::Value> name = names->Get(m_isolate, i);
    if (name.IsEmpty() || !name->IsName()) continue;
    if (name->IsString()) {
      v8::Local<v8::Value> descriptor;
      bool success =
          global()
              ->GetOwnPropertyDescriptor(context(), name.As<v8::String>())
              .ToLocal(&descriptor);
      USE(success);
    }
  }
}

}  // namespace v8_inspector

"""

```