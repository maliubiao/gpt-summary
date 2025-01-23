Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request is to understand the functionality of `v8-console-message.cc` and relate it to JavaScript, providing an example.

2. **Initial Skim and Keywords:**  Quickly read through the code, looking for recurring terms and patterns. Keywords like `ConsoleMessage`, `ConsoleAPIType`, `Runtime`, `Frontend`, `Exception`, `arguments`, `timestamp`, `stackTrace`, `inspector`, `context`, `v8::Local`, `protocol` jump out. This immediately suggests it's about how console messages (like `console.log`, `console.error`, etc.) are handled within the V8 engine and communicated to developer tools.

3. **Identify Core Data Structures:**  Pay attention to class definitions. `V8ConsoleMessage` is central. Notice its members: `m_origin`, `m_timestamp`, `m_message`, `m_lineNumber`, `m_columnNumber`, `m_scriptId`, `m_contextId`, `m_type`, `m_arguments`, `m_stackTrace`. These represent the attributes of a console message.

4. **Trace the Flow of Information:** Look for methods that seem to handle message creation and reporting.
    * `V8ConsoleMessage::createForConsoleAPI`:  This looks like the entry point for creating console API messages (like `console.log`). It takes JavaScript values (`v8::Local<v8::Value>`) as arguments.
    * `V8ConsoleMessage::createForException`:  This handles JavaScript exceptions.
    * `V8ConsoleMessage::reportToFrontend`:  This is crucial. It's responsible for sending the message information to the "frontend," which likely refers to the developer tools. Notice it uses `protocol::Console` and `protocol::Runtime`. This signals communication using the Chrome DevTools Protocol.
    * `V8ConsoleMessageStorage`: This class appears to manage a collection of `V8ConsoleMessage` objects. It handles adding, clearing, and potentially limiting the number of messages.

5. **Connect to JavaScript Concepts:**  At this point, start linking the C++ code back to familiar JavaScript concepts.
    * The different `ConsoleAPIType` enums (`kLog`, `kError`, `kWarning`, etc.) directly correspond to JavaScript console API methods.
    * The `m_arguments` likely store the values passed to the JavaScript console methods.
    * `m_stackTrace` clearly relates to JavaScript stack traces.
    * The handling of exceptions and their reporting is directly tied to how JavaScript errors are surfaced in the console.

6. **Analyze Key Methods in Detail:** Focus on important methods like `reportToFrontend`. Observe how it transforms the internal `V8ConsoleMessage` data into the protocol format (`protocol::Console::ConsoleMessage`, `protocol::Runtime::RemoteObject`, `protocol::Runtime::ExceptionDetails`). The `wrapArguments` and `wrapException` methods are responsible for converting V8's internal representation of JavaScript objects to a format suitable for the DevTools Protocol.

7. **Understand the Role of `V8ConsoleMessageStorage`:** This class acts as a buffer or store for console messages. It prevents the messages from being lost before the developer tools connect or if the frontend is temporarily unavailable. The size limits and clearing mechanism are important for resource management.

8. **Identify the Communication Mechanism:** The use of `protocol::Console` and `protocol::Runtime` namespaces strongly indicates that this code is part of the implementation for the Chrome DevTools Protocol, which is the standard way for debuggers and developer tools to interact with browser engines like V8.

9. **Formulate the Summary:** Based on the analysis, synthesize a concise summary of the file's purpose. Emphasize the core functionality: capturing, formatting, and transmitting console messages and exceptions from the V8 engine to developer tools.

10. **Construct the JavaScript Example:**  Create a simple JavaScript code snippet that demonstrates the console API methods that this C++ code handles. Choose a variety of methods (`log`, `warn`, `error`, `table`, `count`, `time`, `timeEnd`, and throwing an error) to showcase the breadth of functionality covered. Make sure the example is clear and directly relates to the C++ concepts.

11. **Refine and Review:**  Read through the summary and example to ensure clarity, accuracy, and completeness. Double-check for any technical inaccuracies or confusing language. Ensure the JavaScript example aligns with the functionality described in the summary. For instance, if the code handles `console.table`, the JavaScript example should include it.

**Self-Correction/Refinement Example During the Process:**

* **Initial thought:** "This file just handles `console.log`."
* **Correction:**  "Wait, I see code for `ConsoleAPIType::kError`, `kWarning`, `kTable`, `kTimeEnd`, and exception handling. This file is responsible for *more* than just `console.log`. It handles various console API methods and exceptions."
* **Further refinement:** "The `protocol::Console` and `protocol::Runtime` namespaces are key. This is definitely about communicating with developer tools using the Chrome DevTools Protocol."

By following these steps, the understanding of the C++ code becomes progressively clearer, leading to a comprehensive summary and a relevant JavaScript example.
这个C++源代码文件 `v8-console-message.cc` 的主要功能是 **负责创建、存储和向前端（通常是开发者工具）报告 JavaScript 控制台消息和异常信息。**  它在 V8 引擎的 Inspector 模块中扮演着关键角色，连接了 JavaScript 代码的执行环境和调试工具。

更具体地说，它的功能可以归纳为以下几点：

1. **表示控制台消息和异常：** 定义了 `V8ConsoleMessage` 类，用于封装一个控制台消息或异常的各种属性，例如：
    * 消息的来源 (`m_origin`): 是来自 `console` API 调用还是一个异常。
    * 时间戳 (`m_timestamp`)
    * 消息内容 (`m_message`, `m_detailedMessage`)
    * 消息的位置 (URL, 行号, 列号, `m_url`, `m_lineNumber`, `m_columnNumber`)
    * 调用栈信息 (`m_stackTrace`)
    * 关联的 JavaScript 上下文 (`m_contextId`)
    * 控制台 API 类型 (`m_type`)，例如 `log`, `error`, `warn`, `table` 等。
    * 异常 ID (`m_exceptionId`)

2. **创建控制台消息：** 提供了静态方法 `createForConsoleAPI` 用于根据 JavaScript `console` API 的调用创建 `V8ConsoleMessage` 对象。它接收 V8 上下文、消息类型、参数、调用栈等信息。

3. **创建异常消息：** 提供了静态方法 `createForException` 用于根据 JavaScript 抛出的异常创建 `V8ConsoleMessage` 对象。它接收异常信息、发生位置、调用栈等信息。

4. **格式化消息参数：**  使用 `V8ValueStringBuilder` 类将 JavaScript 的值转换为字符串表示形式，用于在控制台消息中显示。这个类考虑了循环引用等问题，并限制了数组的大小，以避免无限递归或过大的消息。

5. **向前端报告消息：** 提供了 `reportToFrontend` 方法，用于将 `V8ConsoleMessage` 对象转换成符合 Chrome DevTools Protocol 格式的消息，然后发送给前端开发者工具。这包括将 V8 的内部对象转换为 `protocol::Runtime::RemoteObject`，以及构建 `protocol::Console::ConsoleMessage` 和 `protocol::Runtime::ExceptionDetails` 对象。

6. **管理控制台消息存储：** 定义了 `V8ConsoleMessageStorage` 类，用于存储一定数量的控制台消息。它可以添加消息、清除消息，并限制消息的数量和总大小，防止内存溢出。它还维护了 `console.count` 和 `console.time` 等 API 的状态。

7. **处理 `console` API 特定的行为：**  实现了 `console.count`, `console.time`, `console.timeEnd` 等 API 的计数和计时功能。

**与 JavaScript 的关系及示例：**

这个 C++ 文件是 V8 引擎内部实现的一部分，直接服务于 JavaScript 的 `console` API。 当你在 JavaScript 代码中使用 `console.log()`, `console.error()`, `console.warn()`, `console.table()`, `console.count()`, `console.time()`, `console.timeEnd()` 等方法时，V8 引擎内部就会调用 `v8-console-message.cc` 中的代码来创建和处理这些消息。

**JavaScript 示例：**

```javascript
console.log("这是一条普通的日志消息");
console.warn("这是一个警告消息", { someData: 123 });
console.error("发生了一个错误", new Error("Something went wrong"));
console.table([{ a: 1, b: 'Y' }, { a: 2, b: 'Z' }]);

console.count("myCounter");
console.count("myCounter");
console.countReset("myCounter");
console.count("myCounter");

console.time("myTimer");
for (let i = 0; i < 100000; i++) {
  // 一些操作
}
console.timeEnd("myTimer");

function throwError() {
  throw new Error("自定义的错误");
}

try {
  throwError();
} catch (e) {
  console.error("捕获到的异常:", e);
}
```

**对应到 C++ 代码的功能：**

* 当执行 `console.log("这是一条普通的日志消息")` 时，`V8ConsoleMessage::createForConsoleAPI` 会被调用，创建一个 `V8ConsoleMessage` 对象，其 `m_type` 为 `ConsoleAPIType::kLog`，`m_message` 为 "这是一条普通的日志消息"。
* 当执行 `console.error("发生了一个错误", new Error("Something went wrong"))` 时，会创建一个 `V8ConsoleMessage` 对象，其 `m_type` 为 `ConsoleAPIType::kError`，`m_message` 为 "发生了一个错误"，`m_arguments` 会包含 `new Error("Something went wrong")` 这个 JavaScript 对象。
* 当执行 `console.table(...)` 时，`V8ConsoleMessage::createForConsoleAPI` 会被调用，且 `m_type` 为 `ConsoleAPIType::kTable`。`wrapArguments` 方法会特殊处理 `table` 类型的消息，将其格式化为表格数据。
* `console.count("myCounter")` 的调用会触发 `V8ConsoleMessageStorage::count` 方法，更新计数器的状态。
* `console.time("myTimer")` 和 `console.timeEnd("myTimer")` 的调用会触发 `V8ConsoleMessageStorage` 中计时器的管理。
* 当 `throw new Error(...)` 被执行时，如果未被 `try...catch` 捕获，V8 引擎会创建一个异常消息，并调用 `V8ConsoleMessage::createForException` 创建 `V8ConsoleMessage` 对象。即使被 `try...catch` 捕获，`console.error("捕获到的异常:", e)` 仍然会调用 `V8ConsoleMessage::createForConsoleAPI`。

总而言之，`v8-console-message.cc` 是 V8 引擎中连接 JavaScript 控制台 API 和开发者工具的关键桥梁，负责将 JavaScript 世界的控制台操作转化为开发者工具能够理解和展示的信息。

### 提示词
```
这是目录为v8/src/inspector/v8-console-message.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/v8-console-message.h"

#include "include/v8-container.h"
#include "include/v8-context.h"
#include "include/v8-inspector.h"
#include "include/v8-microtask-queue.h"
#include "include/v8-primitive-object.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Protocol.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-console-agent-impl.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-runtime-agent-impl.h"
#include "src/inspector/v8-stack-trace-impl.h"
#include "src/inspector/value-mirror.h"
#include "src/tracing/trace-event.h"

namespace v8_inspector {

namespace {

String16 consoleAPITypeValue(ConsoleAPIType type) {
  switch (type) {
    case ConsoleAPIType::kLog:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Log;
    case ConsoleAPIType::kDebug:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Debug;
    case ConsoleAPIType::kInfo:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Info;
    case ConsoleAPIType::kError:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Error;
    case ConsoleAPIType::kWarning:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Warning;
    case ConsoleAPIType::kClear:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Clear;
    case ConsoleAPIType::kDir:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Dir;
    case ConsoleAPIType::kDirXML:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Dirxml;
    case ConsoleAPIType::kTable:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Table;
    case ConsoleAPIType::kTrace:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Trace;
    case ConsoleAPIType::kStartGroup:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::StartGroup;
    case ConsoleAPIType::kStartGroupCollapsed:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::StartGroupCollapsed;
    case ConsoleAPIType::kEndGroup:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::EndGroup;
    case ConsoleAPIType::kAssert:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Assert;
    case ConsoleAPIType::kTimeEnd:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::TimeEnd;
    case ConsoleAPIType::kCount:
      return protocol::Runtime::ConsoleAPICalled::TypeEnum::Count;
  }
  return protocol::Runtime::ConsoleAPICalled::TypeEnum::Log;
}

const char kGlobalConsoleMessageHandleLabel[] = "DevTools console";
const unsigned maxConsoleMessageCount = 1000;
const int maxConsoleMessageV8Size = 10 * 1024 * 1024;
const unsigned maxArrayItemsLimit = 10000;
const unsigned maxStackDepthLimit = 32;

class V8ValueStringBuilder {
 public:
  static String16 toString(v8::Local<v8::Value> value,
                           v8::Local<v8::Context> context) {
    V8ValueStringBuilder builder(context);
    if (!builder.append(value)) return String16();
    return builder.toString();
  }

 private:
  enum {
    IgnoreNull = 1 << 0,
    IgnoreUndefined = 1 << 1,
  };

  explicit V8ValueStringBuilder(v8::Local<v8::Context> context)
      : m_arrayLimit(maxArrayItemsLimit),
        m_isolate(context->GetIsolate()),
        m_visitedArrays(context->GetIsolate()),
        m_tryCatch(context->GetIsolate()),
        m_context(context) {}

  bool append(v8::Local<v8::Value> value, unsigned ignoreOptions = 0) {
    if (value.IsEmpty()) return true;
    if ((ignoreOptions & IgnoreNull) && value->IsNull()) return true;
    if ((ignoreOptions & IgnoreUndefined) && value->IsUndefined()) return true;
    if (value->IsBigIntObject()) {
      value = value.As<v8::BigIntObject>()->ValueOf();
    } else if (value->IsBooleanObject()) {
      value =
          v8::Boolean::New(m_isolate, value.As<v8::BooleanObject>()->ValueOf());
    } else if (value->IsNumberObject()) {
      value =
          v8::Number::New(m_isolate, value.As<v8::NumberObject>()->ValueOf());
    } else if (value->IsStringObject()) {
      value = value.As<v8::StringObject>()->ValueOf();
    } else if (value->IsSymbolObject()) {
      value = value.As<v8::SymbolObject>()->ValueOf();
    }
    if (value->IsString()) return append(value.As<v8::String>());
    if (value->IsBigInt()) return append(value.As<v8::BigInt>());
    if (value->IsSymbol()) return append(value.As<v8::Symbol>());
    if (value->IsArray()) return append(value.As<v8::Array>());
    if (value->IsProxy()) {
      m_builder.append("[object Proxy]");
      return true;
    }
    if (value->IsObject() && !value->IsDate() && !value->IsFunction() &&
        !value->IsNativeError() && !value->IsRegExp()) {
      v8::Local<v8::Object> object = value.As<v8::Object>();
      v8::Local<v8::String> stringValue;
      if (object->ObjectProtoToString(m_context).ToLocal(&stringValue))
        return append(stringValue);
    }
    v8::Local<v8::String> stringValue;
    if (!value->ToString(m_context).ToLocal(&stringValue)) return false;
    return append(stringValue);
  }

  bool append(v8::Local<v8::Array> array) {
    for (const auto& it : m_visitedArrays) {
      if (it == array) return true;
    }
    uint32_t length = array->Length();
    if (length > m_arrayLimit) return false;
    if (m_visitedArrays.size() > maxStackDepthLimit) return false;

    bool result = true;
    m_arrayLimit -= length;
    m_visitedArrays.push_back(array);
    for (uint32_t i = 0; i < length; ++i) {
      if (i) m_builder.append(',');
      v8::Local<v8::Value> value;
      if (!array->Get(m_context, i).ToLocal(&value)) continue;
      if (!append(value, IgnoreNull | IgnoreUndefined)) {
        result = false;
        break;
      }
    }
    m_visitedArrays.pop_back();
    return result;
  }

  bool append(v8::Local<v8::Symbol> symbol) {
    m_builder.append("Symbol(");
    bool result = append(symbol->Description(m_isolate), IgnoreUndefined);
    m_builder.append(')');
    return result;
  }

  bool append(v8::Local<v8::BigInt> bigint) {
    v8::Local<v8::String> bigint_string;
    if (!bigint->ToString(m_context).ToLocal(&bigint_string)) return false;
    bool result = append(bigint_string);
    if (m_tryCatch.HasCaught()) return false;
    m_builder.append('n');
    return result;
  }

  bool append(v8::Local<v8::String> string) {
    if (m_tryCatch.HasCaught()) return false;
    if (!string.IsEmpty()) {
      m_builder.append(toProtocolString(m_isolate, string));
    }
    return true;
  }

  String16 toString() {
    if (m_tryCatch.HasCaught()) return String16();
    return m_builder.toString();
  }

  uint32_t m_arrayLimit;
  v8::Isolate* m_isolate;
  String16Builder m_builder;
  v8::LocalVector<v8::Array> m_visitedArrays;
  v8::TryCatch m_tryCatch;
  v8::Local<v8::Context> m_context;
};

}  // namespace

V8ConsoleMessage::V8ConsoleMessage(V8MessageOrigin origin, double timestamp,
                                   const String16& message)
    : m_origin(origin),
      m_timestamp(timestamp),
      m_message(message),
      m_lineNumber(0),
      m_columnNumber(0),
      m_scriptId(0),
      m_contextId(0),
      m_type(ConsoleAPIType::kLog),
      m_exceptionId(0),
      m_revokedExceptionId(0) {}

V8ConsoleMessage::~V8ConsoleMessage() = default;

void V8ConsoleMessage::setLocation(const String16& url, unsigned lineNumber,
                                   unsigned columnNumber,
                                   std::unique_ptr<V8StackTraceImpl> stackTrace,
                                   int scriptId) {
  const char* dataURIPrefix = "data:";
  if (url.substring(0, strlen(dataURIPrefix)) == dataURIPrefix) {
    m_url = String16();
  } else {
    m_url = url;
  }
  m_lineNumber = lineNumber;
  m_columnNumber = columnNumber;
  m_stackTrace = std::move(stackTrace);
  m_scriptId = scriptId;
}

void V8ConsoleMessage::reportToFrontend(
    protocol::Console::Frontend* frontend) const {
  DCHECK_EQ(V8MessageOrigin::kConsole, m_origin);
  String16 level = protocol::Console::ConsoleMessage::LevelEnum::Log;
  if (m_type == ConsoleAPIType::kDebug || m_type == ConsoleAPIType::kCount ||
      m_type == ConsoleAPIType::kTimeEnd)
    level = protocol::Console::ConsoleMessage::LevelEnum::Debug;
  else if (m_type == ConsoleAPIType::kError ||
           m_type == ConsoleAPIType::kAssert)
    level = protocol::Console::ConsoleMessage::LevelEnum::Error;
  else if (m_type == ConsoleAPIType::kWarning)
    level = protocol::Console::ConsoleMessage::LevelEnum::Warning;
  else if (m_type == ConsoleAPIType::kInfo)
    level = protocol::Console::ConsoleMessage::LevelEnum::Info;
  std::unique_ptr<protocol::Console::ConsoleMessage> result =
      protocol::Console::ConsoleMessage::create()
          .setSource(protocol::Console::ConsoleMessage::SourceEnum::ConsoleApi)
          .setLevel(level)
          .setText(m_message)
          .build();
  if (m_lineNumber) result->setLine(m_lineNumber);
  if (m_columnNumber) result->setColumn(m_columnNumber);
  if (!m_url.isEmpty()) result->setUrl(m_url);
  frontend->messageAdded(std::move(result));
}

std::unique_ptr<protocol::Array<protocol::Runtime::RemoteObject>>
V8ConsoleMessage::wrapArguments(V8InspectorSessionImpl* session,
                                bool generatePreview) const {
  V8InspectorImpl* inspector = session->inspector();
  int contextGroupId = session->contextGroupId();
  int contextId = m_contextId;
  if (m_arguments.empty() || !contextId) return nullptr;
  InspectedContext* inspectedContext =
      inspector->getContext(contextGroupId, contextId);
  if (!inspectedContext) return nullptr;

  v8::Isolate* isolate = inspectedContext->isolate();
  v8::HandleScope handles(isolate);
  v8::Local<v8::Context> context = inspectedContext->context();

  auto args =
      std::make_unique<protocol::Array<protocol::Runtime::RemoteObject>>();

  v8::Local<v8::Value> value = m_arguments[0]->Get(isolate);
  if (value->IsObject() && m_type == ConsoleAPIType::kTable &&
      generatePreview) {
    v8::MaybeLocal<v8::Array> columns;
    if (m_arguments.size() > 1) {
      v8::Local<v8::Value> secondArgument = m_arguments[1]->Get(isolate);
      if (secondArgument->IsArray()) {
        columns = secondArgument.As<v8::Array>();
      } else if (secondArgument->IsString()) {
        v8::TryCatch tryCatch(isolate);
        v8::Local<v8::Array> array = v8::Array::New(isolate);
        if (array->Set(context, 0, secondArgument).IsJust()) {
          columns = array;
        }
      }
    }
    std::unique_ptr<protocol::Runtime::RemoteObject> wrapped =
        session->wrapTable(context, value.As<v8::Object>(), columns);
    inspectedContext = inspector->getContext(contextGroupId, contextId);
    if (!inspectedContext) return nullptr;
    if (wrapped) {
      args->emplace_back(std::move(wrapped));
    } else {
      args = nullptr;
    }
  } else {
    for (size_t i = 0; i < m_arguments.size(); ++i) {
      std::unique_ptr<protocol::Runtime::RemoteObject> wrapped =
          session->wrapObject(context, m_arguments[i]->Get(isolate), "console",
                              generatePreview);
      inspectedContext = inspector->getContext(contextGroupId, contextId);
      if (!inspectedContext) return nullptr;
      if (!wrapped) {
        args = nullptr;
        break;
      }
      args->emplace_back(std::move(wrapped));
    }
  }
  return args;
}

void V8ConsoleMessage::reportToFrontend(protocol::Runtime::Frontend* frontend,
                                        V8InspectorSessionImpl* session,
                                        bool generatePreview) const {
  int contextGroupId = session->contextGroupId();
  V8InspectorImpl* inspector = session->inspector();
  // Protect against reentrant debugger calls via interrupts.
  v8::debug::PostponeInterruptsScope no_interrupts(inspector->isolate());

  if (m_origin == V8MessageOrigin::kException) {
    std::unique_ptr<protocol::Runtime::RemoteObject> exception =
        wrapException(session, generatePreview);
    if (!inspector->hasConsoleMessageStorage(contextGroupId)) return;
    std::unique_ptr<protocol::Runtime::ExceptionDetails> exceptionDetails =
        protocol::Runtime::ExceptionDetails::create()
            .setExceptionId(m_exceptionId)
            .setText(exception ? m_message : m_detailedMessage)
            .setLineNumber(m_lineNumber ? m_lineNumber - 1 : 0)
            .setColumnNumber(m_columnNumber ? m_columnNumber - 1 : 0)
            .build();
    if (m_scriptId)
      exceptionDetails->setScriptId(String16::fromInteger(m_scriptId));
    if (!m_url.isEmpty()) exceptionDetails->setUrl(m_url);
    if (m_stackTrace) {
      exceptionDetails->setStackTrace(
          m_stackTrace->buildInspectorObjectImpl(inspector->debugger()));
    }
    if (m_contextId) exceptionDetails->setExecutionContextId(m_contextId);
    if (exception) exceptionDetails->setException(std::move(exception));
    std::unique_ptr<protocol::DictionaryValue> data =
        getAssociatedExceptionData(inspector, session);
    if (data) exceptionDetails->setExceptionMetaData(std::move(data));
    frontend->exceptionThrown(m_timestamp, std::move(exceptionDetails));
    return;
  }
  if (m_origin == V8MessageOrigin::kRevokedException) {
    frontend->exceptionRevoked(m_message, m_revokedExceptionId);
    return;
  }
  if (m_origin == V8MessageOrigin::kConsole) {
    std::unique_ptr<protocol::Array<protocol::Runtime::RemoteObject>>
        arguments = wrapArguments(session, generatePreview);
    if (!inspector->hasConsoleMessageStorage(contextGroupId)) return;
    if (!arguments) {
      arguments =
          std::make_unique<protocol::Array<protocol::Runtime::RemoteObject>>();
      if (!m_message.isEmpty()) {
        std::unique_ptr<protocol::Runtime::RemoteObject> messageArg =
            protocol::Runtime::RemoteObject::create()
                .setType(protocol::Runtime::RemoteObject::TypeEnum::String)
                .build();
        messageArg->setValue(protocol::StringValue::create(m_message));
        arguments->emplace_back(std::move(messageArg));
      }
    }
    Maybe<String16> consoleContext;
    if (!m_consoleContext.isEmpty()) consoleContext = m_consoleContext;
    std::unique_ptr<protocol::Runtime::StackTrace> stackTrace;
    if (m_stackTrace) {
      switch (m_type) {
        case ConsoleAPIType::kAssert:
        case ConsoleAPIType::kError:
        case ConsoleAPIType::kTrace:
        case ConsoleAPIType::kWarning:
          stackTrace =
              m_stackTrace->buildInspectorObjectImpl(inspector->debugger());
          break;
        default:
          stackTrace =
              m_stackTrace->buildInspectorObjectImpl(inspector->debugger(), 0);
          break;
      }
    }
    frontend->consoleAPICalled(
        consoleAPITypeValue(m_type), std::move(arguments), m_contextId,
        m_timestamp, std::move(stackTrace), std::move(consoleContext));
    return;
  }
  UNREACHABLE();
}

std::unique_ptr<protocol::DictionaryValue>
V8ConsoleMessage::getAssociatedExceptionData(
    V8InspectorImpl* inspector, V8InspectorSessionImpl* session) const {
  if (m_arguments.empty() || !m_contextId) return nullptr;
  DCHECK_EQ(1u, m_arguments.size());

  v8::Isolate* isolate = inspector->isolate();
  v8::HandleScope handles(isolate);
  v8::MaybeLocal<v8::Value> maybe_exception = m_arguments[0]->Get(isolate);
  v8::Local<v8::Value> exception;
  if (!maybe_exception.ToLocal(&exception)) return nullptr;

  return inspector->getAssociatedExceptionDataForProtocol(exception);
}

std::unique_ptr<protocol::Runtime::RemoteObject>
V8ConsoleMessage::wrapException(V8InspectorSessionImpl* session,
                                bool generatePreview) const {
  if (m_arguments.empty() || !m_contextId) return nullptr;
  DCHECK_EQ(1u, m_arguments.size());
  InspectedContext* inspectedContext =
      session->inspector()->getContext(session->contextGroupId(), m_contextId);
  if (!inspectedContext) return nullptr;

  v8::Isolate* isolate = inspectedContext->isolate();
  v8::HandleScope handles(isolate);
  // TODO(dgozman): should we use different object group?
  return session->wrapObject(inspectedContext->context(),
                             m_arguments[0]->Get(isolate), "console",
                             generatePreview);
}

V8MessageOrigin V8ConsoleMessage::origin() const { return m_origin; }

ConsoleAPIType V8ConsoleMessage::type() const { return m_type; }

// static
std::unique_ptr<V8ConsoleMessage> V8ConsoleMessage::createForConsoleAPI(
    v8::Local<v8::Context> v8Context, int contextId, int groupId,
    V8InspectorImpl* inspector, double timestamp, ConsoleAPIType type,
    v8::MemorySpan<const v8::Local<v8::Value>> arguments,
    const String16& consoleContext,
    std::unique_ptr<V8StackTraceImpl> stackTrace) {
  v8::Isolate* isolate = v8Context->GetIsolate();

  std::unique_ptr<V8ConsoleMessage> message(
      new V8ConsoleMessage(V8MessageOrigin::kConsole, timestamp, String16()));
  if (stackTrace && !stackTrace->isEmpty()) {
    message->m_url = toString16(stackTrace->topSourceURL());
    message->m_lineNumber = stackTrace->topLineNumber();
    message->m_columnNumber = stackTrace->topColumnNumber();
  }
  message->m_stackTrace = std::move(stackTrace);
  message->m_consoleContext = consoleContext;
  message->m_type = type;
  message->m_contextId = contextId;
  for (v8::Local<v8::Value> arg : arguments) {
    std::unique_ptr<v8::Global<v8::Value>> argument(
        new v8::Global<v8::Value>(isolate, arg));
    argument->AnnotateStrongRetainer(kGlobalConsoleMessageHandleLabel);
    message->m_arguments.push_back(std::move(argument));
    message->m_v8Size += v8::debug::EstimatedValueSize(isolate, arg);
  }
  bool sep = false;
  for (v8::Local<v8::Value> arg : arguments) {
    if (sep) {
      message->m_message += String16(" ");
    } else {
      sep = true;
    }
    message->m_message += V8ValueStringBuilder::toString(arg, v8Context);
  }

  v8::Isolate::MessageErrorLevel clientLevel = v8::Isolate::kMessageInfo;
  if (type == ConsoleAPIType::kDebug || type == ConsoleAPIType::kCount ||
      type == ConsoleAPIType::kTimeEnd) {
    clientLevel = v8::Isolate::kMessageDebug;
  } else if (type == ConsoleAPIType::kError ||
             type == ConsoleAPIType::kAssert) {
    clientLevel = v8::Isolate::kMessageError;
  } else if (type == ConsoleAPIType::kWarning) {
    clientLevel = v8::Isolate::kMessageWarning;
  } else if (type == ConsoleAPIType::kInfo) {
    clientLevel = v8::Isolate::kMessageInfo;
  } else if (type == ConsoleAPIType::kLog) {
    clientLevel = v8::Isolate::kMessageLog;
  }

  if (type != ConsoleAPIType::kClear) {
    inspector->client()->consoleAPIMessage(
        groupId, clientLevel, toStringView(message->m_message),
        toStringView(message->m_url), message->m_lineNumber,
        message->m_columnNumber, message->m_stackTrace.get());
  }

  return message;
}

// static
std::unique_ptr<V8ConsoleMessage> V8ConsoleMessage::createForException(
    double timestamp, const String16& detailedMessage, const String16& url,
    unsigned lineNumber, unsigned columnNumber,
    std::unique_ptr<V8StackTraceImpl> stackTrace, int scriptId,
    v8::Isolate* isolate, const String16& message, int contextId,
    v8::Local<v8::Value> exception, unsigned exceptionId) {
  std::unique_ptr<V8ConsoleMessage> consoleMessage(
      new V8ConsoleMessage(V8MessageOrigin::kException, timestamp, message));
  consoleMessage->setLocation(url, lineNumber, columnNumber,
                              std::move(stackTrace), scriptId);
  consoleMessage->m_exceptionId = exceptionId;
  consoleMessage->m_detailedMessage = detailedMessage;
  if (contextId && !exception.IsEmpty()) {
    consoleMessage->m_contextId = contextId;
    consoleMessage->m_arguments.push_back(
        std::unique_ptr<v8::Global<v8::Value>>(
            new v8::Global<v8::Value>(isolate, exception)));
    consoleMessage->m_v8Size +=
        v8::debug::EstimatedValueSize(isolate, exception);
  }
  return consoleMessage;
}

// static
std::unique_ptr<V8ConsoleMessage> V8ConsoleMessage::createForRevokedException(
    double timestamp, const String16& messageText,
    unsigned revokedExceptionId) {
  std::unique_ptr<V8ConsoleMessage> message(new V8ConsoleMessage(
      V8MessageOrigin::kRevokedException, timestamp, messageText));
  message->m_revokedExceptionId = revokedExceptionId;
  return message;
}

void V8ConsoleMessage::contextDestroyed(int contextId) {
  if (contextId != m_contextId) return;
  m_contextId = 0;
  if (m_message.isEmpty()) m_message = "<message collected>";
  Arguments empty;
  m_arguments.swap(empty);
  m_v8Size = 0;
}

// ------------------------ V8ConsoleMessageStorage
// ----------------------------

V8ConsoleMessageStorage::V8ConsoleMessageStorage(V8InspectorImpl* inspector,
                                                 int contextGroupId)
    : m_inspector(inspector), m_contextGroupId(contextGroupId) {}

V8ConsoleMessageStorage::~V8ConsoleMessageStorage() { clear(); }

namespace {

void TraceV8ConsoleMessageEvent(V8MessageOrigin origin, ConsoleAPIType type) {
  // Change in this function requires adjustment of Catapult/Telemetry metric
  // tracing/tracing/metrics/console_error_metric.html.
  // See https://crbug.com/880432
  if (origin == V8MessageOrigin::kException) {
    TRACE_EVENT_INSTANT0("v8.console", "V8ConsoleMessage::Exception",
                         TRACE_EVENT_SCOPE_THREAD);
  } else if (type == ConsoleAPIType::kError) {
    TRACE_EVENT_INSTANT0("v8.console", "V8ConsoleMessage::Error",
                         TRACE_EVENT_SCOPE_THREAD);
  } else if (type == ConsoleAPIType::kAssert) {
    TRACE_EVENT_INSTANT0("v8.console", "V8ConsoleMessage::Assert",
                         TRACE_EVENT_SCOPE_THREAD);
  }
}

}  // anonymous namespace

void V8ConsoleMessageStorage::addMessage(
    std::unique_ptr<V8ConsoleMessage> message) {
  int contextGroupId = m_contextGroupId;
  V8InspectorImpl* inspector = m_inspector;
  if (message->type() == ConsoleAPIType::kClear) clear();

  TraceV8ConsoleMessageEvent(message->origin(), message->type());

  inspector->forEachSession(
      contextGroupId, [&message](V8InspectorSessionImpl* session) {
        if (message->origin() == V8MessageOrigin::kConsole)
          session->consoleAgent()->messageAdded(message.get());
        session->runtimeAgent()->messageAdded(message.get());
      });
  if (!inspector->hasConsoleMessageStorage(contextGroupId)) return;

  DCHECK(m_messages.size() <= maxConsoleMessageCount);
  if (m_messages.size() == maxConsoleMessageCount) {
    m_estimatedSize -= m_messages.front()->estimatedSize();
    m_messages.pop_front();
  }
  while (m_estimatedSize + message->estimatedSize() > maxConsoleMessageV8Size &&
         !m_messages.empty()) {
    m_estimatedSize -= m_messages.front()->estimatedSize();
    m_messages.pop_front();
  }

  m_messages.push_back(std::move(message));
  m_estimatedSize += m_messages.back()->estimatedSize();
}

void V8ConsoleMessageStorage::clear() {
  m_messages.clear();
  m_estimatedSize = 0;
  m_inspector->forEachSession(m_contextGroupId,
                              [](V8InspectorSessionImpl* session) {
                                session->releaseObjectGroup("console");
                              });
  for (auto& data : m_data) {
    data.second.m_counters.clear();
    data.second.m_reportedDeprecationMessages.clear();
  }
}

bool V8ConsoleMessageStorage::shouldReportDeprecationMessage(
    int contextId, const String16& method) {
  std::set<String16>& reportedDeprecationMessages =
      m_data[contextId].m_reportedDeprecationMessages;
  auto it = reportedDeprecationMessages.find(method);
  if (it != reportedDeprecationMessages.end()) return false;
  reportedDeprecationMessages.insert(it, method);
  return true;
}

int V8ConsoleMessageStorage::count(int contextId, int consoleContextId,
                                   const String16& label) {
  return ++m_data[contextId].m_counters[LabelKey{consoleContextId, label}];
}

bool V8ConsoleMessageStorage::countReset(int contextId, int consoleContextId,
                                         const String16& label) {
  std::map<LabelKey, int>& counters = m_data[contextId].m_counters;
  auto it = counters.find(LabelKey{consoleContextId, label});
  if (it == counters.end()) return false;
  counters.erase(it);
  return true;
}

bool V8ConsoleMessageStorage::time(int contextId, int consoleContextId,
                                   const String16& label) {
  return m_data[contextId]
      .m_timers
      .try_emplace(LabelKey{consoleContextId, label},
                   m_inspector->client()->currentTimeMS())
      .second;
}

std::optional<double> V8ConsoleMessageStorage::timeLog(int contextId,
                                                       int consoleContextId,
                                                       const String16& label) {
  auto& timers = m_data[contextId].m_timers;
  auto it = timers.find(std::make_pair(consoleContextId, label));
  if (it == timers.end()) return std::nullopt;
  return m_inspector->client()->currentTimeMS() - it->second;
}

std::optional<double> V8ConsoleMessageStorage::timeEnd(int contextId,
                                                       int consoleContextId,
                                                       const String16& label) {
  auto& timers = m_data[contextId].m_timers;
  auto it = timers.find(std::make_pair(consoleContextId, label));
  if (it == timers.end()) return std::nullopt;
  double result = m_inspector->client()->currentTimeMS() - it->second;
  timers.erase(it);
  return result;
}

void V8ConsoleMessageStorage::contextDestroyed(int contextId) {
  m_estimatedSize = 0;
  for (size_t i = 0; i < m_messages.size(); ++i) {
    m_messages[i]->contextDestroyed(contextId);
    m_estimatedSize += m_messages[i]->estimatedSize();
  }
  {
    auto it = m_data.find(contextId);
    if (it != m_data.end()) m_data.erase(contextId);
  }
}

}  // namespace v8_inspector
```