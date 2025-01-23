Response:
Let's break down the thought process for analyzing this C++ code.

**1. Initial Understanding of the Request:**

The request asks for the functionality of the provided C++ code, specifically `v8/src/inspector/v8-console-message.cc`. It also includes several conditional requests based on file extension and relation to JavaScript.

**2. High-Level Overview (Skimming):**

The first step is to skim the code, looking for key classes, functions, and included headers. This gives a general idea of the code's purpose. I notice:

* Includes related to `v8-inspector`, `v8-context`, `protocol`, suggesting this code is part of V8's debugging/inspection framework.
* Classes like `V8ConsoleMessage` and `V8ConsoleMessageStorage`. These are likely the core components.
* Functions related to reporting to the frontend (e.g., `reportToFrontend`).
* Methods for handling different console API calls (like `kLog`, `kError`, `kTable`).

**3. Deep Dive into Core Classes:**

* **`V8ConsoleMessage`:**  The name strongly suggests it represents a console message. I examine its members and methods:
    * `m_origin`, `m_timestamp`, `m_message`: Basic message information.
    * `m_lineNumber`, `m_columnNumber`, `m_url`: Location information.
    * `m_type`:  The type of console message (log, error, etc.).
    * `m_arguments`:  The arguments passed to the console function.
    * `reportToFrontend`:  Responsible for sending the message to the DevTools frontend. It has different overloads for `protocol::Console::Frontend` and `protocol::Runtime::Frontend`.
    * `wrapArguments`, `wrapException`: Functions to format arguments and exceptions for the protocol.
    * `createForConsoleAPI`, `createForException`, `createForRevokedException`: Static factory methods for creating different types of console messages.
    * `contextDestroyed`: Handles cleanup when a context is destroyed.

* **`V8ConsoleMessageStorage`:** This class likely manages a collection of `V8ConsoleMessage` objects.
    * `m_messages`: A container (likely a `std::deque`) to store the messages.
    * `addMessage`: Adds a new message to the storage, handling size limits.
    * `clear`: Clears all stored messages.
    * Methods like `count`, `countReset`, `time`, `timeLog`, `timeEnd`:  These clearly relate to the `console.count()` and `console.time()` family of JavaScript console API methods.
    * `shouldReportDeprecationMessage`:  Handles logic for reporting deprecation warnings.
    * `contextDestroyed`:  Cleans up messages associated with a destroyed context.

**4. Analyzing Key Functionality and Logic:**

* **Console API Handling:** The `consoleAPITypeValue` function and the `createForConsoleAPI` method demonstrate how different JavaScript console API calls are mapped to internal representations and how arguments are processed.
* **Exception Handling:** The `createForException` method and the `reportToFrontend` overload for `V8MessageOrigin::kException` show how exceptions are captured and reported, including stack traces.
* **Message Formatting:**  The `V8ValueStringBuilder` class is crucial for converting V8 values (JavaScript objects, strings, etc.) into a human-readable string format for display in the console. It also handles potential recursion and size limits.
* **Frontend Communication:**  The `reportToFrontend` methods demonstrate how console messages are transformed into protocol messages (`protocol::Console::ConsoleMessage` and `protocol::Runtime::ExceptionDetails`) to be sent to the DevTools frontend.
* **Message Storage and Limits:**  `V8ConsoleMessageStorage` implements logic to limit the number and total size of stored console messages.

**5. Addressing Specific Request Points:**

* **Functionality Listing:** Summarize the identified functionalities based on the class and method analysis.
* **Torque Check:** Check the file extension. It's `.cc`, not `.tq`, so it's not Torque.
* **JavaScript Relation:** Identify the clear connection to JavaScript's `console` API and provide corresponding examples.
* **Code Logic Inference:** Choose a specific, understandable piece of logic (like `console.count`) and demonstrate its behavior with inputs and outputs.
* **Common Programming Errors:**  Think about how developers might misuse the `console` API or encounter issues related to the concepts in the code (e.g., logging large objects).

**6. Structuring the Answer:**

Organize the findings into clear sections based on the request's points. Use headings and bullet points for readability. Provide code examples in a code block.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps the code directly sends messages to the console.
* **Correction:** Realize it's interacting with the *DevTools frontend* via a protocol, hence the `protocol::Console` and `protocol::Runtime` usage.
* **Initial thought:** Focus heavily on every single function.
* **Refinement:** Prioritize the core classes and their main methods to understand the overall flow, then delve into specifics if needed.
* **Initial thought:**  Overlook the JavaScript relation.
* **Correction:** Explicitly connect the C++ code to the corresponding JavaScript `console` API methods.

By following this structured approach, combining skimming for a high-level understanding with deep dives into key components, and by constantly relating the C++ code back to its purpose within V8's debugging infrastructure, I can effectively analyze and explain the functionality of `v8-console-message.cc`.
好的，让我们来分析一下 `v8/src/inspector/v8-console-message.cc` 这个文件。

**功能列举:**

这个 C++ 源代码文件 `v8-console-message.cc` 的主要功能是**处理和表示 JavaScript 控制台消息**，这些消息通常是通过 `console` 对象的方法（如 `console.log()`, `console.error()` 等）产生的。更具体地说，它的功能包括：

1. **表示控制台消息:**  定义了 `V8ConsoleMessage` 类，用于存储关于单个控制台消息的所有必要信息，包括：
    * 消息的来源 (`m_origin`): 例如，是来自控制台 API 调用还是异常。
    * 时间戳 (`m_timestamp`)
    * 消息文本 (`m_message`)
    * 消息的来源 URL (`m_url`)、行号 (`m_lineNumber`) 和列号 (`m_columnNumber`)
    * 消息关联的脚本 ID (`m_scriptId`) 和上下文 ID (`m_contextId`)
    * 控制台 API 类型 (`m_type`): 例如，`log`, `error`, `warn`, `table` 等。
    * 消息的参数 (`m_arguments`):  传递给 `console` 方法的 JavaScript 值。
    * 异常 ID (`m_exceptionId`) 和撤销的异常 ID (`m_revokedExceptionId`) (用于异常消息)。
    * 详细的消息文本 (`m_detailedMessage`)，用于异常消息。
    * 关联的堆栈跟踪 (`m_stackTrace`)。
    * 控制台上下文 (`m_consoleContext`)。
    * 估计的消息大小 (`m_v8Size`)。

2. **格式化消息参数:**  提供 `V8ValueStringBuilder` 类，用于将 JavaScript 的 `v8::Value` 对象转换为可读的字符串形式，用于显示在控制台中。这个类处理了不同类型的 JavaScript 值（字符串、数字、对象、数组等），并避免了无限递归。

3. **报告消息到前端 (DevTools):**  `V8ConsoleMessage` 提供了 `reportToFrontend` 方法，用于将消息以特定的协议格式发送到开发者工具的前端。这个方法会根据消息的类型和来源，生成相应的 `protocol::Console::ConsoleMessage` 或 `protocol::Runtime::ExceptionDetails` 对象。

4. **管理控制台消息存储:**  定义了 `V8ConsoleMessageStorage` 类，用于存储和管理一定数量的控制台消息。这个类负责：
    * 存储最近的控制台消息 (`m_messages`)。
    * 限制存储的消息数量和总大小，防止内存占用过高。
    * 处理 `console.clear()` 调用，清空存储的消息。
    * 跟踪 `console.count()` 的计数器。
    * 跟踪 `console.time()` 的计时器。
    * 管理每个上下文的已报告的弃用消息，以避免重复报告。
    * 在上下文销毁时清理相关的数据。

5. **处理不同类型的控制台 API 调用:**  `V8ConsoleMessage::createForConsoleAPI` 方法根据不同的 `ConsoleAPIType` 创建相应的 `V8ConsoleMessage` 对象。

6. **处理异常消息:** `V8ConsoleMessage::createForException` 和 `V8ConsoleMessage::createForRevokedException` 方法用于创建表示 JavaScript 异常的消息。

**关于文件扩展名和 Torque:**

正如你所说，如果 `v8/src/inspector/v8-console-message.cc` 的扩展名是 `.tq`，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种用于编写 V8 内部运行时函数的领域特定语言。 由于它的扩展名是 `.cc`，所以它是标准的 C++ 源代码。

**与 JavaScript 功能的关系 (带有 JavaScript 示例):**

`v8-console-message.cc` 的核心功能是处理与 JavaScript `console` 对象相关的操作。以下是一些 JavaScript 示例，以及它们在 `v8-console-message.cc` 中的表示：

```javascript
console.log("Hello, world!");
console.error("An error occurred.");
console.warn("This is a warning.");
console.info("Some information.");
console.debug("Debug message.");
console.table({ a: 1, b: 2 });
console.count("myCounter");
console.count("myCounter");
console.countReset("myCounter");
console.time("myTimer");
console.timeLog("myTimer");
console.timeEnd("myTimer");
assert(1 === 2, "Assertion failed!"); // 使用 assert 需要启用
throw new Error("Something went wrong!");
```

当这些 JavaScript 代码在 V8 引擎中执行时，`v8-console-message.cc` 中的代码会参与以下过程：

* **捕获控制台 API 调用:** 当 JavaScript 代码调用 `console.log()`, `console.error()` 等方法时，V8 引擎内部会调用相应的 C++ 函数。这些函数会收集调用的参数、上下文信息、堆栈跟踪等。
* **创建 `V8ConsoleMessage` 对象:**  `V8ConsoleMessage::createForConsoleAPI` 会被调用，根据调用的 `console` 方法类型（`ConsoleAPIType::kLog`, `ConsoleAPIType::kError` 等）创建一个 `V8ConsoleMessage` 对象，并将收集到的信息存储在该对象中。
* **格式化消息参数:**  传递给 `console` 方法的 JavaScript 值会被 `V8ValueStringBuilder::toString` 转换为字符串，以便显示在控制台中。例如，`console.log({ a: 1, b: 2 })` 中的对象会被格式化为 `"{a: 1, b: 2}"` 这样的字符串。
* **报告到前端:**  `V8ConsoleMessage::reportToFrontend` 会将 `V8ConsoleMessage` 对象转换为符合 Chrome DevTools 协议的消息，然后发送到开发者工具的前端进行显示。
* **存储消息:**  `V8ConsoleMessageStorage::addMessage` 会将创建的 `V8ConsoleMessage` 对象添加到存储中。对于 `console.count()` 和 `console.time()` 等方法，`V8ConsoleMessageStorage` 还会更新相应的计数器和计时器。
* **处理异常:** 当 JavaScript 代码抛出异常时，V8 引擎会捕获该异常，并调用 `V8ConsoleMessage::createForException` 创建一个表示异常的 `V8ConsoleMessage` 对象。这个对象会包含异常消息、堆栈跟踪等信息。

**代码逻辑推理 (假设输入与输出):**

假设 JavaScript 代码执行了以下操作：

```javascript
console.count("myCounter"); // 第一次调用
console.count("myCounter"); // 第二次调用
console.countReset("myCounter");
console.count("myCounter"); // 第三次调用，在 reset 之后
```

**假设输入:**

* 上下文 ID: 123
* 控制台上下文 ID: 456
* 标签: "myCounter"

**代码逻辑推理 (在 `V8ConsoleMessageStorage` 中):**

1. **第一次 `console.count("myCounter")`:**
   - `V8ConsoleMessageStorage::count(123, 456, "myCounter")` 被调用。
   - `m_data[123].m_counters[{456, "myCounter"}]` 的值从不存在变为 1。
   - 输出 (返回值): 1

2. **第二次 `console.count("myCounter")`:**
   - `V8ConsoleMessageStorage::count(123, 456, "myCounter")` 被调用。
   - `m_data[123].m_counters[{456, "myCounter"}]` 的值从 1 变为 2。
   - 输出 (返回值): 2

3. **`console.countReset("myCounter")`:**
   - `V8ConsoleMessageStorage::countReset(123, 456, "myCounter")` 被调用。
   - `m_data[123].m_counters[{456, "myCounter"}]` 的条目被删除。
   - 输出 (返回值): `true` (表示重置成功)

4. **第三次 `console.count("myCounter")`:**
   - `V8ConsoleMessageStorage::count(123, 456, "myCounter")` 被调用。
   - `m_data[123].m_counters[{456, "myCounter"}]` 的值从不存在变为 1。
   - 输出 (返回值): 1

**涉及用户常见的编程错误 (举例说明):**

1. **尝试打印大型或循环引用的对象:**

   ```javascript
   const obj = {};
   obj.circular = obj;
   console.log(obj); // 可能导致堆栈溢出或性能问题，V8ValueStringBuilder 会尝试处理
   ```

   `V8ValueStringBuilder` 内部有 `m_visitedArrays` 和 `maxStackDepthLimit` 来防止无限递归和过深的调用栈，但打印非常大的对象仍然可能影响性能。

2. **过度使用 `console.log` 导致性能问题:**

   ```javascript
   for (let i = 0; i < 100000; i++) {
       console.log("Processing item:", i); // 大量输出会影响性能
   }
   ```

   虽然 `V8ConsoleMessageStorage` 会限制存储的消息数量，但大量的 `console.log` 调用仍然会在 V8 引擎和 DevTools 前端产生开销。

3. **在生产环境遗留 `console.log`:**

   ```javascript
   function calculateSomething(input) {
       console.log("Input received:", input); // 调试代码，应在生产环境移除
       // ... 复杂的计算 ...
       return result;
   }
   ```

   在生产环境中，不必要的 `console.log` 调用会浪费资源，并可能暴露敏感信息。

4. **混淆 `console.log` 和 `console.dir`:**

   ```javascript
   const myObject = { a: 1, b: { c: 2 } };
   console.log(myObject); // 通常以字符串形式显示对象
   console.dir(myObject); // 以交互式的方式显示对象的属性
   ```

   开发者可能不清楚 `console.log` 和 `console.dir` 的区别，导致输出的信息不符合预期。

5. **忘记使用字符串模板或 JSON.stringify 来查看对象内容:**

   ```javascript
   const user = { name: "Alice", age: 30 };
   console.log("User object:" + user); // 输出 "User object:[object Object]"
   console.log("User object:", user);   // 更好的方式，会显示对象的内容
   console.log(`User object: ${JSON.stringify(user)}`); // 以 JSON 字符串显示
   ```

   初学者可能会犯这种错误，导致无法正确查看对象的内容。

总而言之，`v8-console-message.cc` 是 V8 引擎中负责处理 JavaScript 控制台消息的关键组件，它将 JavaScript 的 `console` API 调用转化为结构化的数据，并将其传递到开发者工具进行展示。

### 提示词
```
这是目录为v8/src/inspector/v8-console-message.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-console-message.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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