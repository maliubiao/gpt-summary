Response:
Let's break down the thought process for analyzing the provided C++ code and generating the summary.

**1. Initial Understanding and Goal:**

The primary goal is to understand the functionality of `v8/src/execution/messages.cc` and summarize its purpose. The prompt also provides specific points to address: .tq file status, relation to JavaScript, code logic inference (with examples), common programming errors, and finally, a concise summary.

**2. High-Level Overview by Scanning Includes:**

The included headers provide strong hints about the file's purpose:

* `"src/execution/messages.h"`:  This is the most crucial. It suggests this file *defines* the messages functionality.
* `"src/api/api-inl.h"` and related:  Indicates interaction with the V8 API, meaning this code likely bridges the internal workings with the external JavaScript environment.
* `"src/ast/ast.h"`, `"src/parsing/parse-info.h"`, `"src/parsing/parsing.h"`: Suggests involvement in handling syntax, parsing, and potentially error reporting during these phases.
* `"src/execution/execution.h"`, `"src/execution/frames-inl.h"`, `"src/execution/frames.h"`, `"src/execution/isolate-inl.h"`, `"src/execution/isolate.h"`: Clearly points to managing the execution environment, stack frames, and the isolate (V8's independent execution context).
* `"src/handles/maybe-handles.h"`:  Deals with managing V8's garbage-collected objects.
* `"src/logging/runtime-call-stats-scope.h"`: Likely used for performance tracking and debugging.
* `"src/objects/call-site-info-inl.h"`, `"src/objects/foreign-inl.h"`, `"src/objects/js-array-inl.h"`, `"src/objects/property-descriptor.h"`, `"src/objects/struct-inl.h"`: Implies manipulation of various V8 object types.
* `"src/roots/roots.h"`: Related to V8's internal object roots.
* `"src/strings/string-builder-inl.h"`: Used for efficient string manipulation.

From these includes, we can infer that `messages.cc` is likely responsible for:

* Creating and formatting error and informational messages.
* Handling message reporting to the embedder.
* Potentially dealing with stack traces associated with errors.

**3. Analyzing Key Classes and Functions:**

* **`MessageLocation`:** This class clearly holds information about where a message originated (script, position, bytecode offset, shared function info).
* **`MessageHandler`:** This is a central class. Its methods like `DefaultMessageReport`, `MakeMessageObject`, `ReportMessage`, `ReportMessageNoExceptions`, `GetMessage`, and `GetLocalizedMessage` strongly suggest it's the core component for message handling. The presence of listener-related code (`message_listeners()`, callback invocation) is also evident.
* **`ErrorUtils`:**  Functions like `FormatStackTrace`, `Construct`, `ToString`, and `MakeGenericError` indicate this class is responsible for creating and formatting error objects, including their stack traces.
* **`MessageFormatter`:** The `Format` and `TryFormat` methods confirm its role in substituting arguments into message templates.

**4. Answering Specific Prompt Questions:**

* **`.tq` File:** The code starts with `#include`, indicating it's C++. Therefore, it's not a Torque file.
* **Relation to JavaScript:** The file directly deals with JavaScript errors, stack traces, and the reporting of these events. The interaction with the V8 API (`v8::Local<v8::Message>`, `v8::Utils`) confirms this connection. JavaScript examples showing how errors are thrown and caught, and how `try...catch` works, are relevant here.
* **Code Logic Inference:** Focus on key functions like `ReportMessage`. It handles different error levels, calls listeners, and has logic for converting exception objects to strings. We can create a simple scenario: a JavaScript error occurs, triggering `ReportMessage`. If there's a listener, it gets called; otherwise, the default handler is invoked. A specific example with input and output for `GetMessage` or `MessageFormatter::Format` can also be devised.
* **Common Programming Errors:**  Think about the errors that JavaScript developers commonly encounter: `TypeError`, `ReferenceError`, syntax errors. Relate these back to the message templates and how V8 might report them. A `TypeError` example with an attempt to call a non-function is a good illustration.
* **Functionality Summary (Part 1):** Combine the observations from the includes and the analysis of key classes. Focus on the core responsibilities: creating, formatting, and reporting messages (especially errors) within the V8 engine. Mention the involvement of message listeners and the handling of stack traces.

**5. Refinement and Structuring the Answer:**

Organize the information logically. Start with the basic identification of the file and its language. Then, address each of the specific points raised in the prompt. Use clear headings and bullet points to make the answer easy to read. Provide concrete JavaScript examples where requested.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:** Maybe the file deals with all sorts of logging.
* **Correction:** The includes and class names heavily emphasize *messages*, particularly *error messages*. Adjust the focus accordingly.
* **Initial Thought:**  The code might directly execute JavaScript.
* **Correction:**  The code is C++; it *supports* the execution of JavaScript by handling error reporting and related tasks. It doesn't directly run JavaScript code.
* **Initial Thought:**  The examples should be very complex.
* **Correction:** Simple, illustrative JavaScript examples are more effective for conveying the relationship. Focus on the core concept being demonstrated.

By following these steps of initial scanning, detailed analysis, addressing specific points, and refining the output, we arrive at a comprehensive and accurate summary of the `v8/src/execution/messages.cc` file's functionality.```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/messages.h"

#include <memory>

#include "src/api/api-inl.h"
#include "src/ast/ast.h"
#include "src/ast/prettyprinter.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate.h"
#include "src/handles/maybe-handles.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/foreign-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/struct-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"
#include "src/roots/roots.h"
#include "src/strings/string-builder-inl.h"

namespace v8 {
namespace internal {

// ... (rest of the code)
```

## 功能列举：

`v8/src/execution/messages.cc` 文件的主要功能是处理 V8 引擎中的消息，特别是错误和警告消息。它负责：

1. **定义消息的位置信息 (`MessageLocation`)**:  记录消息发生的脚本、起始和结束位置、以及字节码偏移量和相关的共享函数信息。

2. **提供默认的消息处理机制 (`MessageHandler::DefaultMessageReport`)**: 当没有注册自定义消息监听器时，使用此方法打印消息到控制台，包含文件名和位置信息。

3. **创建消息对象 (`MessageHandler::MakeMessageObject`)**:  根据消息模板、位置信息、参数和堆栈跟踪信息，创建一个 `JSMessageObject`，该对象包含了消息的详细信息。

4. **报告消息 (`MessageHandler::ReportMessage`, `MessageHandler::ReportMessageNoExceptions`)**:
   - 将内部的 `JSMessageObject` 转换为 V8 API 的 `v8::Message` 对象。
   - 处理不同错误级别的消息。
   - 调用注册的全局消息监听器 (如果有)。
   - 如果发生异常，会尝试将异常对象转换为字符串。
   - 如果没有全局监听器，则调用默认的消息处理方法。

5. **获取消息字符串 (`MessageHandler::GetMessage`, `MessageHandler::GetLocalizedMessage`)**:  根据消息模板和参数，格式化生成最终的消息字符串。`GetLocalizedMessage` 将结果转换为 C 风格的字符串。

6. **处理和格式化堆栈跟踪信息 (`ErrorUtils::FormatStackTrace`, `GetStackFrames`)**:
   - 将原始的堆栈帧信息 (`FixedArray`) 转换为 `JSCallSite` 对象的 `JSArray`。
   - 支持自定义的 `prepareStackTrace` 函数来格式化堆栈信息。
   - 如果没有自定义函数，则使用 V8 内部的逻辑格式化堆栈信息，包括错误信息和调用栈。

7. **提供创建错误对象 (`ErrorUtils::Construct`, `ErrorUtils::MakeGenericError`) 的方法**:
   - 创建不同类型的 JavaScript 错误对象 (例如 `TypeError`, `RangeError`)。
   - 设置错误对象的 `message` 属性。
   - 支持 `cause` 选项，用于指定导致当前错误的原始错误。
   - 捕获和设置错误对象的堆栈信息。

8. **实现 `Error.prototype.toString()` (`ErrorUtils::ToString`)**:  定义了如何将错误对象转换为字符串表示形式，包括错误名和消息。

9. **消息模板格式化 (`MessageFormatter::Format`, `MessageFormatter::TryFormat`, `MessageFormatter::TemplateString`)**:
   - 使用预定义的消息模板 (`MESSAGE_TEMPLATES`) 和提供的参数来生成最终的消息字符串。
   - 处理模板中的占位符 (`%`)。

## 关于文件类型和 Torque：

你提到的 `.tq` 后缀是用于 V8 的 **Torque** 语言的源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**根据提供的内容，`v8/src/execution/messages.cc`  是以 `.cc` 结尾的，所以它是一个 C++ 源代码文件，而不是 Torque 文件。**

## 与 JavaScript 的关系及示例：

`v8/src/execution/messages.cc` 文件与 JavaScript 的功能密切相关，因为它直接负责处理 JavaScript 运行时产生的错误和警告消息。

**JavaScript 示例：**

当 JavaScript 代码执行出错时，例如：

```javascript
function myFunction(value) {
  if (typeof value !== 'number') {
    throw new TypeError('Input must be a number');
  }
  // ... 其它逻辑
}

myFunction("hello"); // 这会抛出一个 TypeError
```

或者当发生一些内部错误或警告时，V8 引擎会使用 `v8/src/execution/messages.cc` 中的代码来：

1. **确定错误发生的位置** (文件名、行号等)。
2. **创建包含错误信息的对象** (`JSMessageObject`)。
3. **格式化错误消息字符串** ("TypeError: Input must be a number")。
4. **生成堆栈跟踪信息**，显示函数调用路径。
5. **将错误信息报告给 JavaScript 环境**，例如通过 `try...catch` 语句捕获，或者在控制台中显示。

**消息监听器示例：**

V8 允许注册消息监听器来捕获和处理这些消息：

```javascript
// 注册一个全局消息监听器
v8.setGlobalMessageHandler(function(message, data) {
  console.log("捕获到消息：");
  console.log("级别:", message.getErrorLevel());
  console.log("消息文本:", message.get());
  console.log("文件名:", message.getScriptName());
  console.log("行号:", message.getLineNumber());
  console.log("堆栈跟踪:", message.getStackTrace());
});

// 触发一个错误
function causeError() {
  throw new Error("Something went wrong!");
}

try {
  causeError();
} catch (e) {
  // 错误通常在这里被捕获，但全局消息监听器也会收到消息
}
```

在这个例子中，`v8.setGlobalMessageHandler` 函数允许 JavaScript 代码拦截 V8 引擎产生的消息，这些消息的处理逻辑就在 `v8/src/execution/messages.cc` 中。

## 代码逻辑推理示例：

**假设输入：**  JavaScript 代码抛出一个 `TypeError`，尝试将一个非对象值解构。

```javascript
let notAnObject = 123;
let { prop } = notAnObject; // This will cause a TypeError
```

**代码逻辑推理 (简化)：**

1. 当执行到解构赋值时，V8 引擎会检查 `notAnObject` 是否为对象。
2. 因为 `notAnObject` 是一个数字，V8 内部会检测到类型错误。
3. `ErrorUtils::MakeGenericError` 函数可能会被调用，并传入 `MessageTemplate::kIncompatibleReceiver` (或者类似的模板) 以及相关的参数 (例如期待的对象类型，实际的类型)。
4. `MessageFormatter::Format` 函数会使用 `MessageTemplate::kIncompatibleReceiver` 对应的模板字符串，并替换参数，生成类似 "TypeError: Cannot destructure property 'prop' of '123' as it is not an object." 的消息。
5. `MessageHandler::MakeMessageObject` 会创建包含此消息和位置信息的 `JSMessageObject`。
6. `MessageHandler::ReportMessage` 会处理该消息，并可能调用注册的消息监听器或默认的报告方法。

**输出：**

- 如果没有消息监听器，控制台会输出类似：
  ```
  <anonymous>:<line_number>: TypeError: Cannot destructure property 'prop' of '123' as it is not an object.
      at <anonymous> (<anonymous>:<line_number>:<column_number>)
  ```
- 如果有消息监听器，监听器函数会接收到一个 `v8::Message` 对象，其中包含了错误级别、消息文本、文件名、行号、堆栈跟踪等信息。

## 用户常见的编程错误示例：

`v8/src/execution/messages.cc` 参与处理许多用户常见的编程错误，例如：

1. **`TypeError`**: 类型错误，例如尝试调用非函数的值，访问 `null` 或 `undefined` 的属性。

   ```javascript
   let obj = null;
   obj.property; // TypeError: Cannot read properties of null (reading 'property')
   ```

2. **`ReferenceError`**: 引用错误，例如使用未声明的变量。

   ```javascript
   console.log(undeclaredVariable); // ReferenceError: undeclaredVariable is not defined
   ```

3. **`SyntaxError`**: 语法错误，代码不符合 JavaScript 语法规则。

   ```javascript
   if (condition // SyntaxError: Unexpected end of input
   ```

4. **`RangeError`**: 值超出有效范围，例如数组长度为负数。

   ```javascript
   let arr = new Array(-1); // RangeError: Invalid array length
   ```

5. **`URIError`**: 与 URI 处理相关的错误。

   ```javascript
   decodeURIComponent('%'); // URIError: URI malformed
   ```

当这些错误发生时，`v8/src/execution/messages.cc` 中的代码负责生成包含这些错误信息的 `JSMessageObject`，并以用户友好的方式报告出来。

## 功能归纳 (第 1 部分)：

`v8/src/execution/messages.cc` 的主要功能是作为 V8 引擎中消息处理的核心组件，尤其专注于错误和警告消息的处理流程。它定义了消息的结构、创建了消息对象、格式化了消息内容、并提供了报告消息给 JavaScript 环境和注册消息监听器的机制。 该文件还负责处理和格式化 JavaScript 错误的堆栈跟踪信息，并提供了创建各种 JavaScript 错误对象的方法。 简而言之，它是 V8 引擎向 JavaScript 开发者和嵌入环境传递运行时信息 (尤其是错误信息) 的关键模块。

### 提示词
```
这是目录为v8/src/execution/messages.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/messages.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/messages.h"

#include <memory>

#include "src/api/api-inl.h"
#include "src/ast/ast.h"
#include "src/ast/prettyprinter.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate.h"
#include "src/handles/maybe-handles.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/foreign-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/struct-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"
#include "src/roots/roots.h"
#include "src/strings/string-builder-inl.h"

namespace v8 {
namespace internal {

MessageLocation::MessageLocation(Handle<Script> script, int start_pos,
                                 int end_pos)
    : script_(script),
      start_pos_(start_pos),
      end_pos_(end_pos),
      bytecode_offset_(-1) {}

MessageLocation::MessageLocation(Handle<Script> script, int start_pos,
                                 int end_pos, Handle<SharedFunctionInfo> shared)
    : script_(script),
      start_pos_(start_pos),
      end_pos_(end_pos),
      bytecode_offset_(-1),
      shared_(shared) {}

MessageLocation::MessageLocation(Handle<Script> script,
                                 Handle<SharedFunctionInfo> shared,
                                 int bytecode_offset)
    : script_(script),
      start_pos_(-1),
      end_pos_(-1),
      bytecode_offset_(bytecode_offset),
      shared_(shared) {}

MessageLocation::MessageLocation()
    : start_pos_(-1), end_pos_(-1), bytecode_offset_(-1) {}

// If no message listeners have been registered this one is called
// by default.
void MessageHandler::DefaultMessageReport(Isolate* isolate,
                                          const MessageLocation* loc,
                                          DirectHandle<Object> message_obj) {
  std::unique_ptr<char[]> str = GetLocalizedMessage(isolate, message_obj);
  if (loc == nullptr) {
    PrintF("%s\n", str.get());
  } else {
    HandleScope scope(isolate);
    DirectHandle<Object> data(loc->script()->name(), isolate);
    std::unique_ptr<char[]> data_str;
    if (IsString(*data)) data_str = Cast<String>(data)->ToCString();
    PrintF("%s:%i: %s\n", data_str ? data_str.get() : "<unknown>",
           loc->start_pos(), str.get());
  }
}

Handle<JSMessageObject> MessageHandler::MakeMessageObject(
    Isolate* isolate, MessageTemplate message, const MessageLocation* location,
    DirectHandle<Object> argument, DirectHandle<StackTraceInfo> stack_trace) {
  int start = -1;
  int end = -1;
  int bytecode_offset = -1;
  DirectHandle<Script> script_handle = isolate->factory()->empty_script();
  DirectHandle<SharedFunctionInfo> shared_info;
  if (location != nullptr && !v8_flags.correctness_fuzzer_suppressions) {
    start = location->start_pos();
    end = location->end_pos();
    script_handle = location->script();
    bytecode_offset = location->bytecode_offset();
    shared_info = location->shared();
  }

  return isolate->factory()->NewJSMessageObject(message, argument, start, end,
                                                shared_info, bytecode_offset,
                                                script_handle, stack_trace);
}

void MessageHandler::ReportMessage(Isolate* isolate, const MessageLocation* loc,
                                   DirectHandle<JSMessageObject> message) {
  v8::Local<v8::Message> api_message_obj = v8::Utils::MessageToLocal(message);

  if (api_message_obj->ErrorLevel() != v8::Isolate::kMessageError) {
    ReportMessageNoExceptions(isolate, loc, message, v8::Local<v8::Value>());
    return;
  }

  // We are calling into embedder's code which can throw exceptions.
  // Thus we need to save current exception state, reset it to the clean one
  // and ignore scheduled exceptions callbacks can throw.

  // We pass the exception object into the message handler callback though.
  Handle<Object> exception = isolate->factory()->undefined_value();
  if (isolate->has_exception()) {
    exception = handle(isolate->exception(), isolate);
  }

  Isolate::ExceptionScope exception_scope(isolate);
  isolate->clear_pending_message();

  // Turn the exception on the message into a string if it is an object.
  if (IsJSObject(message->argument())) {
    HandleScope scope(isolate);
    DirectHandle<Object> argument(message->argument(), isolate);

    MaybeDirectHandle<Object> maybe_stringified;
    DirectHandle<Object> stringified;
    // Make sure we don't leak uncaught internally generated Error objects.
    if (IsJSError(*argument)) {
      maybe_stringified = Object::NoSideEffectsToString(isolate, argument);
    } else {
      v8::TryCatch catcher(reinterpret_cast<v8::Isolate*>(isolate));
      catcher.SetVerbose(false);
      catcher.SetCaptureMessage(false);

      maybe_stringified = Object::ToString(isolate, argument);
    }

    if (!maybe_stringified.ToHandle(&stringified)) {
      isolate->clear_pending_message();
      stringified = isolate->factory()->exception_string();
    }
    message->set_argument(*stringified);
  }

  v8::Local<v8::Value> api_exception_obj = v8::Utils::ToLocal(exception);
  ReportMessageNoExceptions(isolate, loc, message, api_exception_obj);
}

void MessageHandler::ReportMessageNoExceptions(
    Isolate* isolate, const MessageLocation* loc, DirectHandle<Object> message,
    v8::Local<v8::Value> api_exception_obj) {
  v8::Local<v8::Message> api_message_obj = v8::Utils::MessageToLocal(message);
  int error_level = api_message_obj->ErrorLevel();

  DirectHandle<ArrayList> global_listeners =
      isolate->factory()->message_listeners();
  int global_length = global_listeners->length();
  if (global_length == 0) {
    DefaultMessageReport(isolate, loc, message);
  } else {
    for (int i = 0; i < global_length; i++) {
      HandleScope scope(isolate);
      if (IsUndefined(global_listeners->get(i), isolate)) continue;
      Tagged<FixedArray> listener = Cast<FixedArray>(global_listeners->get(i));
      Tagged<Foreign> callback_obj = Cast<Foreign>(listener->get(0));
      int32_t message_levels =
          static_cast<int32_t>(Smi::ToInt(listener->get(2)));
      if (!(message_levels & error_level)) {
        continue;
      }
      v8::MessageCallback callback = FUNCTION_CAST<v8::MessageCallback>(
          callback_obj->foreign_address<kMessageListenerTag>());
      DirectHandle<Object> callback_data(listener->get(1), isolate);
      {
        RCS_SCOPE(isolate, RuntimeCallCounterId::kMessageListenerCallback);
        // Do not allow exceptions to propagate.
        v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
        callback(api_message_obj, IsUndefined(*callback_data, isolate)
                                      ? api_exception_obj
                                      : v8::Utils::ToLocal(callback_data));
      }
    }
  }
}

Handle<String> MessageHandler::GetMessage(Isolate* isolate,
                                          DirectHandle<Object> data) {
  DirectHandle<JSMessageObject> message = Cast<JSMessageObject>(data);
  DirectHandle<Object> arg{message->argument(), isolate};
  return MessageFormatter::Format(isolate, message->type(),
                                  base::VectorOf({arg}));
}

std::unique_ptr<char[]> MessageHandler::GetLocalizedMessage(
    Isolate* isolate, DirectHandle<Object> data) {
  HandleScope scope(isolate);
  return GetMessage(isolate, data)->ToCString();
}

namespace {

// Convert the raw frames as written by Isolate::CaptureSimpleStackTrace into
// a JSArray of JSCallSite objects.
MaybeHandle<JSArray> GetStackFrames(Isolate* isolate,
                                    DirectHandle<FixedArray> frames) {
  int frame_count = frames->length();
  Handle<JSFunction> constructor = isolate->callsite_function();
  DirectHandle<FixedArray> sites =
      isolate->factory()->NewFixedArray(frame_count);
  for (int i = 0; i < frame_count; ++i) {
    Handle<CallSiteInfo> frame(Cast<CallSiteInfo>(frames->get(i)), isolate);
    Handle<JSObject> site;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, site,
                               JSObject::New(constructor, constructor,
                                             Handle<AllocationSite>::null()));
    RETURN_ON_EXCEPTION(
        isolate, JSObject::SetOwnPropertyIgnoreAttributes(
                     site, isolate->factory()->call_site_info_symbol(), frame,
                     DONT_ENUM));
    sites->set(i, *site);
  }

  return isolate->factory()->NewJSArrayWithElements(sites);
}

MaybeHandle<Object> AppendErrorString(Isolate* isolate, Handle<Object> error,
                                      IncrementalStringBuilder* builder) {
  v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  try_catch.SetVerbose(false);
  try_catch.SetCaptureMessage(false);
  MaybeHandle<String> err_str = ErrorUtils::ToString(
      isolate, Cast<Object>(error),
      ErrorUtils::ToStringMessageSource::kPreferOriginalMessage);
  if (err_str.is_null()) {
    // Error.toString threw. Try to return a string representation of the thrown
    // exception instead.

    DCHECK(isolate->has_exception());
    if (isolate->is_execution_terminating()) {
      return {};
    }
    Handle<Object> exception = handle(isolate->exception(), isolate);
    try_catch.Reset();

    err_str = ErrorUtils::ToString(
        isolate, exception,
        ErrorUtils::ToStringMessageSource::kPreferOriginalMessage);
    if (err_str.is_null()) {
      // Formatting the thrown exception threw again, give up.
      DCHECK(isolate->has_exception());
      if (isolate->is_execution_terminating()) return {};
      builder->AppendCStringLiteral("<error>");
    } else {
      // Formatted thrown exception successfully, append it.
      builder->AppendCStringLiteral("<error: ");
      builder->AppendString(err_str.ToHandleChecked());
      builder->AppendCharacter('>');
    }
  } else {
    builder->AppendString(err_str.ToHandleChecked());
  }

  return error;
}

class V8_NODISCARD PrepareStackTraceScope {
 public:
  explicit PrepareStackTraceScope(Isolate* isolate) : isolate_(isolate) {
    DCHECK(!isolate_->formatting_stack_trace());
    isolate_->set_formatting_stack_trace(true);
  }

  ~PrepareStackTraceScope() { isolate_->set_formatting_stack_trace(false); }

  PrepareStackTraceScope(const PrepareStackTraceScope&) = delete;
  PrepareStackTraceScope& operator=(const PrepareStackTraceScope&) = delete;

 private:
  Isolate* isolate_;
};

}  // namespace

// static
MaybeHandle<Object> ErrorUtils::FormatStackTrace(
    Isolate* isolate, Handle<JSObject> error, DirectHandle<Object> raw_stack) {
  if (v8_flags.correctness_fuzzer_suppressions) {
    return isolate->factory()->empty_string();
  }
  DCHECK(IsFixedArray(*raw_stack));
  auto elems = Cast<FixedArray>(raw_stack);

  const bool in_recursion = isolate->formatting_stack_trace();
  const bool has_overflowed = i::StackLimitCheck{isolate}.HasOverflowed();
  Handle<NativeContext> error_context;
  if (!in_recursion && !has_overflowed &&
      error->GetCreationContext(isolate).ToHandle(&error_context)) {
    if (isolate->HasPrepareStackTraceCallback()) {
      PrepareStackTraceScope scope(isolate);

      Handle<JSArray> sites;
      ASSIGN_RETURN_ON_EXCEPTION(isolate, sites,
                                 GetStackFrames(isolate, elems));

      Handle<Object> result;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, result,
          isolate->RunPrepareStackTraceCallback(error_context, error, sites));
      return result;
    } else {
      Handle<JSFunction> global_error =
          handle(error_context->error_function(), isolate);

      // If there's a user-specified "prepareStackTrace" function, call it on
      // the frames and use its result.

      Handle<Object> prepare_stack_trace;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, prepare_stack_trace,
          JSFunction::GetProperty(isolate, global_error, "prepareStackTrace"));

      if (IsJSFunction(*prepare_stack_trace)) {
        PrepareStackTraceScope scope(isolate);

        isolate->CountUsage(v8::Isolate::kErrorPrepareStackTrace);

        Handle<JSArray> sites;
        ASSIGN_RETURN_ON_EXCEPTION(isolate, sites,
                                   GetStackFrames(isolate, elems));

        constexpr int argc = 2;
        std::array<Handle<Object>, argc> argv;
        if (V8_UNLIKELY(IsJSGlobalObject(*error))) {
          // Pass global proxy instead of global object.
          argv[0] =
              handle(Cast<JSGlobalObject>(*error)->global_proxy(), isolate);
        } else {
          argv[0] = error;
        }
        argv[1] = sites;

        Handle<Object> result;

        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, result,
            Execution::Call(isolate, prepare_stack_trace, global_error, argc,
                            argv.data()));
        return result;
      }
    }
  }

  // Otherwise, run our internal formatting logic.
  IncrementalStringBuilder builder(isolate);

  RETURN_ON_EXCEPTION(isolate, AppendErrorString(isolate, error, &builder));

  for (int i = 0; i < elems->length(); ++i) {
    builder.AppendCStringLiteral("\n    at ");

    DirectHandle<CallSiteInfo> frame(Cast<CallSiteInfo>(elems->get(i)),
                                     isolate);

    v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
    SerializeCallSiteInfo(isolate, frame, &builder);

    if (isolate->has_exception()) {
      // CallSite.toString threw. Parts of the current frame might have been
      // stringified already regardless. Still, try to append a string
      // representation of the thrown exception.

      Handle<Object> exception(isolate->exception(), isolate);
      try_catch.Reset();

      MaybeHandle<String> exception_string =
          ErrorUtils::ToString(isolate, exception);
      if (exception_string.is_null()) {
        // Formatting the thrown exception threw again, give up.

        builder.AppendCStringLiteral("<error>");
      } else {
        // Formatted thrown exception successfully, append it.
        builder.AppendCStringLiteral("<error: ");
        builder.AppendString(exception_string.ToHandleChecked());
        builder.AppendCStringLiteral("<error>");
      }
    }
  }

  return indirect_handle(builder.Finish(), isolate);
}

Handle<String> MessageFormatter::Format(
    Isolate* isolate, MessageTemplate index,
    base::Vector<const DirectHandle<Object>> args) {
  constexpr size_t kMaxArgs = 3;
  DirectHandle<String> arg_strings[kMaxArgs];
  DCHECK_LE(args.size(), kMaxArgs);
  for (size_t i = 0; i < args.size(); ++i) {
    DCHECK(!args[i].is_null());
    arg_strings[i] = Object::NoSideEffectsToString(isolate, args[i]);
  }
  v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  try_catch.SetVerbose(false);
  try_catch.SetCaptureMessage(false);
  MaybeHandle<String> maybe_result_string = MessageFormatter::TryFormat(
      isolate, index, base::VectorOf(arg_strings, args.size()));
  Handle<String> result_string;
  if (!maybe_result_string.ToHandle(&result_string)) {
    DCHECK(isolate->has_exception());
    return isolate->factory()->InternalizeString(
        base::StaticCharVector("<error>"));
  }
  // A string that has been obtained from JS code in this way is
  // likely to be a complicated ConsString of some sort.  We flatten it
  // here to improve the efficiency of converting it to a C string and
  // other operations that are likely to take place (see GetLocalizedMessage
  // for example).
  return String::Flatten(isolate, result_string);
}

const char* MessageFormatter::TemplateString(MessageTemplate index) {
  switch (index) {
#define CASE(NAME, STRING)       \
  case MessageTemplate::k##NAME: \
    return STRING;
    MESSAGE_TEMPLATES(CASE)
#undef CASE
    case MessageTemplate::kMessageCount:
      UNREACHABLE();
  }
}

MaybeHandle<String> MessageFormatter::TryFormat(
    Isolate* isolate, MessageTemplate index,
    base::Vector<const DirectHandle<String>> args) {
  const char* template_string = TemplateString(index);

  IncrementalStringBuilder builder(isolate);

  // TODO(14386): Get this list empty.
  static constexpr MessageTemplate kTemplatesWithMismatchedArguments[] = {
      MessageTemplate::kConstAssign,
      MessageTemplate::kConstructorNotReceiver,
      MessageTemplate::kDataCloneErrorDetachedArrayBuffer,
      MessageTemplate::kDataCloneErrorOutOfMemory,
      MessageTemplate::kIncompatibleMethodReceiver,
      MessageTemplate::kInvalidArgument,
      MessageTemplate::kInvalidArrayLength,
      MessageTemplate::kInvalidAtomicAccessIndex,
      MessageTemplate::kInvalidDataViewLength,
      MessageTemplate::kInvalidIndex,
      MessageTemplate::kInvalidLhsInAssignment,
      MessageTemplate::kInvalidLhsInFor,
      MessageTemplate::kInvalidLhsInPostfixOp,
      MessageTemplate::kInvalidLhsInPrefixOp,
      MessageTemplate::kInvalidPrivateBrandReinitialization,
      MessageTemplate::kInvalidPrivateFieldReinitialization,
      MessageTemplate::kInvalidPrivateMemberWrite,
      MessageTemplate::kInvalidRegExpExecResult,
      MessageTemplate::kInvalidTimeValue,
      MessageTemplate::kInvalidWeakMapKey,
      MessageTemplate::kInvalidWeakSetValue,
      MessageTemplate::kIteratorReduceNoInitial,
      MessageTemplate::kJsonParseShortString,
      MessageTemplate::kJsonParseUnexpectedEOS,
      MessageTemplate::kJsonParseUnexpectedTokenEndStringWithContext,
      MessageTemplate::kJsonParseUnexpectedTokenShortString,
      MessageTemplate::kJsonParseUnexpectedTokenStartStringWithContext,
      MessageTemplate::kJsonParseUnexpectedTokenSurroundStringWithContext,
      MessageTemplate::kMustBePositive,
      MessageTemplate::kNotIterable,
      MessageTemplate::kNotTypedArray,
      MessageTemplate::kProxyNonObject,
      MessageTemplate::kProxyPrivate,
      MessageTemplate::kProxyRevoked,
      MessageTemplate::kProxyTrapReturnedFalsishFor,
      MessageTemplate::kReduceNoInitial,
      MessageTemplate::kSpreadIteratorSymbolNonCallable,
      MessageTemplate::kSymbolIteratorInvalid,
      MessageTemplate::kTopLevelAwaitStalled,
      MessageTemplate::kUndefinedOrNullToObject,
      MessageTemplate::kUnexpectedStrictReserved,
      MessageTemplate::kUnexpectedTokenIdentifier,
      MessageTemplate::kWeakRefsCleanupMustBeCallable};

  base::Vector<const DirectHandle<String>> remaining_args = args;
  for (const char* c = template_string; *c != '\0'; c++) {
    if (*c == '%') {
      // %% results in verbatim %.
      if (*(c + 1) == '%') {
        c++;
        builder.AppendCharacter('%');
      } else {
        // TODO(14386): Remove this fallback.
        if (remaining_args.empty()) {
          if (std::count(std::begin(kTemplatesWithMismatchedArguments),
                         std::end(kTemplatesWithMismatchedArguments), index)) {
            builder.AppendCString("undefined");
          } else {
            FATAL("Missing argument to template (got %zu): %s", args.size(),
                  template_string);
          }
        } else {
          DirectHandle<String> arg = remaining_args[0];
          remaining_args += 1;
          builder.AppendString(arg);
        }
      }
    } else {
      builder.AppendCharacter(*c);
    }
  }
  if (!remaining_args.empty() &&
      std::count(std::begin(kTemplatesWithMismatchedArguments),
                 std::end(kTemplatesWithMismatchedArguments), index) == 0) {
    FATAL("Too many arguments to template (expected %zu, got %zu): %s",
          args.size() - remaining_args.size(), args.size(), template_string);
  }

  return indirect_handle(builder.Finish(), isolate);
}

MaybeHandle<JSObject> ErrorUtils::Construct(Isolate* isolate,
                                            Handle<JSFunction> target,
                                            Handle<Object> new_target,
                                            DirectHandle<Object> message,
                                            Handle<Object> options) {
  FrameSkipMode mode = SKIP_FIRST;
  Handle<Object> caller;

  // When we're passed a JSFunction as new target, we can skip frames until that
  // specific function is seen instead of unconditionally skipping the first
  // frame.
  if (IsJSFunction(*new_target)) {
    mode = SKIP_UNTIL_SEEN;
    caller = new_target;
  }

  return ErrorUtils::Construct(isolate, target, new_target, message, options,
                               mode, caller,
                               ErrorUtils::StackTraceCollection::kEnabled);
}

MaybeHandle<JSObject> ErrorUtils::Construct(
    Isolate* isolate, Handle<JSFunction> target, Handle<Object> new_target,
    DirectHandle<Object> message, Handle<Object> options, FrameSkipMode mode,
    Handle<Object> caller, StackTraceCollection stack_trace_collection) {
  if (v8_flags.correctness_fuzzer_suppressions) {
    // Abort range errors in correctness fuzzing, as their causes differ
    // accross correctness-fuzzing scenarios.
    if (target.is_identical_to(isolate->range_error_function())) {
      FATAL("Aborting on range error");
    }
    // Ignore error messages in correctness fuzzing, because the spec leaves
    // room for undefined behavior.
    message = isolate->factory()->InternalizeUtf8String(
        "Message suppressed for fuzzers (--correctness-fuzzer-suppressions)");
  }

  // 1. If NewTarget is undefined, let newTarget be the active function object,
  // else let newTarget be NewTarget.
  Handle<JSReceiver> new_target_recv = IsJSReceiver(*new_target)
                                           ? Cast<JSReceiver>(new_target)
                                           : Cast<JSReceiver>(target);

  // 2. Let O be ? OrdinaryCreateFromConstructor(newTarget, "%ErrorPrototype%",
  //    « [[ErrorData]] »).
  Handle<JSObject> err;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, err,
      JSObject::New(target, new_target_recv, Handle<AllocationSite>::null()));

  // 3. If message is not undefined, then
  //  a. Let msg be ? ToString(message).
  //  b. Let msgDesc be the PropertyDescriptor{[[Value]]: msg, [[Writable]]:
  //     true, [[Enumerable]]: false, [[Configurable]]: true}.
  //  c. Perform ! DefinePropertyOrThrow(O, "message", msgDesc).
  // 4. Return O.
  if (!IsUndefined(*message, isolate)) {
    Handle<String> msg_string;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, msg_string,
        indirect_handle(Object::ToString(isolate, message), isolate));
    RETURN_ON_EXCEPTION(isolate, JSObject::SetOwnPropertyIgnoreAttributes(
                                     err, isolate->factory()->message_string(),
                                     msg_string, DONT_ENUM));

    if (v8_flags.use_original_message_for_stack_trace) {
      RETURN_ON_EXCEPTION(isolate,
                          JSObject::SetOwnPropertyIgnoreAttributes(
                              err, isolate->factory()->error_message_symbol(),
                              msg_string, DONT_ENUM));
    }
  }

  if (!IsUndefined(*options, isolate)) {
    // If Type(options) is Object and ? HasProperty(options, "cause") then
    //   a. Let cause be ? Get(options, "cause").
    //   b. Perform ! CreateNonEnumerableDataPropertyOrThrow(O, "cause", cause).
    Handle<Name> cause_string = isolate->factory()->cause_string();
    if (IsJSReceiver(*options)) {
      Handle<JSReceiver> js_options = Cast<JSReceiver>(options);
      Maybe<bool> has_cause =
          JSObject::HasProperty(isolate, js_options, cause_string);
      if (has_cause.IsNothing()) {
        DCHECK((isolate)->has_exception());
        return MaybeHandle<JSObject>();
      }
      if (has_cause.ToChecked()) {
        Handle<Object> cause;
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, cause,
            JSObject::GetProperty(isolate, js_options, cause_string));
        RETURN_ON_EXCEPTION(isolate, JSObject::SetOwnPropertyIgnoreAttributes(
                                         err, cause_string, cause, DONT_ENUM));
      }
    }
  }

  switch (stack_trace_collection) {
    case StackTraceCollection::kEnabled:
      RETURN_ON_EXCEPTION(isolate,
                          isolate->CaptureAndSetErrorStack(err, mode, caller));
      break;
    case StackTraceCollection::kDisabled:
      break;
  }
  return err;
}

namespace {

MaybeHandle<String> GetStringPropertyOrDefault(Isolate* isolate,
                                               Handle<JSReceiver> recv,
                                               Handle<String> key,
                                               Handle<String> default_str) {
  Handle<Object> obj;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, obj,
                             JSObject::GetProperty(isolate, recv, key));

  Handle<String> str;
  if (IsUndefined(*obj, isolate)) {
    str = default_str;
  } else {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, str, Object::ToString(isolate, obj));
  }

  return str;
}

}  // namespace

// ES6 section 19.5.3.4 Error.prototype.toString ( )
MaybeHandle<String> ErrorUtils::ToString(Isolate* isolate,
                                         Handle<Object> receiver,
                                         ToStringMessageSource message_source) {
  // 1. Let O be the this value.
  // 2. If Type(O) is not Object, throw a TypeError exception.
  Handle<JSReceiver> recv;
  if (!TryCast<JSReceiver>(receiver, &recv)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "Error.prototype.toString"),
                                 receiver));
  }
  // 3. Let name be ? Get(O, "name").
  // 4. If name is undefined, let name be "Error"; otherwise let name be
  // ? ToString(name).
  Handle<String> name_key = isolate->factory()->name_string();
  Handle<String> name_default = isolate->factory()->Error_string();
  Handle<String> name;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, name,
      GetStringPropertyOrDefault(isolate, recv, name_key, name_default));

  // 5. Let msg be ? Get(O, "message").
  // 6. If msg is undefined, let msg be the empty String; otherwise let msg be
  // ? ToString(msg).
  Handle<String> msg;
  Handle<String> msg_default = isolate->factory()->empty_string();
  if (message_source == ToStringMessageSource::kPreferOriginalMessage) {
    // V8-specific extension for Error.stack: Use the original message with
    // which the Error constructor was called. This keeps Error.stack consistent
    // w.r.t. "message" property changes regardless of the time when Error.stack
    // is accessed the first time.
    //
    // If |recv| was not constructed with %Error%, use the "message" property.
    LookupIterator it(isolate, LookupIterator::PROTOTYPE_CHAIN_SKIP_INTERCEPTOR,
                      recv, isolate->factory()->error_message_symbol());
    Handle<Object> result = JSReceiver::GetDataProperty(&it);
    if (it.IsFound() && IsUndefined(*result, isolate)) {
      msg = msg_default;
    } else if (it.IsFound()) {
      ASSIGN_RETURN_ON_EXCEPTION(isolate, msg,
                                 Object::ToString(isolate, result));
    }
  }

  if (msg.is_null()) {
    Handle<String> msg_key = isolate->factory()->message_string();
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, msg,
        GetStringPropertyOrDefault(isolate, recv, msg_key, msg_default));
  }

  // 7. If name is the empty String, return msg.
  // 8. If msg is the empty String, return name.
  if (name->length() == 0) return msg;
  if (msg->length() == 0) return name;

  // 9. Return the result of concatenating name, the code unit 0x003A (COLON),
  // the code unit 0x0020 (SPACE), and msg.
  IncrementalStringBuilder builder(isolate);
  builder.AppendString(name);
  builder.AppendCStringLiteral(": ");
  builder.AppendString(msg);

  Handle<String> result;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                             indirect_handle(builder.Finish(), isolate));
  return result;
}

// static
Handle<JSObject> ErrorUtils::MakeGenericError(
    Isolate* isolate, Handle<JSFunction> constructor, MessageTemplate index,
    base::Vector<const DirectHandle<Object>> args, FrameSkipMode mode) {
  if (v8_flags.clear_exceptions_on_js_entry) {
    // This function used to be implemented in JavaScript, and JSEntry
    // clears any exceptions - so whenever we'd call this from C++,
    // exceptions would be cleared. Preserve this behavior.
    isolate->clear_exception();
    isolate->clear_pending_message();
  }
  DirectHandle<String> msg = MessageFormatter::Format(isolate, index, args);
  Handle<Object> options = isolate->factory()->undefined_value();

  DCHECK(mode != SKIP_UNTIL_SEEN);

  Handle<Object> no_caller;
  // The call below can't fail because constructor is a builtin.
  DCHECK(constructor->shared()->HasBuiltinId());
  return ErrorUtils::Construct(isolate, constructor, constructor, msg, options,
                               mode, no_caller, StackTraceCollection::kEnabled)
      .ToHandleChecked();
}

// static
Handle<JSObject> ErrorUtils::ShadowRealmConstructTypeErrorCopy(
    Isolate* isolate, Handle<Object> original, MessageTemplate index,
    base::Vector<const DirectHandle<Object>> args) {
  if (v8_flags.clear_exceptions_on_js_entry) {
    // This function used to be implemented in JavaScript, and JSEntry
    // clears any exceptions - so whenever we'd call this from C++,
    // exceptions would be cleared. Preserve this behavior.
    isolate->clear_exception();
    isolate->clear_pending_message();
  }
  DirectHandle<String> msg = MessageFormatter::Format(isolate, index, args);
  Handle<Object> options = isolate->factory()->undefined_value();

  Handle<JSObject> maybe_error_object;
  Handle<Object> error_stack;
  StackTraceCollection collection = StackTraceCollection::kEnabled;
  if (IsJSObject(*original)) {
    maybe_error_object = Cast<JSObject>(original);
    if (!ErrorUtils::GetFormattedStack(isolate, maybe_error_object)
             .ToHandle(&error_stack)) {
      DCHECK(isolate->has_exception());
      DirectHandle<Object> exception = handle(isolate->exception(), isolate);
      isolate->clear_exception();
      // Return a new side-effect-free TypeError to be loud about inner error.
      DirectHandle<String> string =
          Object::NoSideEffectsToString(isolate, exception);
      return isolate->factory()->NewTypeError(
          MessageTemplate::kShadowRealmErrorStackThrows, string);
    } else if (IsNullOrUndefined(*error_stack)) {
      // If the error stack property is null or undefined, create a new error.
      collection = StackTraceCollection::kEnabled;
    } else if (IsPrimitive(*error_stack)) {
      // If the error stack property is found (must be a formatted string, not
      // an unformatted FixedArray), set collection to disabled and reuse the
      // existing stack. If the `Error.prepareStackTrace` returned a primitive,
      // use it as the stack as well.
      collection = StackTraceCollection::kDisabled;
    } else {
      // The error stack property is an arbitrary value. Return a new TypeError
      // about the non-string value.
      DirectHandle<String> string =
          Object::NoSideEffectsToString(isolate, error_stack);
      return isolate->factory()->NewTypeError(
          MessageTemplate::kShadowRealmErrorStackNonString, string);
    }
  }

  Handle<Object> no_caller;
  Handle<JSFunction> constructor = isolate->type_error_function();
  Handle<JSObject> new_error =
      ErrorUtils::Construct(isolate, constructor, constructor, msg, options,
                            FrameSkipMode::SKIP_NONE, no_caller, collection)
          .ToHandleChecked();

  // If collection is disabled, reuse the existing stack string from the
  // original error object.
  if (collection == StackTraceCollection::kDisabled) {
    // Error stack symbol is a private symbol and set it on an error object
    // created from built-in error constructor should not throw.
    Object::SetProperty(
        isolate, new_error, isolate->factory()->error_stack_symbol(),
        error_stack, StoreOrigin::kMaybeKeyed, Just(ShouldThrow::kThrowOnError))
        .Check();
  }

  return new_error;
}

namespace {

bool ComputeLocation(Isolate* isolate, MessageLocation* target) {
  JavaScriptStackFrameIterator it(isolate);
  if (!it.done()) {
    // Compute the location from the function and the relocation info of the
    // baseline code. For optimized code this will use the deoptimization
```