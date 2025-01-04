Response: Let's break down the thought process for analyzing this C++ test file for V8 and relating it to JavaScript.

1. **Understanding the Goal:** The primary goal is to understand what this C++ code *tests* and how that relates to JavaScript's behavior, specifically around stack traces.

2. **Initial Scan for Keywords:** I'd quickly scan the code for obvious keywords related to stack traces. I see:
    * `PrepareStackTrace` (used in two test cases)
    * `StackTrace` (used in several tests and as a class name)
    * `Exception::CreateMessage` and `Exception::GetStackTrace`
    * `GetLineNumber`, `GetColumn`, `GetFunctionName`, `GetScriptName`, `IsEval`, `IsConstructor` (methods of `v8::StackFrame`)
    * `SetCaptureStackTraceForUncaughtExceptions`
    * `AddMessageListener` (used with stack trace related handlers)
    * `CompileRun` (a helper function for running JavaScript code within the test)

3. **Analyzing Individual Test Cases:** I'd go through each `TEST` or `THREADED_TEST` block and try to understand its purpose:

    * **`IsolatePrepareStackTrace` and `IsolatePrepareStackTraceThrow`:** These tests clearly involve the `SetPrepareStackTraceCallback`. The first one checks that a custom callback can modify the `stack` property of an error. The second checks what happens when the callback itself throws an error. *JavaScript connection:* This directly maps to the `Error.prepareStackTrace` functionality in JavaScript.

    * **`ExceptionCreateMessage`:** This test uses `ThrowV8Exception` (a C++ function called from JS) and then `v8::Exception::CreateMessage`. It checks the line number and column of the error and the stack trace. *JavaScript connection:*  This is about how V8 formats error messages and provides stack trace information when exceptions occur.

    * **`StackTrace` (the one without `THREADED_`):** This test directly executes JavaScript code that throws an error and then uses `try_catch.StackTrace()` to get the stack trace as a string. It checks that the function name and script name are present in the output. *JavaScript connection:* This tests the basic functionality of accessing the `stack` property of an error object.

    * **Tests involving `AnalyzeStackInNativeCode`:**  These are more complex. The C++ function `AnalyzeStackInNativeCode` is called from JavaScript. Inside this C++ function, `v8::StackTrace::CurrentStackTrace` is used with different options (`kOverview`, `kDetailed`, `kScriptId`). The `checkStackFrame` helper function confirms the properties of each stack frame. *JavaScript connection:*  This is testing the API for getting detailed information about the call stack programmatically from within native code when called from JavaScript. It explores different levels of detail and different properties of the stack frames.

    * **`CaptureStackTraceForUncaughtException`:** This test uses `AddMessageListener` to intercept uncaught exceptions and checks the stack trace of those exceptions. It also uses `SetCaptureStackTraceForUncaughtExceptions(true)`. *JavaScript connection:* This tests how V8 captures stack traces for uncaught exceptions and how developers can access this information.

    * **`CaptureStackTraceForUncaughtExceptionAndSetters`:** This test is similar but involves an exception thrown in a setter. *JavaScript connection:* This explores edge cases in exception handling related to property setters.

    * **Tests with `StackTraceFunctionNameListener`:**  These tests examine how function names (including those dynamically set or having getters) are reflected in stack traces. *JavaScript connection:* This relates to how JavaScript function names are tracked and displayed in error messages and stack traces.

    * **Rethrow tests (`RethrowStackTrace`, `RethrowPrimitiveStackTrace`, `RethrowExistingStackTrace`, `RethrowBogusErrorStackTrace`):** These tests explore how stack traces are handled when exceptions are caught and rethrown. They test different scenarios, including rethrowing primitive values and objects that aren't true `Error` instances. *JavaScript connection:* This tests the behavior of JavaScript's `try...catch` and `throw` statements with respect to stack trace preservation.

    * **Tests with "SourceURL" in the name:** These tests specifically focus on how `//# sourceURL` or `//@ sourceURL` directives are reflected in the stack trace information, particularly in `eval` and dynamically created scripts. *JavaScript connection:* This is about how debugging tools can map code executed via `eval` or dynamic script creation back to source files.

    * **`ScriptIdInStackTrace`:** This test specifically checks that the `scriptId` is correctly reported in the stack trace. *JavaScript connection:*  This is a more internal detail, but it's important for tools that need to uniquely identify scripts.

    * **`CaptureStackTraceForStackOverflow`:** This test deliberately causes a stack overflow and checks if a stack trace is still captured. *JavaScript connection:* This tests the robustness of stack trace capture even under extreme conditions.

    * **`CurrentScriptNameOrSourceURL` tests:** These tests examine the `v8::StackTrace::CurrentScriptNameOrSourceURL` API to get the name or URL of the currently executing script. *JavaScript connection:*  While not directly exposed in JavaScript, this underlies how the script name is determined in stack traces.

4. **Identifying Core Functionality and JavaScript Equivalents:** After analyzing the tests, I would summarize the key areas being tested and their JavaScript counterparts:

    * **Customizing Stack Traces:** The `IsolatePrepareStackTrace` tests directly correspond to `Error.prepareStackTrace`.
    * **Basic Stack Trace Generation:** The `StackTrace` test using `try...catch` and `.stack` is the most fundamental way to get a stack trace in JavaScript.
    * **Programmatic Stack Trace Access:** The `AnalyzeStackInNativeCode` tests using `v8::StackTrace::CurrentStackTrace` don't have a direct JavaScript equivalent for *full* programmatic access. However, libraries or browser extensions might use similar native APIs.
    * **Stack Traces for Uncaught Exceptions:** The `CaptureStackTraceForUncaughtException` tests relate to how browsers typically log uncaught exceptions with stack traces in the console. There's no direct JavaScript API to intercept these *before* they reach the browser's default handler.
    * **Handling Rethrown Exceptions:** The rethrow tests directly demonstrate the behavior of `try...catch` and `throw` in JavaScript and how stack traces are (or are not) modified.
    * **Source Maps and `eval`:** The "SourceURL" tests are crucial for understanding how JavaScript debugging works with code generated by `eval` or similar mechanisms.
    * **Stack Overflow Handling:** The `CaptureStackTraceForStackOverflow` test shows V8's ability to provide *some* information even in stack overflow situations.

5. **Structuring the Explanation:**  Finally, I'd organize the findings into a clear and concise explanation, using JavaScript examples where appropriate to illustrate the concepts. The initial decomposed thoughts would be synthesized into a more structured summary. The use of code blocks for JavaScript examples is important for clarity.

This step-by-step approach, combining code analysis with knowledge of JavaScript behavior, allows for a comprehensive understanding of the C++ test file's purpose and its connection to JavaScript.
这个C++源代码文件 `v8/test/cctest/test-api-stack-traces.cc` 的主要功能是 **测试 V8 引擎中关于堆栈跟踪 (stack traces) 的 API 功能**。它通过编写一系列的单元测试来验证 V8 在生成、获取和处理堆栈跟踪信息时的正确性。

以下是它涵盖的主要测试点：

1. **自定义堆栈跟踪的准备 (Customizing Stack Trace Preparation):**
   - 测试了 `Isolate::SetPrepareStackTraceCallback` API，该 API 允许开发者自定义 `Error` 对象的 `stack` 属性的生成方式。
   - 测试了自定义回调函数可以返回一个值（例如数字），也可以抛出异常。

2. **创建异常消息 (Creating Exception Messages):**
   - 测试了 `v8::Exception::CreateMessage` API，用于根据一个 `Value` (通常是 `Error` 对象) 创建一个 `v8::Message` 对象，其中包含了异常的信息，包括行号、列号和堆栈跟踪。

3. **获取堆栈跟踪信息 (Getting Stack Trace Information):**
   - 测试了 `v8::Exception::GetStackTrace` API，用于直接从一个 `Value` (通常是 `Error` 对象) 获取 `v8::StackTrace` 对象。
   - 测试了 `v8::Message::GetStackTrace` API，用于从 `v8::Message` 对象获取 `v8::StackTrace` 对象。
   - 测试了 `v8::StackTrace::CurrentStackTrace` API，用于在 C++ 代码中获取当前的堆栈跟踪信息。它测试了不同的模式，如 `kOverview` (概览信息) 和 `kDetailed` (详细信息)。
   - 测试了 `v8::StackFrame` 的各种方法，如 `GetFunctionName`、`GetScriptName`、`GetLineNumber`、`GetColumn`、`IsEval`、`IsConstructor` 等，用于获取堆栈帧的详细信息。

4. **捕获未捕获的异常的堆栈跟踪 (Capturing Stack Traces for Uncaught Exceptions):**
   - 测试了 `Isolate::SetCaptureStackTraceForUncaughtExceptions` API，该 API 允许在发生未捕获的异常时捕获堆栈跟踪信息。
   - 测试了如何通过 `Isolate::AddMessageListener` 监听异常消息，并从中获取堆栈跟踪信息。
   - 测试了在 setter 中抛出异常时如何捕获堆栈跟踪。

5. **处理函数名 (Handling Function Names):**
   - 测试了当 JavaScript 函数具有 `name` 属性或 `displayName` 属性时，这些信息如何在堆栈跟踪中体现。

6. **处理重新抛出的异常 (Handling Rethrown Exceptions):**
   - 测试了当异常被捕获并重新抛出时，堆栈跟踪信息是否指向原始抛出点，而不是重新抛出的位置。
   - 测试了原始类型 (primitive) 的异常在重新抛出时的堆栈跟踪行为。
   - 测试了当一个已存在的 `Error` 对象被抛出时，堆栈跟踪信息是在对象创建时捕获的。

7. **SourceURL 支持 (SourceURL Support):**
   - 测试了 `//# sourceURL` 和 `//@ sourceURL` 注释在 `eval` 和动态创建的脚本中如何影响堆栈跟踪中显示的文件名或 URL。

8. **Script ID 支持 (Script ID Support):**
   - 测试了 `v8::StackTrace::kScriptId` 模式，可以获取堆栈帧对应的脚本 ID。

9. **内联脚本和动态脚本的 SourceURL (SourceURL for Inline and Dynamic Scripts):**
   - 测试了内联脚本和动态脚本的 `sourceURL` 在堆栈跟踪中的显示。

10. **堆栈溢出时的堆栈跟踪 (Stack Trace for Stack Overflow):**
    - 测试了在发生堆栈溢出时，V8 仍然能够捕获堆栈跟踪信息。

11. **获取当前脚本名或 SourceURL (Getting Current Script Name or SourceURL):**
    - 测试了 `v8::StackTrace::CurrentScriptNameOrSourceURL` API，用于获取当前执行脚本的文件名或 SourceURL。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个 C++ 测试文件验证的是 V8 引擎的底层实现，这些实现直接影响 JavaScript 中与错误处理和调试相关的行为。以下是一些 JavaScript 示例，展示了这些测试所覆盖的 JavaScript 功能：

**1. 自定义堆栈跟踪 (Using `Error.prepareStackTrace`)**

```javascript
Error.prepareStackTrace = function(error, structuredStackTrace) {
  return structuredStackTrace.map(function(frame) {
    return `  at ${frame.getFunctionName()} (${frame.getFileName()}:${frame.getLineNumber()}:${frame.getColumnNumber()})`;
  }).join('\n');
};

try {
  throw new Error('Something went wrong');
} catch (e) {
  console.log(e.stack);
}
```

**2. 获取堆栈信息 (`error.stack`)**

```javascript
function foo() {
  bar();
}

function bar() {
  try {
    throw new Error('An error occurred');
  } catch (e) {
    console.log(e.stack); // 输出堆栈信息
  }
}

foo();
```

**3. 捕获未捕获的异常 (Browser's Error Handling)**

当 JavaScript 代码中发生未捕获的异常时，浏览器通常会在控制台中打印错误消息和堆栈跟踪。`Isolate::SetCaptureStackTraceForUncaughtExceptions` 的测试就是模拟和验证 V8 引擎在这种情况下的行为。

**4. SourceURL 的作用**

```javascript
// eval 代码
eval('function hello() { console.log("Hello from eval"); throw new Error("Eval Error"); } hello(); //# sourceURL=eval_script.js');

// 动态创建 script 标签
const script = document.createElement('script');
script.text = 'function dynamicFunc() { console.log("Hello from dynamic"); throw new Error("Dynamic Error"); } dynamicFunc(); // @ sourceURL=dynamic_script.js';
document.body.appendChild(script);
```

在开发者工具中，当这些代码抛出错误时，堆栈跟踪会显示 `eval_script.js` 或 `dynamic_script.js` 作为文件名，这就是 C++ 测试中 SourceURL 相关测试所验证的功能。

**总结:**

`test-api-stack-traces.cc` 文件是 V8 引擎中一个非常重要的测试文件，它确保了 V8 提供的用于处理和生成堆栈跟踪的 API 的正确性和稳定性。这些 API 直接影响着 JavaScript 开发者在调试和错误处理过程中所能获取的信息的准确性，例如 `error.stack` 属性的内容以及浏览器控制台中显示的错误堆栈信息。理解这个测试文件有助于深入了解 V8 引擎的内部工作原理以及 JavaScript 错误处理机制的底层实现。

Prompt: 
```
这是目录为v8/test/cctest/test-api-stack-traces.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/base/strings.h"
#include "test/cctest/test-api.h"

using ::v8::Array;
using ::v8::Context;
using ::v8::Local;
using ::v8::ObjectTemplate;
using ::v8::String;
using ::v8::TryCatch;
using ::v8::Value;

static v8::MaybeLocal<Value> PrepareStackTrace42(v8::Local<Context> context,
                                                 v8::Local<Value> error,
                                                 v8::Local<Array> trace) {
  return v8::Number::New(context->GetIsolate(), 42);
}

static v8::MaybeLocal<Value> PrepareStackTraceThrow(v8::Local<Context> context,
                                                    v8::Local<Value> error,
                                                    v8::Local<Array> trace) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<String> message = v8_str("42");
  isolate->ThrowException(v8::Exception::Error(message));
  return v8::MaybeLocal<Value>();
}

THREADED_TEST(IsolatePrepareStackTrace) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetPrepareStackTraceCallback(PrepareStackTrace42);

  v8::Local<Value> v = CompileRun("new Error().stack");

  CHECK(v->IsNumber());
  CHECK_EQ(v.As<v8::Number>()->Int32Value(context.local()).FromJust(), 42);
}

THREADED_TEST(IsolatePrepareStackTraceThrow) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetPrepareStackTraceCallback(PrepareStackTraceThrow);

  v8::Local<Value> v = CompileRun("try { new Error().stack } catch (e) { e }");

  CHECK(v->IsNativeError());

  v8::Local<String> message = v8::Exception::CreateMessage(isolate, v)->Get();

  CHECK(message->StrictEquals(v8_str("Uncaught Error: 42")));
}

static void ThrowV8Exception(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Local<String> foo = v8_str("foo");
  v8::Local<String> message = v8_str("message");
  v8::Local<Value> error = v8::Exception::Error(foo);
  CHECK(error->IsObject());
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  CHECK(error.As<v8::Object>()
            ->Get(context, message)
            .ToLocalChecked()
            ->Equals(context, foo)
            .FromJust());
  info.GetIsolate()->ThrowException(error);
  info.GetReturnValue().SetUndefined();
}

THREADED_TEST(ExceptionCreateMessage) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<String> foo_str = v8_str("foo");
  v8::Local<String> message_str = v8_str("message");

  context->GetIsolate()->SetCaptureStackTraceForUncaughtExceptions(true);

  Local<v8::FunctionTemplate> fun =
      v8::FunctionTemplate::New(context->GetIsolate(), ThrowV8Exception);
  v8::Local<v8::Object> global = context->Global();
  CHECK(global
            ->Set(context.local(), v8_str("throwV8Exception"),
                  fun->GetFunction(context.local()).ToLocalChecked())
            .FromJust());

  TryCatch try_catch(context->GetIsolate());
  CompileRun(
      "function f1() {\n"
      "  throwV8Exception();\n"
      "};\n"
      "f1();");
  CHECK(try_catch.HasCaught());

  v8::Local<v8::Value> error = try_catch.Exception();
  CHECK(error->IsObject());
  CHECK(error.As<v8::Object>()
            ->Get(context.local(), message_str)
            .ToLocalChecked()
            ->Equals(context.local(), foo_str)
            .FromJust());

  v8::Local<v8::Message> message =
      v8::Exception::CreateMessage(context->GetIsolate(), error);
  CHECK(!message.IsEmpty());
  CHECK_EQ(2, message->GetLineNumber(context.local()).FromJust());
  CHECK_EQ(2, message->GetStartColumn(context.local()).FromJust());

  v8::Local<v8::StackTrace> stackTrace = message->GetStackTrace();
  CHECK(!stackTrace.IsEmpty());
  CHECK_EQ(2, stackTrace->GetFrameCount());

  stackTrace = v8::Exception::GetStackTrace(error);
  CHECK(!stackTrace.IsEmpty());
  CHECK_EQ(2, stackTrace->GetFrameCount());

  context->GetIsolate()->SetCaptureStackTraceForUncaughtExceptions(false);

  // Now check message location when SetCaptureStackTraceForUncaughtExceptions
  // is false.
  try_catch.Reset();

  CompileRun(
      "function f2() {\n"
      "  return throwV8Exception();\n"
      "};\n"
      "f2();");
  CHECK(try_catch.HasCaught());

  error = try_catch.Exception();
  CHECK(error->IsObject());
  CHECK(error.As<v8::Object>()
            ->Get(context.local(), message_str)
            .ToLocalChecked()
            ->Equals(context.local(), foo_str)
            .FromJust());

  message = v8::Exception::CreateMessage(context->GetIsolate(), error);
  CHECK(!message.IsEmpty());
  CHECK_EQ(2, message->GetLineNumber(context.local()).FromJust());
  CHECK_EQ(9, message->GetStartColumn(context.local()).FromJust());

  // Should be empty stack trace.
  stackTrace = message->GetStackTrace();
  CHECK(stackTrace.IsEmpty());
  CHECK(v8::Exception::GetStackTrace(error).IsEmpty());
}

// TODO(szuend): Re-enable as a threaded test once investigated and fixed.
// THREADED_TEST(StackTrace) {
TEST(StackTrace) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  const char* source = "function foo() { FAIL.FAIL; }; foo();";
  v8::Local<v8::String> src = v8_str(source);
  v8::Local<v8::String> origin = v8_str("stack-trace-test");
  v8::ScriptCompiler::Source script_source(src, v8::ScriptOrigin(origin));
  CHECK(v8::ScriptCompiler::CompileUnboundScript(context->GetIsolate(),
                                                 &script_source)
            .ToLocalChecked()
            ->BindToCurrentContext()
            ->Run(context.local())
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  v8::String::Utf8Value stack(
      context->GetIsolate(),
      try_catch.StackTrace(context.local()).ToLocalChecked());
  CHECK_NOT_NULL(strstr(*stack, "at foo (stack-trace-test"));
}

// Checks that a StackFrame has certain expected values.
static void checkStackFrame(const char* expected_script_name,
                            const char* expected_script_source,
                            const char* expected_script_source_mapping_url,
                            const char* expected_func_name,
                            int expected_line_number, int expected_column,
                            bool is_eval, bool is_constructor,
                            v8::Local<v8::StackFrame> frame) {
  v8::HandleScope scope(CcTest::isolate());
  v8::String::Utf8Value func_name(CcTest::isolate(), frame->GetFunctionName());
  v8::String::Utf8Value script_name(CcTest::isolate(), frame->GetScriptName());
  v8::String::Utf8Value script_source(CcTest::isolate(),
                                      frame->GetScriptSource());
  v8::String::Utf8Value script_source_mapping_url(
      CcTest::isolate(), frame->GetScriptSourceMappingURL());
  if (*script_name == nullptr) {
    // The situation where there is no associated script, like for evals.
    CHECK_NULL(expected_script_name);
  } else {
    CHECK_NOT_NULL(strstr(*script_name, expected_script_name));
  }
  CHECK_NOT_NULL(strstr(*script_source, expected_script_source));
  if (*script_source_mapping_url == nullptr) {
    CHECK_NULL(expected_script_source_mapping_url);
  } else {
    CHECK_NOT_NULL(expected_script_source_mapping_url);
    CHECK_NOT_NULL(
        strstr(*script_source_mapping_url, expected_script_source_mapping_url));
  }
  if (!frame->GetFunctionName().IsEmpty()) {
    CHECK_NOT_NULL(strstr(*func_name, expected_func_name));
  }
  CHECK_EQ(expected_line_number, frame->GetLineNumber());
  CHECK_EQ(expected_column, frame->GetColumn());
  CHECK_EQ(is_eval, frame->IsEval());
  CHECK_EQ(is_constructor, frame->IsConstructor());
  CHECK(frame->IsUserJavaScript());
}

// Tests the C++ StackTrace API.

// Test getting OVERVIEW information. Should ignore information that is not
// script name, function name, line number, and column offset.
const char* overview_source_eval = "new foo();";
const char* overview_source =
    "function bar() {\n"
    "  var y; AnalyzeStackInNativeCode(1);\n"
    "}\n"
    "function foo() {\n"
    "\n"
    "  bar();\n"
    "}\n"
    "//# sourceMappingURL=http://foobar.com/overview.ts\n"
    "var x;eval('new foo();');";

// Test getting DETAILED information.
const char* detailed_source =
    "function bat() {AnalyzeStackInNativeCode(2);\n"
    "}\n"
    "\n"
    "function baz() {\n"
    "  bat();\n"
    "}\n"
    "eval('new baz();');";

// Test using function.name and function.displayName in stack trace
const char function_name_source[] =
    "function bar(function_name, display_name, testGroup) {\n"
    "  var f = new Function(`AnalyzeStackInNativeCode(${testGroup});`);\n"
    "  if (function_name) {\n"
    "    Object.defineProperty(f, 'name', { value: function_name });\n"
    "  }\n"
    "  if (display_name) {\n"
    "    f.displayName = display_name;"
    "  }\n"
    "  f()\n"
    "}\n"
    "bar('function.name', undefined, 3);\n"
    "bar('function.name', 'function.displayName', 4);\n"
    "bar(239, undefined, 5);\n";

// Maybe it's a bit pathological to depend on the exact format of the wrapper
// the Function constructor puts around it's input string. If this becomes a
// hassle, maybe come up with some regex matching approach?
const char function_name_source_anon3[] =
    "(function anonymous(\n"
    ") {\n"
    "AnalyzeStackInNativeCode(3);\n"
    "})";
const char function_name_source_anon4[] =
    "(function anonymous(\n"
    ") {\n"
    "AnalyzeStackInNativeCode(4);\n"
    "})";
const char function_name_source_anon5[] =
    "(function anonymous(\n"
    ") {\n"
    "AnalyzeStackInNativeCode(5);\n"
    "})";

static void AnalyzeStackInNativeCode(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::HandleScope scope(info.GetIsolate());
  const char* origin = "capture-stack-trace-test";
  const int kOverviewTest = 1;
  const int kDetailedTest = 2;
  const int kFunctionName = 3;
  const int kFunctionNameAndDisplayName = 4;
  const int kFunctionNameIsNotString = 5;

  CHECK_EQ(info.Length(), 1);

  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Isolate* isolate = info.GetIsolate();
  int testGroup = info[0]->Int32Value(context).FromJust();
  if (testGroup == kOverviewTest) {
    v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
        info.GetIsolate(), 10, v8::StackTrace::kOverview);
    CHECK_EQ(4, stackTrace->GetFrameCount());
    checkStackFrame(origin, overview_source, "//foobar.com/overview.ts", "bar",
                    2, 10, false, false,
                    stackTrace->GetFrame(info.GetIsolate(), 0));
    checkStackFrame(origin, overview_source, "//foobar.com/overview.ts", "foo",
                    6, 3, false, true, stackTrace->GetFrame(isolate, 1));
    // This is the source string inside the eval which has the call to foo.
    checkStackFrame(nullptr, "new foo();", nullptr, "", 1, 1, true, false,
                    stackTrace->GetFrame(isolate, 2));
    // The last frame is an anonymous function which has the initial eval call.
    checkStackFrame(origin, overview_source, "//foobar.com/overview.ts", "", 9,
                    7, false, false, stackTrace->GetFrame(isolate, 3));
  } else if (testGroup == kDetailedTest) {
    v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
        info.GetIsolate(), 10, v8::StackTrace::kDetailed);
    CHECK_EQ(4, stackTrace->GetFrameCount());
    checkStackFrame(origin, detailed_source, nullptr, "bat", 4, 22, false,
                    false, stackTrace->GetFrame(isolate, 0));
    checkStackFrame(origin, detailed_source, nullptr, "baz", 8, 3, false, true,
                    stackTrace->GetFrame(isolate, 1));
    bool is_eval = true;
    // This is the source string inside the eval which has the call to baz.
    checkStackFrame(nullptr, "new baz();", nullptr, "", 1, 1, is_eval, false,
                    stackTrace->GetFrame(isolate, 2));
    // The last frame is an anonymous function which has the initial eval call.
    checkStackFrame(origin, detailed_source, nullptr, "", 10, 1, false, false,
                    stackTrace->GetFrame(isolate, 3));
  } else if (testGroup == kFunctionName) {
    v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
        info.GetIsolate(), 5, v8::StackTrace::kOverview);
    CHECK_EQ(3, stackTrace->GetFrameCount());
    checkStackFrame(nullptr, function_name_source_anon3, nullptr,
                    "function.name", 3, 1, true, false,
                    stackTrace->GetFrame(isolate, 0));
  } else if (testGroup == kFunctionNameAndDisplayName) {
    v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
        info.GetIsolate(), 5, v8::StackTrace::kOverview);
    CHECK_EQ(3, stackTrace->GetFrameCount());
    checkStackFrame(nullptr, function_name_source_anon4, nullptr,
                    "function.name", 3, 1, true, false,
                    stackTrace->GetFrame(isolate, 0));
  } else if (testGroup == kFunctionNameIsNotString) {
    v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
        info.GetIsolate(), 5, v8::StackTrace::kOverview);
    CHECK_EQ(3, stackTrace->GetFrameCount());
    checkStackFrame(nullptr, function_name_source_anon5, nullptr, "", 3, 1,
                    true, false, stackTrace->GetFrame(isolate, 0));
  }
}

THREADED_TEST(CaptureStackTrace) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> origin = v8_str("capture-stack-trace-test");
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "AnalyzeStackInNativeCode",
             v8::FunctionTemplate::New(isolate, AnalyzeStackInNativeCode));
  LocalContext context(nullptr, templ);

  v8::Local<v8::String> overview_src = v8_str(overview_source);
  v8::ScriptCompiler::Source script_source(overview_src,
                                           v8::ScriptOrigin(origin));
  v8::Local<Value> overview_result(
      v8::ScriptCompiler::CompileUnboundScript(isolate, &script_source)
          .ToLocalChecked()
          ->BindToCurrentContext()
          ->Run(context.local())
          .ToLocalChecked());
  CHECK(!overview_result.IsEmpty());
  CHECK(overview_result->IsObject());

  v8::Local<v8::String> detailed_src = v8_str(detailed_source);
  // Make the script using a non-zero line and column offset.
  v8::ScriptOrigin detailed_origin(origin, 3, 5);
  v8::ScriptCompiler::Source script_source2(detailed_src, detailed_origin);
  v8::Local<v8::UnboundScript> detailed_script(
      v8::ScriptCompiler::CompileUnboundScript(isolate, &script_source2)
          .ToLocalChecked());
  v8::Local<Value> detailed_result(detailed_script->BindToCurrentContext()
                                       ->Run(context.local())
                                       .ToLocalChecked());
  CHECK(!detailed_result.IsEmpty());
  CHECK(detailed_result->IsObject());

  v8::Local<v8::String> function_name_src =
      v8::String::NewFromUtf8Literal(isolate, function_name_source);
  v8::ScriptCompiler::Source script_source3(function_name_src,
                                            v8::ScriptOrigin(origin));
  v8::Local<Value> function_name_result(
      v8::ScriptCompiler::CompileUnboundScript(isolate, &script_source3)
          .ToLocalChecked()
          ->BindToCurrentContext()
          ->Run(context.local())
          .ToLocalChecked());
  CHECK(!function_name_result.IsEmpty());
}

static int report_count = 0;

// Test uncaught exception
const char uncaught_exception_source[] =
    "function foo() {\n"
    "  throw 1;\n"
    "};\n"
    "function bar() {\n"
    "  foo();\n"
    "};";

static void StackTraceForUncaughtExceptionListener(
    v8::Local<v8::Message> message, v8::Local<Value>) {
  report_count++;
  v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();
  CHECK_EQ(2, stack_trace->GetFrameCount());
  checkStackFrame("origin", uncaught_exception_source, nullptr, "foo", 2, 3,
                  false, false,
                  stack_trace->GetFrame(message->GetIsolate(), 0));
  checkStackFrame("origin", uncaught_exception_source, nullptr, "bar", 5, 3,
                  false, false,
                  stack_trace->GetFrame(message->GetIsolate(), 1));
}

TEST(CaptureStackTraceForUncaughtException) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->AddMessageListener(StackTraceForUncaughtExceptionListener);
  isolate->SetCaptureStackTraceForUncaughtExceptions(true);

  CompileRunWithOrigin(uncaught_exception_source, "origin");
  v8::Local<v8::Object> global = env->Global();
  Local<Value> trouble =
      global->Get(env.local(), v8_str("bar")).ToLocalChecked();
  CHECK(trouble->IsFunction());
  CHECK(v8::Function::Cast(*trouble)
            ->Call(env.local(), global, 0, nullptr)
            .IsEmpty());
  isolate->SetCaptureStackTraceForUncaughtExceptions(false);
  isolate->RemoveMessageListeners(StackTraceForUncaughtExceptionListener);
  CHECK_EQ(1, report_count);
}

// Test uncaught exception in a setter
const char uncaught_setter_exception_source[] =
    "var setters = ['column', 'lineNumber', 'scriptName',\n"
    "    'scriptNameOrSourceURL', 'functionName', 'isEval',\n"
    "    'isConstructor'];\n"
    "for (let i = 0; i < setters.length; i++) {\n"
    "  let prop = setters[i];\n"
    "  Object.prototype.__defineSetter__(prop, function() { throw prop; });\n"
    "}\n";

static void StackTraceForUncaughtExceptionAndSettersListener(
    v8::Local<v8::Message> message, v8::Local<Value> value) {
  CHECK(value->IsObject());
  v8::Isolate* isolate = message->GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  report_count++;
  v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();
  CHECK_EQ(1, stack_trace->GetFrameCount());
  checkStackFrame(nullptr, "throw 'exception';", nullptr, nullptr, 1, 1, false,
                  false, stack_trace->GetFrame(isolate, 0));
  v8::Local<v8::StackFrame> stack_frame = stack_trace->GetFrame(isolate, 0);
  v8::Local<v8::Object> object = v8::Local<v8::Object>::Cast(value);
  CHECK(object
            ->Set(context,
                  v8::String::NewFromUtf8Literal(isolate, "lineNumber"),
                  v8::Integer::New(isolate, stack_frame->GetLineNumber()))
            .IsNothing());
}

TEST(CaptureStackTraceForUncaughtExceptionAndSetters) {
  report_count = 0;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> object = v8::Object::New(isolate);
  isolate->AddMessageListener(StackTraceForUncaughtExceptionAndSettersListener,
                              object);
  isolate->SetCaptureStackTraceForUncaughtExceptions(true, 1024,
                                                     v8::StackTrace::kDetailed);

  CompileRun(uncaught_setter_exception_source);
  CompileRun("throw 'exception';");
  isolate->SetCaptureStackTraceForUncaughtExceptions(false);
  isolate->RemoveMessageListeners(
      StackTraceForUncaughtExceptionAndSettersListener);
  CHECK(object
            ->Get(isolate->GetCurrentContext(),
                  v8::String::NewFromUtf8Literal(isolate, "lineNumber"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK_EQ(report_count, 1);
}

const char functions_with_function_name[] =
    "function gen(name, counter) {\n"
    "  var f = function foo() {\n"
    "    if (counter === 0)\n"
    "      throw 1;\n"
    "    gen(name, counter - 1)();\n"
    "  };\n"
    "  if (counter == 3) {\n"
    "    Object.defineProperty(f, 'name', {get: function(){ throw 239; }});\n"
    "  } else {\n"
    "    Object.defineProperty(f, 'name', {writable:true});\n"
    "    if (counter == 2)\n"
    "      f.name = 42;\n"
    "    else\n"
    "      f.name = name + ':' + counter;\n"
    "  }\n"
    "  return f;\n"
    "};"
    "//# sourceMappingURL=local/functional.sc";

const char functions_with_function_name_caller[] = "gen('foo', 3)();";

static void StackTraceFunctionNameListener(v8::Local<v8::Message> message,
                                           v8::Local<Value>) {
  v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();
  v8::Isolate* isolate = message->GetIsolate();
  CHECK_EQ(5, stack_trace->GetFrameCount());
  checkStackFrame("origin", functions_with_function_name, "local/functional.sc",
                  "foo:0", 4, 7, false, false,
                  stack_trace->GetFrame(isolate, 0));
  checkStackFrame("origin", functions_with_function_name, "local/functional.sc",
                  "foo:1", 5, 27, false, false,
                  stack_trace->GetFrame(isolate, 1));
  checkStackFrame("origin", functions_with_function_name, "local/functional.sc",
                  "foo", 5, 27, false, false,
                  stack_trace->GetFrame(isolate, 2));
  checkStackFrame("origin", functions_with_function_name, "local/functional.sc",
                  "foo", 5, 27, false, false,
                  stack_trace->GetFrame(isolate, 3));
  checkStackFrame("origin", functions_with_function_name_caller, nullptr, "", 1,
                  14, false, false, stack_trace->GetFrame(isolate, 4));
}

TEST(GetStackTraceContainsFunctionsWithFunctionName) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  CompileRunWithOrigin(functions_with_function_name, "origin");

  isolate->AddMessageListener(StackTraceFunctionNameListener);
  isolate->SetCaptureStackTraceForUncaughtExceptions(true);
  CompileRunWithOrigin(functions_with_function_name_caller, "origin");
  isolate->SetCaptureStackTraceForUncaughtExceptions(false);
  isolate->RemoveMessageListeners(StackTraceFunctionNameListener);
}

static void RethrowStackTraceHandler(v8::Local<v8::Message> message,
                                     v8::Local<v8::Value> data) {
  // Use the frame where JavaScript is called from.
  v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();
  CHECK(!stack_trace.IsEmpty());
  int frame_count = stack_trace->GetFrameCount();
  CHECK_EQ(3, frame_count);
  int line_number[] = {1, 2, 5};
  for (int i = 0; i < frame_count; i++) {
    CHECK_EQ(line_number[i],
             stack_trace->GetFrame(message->GetIsolate(), i)->GetLineNumber());
  }
}

// Test that we only return the stack trace at the site where the exception
// is first thrown (not where it is rethrown).
TEST(RethrowStackTrace) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  // We make sure that
  // - the stack trace of the ReferenceError in g() is reported.
  // - the stack trace is not overwritten when e1 is rethrown by t().
  // - the stack trace of e2 does not overwrite that of e1.
  const char* source =
      "function g() { error; }          \n"
      "function f() { g(); }            \n"
      "function t(e) { throw e; }       \n"
      "try {                            \n"
      "  f();                           \n"
      "} catch (e1) {                   \n"
      "  try {                          \n"
      "    error;                       \n"
      "  } catch (e2) {                 \n"
      "    t(e1);                       \n"
      "  }                              \n"
      "}                                \n";
  isolate->AddMessageListener(RethrowStackTraceHandler);
  isolate->SetCaptureStackTraceForUncaughtExceptions(true);
  CompileRun(source);
  isolate->SetCaptureStackTraceForUncaughtExceptions(false);
  isolate->RemoveMessageListeners(RethrowStackTraceHandler);
}

static void RethrowPrimitiveStackTraceHandler(v8::Local<v8::Message> message,
                                              v8::Local<v8::Value> data) {
  v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();
  CHECK(!stack_trace.IsEmpty());
  int frame_count = stack_trace->GetFrameCount();
  CHECK_EQ(2, frame_count);
  int line_number[] = {3, 7};
  for (int i = 0; i < frame_count; i++) {
    CHECK_EQ(line_number[i],
             stack_trace->GetFrame(message->GetIsolate(), i)->GetLineNumber());
  }
}

// Test that we do not recognize identity for primitive exceptions.
TEST(RethrowPrimitiveStackTrace) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  // We do not capture stack trace for non Error objects on creation time.
  // Instead, we capture the stack trace on last throw.
  const char* source =
      "function g() { throw 404; }      \n"
      "function f() { g(); }            \n"
      "function t(e) { throw e; }       \n"
      "try {                            \n"
      "  f();                           \n"
      "} catch (e1) {                   \n"
      "  t(e1)                          \n"
      "}                                \n";
  isolate->AddMessageListener(RethrowPrimitiveStackTraceHandler);
  isolate->SetCaptureStackTraceForUncaughtExceptions(true);
  CompileRun(source);
  isolate->SetCaptureStackTraceForUncaughtExceptions(false);
  isolate->RemoveMessageListeners(RethrowPrimitiveStackTraceHandler);
}

static void RethrowExistingStackTraceHandler(v8::Local<v8::Message> message,
                                             v8::Local<v8::Value> data) {
  // Use the frame where JavaScript is called from.
  v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();
  CHECK(!stack_trace.IsEmpty());
  CHECK_EQ(1, stack_trace->GetFrameCount());
  CHECK_EQ(1, stack_trace->GetFrame(message->GetIsolate(), 0)->GetLineNumber());
}

// Test that the stack trace is captured when the error object is created and
// not where it is thrown.
TEST(RethrowExistingStackTrace) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  const char* source =
      "var e = new Error();           \n"
      "throw e;                       \n";
  isolate->AddMessageListener(RethrowExistingStackTraceHandler);
  isolate->SetCaptureStackTraceForUncaughtExceptions(true);
  CompileRun(source);
  isolate->SetCaptureStackTraceForUncaughtExceptions(false);
  isolate->RemoveMessageListeners(RethrowExistingStackTraceHandler);
}

static void RethrowBogusErrorStackTraceHandler(v8::Local<v8::Message> message,
                                               v8::Local<v8::Value> data) {
  // Use the frame where JavaScript is called from.
  v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();
  CHECK(!stack_trace.IsEmpty());
  CHECK_EQ(1, stack_trace->GetFrameCount());
  CHECK_EQ(1, stack_trace->GetFrame(message->GetIsolate(), 0)->GetLineNumber());
}

// Test that the stack trace is captured where the bogus Error object is created
// and not where it is thrown.
TEST(RethrowBogusErrorStackTrace) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  const char* source =
      "var e = {__proto__: new Error()} \n"
      "throw e;                         \n";
  isolate->AddMessageListener(RethrowBogusErrorStackTraceHandler);
  isolate->SetCaptureStackTraceForUncaughtExceptions(true);
  CompileRun(source);
  isolate->SetCaptureStackTraceForUncaughtExceptions(false);
  isolate->RemoveMessageListeners(RethrowBogusErrorStackTraceHandler);
}

void AnalyzeStackOfEvalWithSourceURL(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::HandleScope scope(info.GetIsolate());
  v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
      info.GetIsolate(), 10, v8::StackTrace::kDetailed);
  CHECK_EQ(5, stackTrace->GetFrameCount());
  v8::Local<v8::String> url = v8_str("eval_url");
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::String> name =
        stackTrace->GetFrame(info.GetIsolate(), i)->GetScriptNameOrSourceURL();
    CHECK(!name.IsEmpty());
    CHECK(url->Equals(info.GetIsolate()->GetCurrentContext(), name).FromJust());
  }
}

TEST(SourceURLInStackTrace) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(
      isolate, "AnalyzeStackOfEvalWithSourceURL",
      v8::FunctionTemplate::New(isolate, AnalyzeStackOfEvalWithSourceURL));
  LocalContext context(nullptr, templ);

  const char* source =
      "function outer() {\n"
      "function bar() {\n"
      "  AnalyzeStackOfEvalWithSourceURL();\n"
      "}\n"
      "function foo() {\n"
      "\n"
      "  bar();\n"
      "}\n"
      "foo();\n"
      "}\n"
      "eval('(' + outer +')()%s');";

  v8::base::ScopedVector<char> code(1024);
  v8::base::SNPrintF(code, source, "//# sourceURL=eval_url");
  CHECK(CompileRun(code.begin())->IsUndefined());
  v8::base::SNPrintF(code, source, "//@ sourceURL=eval_url");
  CHECK(CompileRun(code.begin())->IsUndefined());
}

static int scriptIdInStack[2];

void AnalyzeScriptIdInStack(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::HandleScope scope(info.GetIsolate());
  v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
      info.GetIsolate(), 10, v8::StackTrace::kScriptId);
  CHECK_EQ(2, stackTrace->GetFrameCount());
  for (int i = 0; i < 2; i++) {
    scriptIdInStack[i] =
        stackTrace->GetFrame(info.GetIsolate(), i)->GetScriptId();
  }
}

TEST(ScriptIdInStackTrace) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "AnalyzeScriptIdInStack",
             v8::FunctionTemplate::New(isolate, AnalyzeScriptIdInStack));
  LocalContext context(nullptr, templ);

  v8::Local<v8::String> scriptSource = v8_str(
      "function foo() {\n"
      "  AnalyzeScriptIdInStack();"
      "}\n"
      "foo();\n");
  v8::Local<v8::Script> script = CompileWithOrigin(scriptSource, "test", false);
  script->Run(context.local()).ToLocalChecked();
  for (int i = 0; i < 2; i++) {
    CHECK_NE(scriptIdInStack[i], v8::Message::kNoScriptIdInfo);
    CHECK_EQ(scriptIdInStack[i], script->GetUnboundScript()->GetId());
  }
}

void AnalyzeStackOfInlineScriptWithSourceURL(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::HandleScope scope(info.GetIsolate());
  v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
      info.GetIsolate(), 10, v8::StackTrace::kDetailed);
  CHECK_EQ(4, stackTrace->GetFrameCount());
  v8::Local<v8::String> url = v8_str("source_url");
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::String> name =
        stackTrace->GetFrame(info.GetIsolate(), i)->GetScriptNameOrSourceURL();
    CHECK(!name.IsEmpty());
    CHECK(url->Equals(info.GetIsolate()->GetCurrentContext(), name).FromJust());
  }
}

TEST(InlineScriptWithSourceURLInStackTrace) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "AnalyzeStackOfInlineScriptWithSourceURL",
             v8::FunctionTemplate::New(
                 CcTest::isolate(), AnalyzeStackOfInlineScriptWithSourceURL));
  LocalContext context(nullptr, templ);

  const char* source =
      "function outer() {\n"
      "function bar() {\n"
      "  AnalyzeStackOfInlineScriptWithSourceURL();\n"
      "}\n"
      "function foo() {\n"
      "\n"
      "  bar();\n"
      "}\n"
      "foo();\n"
      "}\n"
      "outer()\n%s";

  v8::base::ScopedVector<char> code(1024);
  v8::base::SNPrintF(code, source, "//# sourceURL=source_url");
  CHECK(CompileRunWithOrigin(code.begin(), "url", 0, 1)->IsUndefined());
  v8::base::SNPrintF(code, source, "//@ sourceURL=source_url");
  CHECK(CompileRunWithOrigin(code.begin(), "url", 0, 1)->IsUndefined());
}

void AnalyzeStackOfDynamicScriptWithSourceURL(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::HandleScope scope(info.GetIsolate());
  v8::Local<v8::StackTrace> stackTrace = v8::StackTrace::CurrentStackTrace(
      info.GetIsolate(), 10, v8::StackTrace::kDetailed);
  CHECK_EQ(4, stackTrace->GetFrameCount());
  v8::Local<v8::String> url = v8_str("source_url");
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::String> name =
        stackTrace->GetFrame(info.GetIsolate(), i)->GetScriptNameOrSourceURL();
    CHECK(!name.IsEmpty());
    CHECK(url->Equals(info.GetIsolate()->GetCurrentContext(), name).FromJust());
  }
}

TEST(DynamicWithSourceURLInStackTrace) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "AnalyzeStackOfDynamicScriptWithSourceURL",
             v8::FunctionTemplate::New(
                 CcTest::isolate(), AnalyzeStackOfDynamicScriptWithSourceURL));
  LocalContext context(nullptr, templ);

  const char* source =
      "function outer() {\n"
      "function bar() {\n"
      "  AnalyzeStackOfDynamicScriptWithSourceURL();\n"
      "}\n"
      "function foo() {\n"
      "\n"
      "  bar();\n"
      "}\n"
      "foo();\n"
      "}\n"
      "outer()\n%s";

  v8::base::ScopedVector<char> code(1024);
  v8::base::SNPrintF(code, source, "//# sourceURL=source_url");
  CHECK(CompileRunWithOrigin(code.begin(), "url", 0, 0)->IsUndefined());
  v8::base::SNPrintF(code, source, "//@ sourceURL=source_url");
  CHECK(CompileRunWithOrigin(code.begin(), "url", 0, 0)->IsUndefined());
}

TEST(DynamicWithSourceURLInStackTraceString) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char* source =
      "function outer() {\n"
      "  function foo() {\n"
      "    FAIL.FAIL;\n"
      "  }\n"
      "  foo();\n"
      "}\n"
      "outer()\n%s";

  v8::base::ScopedVector<char> code(1024);
  v8::base::SNPrintF(code, source, "//# sourceURL=source_url");
  v8::TryCatch try_catch(context->GetIsolate());
  CompileRunWithOrigin(code.begin(), "", 0, 0);
  CHECK(try_catch.HasCaught());
  v8::String::Utf8Value stack(
      context->GetIsolate(),
      try_catch.StackTrace(context.local()).ToLocalChecked());
  CHECK_NOT_NULL(strstr(*stack, "at foo (source_url:3:5)"));
}

UNINITIALIZED_TEST(CaptureStackTraceForStackOverflow) {
  // We must set v8_flags.stack_size before initializing the isolate.
  v8::internal::v8_flags.stack_size = 150;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();
  {
    LocalContext current(isolate);
    v8::HandleScope scope(isolate);
    isolate->SetCaptureStackTraceForUncaughtExceptions(
        true, 10, v8::StackTrace::kDetailed);
    v8::TryCatch try_catch(isolate);
    CompileRun("(function f(x) { f(x+1); })(0)");
    CHECK(try_catch.HasCaught());
  }
  isolate->Exit();
  isolate->Dispose();
}

void AnalyzeScriptNameInStack(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::HandleScope scope(info.GetIsolate());
  v8::Local<v8::String> name =
      v8::StackTrace::CurrentScriptNameOrSourceURL(info.GetIsolate());
  CHECK(!name.IsEmpty());
  CHECK(name->StringEquals(v8_str("test.js")));
}

TEST(CurrentScriptNameOrSourceURL_Name) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(
      isolate, "AnalyzeScriptNameInStack",
      v8::FunctionTemplate::New(CcTest::isolate(), AnalyzeScriptNameInStack));
  LocalContext context(nullptr, templ);

  const char* source = R"(
    function foo() {
      AnalyzeScriptNameInStack();
    }
    foo();
  )";

  CHECK(CompileRunWithOrigin(source, "test.js")->IsUndefined());
}

void AnalyzeScriptURLInStack(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::HandleScope scope(info.GetIsolate());
  v8::Local<v8::String> name =
      v8::StackTrace::CurrentScriptNameOrSourceURL(info.GetIsolate());
  CHECK(!name.IsEmpty());
  CHECK(name->StringEquals(v8_str("foo.js")));
}

TEST(CurrentScriptNameOrSourceURL_SourceURL) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(
      isolate, "AnalyzeScriptURLInStack",
      v8::FunctionTemplate::New(CcTest::isolate(), AnalyzeScriptURLInStack));
  LocalContext context(nullptr, templ);

  const char* source = R"(
    function foo() {
      AnalyzeScriptURLInStack();
    }
    foo();
    //# sourceURL=foo.js
  )";

  CHECK(CompileRunWithOrigin(source, "")->IsUndefined());
}

"""

```