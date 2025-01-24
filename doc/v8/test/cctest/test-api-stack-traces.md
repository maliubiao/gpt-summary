Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The primary goal is to analyze a V8 test file (`test-api-stack-traces.cc`) and describe its functionality. The prompt also includes specific instructions related to Torque, JavaScript examples, logic inference, common errors, and a final summarization.

2. **Initial Scan for Keywords and Structure:**  Quickly skim the code, looking for familiar V8 API elements, test frameworks, and overall organization. Keywords like `TEST`, `THREADED_TEST`, `LocalContext`, `v8::Isolate`, `v8::String`, `v8::Exception`, `v8::StackTrace`, and function definitions immediately stand out. The `#include` directives at the beginning also provide context about the V8 APIs being used.

3. **Identify Key Test Cases:** The code is structured as a series of individual test cases using `TEST` and `THREADED_TEST`. Each test case seems to focus on a specific aspect of stack trace generation or manipulation. List out the test names to get a high-level understanding:

    * `IsolatePrepareStackTrace`
    * `IsolatePrepareStackTraceThrow`
    * `ExceptionCreateMessage`
    * `StackTrace`
    * `CaptureStackTrace`
    * `CaptureStackTraceForUncaughtException`
    * `CaptureStackTraceForUncaughtExceptionAndSetters`
    * `GetStackTraceContainsFunctionsWithFunctionName`
    * `RethrowStackTrace`
    * `RethrowPrimitiveStackTrace`
    * `RethrowExistingStackTrace`
    * `RethrowBogusErrorStackTrace`
    * `SourceURLInStackTrace`
    * `ScriptIdInStackTrace`
    * `InlineScriptWithSourceURLInStackTrace`
    * `AnalyzeStackOfDynamicScriptWithSourceURL` (truncated in the provided snippet)

4. **Analyze Individual Test Cases:**  Go through each test case, focusing on what it's doing:

    * **`IsolatePrepareStackTrace` and `IsolatePrepareStackTraceThrow`:** These tests clearly involve setting a custom `PrepareStackTraceCallback` on the `v8::Isolate`. The first returns a fixed number, and the second throws an exception. This hints at the ability to customize how stack traces are generated at the isolate level.

    * **`ExceptionCreateMessage`:** This test uses `ThrowV8Exception` to create and throw a V8 exception. It then uses `v8::Exception::CreateMessage` to extract information from the exception, including line number, column, and stack trace. This focuses on the information available from a caught exception. The part about `SetCaptureStackTraceForUncaughtExceptions` is also important.

    * **`StackTrace`:** This test compiles and runs some JavaScript that causes an error (`FAIL.FAIL`). It then retrieves the stack trace using `try_catch.StackTrace()`. This demonstrates basic stack trace retrieval for synchronous errors.

    * **`CaptureStackTrace`:** This test introduces the native function `AnalyzeStackInNativeCode` and calls `v8::StackTrace::CurrentStackTrace`. It checks the content of the stack frames (function name, script name, line number, column, etc.) for different scenarios, including `eval`. This delves into the programmatic access to stack trace information from within native code.

    * **`CaptureStackTraceForUncaughtException`:** This test sets up a message listener (`StackTraceForUncaughtExceptionListener`) to capture stack traces for *uncaught* exceptions. It verifies the stack frames when an uncaught exception occurs.

    * **`CaptureStackTraceForUncaughtExceptionAndSetters`:** This test is similar but explores the interaction between uncaught exceptions and property setters.

    * **`GetStackTraceContainsFunctionsWithFunctionName`:** This test focuses on how function names are captured in stack traces, especially when the `name` property is manipulated (writable or has a getter that throws).

    * **`RethrowStackTrace`, `RethrowPrimitiveStackTrace`, `RethrowExistingStackTrace`, `RethrowBogusErrorStackTrace`:** These tests examine how stack traces are handled when exceptions are rethrown. They highlight the distinction between rethrowing object exceptions and primitive exceptions and when the stack trace is initially captured (at creation or throw time).

    * **`SourceURLInStackTrace`, `ScriptIdInStackTrace`, `InlineScriptWithSourceURLInStackTrace`, `AnalyzeStackOfDynamicScriptWithSourceURL`:** These tests verify how source URLs and script IDs are reflected in stack traces for different code evaluation scenarios (eval, inline scripts, dynamic scripts).

5. **Identify Core Functionality:** Based on the analysis of the individual test cases, identify the main functionalities being tested:

    * **Customizing Stack Trace Generation:** Using `SetPrepareStackTraceCallback`.
    * **Retrieving Stack Traces for Caught Exceptions:** Using `v8::Exception::CreateMessage` and `v8::Exception::GetStackTrace`.
    * **Retrieving Stack Traces for Synchronous Errors:** Using `try_catch.StackTrace()`.
    * **Programmatic Access to Stack Traces:** Using `v8::StackTrace::CurrentStackTrace` from native code.
    * **Capturing Stack Traces for Uncaught Exceptions:** Using message listeners and `SetCaptureStackTraceForUncaughtExceptions`.
    * **Handling Function Names in Stack Traces:** Considering the `name` property.
    * **Behavior of Stack Traces on Rethrowing Exceptions:**  Distinguishing between object and primitive exceptions.
    * **Including Source URLs and Script IDs in Stack Traces:** For various code evaluation methods.

6. **Address Specific Instructions:**

    * **Torque:**  The prompt explicitly asks about `.tq` files. A quick scan confirms the file name ends in `.cc`, so it's not a Torque file.

    * **JavaScript Examples:**  For each identified functionality related to JavaScript, provide illustrative JavaScript code snippets. Think about how you would trigger the behavior being tested in the C++ code from a JavaScript context.

    * **Logic Inference (Assumptions and Outputs):**  For parts of the code that involve conditional logic or specific behavior, describe the input and expected output. This is more relevant for functions like `PrepareStackTrace42` and `PrepareStackTraceThrow`.

    * **Common Programming Errors:**  Relate the tested scenarios to common mistakes developers might make, like forgetting to catch exceptions or misunderstanding how rethrowing works.

7. **Synthesize the Summary:** Combine the identified functionalities into a concise summary, as requested in the final part of the prompt.

8. **Review and Refine:** Go through the analysis, ensuring accuracy, clarity, and completeness. Check that all parts of the prompt have been addressed. Make sure the JavaScript examples are correct and easy to understand. Refine the language for better readability.

This detailed breakdown allows for a comprehensive understanding of the test file's purpose and enables the creation of a well-structured and informative response.
好的，这是对 `v8/test/cctest/test-api-stack-traces.cc` 源代码的功能分析：

**文件功能归纳：**

`v8/test/cctest/test-api-stack-traces.cc` 是 V8 JavaScript 引擎的 C++ 单元测试文件。它主要用于测试与 JavaScript 堆栈跟踪（stack traces）相关的 V8 API 功能。  该文件涵盖了以下几个核心方面的测试：

1. **自定义堆栈跟踪格式:**  测试了通过 `Isolate::SetPrepareStackTraceCallback`  API  自定义堆栈跟踪信息的能力。允许开发者在生成堆栈跟踪时插入自定义的逻辑。

2. **创建和获取异常消息:**  测试了使用 `v8::Exception::CreateMessage` API 从捕获的异常中提取详细信息，包括错误消息、发生错误的行号、列号以及堆栈跟踪信息。

3. **获取当前堆栈跟踪:** 测试了 `v8::StackTrace::CurrentStackTrace` API，允许在原生 C++ 代码中获取当前的 JavaScript 调用堆栈。 可以获取概要信息（overview）或详细信息（detailed）。

4. **捕获未捕获异常的堆栈跟踪:** 测试了 `Isolate::SetCaptureStackTraceForUncaughtExceptions` API， 允许 V8 自动捕获未捕获异常的堆栈跟踪信息，并通过消息监听器（message listener）进行处理。

5. **堆栈跟踪中包含函数名:** 验证了堆栈跟踪中是否能正确显示函数名，即使函数名的属性被修改（例如，通过 `Object.defineProperty` 修改了 `name` 属性）。

6. **处理重新抛出的异常:** 测试了在重新抛出异常时，堆栈跟踪信息是否保持在最初抛出异常的位置，而不是在重新抛出的位置。  区分了对象异常和原始类型异常的处理方式。

7. **堆栈跟踪中包含源代码 URL 和 Script ID:**  测试了在 `eval()` 调用、内联脚本和动态脚本中，堆栈跟踪信息是否能正确包含源代码的 URL (`//# sourceURL` 或 `//@ sourceURL`) 和脚本的 ID。

**关于文件类型：**

`v8/test/cctest/test-api-stack-traces.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。根据您提供的说明，如果文件以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 功能的关系及示例：**

该文件测试的都是直接与 JavaScript 错误处理和调试密切相关的功能。以下是一些 JavaScript 示例，可以触发 `v8/test/cctest/test-api-stack-traces.cc` 中测试的功能：

**1. 自定义堆栈跟踪格式 (`IsolatePrepareStackTrace`)：**

虽然 JavaScript 代码本身无法直接设置 `PrepareStackTraceCallback`，但这个 C++ 测试验证了当 V8 宿主环境（例如 Node.js 或 Chrome 开发者工具）设置了该回调时，`new Error().stack` 的行为。

```javascript
// 假设 V8 宿主环境设置了 PrepareStackTrace42 回调
try {
  throw new Error("Something went wrong");
} catch (e) {
  console.log(e.stack); // 预期输出可能是 "42" 而不是标准的堆栈信息
}
```

**2. 创建和获取异常消息 (`ExceptionCreateMessage`)：**

```javascript
try {
  throw new Error("This is an error message");
} catch (e) {
  console.log(e.message); // 输出: This is an error message
  console.log(e.stack);   // 输出包含堆栈信息的字符串
}
```

**3. 获取当前堆栈跟踪 (`CaptureStackTrace`)：**

JavaScript 本身并没有直接对应 `v8::StackTrace::CurrentStackTrace` 的 API。这个功能主要用于 V8 内部或嵌入 V8 的环境，例如在浏览器开发者工具或 Node.js 的内部模块中。  C++ 代码中的 `AnalyzeStackInNativeCode` 函数模拟了在原生代码中获取 JavaScript 堆栈的场景。

**4. 捕获未捕获异常的堆栈跟踪 (`CaptureStackTraceForUncaughtException`)：**

```javascript
function foo() {
  throw new Error("Uncaught exception!");
}

function bar() {
  foo();
}

bar(); // 运行这段代码，如果 V8 配置了捕获未捕获异常的堆栈跟踪，
       // 则会触发 C++ 测试中设置的消息监听器。
```

**5. 堆栈跟踪中包含函数名 (`GetStackTraceContainsFunctionsWithFunctionName`)：**

```javascript
function namedFunction() {
  console.trace();
}

const anonymousFunction = function() {
  console.trace();
};

const objectMethod = {
  method: function namedMethod() {
    console.trace();
  }
};

namedFunction();
anonymousFunction();
objectMethod.method();

// 修改函数名属性
function anotherFunction() {}
Object.defineProperty(anotherFunction, 'name', { value: 'renamedFunction' });
console.log(anotherFunction.name); // 输出: renamedFunction
console.trace(anotherFunction); // 堆栈信息中应该显示 'renamedFunction'
```

**6. 处理重新抛出的异常 (`RethrowStackTrace`, `RethrowPrimitiveStackTrace`, `RethrowExistingStackTrace`)：**

```javascript
function g() {
  throw new Error("Error in g");
}

function f() {
  g();
}

function t(e) {
  throw e;
}

try {
  f();
} catch (e1) {
  try {
    throw new Error("Another error");
  } catch (e2) {
    t(e1); // 重新抛出 e1
  }
}
```

```javascript
function h() {
  throw "primitive error";
}

function i() {
  h();
}

function u(e) {
  throw e;
}

try {
  i();
} catch (e1) {
  u(e1); // 重新抛出原始类型错误
}
```

```javascript
const existingError = new Error("Created earlier");
try {
  throw existingError;
} catch (e) {
  console.log(e.stack); // 堆栈信息应该指向创建 Error 对象的位置
}
```

**7. 堆栈跟踪中包含源代码 URL 和 Script ID (`SourceURLInStackTrace`, `ScriptIdInStackTrace`, `InlineScriptWithSourceURLInStackTrace`)：**

```javascript
eval('console.trace(); //# sourceURL=my-eval.js');

function outerFunction() {
  eval('console.trace(); //@ sourceURL=inner-eval.js');
}
outerFunction();
```

```javascript
// 内联脚本 (通常在 HTML 中)
// <script src="my-script.js">
//   console.trace(); // 假设 my-script.js 中有这行代码，
//                     // 堆栈信息中会包含 my-script.js 的 URL
// </script>
```

**代码逻辑推理与假设输入输出：**

让我们看 `IsolatePrepareStackTrace` 测试：

**假设输入：**  在 JavaScript 中执行 `new Error().stack`。

**代码逻辑：**

1. `isolate->SetPrepareStackTraceCallback(PrepareStackTrace42);` 设置了当需要生成堆栈跟踪时，V8 会调用 `PrepareStackTrace42` 函数。
2. `PrepareStackTrace42` 函数接收错误对象和原始的堆栈帧数组，但它忽略这些信息，直接返回一个值为 42 的 `v8::Number`。
3. `CompileRun("new Error().stack");` 执行 JavaScript 代码，这会触发堆栈跟踪的生成。
4. 由于设置了自定义回调，`PrepareStackTrace42` 被调用，并返回 42。
5. 因此，`new Error().stack` 的结果不再是标准的堆栈字符串，而是数字 42。

**预期输出：**  `v` 变量将包含一个 `v8::Number` 对象，其值为 42。`CHECK_EQ` 断言会验证这一点。

让我们看 `IsolatePrepareStackTraceThrow` 测试：

**假设输入：** 在 JavaScript 中执行 `new Error().stack`，但被包裹在 `try...catch` 块中。

**代码逻辑：**

1. `isolate->SetPrepareStackTraceCallback(PrepareStackTraceThrow);` 设置了当需要生成堆栈跟踪时，V8 会调用 `PrepareStackTraceThrow` 函数。
2. `PrepareStackTraceThrow` 函数接收错误对象和原始的堆栈帧数组，但它不返回任何值，而是直接抛出一个新的 `v8::Exception::Error`，消息为 "42"。
3. `CompileRun("try { new Error().stack } catch (e) { e }");` 执行 JavaScript 代码。当执行到 `new Error().stack` 时，会尝试生成堆栈跟踪。
4. 由于设置了自定义回调，`PrepareStackTraceThrow` 被调用，并抛出了一个异常。
5. 这个异常被 `try...catch` 块捕获。
6. 因此，`v` 变量将包含被捕获的异常对象。

**预期输出：** `v` 变量将包含一个原生错误对象。通过 `v8::Exception::CreateMessage` 获取的消息应该是 "Uncaught Error: 42"。

**用户常见的编程错误：**

该测试文件涵盖了与堆栈跟踪相关的多个方面，也间接反映了一些用户常见的编程错误：

1. **不理解异步操作的堆栈信息：** 虽然这个文件没有直接测试异步，但理解堆栈跟踪对于调试异步代码至关重要。用户可能难以追踪异步操作的调用链。

2. **错误地处理或忽略异常：** 测试中使用了 `try...catch` 块，展示了如何捕获和检查异常。用户可能因为不当的异常处理而丢失有用的堆栈信息。

3. **不熟悉 `eval()` 和动态代码的调试：**  测试了 `eval()` 的堆栈跟踪，用户可能不清楚如何调试 `eval()` 中产生的错误以及如何使用 `//# sourceURL` 帮助调试。

4. **误解重新抛出异常后的堆栈信息：**  测试明确指出了重新抛出异常时，堆栈信息会指向最初抛出的位置。用户可能会错误地认为堆栈信息会指向重新抛出的位置。

5. **依赖于默认的堆栈格式：**  测试了自定义堆栈跟踪格式的功能。用户可能不知道可以自定义堆栈信息的生成方式。

**总结 - 第 1 部分功能归纳：**

`v8/test/cctest/test-api-stack-traces.cc` 的第一部分主要测试了 V8 API 中与以下堆栈跟踪功能相关的能力：

* **自定义堆栈跟踪的生成方式** (`Isolate::SetPrepareStackTraceCallback`).
* **从捕获的异常中获取详细的错误消息和堆栈信息** (`v8::Exception::CreateMessage`).
* **获取当前 JavaScript 执行的堆栈信息** (`v8::StackTrace::CurrentStackTrace`).
* **捕获未捕获异常的堆栈信息** (`Isolate::SetCaptureStackTraceForUncaughtExceptions`).

这些测试确保了 V8 引擎能够正确地生成和提供用于调试和错误分析的堆栈跟踪信息，并允许开发者在必要时对其进行定制。

### 提示词
```
这是目录为v8/test/cctest/test-api-stack-traces.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-stack-traces.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
    CHECK(url->Eq
```