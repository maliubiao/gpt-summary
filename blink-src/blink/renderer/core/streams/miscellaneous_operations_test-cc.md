Response:
Let's break down the thought process for analyzing this C++ test file for Blink's Streams API.

1. **Understand the Goal:** The request asks for the functionality of the file `miscellaneous_operations_test.cc`, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common usage errors, and debugging information.

2. **Initial Scan and Keywords:** Quickly read through the file, looking for key terms and patterns. I see:
    * `TEST`:  This immediately tells me it's a test file using Google Test.
    * `MiscellaneousOperations`:  This hints at the types of functions being tested. They are likely utility functions or helper functions used in the Streams API.
    * `CreateAlgorithmFromUnderlyingMethod`, `CreateStartAlgorithm`, `CallOrNoop1`, `PromiseCall`, `ValidateAndNormalizeHighWaterMark`, `MakeSizeAlgorithmFromSizeFunction`, `PromiseResolve`, `PromiseReject`: These are function names that strongly suggest the file tests specific operations within the Streams API.
    * `ScriptState`, `V8TestingScope`, `ScriptValue`, `v8::Object`, `v8::Promise`: These terms indicate interaction with V8, the JavaScript engine, and the core concepts of the Streams API (which involves promises and JavaScript objects).

3. **Deduce Core Functionality:** Based on the function names, I can infer the file's primary purpose:  to test the low-level mechanisms for:
    * Creating algorithms/functions from JavaScript objects (especially methods within those objects).
    * Calling these algorithms, handling arguments, and managing promises.
    * Validating parameters (like `highWaterMark`).
    * Handling different scenarios like missing methods, methods returning values or promises, and methods throwing exceptions.

4. **Relate to Web Technologies:** Now, I connect these low-level operations to the higher-level concepts of web technologies:
    * **JavaScript:** The tests directly manipulate JavaScript objects and functions. The Streams API itself is a JavaScript API. The functions being tested are the *implementation* of how JavaScript streams work in the browser.
    * **HTML:** While the file doesn't directly create HTML elements, the Streams API is used in JavaScript, which *is* used to manipulate the DOM. For example, you might use a ReadableStream to fetch data and then use JavaScript to update the HTML.
    * **CSS:**  Less direct relation than HTML, but potentially involved. For instance, a stream could be used to process image data, and CSS could style how that image is displayed.

5. **Identify Logical Reasoning and Assumptions:** The tests themselves demonstrate logical reasoning. Each `TEST` case sets up a specific input (e.g., an object with or without a 'pull' method) and asserts an expected output (e.g., an algorithm is created successfully or an exception is thrown).
    * **Assumption Example:**  When testing `CreateAlgorithmNoMethod`, the assumption is that if an underlying object *doesn't* have the specified method, the `CreateAlgorithmFromUnderlyingMethod` function should still produce a valid algorithm that, when run, resolves its promise to `undefined`.

6. **Pinpoint Common Usage Errors:** Looking at the test cases that intentionally cause errors (e.g., `CreateAlgorithmNullMethod`, `CreateAlgorithmThrowingGetter`, `NegativeHighWaterMarkInvalid`), I can identify potential developer errors:
    * Providing `null` or `undefined` where a function is expected.
    * Having getters that throw exceptions (which can be unexpected behavior).
    * Using invalid values for parameters like `highWaterMark`.

7. **Trace User Operations to the Code:**  This is about understanding how user actions trigger the code being tested.
    * A user interacts with a web page.
    * JavaScript code on that page uses the Streams API (e.g., creating a `ReadableStream`, `WritableStream`, or `TransformStream`).
    * When these stream objects are created or manipulated, the browser's JavaScript engine calls the underlying C++ implementation of the Streams API in Blink.
    * The functions tested in this file (`CreateAlgorithmFromUnderlyingMethod`, etc.) are part of that underlying implementation.

8. **Construct Examples and Explanations:**  Based on the above analysis, I start formulating concrete examples for each point, particularly the JavaScript, HTML, and CSS relationships, logical reasoning, and usage errors. I try to make these examples practical and easy to understand.

9. **Structure the Answer:**  I organize the information logically, starting with the main function of the file, then moving to related concepts, examples, and debugging information. Using headings and bullet points improves readability.

10. **Refine and Review:** Finally, I reread the generated answer to ensure accuracy, clarity, and completeness, checking that it directly addresses all parts of the original request. I might rephrase some sentences or add more detail where necessary. For example, I might initially forget to explicitly mention the role of promises and then add that in.

This systematic approach, combining code analysis, domain knowledge (web technologies and the Streams API), and structured thinking, allows for a comprehensive and accurate answer to the request.
这个文件 `miscellaneous_operations_test.cc` 是 Chromium Blink 引擎中，专门用于测试与 Web Streams API 相关的**杂项操作（miscellaneous operations）** 的单元测试文件。 这些操作通常是构成 Streams API 基础的辅助函数或算法，不属于主要的 Stream 类型（如 `ReadableStream`, `WritableStream`, `TransformStream`）的核心功能，但对它们的正常运行至关重要。

**主要功能:**

这个文件主要测试了以下几个方面的功能：

1. **从底层方法创建算法 (Creating Algorithms from Underlying Methods):**
   - 测试了如何从 JavaScript 对象的属性（通常是函数）创建可以在 C++ 代码中调用的算法对象 (`CreateAlgorithmFromUnderlyingMethod`)。这对于连接 JavaScript 层的 Stream 定义和 C++ 层的实现至关重要。
   - 涵盖了方法不存在、方法为 `undefined`、方法为 `null` 以及获取方法时抛出异常等多种情况。

2. **创建启动算法 (Creating Start Algorithms):**
   - 测试了如何为 Sink (WritableStream 的底层实现) 创建启动算法 (`CreateStartAlgorithm`)。启动算法在 Stream 实例化时被调用，用于执行一些初始化操作。
   - 测试了方法不存在、方法为 `null` 以及方法抛出异常等情况。
   - 特别测试了 `start` 方法返回 Controller 的情况。

3. **调用或无操作 (Call or No-op):**
   - 测试了 `CallOrNoop1` 函数，该函数用于安全地调用一个可能不存在的方法。如果方法存在则调用并传入一个参数，否则不执行任何操作。
   - 测试了方法不存在、方法为 `null`、方法被正常调用以及方法抛出异常的情况。

4. **Promise 调用 (Promise Call):**
   - 测试了 `PromiseCall` 函数，该函数用于在一个特定的对象上调用一个函数，并将结果包装在一个 Promise 中。这对于异步操作和错误处理非常重要。
   - 测试了函数调用时 `this` 的绑定，以及函数抛出异常或返回 rejected Promise 的情况。

5. **校验和标准化 High Water Mark (Validate and Normalize High Water Mark):**
   - 测试了 `ValidateAndNormalizeHighWaterMark` 函数，该函数用于校验并标准化 Stream 的 `highWaterMark` 属性。`highWaterMark` 用于控制 Stream 内部缓冲的大小。
   - 测试了正数、无穷大、负数和 NaN 等各种输入。

6. **创建 Size 算法 (Creating Size Algorithms):**
   - 测试了 `MakeSizeAlgorithmFromSizeFunction` 函数，该函数用于从用户提供的 size 函数创建 size 算法。Size 函数用于确定 Stream 中每个 chunk 的大小，用于 backpressure 控制。
   - 测试了 size 函数为 `undefined`、`null`、正常函数、返回非数字值以及抛出异常的情况。

7. **Promise Resolve 和 Reject:**
   - 测试了 `PromiseResolve` 和 `PromiseReject` 函数，它们是用于创建 resolved 和 rejected Promise 的辅助函数。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关联到 **JavaScript** 的 Web Streams API。 Web Streams API 允许 JavaScript 代码以更强大和灵活的方式处理流式数据，例如网络请求、文件操作等。

* **JavaScript 示例:**  在 JavaScript 中创建一个 `ReadableStream` 或 `WritableStream` 时，你可以提供一个底层源 (underlying source) 或底层 Sink (underlying sink) 对象。 这些对象可以包含 `start`, `pull`, `write`, `close`, `abort` 等方法。  `miscellaneous_operations_test.cc` 中测试的函数，例如 `CreateAlgorithmFromUnderlyingMethod` 和 `CreateStartAlgorithm`，正是 Blink 引擎用来将 JavaScript 中定义的这些方法转换为 C++ 中可执行的算法的机制。

   ```javascript
   const readableStream = new ReadableStream({
     start(controller) {
       // 这里定义的 start 方法对应测试中的 CreateStartAlgorithm
       controller.enqueue("hello");
       controller.close();
     },
     pull(controller) {
       // 这里定义的 pull 方法对应测试中的 CreateAlgorithmFromUnderlyingMethod
     }
   });

   const writableStream = new WritableStream({
     start(controller) {
       // 同样，这里的 start 方法也对应测试中的 CreateStartAlgorithm
     },
     write(chunk) {
       // ...
     }
   });
   ```

* **HTML 和 CSS:**  虽然这个测试文件本身不直接涉及 HTML 或 CSS 的解析或渲染，但 Web Streams API 经常被用于处理来自网络的数据，这些数据最终可能用于更新 HTML 结构或应用 CSS 样式。例如：
    * 使用 `fetch` API 获取一个大的文本文件，并通过 `response.body` 获取一个 `ReadableStream`，然后逐步处理内容并更新页面上的 HTML 元素。
    * 使用 `MediaRecorder` API 录制音频或视频，并将数据作为 `ReadableStream` 提供，然后可以通过网络发送或在本地处理。

**逻辑推理、假设输入与输出:**

以下举例说明 `CreateAlgorithmFromUnderlyingMethod` 的逻辑推理：

**假设输入:**

* `underlying_object`: 一个 JavaScript 对象。
* `method_name`: 字符串 "pull"。
* `property_name`: 字符串 "underlyingSource.pull"。

**测试用例 1: 方法存在且为函数**

* **假设输入:** `underlying_object` 包含一个名为 `pull` 的属性，其值为一个 JavaScript 函数。
* **预期输出:** `CreateAlgorithmFromUnderlyingMethod` 成功创建一个算法对象，该算法对象可以执行 JavaScript 的 `pull` 函数。当运行该算法时，会调用 JavaScript 的 `pull` 函数，并返回一个 resolved 的 Promise (因为示例代码中的 `EmptyExtraArg` 和后续的 `algo->Run` 没有传入拒绝 Promise 的机制)。

**测试用例 2: 方法不存在**

* **假设输入:** `underlying_object` 不包含名为 `pull` 的属性。
* **预期输出:** `CreateAlgorithmFromUnderlyingMethod` 成功创建一个算法对象。当运行该算法时，它会返回一个 resolved 的 Promise，其结果是 `undefined`，这符合 Web Streams 规范中对于缺失方法处理的规定。

**测试用例 3: 方法为 `null`**

* **假设输入:** `underlying_object` 包含一个名为 `pull` 的属性，其值为 `null`.
* **预期输出:** `CreateAlgorithmFromUnderlyingMethod` 返回 `nullptr`，并且 `exception_state` 中记录了一个异常，因为 Web Streams 规范通常不允许底层方法为 `null`。

**用户或编程常见的使用错误:**

1. **在 underlying source 或 sink 对象中将方法名拼写错误:**  例如，在 JavaScript 中定义了 `staart()` 而不是 `start()`。Blink 引擎会尝试查找 `staart` 方法，但找不到，导致某些操作无法正常进行。测试用例 `MiscellaneousOperationsTest, CreateStartAlgorithmNoMethod` 就模拟了这种情况。

2. **假设底层方法总是存在的:**  开发者可能在某些情况下假设 underlying source 或 sink 对象总是包含特定的方法，而没有进行检查。例如，假设 `pull` 方法总是存在，但由于某些原因（例如用户提供的对象不完整），该方法不存在，这会导致错误。

3. **在 size 函数中返回非数字值或抛出异常:**  如果为 `ReadableByteStream` 提供了 `size` 函数，该函数应该返回一个数字。如果返回了其他类型或抛出了异常，会导致 backpressure 计算错误。测试用例 `MiscellaneousOperationsTest, ThrowingSizeAlgorithm` 和 `MiscellaneousOperationsTest, UnconvertibleSize` 就模拟了这种情况。

4. **为 `highWaterMark` 设置无效值:** 用户可能会尝试将 `highWaterMark` 设置为负数或 NaN，这在 Web Streams 规范中是不允许的。测试用例 `MiscellaneousOperationsTest, NegativeHighWaterMarkInvalid` 和 `MiscellaneousOperationsTest, NaNHighWaterMarkInvalid` 验证了这种情况下的行为。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **网页的 JavaScript 代码使用了 Web Streams API。** 例如，可能创建了一个 `ReadableStream` 来处理来自 `fetch` API 的响应体：
   ```javascript
   fetch('https://example.com/data.txt')
     .then(response => response.body) // response.body 是一个 ReadableStream
     .getReader()
     .read()
     .then(result => {
       // 处理读取到的数据
     });
   ```
3. **当 `ReadableStream` 被创建时，如果提供了 underlying source 对象，Blink 引擎会调用 `CreateStartAlgorithm` 来处理 underlying source 的 `start` 方法。**
4. **当需要从 Stream 中读取数据时（例如，调用 `reader.read()`），Blink 引擎可能会调用 `CreateAlgorithmFromUnderlyingMethod` 来处理 underlying source 的 `pull` 方法。**
5. **如果在 Stream 的策略中定义了 `size` 函数，当有新的 chunk 需要入队时，Blink 引擎会调用 `MakeSizeAlgorithmFromSizeFunction` 来处理 size 函数。**
6. **如果在 Stream 的操作过程中发生了错误，Blink 引擎可能会使用 `PromiseReject` 创建一个 rejected 的 Promise 并传递给 JavaScript。**

**作为调试线索:**

* **崩溃或异常发生在 Stream 的创建或操作阶段:** 如果在创建 `ReadableStream` 或 `WritableStream` 时遇到崩溃或异常，可以查看调用堆栈，可能会涉及到 `CreateStartAlgorithm` 或 `CreateAlgorithmFromUnderlyingMethod` 等函数。
* **Stream 的 backpressure 机制异常:** 如果怀疑 backpressure 计算有问题，可以查看是否涉及到 `MakeSizeAlgorithmFromSizeFunction` 以及用户提供的 size 函数的执行结果。
* **Promise 链中出现未处理的 rejection:** 如果在处理 Stream 的 Promise 链中出现 rejection，可以查看 rejection 的原因，这可能与 underlying source 或 sink 方法的执行结果有关。

总而言之，`miscellaneous_operations_test.cc` 文件是 Blink 引擎中测试 Web Streams API 内部机制的关键组成部分，它确保了各种辅助函数和算法的正确性和健壮性，从而保证了 Web Streams API 的稳定运行。 开发者在使用 Web Streams API 时，其 JavaScript 代码最终会通过这些底层的 C++ 实现来执行。

Prompt: 
```
这是目录为blink/renderer/core/streams/miscellaneous_operations_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"

#include <math.h>

#include <limits>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/core/streams/test_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

// Tests in this file are named MiscellaneousOperations* so that it is easy to
// select them with gtest_filter.

v8::MaybeLocal<v8::Value> EmptyExtraArg() {
  return v8::MaybeLocal<v8::Value>();
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmNoMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto underlying_object = v8::Object::New(scope.GetIsolate());
  auto* algo = CreateAlgorithmFromUnderlyingMethod(
      scope.GetScriptState(), underlying_object, "pull",
      "underlyingSource.pull", EmptyExtraArg(), ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(algo);
  auto promise = algo->Run(scope.GetScriptState(), 0, nullptr);
  ASSERT_FALSE(promise.IsEmpty());
  ASSERT_EQ(promise.V8Promise()->State(), v8::Promise::kFulfilled);
  EXPECT_TRUE(promise.V8Promise()->Result()->IsUndefined());
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmUndefinedMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto underlying_object = v8::Object::New(scope.GetIsolate());
  underlying_object
      ->Set(scope.GetContext(), V8String(scope.GetIsolate(), "pull"),
            v8::Undefined(scope.GetIsolate()))
      .Check();
  auto* algo = CreateAlgorithmFromUnderlyingMethod(
      scope.GetScriptState(), underlying_object, "pull",
      "underlyingSource.pull", EmptyExtraArg(), ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(algo);
  auto promise = algo->Run(scope.GetScriptState(), 0, nullptr);
  ASSERT_FALSE(promise.IsEmpty());
  ASSERT_EQ(promise.V8Promise()->State(), v8::Promise::kFulfilled);
  EXPECT_TRUE(promise.V8Promise()->Result()->IsUndefined());
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmNullMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto underlying_object = v8::Object::New(scope.GetIsolate());
  underlying_object
      ->Set(scope.GetContext(), V8String(scope.GetIsolate(), "pull"),
            v8::Null(scope.GetIsolate()))
      .Check();
  ExceptionState exception_state(scope.GetIsolate(),
                                 v8::ExceptionContext::kOperation, "", "");
  auto* algo = CreateAlgorithmFromUnderlyingMethod(
      scope.GetScriptState(), underlying_object, "pull",
      "underlyingSource.pull", EmptyExtraArg(), exception_state);
  EXPECT_FALSE(algo);
  EXPECT_TRUE(exception_state.HadException());
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmThrowingGetter) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptValue underlying_value = EvalWithPrintingError(
      &scope, "({ get pull() { throw new TypeError(); } })");
  ASSERT_TRUE(underlying_value.IsObject());
  auto underlying_object = underlying_value.V8Value().As<v8::Object>();
  ExceptionState exception_state(scope.GetIsolate(),
                                 v8::ExceptionContext::kOperation, "", "");
  auto* algo = CreateAlgorithmFromUnderlyingMethod(
      scope.GetScriptState(), underlying_object, "pull",
      "underlyingSource.pull", EmptyExtraArg(), exception_state);
  EXPECT_FALSE(algo);
  EXPECT_TRUE(exception_state.HadException());
}

v8::Local<v8::Value> CreateFromFunctionAndGetResult(
    V8TestingScope* scope,
    const char* function_definition,
    v8::MaybeLocal<v8::Value> extra_arg = v8::MaybeLocal<v8::Value>(),
    int argc = 0,
    v8::Local<v8::Value> argv[] = nullptr) {
  String js = String("({start: ") + function_definition + "})" + '\0';
  ScriptValue underlying_value =
      EvalWithPrintingError(scope, js.Utf8().c_str());
  auto underlying_object = underlying_value.V8Value().As<v8::Object>();
  auto* algo = CreateAlgorithmFromUnderlyingMethod(
      scope->GetScriptState(), underlying_object, "start",
      "underlyingSource.start", extra_arg, ASSERT_NO_EXCEPTION);
  auto promise = algo->Run(scope->GetScriptState(), argc, argv);
  EXPECT_EQ(promise.V8Promise()->State(), v8::Promise::kFulfilled);
  return promise.V8Promise()->Result();
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmReturnsInteger) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto result = CreateFromFunctionAndGetResult(&scope, "() => 5");
  ASSERT_TRUE(result->IsNumber());
  EXPECT_EQ(result.As<v8::Number>()->Value(), 5);
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmReturnsPromise) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto result =
      CreateFromFunctionAndGetResult(&scope, "() => Promise.resolve(2)");
  ASSERT_TRUE(result->IsNumber());
  EXPECT_EQ(result.As<v8::Number>()->Value(), 2);
}

bool CreateFromFunctionAndGetSuccess(
    V8TestingScope* scope,
    const char* function_definition,
    v8::MaybeLocal<v8::Value> extra_arg = v8::MaybeLocal<v8::Value>(),
    int argc = 0,
    v8::Local<v8::Value> argv[] = nullptr) {
  auto result = CreateFromFunctionAndGetResult(scope, function_definition,
                                               extra_arg, argc, argv);
  if (!result->IsBoolean()) {
    return false;
  }
  return result.As<v8::Boolean>()->Value();
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmNoArgs) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  EXPECT_TRUE(CreateFromFunctionAndGetSuccess(
      &scope, "(...args) => args.length === 0"));
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmExtraArg) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::Local<v8::Number> extra_arg = v8::Number::New(scope.GetIsolate(), 7);
  EXPECT_TRUE(CreateFromFunctionAndGetSuccess(
      &scope, "(...args) => args.length === 1 && args[0] === 7", extra_arg));
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmPassOneArg) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::MaybeLocal<v8::Value> extra_arg;
  v8::Local<v8::Value> argv[] = {v8::Number::New(scope.GetIsolate(), 10)};
  EXPECT_TRUE(CreateFromFunctionAndGetSuccess(
      &scope, "(...args) => args.length === 1 && args[0] === 10",
      EmptyExtraArg(), 1, argv));
}

TEST(MiscellaneousOperationsTest, CreateAlgorithmPassBoth) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::MaybeLocal<v8::Value> extra_arg = v8::Number::New(scope.GetIsolate(), 5);
  v8::Local<v8::Value> argv[] = {v8::Number::New(scope.GetIsolate(), 10)};
  EXPECT_TRUE(CreateFromFunctionAndGetSuccess(
      &scope,
      "(...args) => args.length === 2 && args[0] === 10 && args[1] === 5",
      extra_arg, 1, argv));
}

TEST(MiscellaneousOperationsTest, CreateStartAlgorithmNoMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto underlying_object = v8::Object::New(scope.GetIsolate());
  v8::Local<v8::Value> controller = v8::Undefined(scope.GetIsolate());
  auto* algo = CreateStartAlgorithm(scope.GetScriptState(), underlying_object,
                                    "underlyingSink.start", controller);
  ASSERT_TRUE(algo);
  auto result = algo->Run(scope.GetScriptState());
  ASSERT_EQ(result.V8Promise()->State(), v8::Promise::kFulfilled);
  EXPECT_TRUE(result.V8Promise()->Result()->IsUndefined());
}

TEST(MiscellaneousOperationsTest, CreateStartAlgorithmNullMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto underlying_object = v8::Object::New(scope.GetIsolate());
  underlying_object
      ->Set(scope.GetContext(), V8String(scope.GetIsolate(), "start"),
            v8::Null(scope.GetIsolate()))
      .Check();
  v8::Local<v8::Value> controller = v8::Undefined(scope.GetIsolate());
  auto* algo = CreateStartAlgorithm(scope.GetScriptState(), underlying_object,
                                    "underlyingSink.start", controller);
  ASSERT_TRUE(algo);
  v8::TryCatch try_catch(scope.GetIsolate());
  auto result = algo->Run(scope.GetScriptState());
  EXPECT_TRUE(try_catch.HasCaught());
  EXPECT_TRUE(result.IsEmpty());
}

TEST(MiscellaneousOperationsTest, CreateStartAlgorithmThrowingMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptValue underlying_value = EvalWithPrintingError(&scope,
                                                       R"(({
  start() {
    throw new Error();
  }
}))");
  ASSERT_TRUE(underlying_value.IsObject());
  auto underlying_object = underlying_value.V8Value().As<v8::Object>();
  v8::Local<v8::Value> controller = v8::Undefined(scope.GetIsolate());
  auto* algo = CreateStartAlgorithm(scope.GetScriptState(), underlying_object,
                                    "underlyingSink.start", controller);
  ASSERT_TRUE(algo);
  v8::TryCatch try_catch(scope.GetIsolate());
  auto result = algo->Run(scope.GetScriptState());
  EXPECT_TRUE(try_catch.HasCaught());
  EXPECT_TRUE(result.IsEmpty());
}

TEST(MiscellaneousOperationsTest, CreateStartAlgorithmReturningController) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptValue underlying_value = EvalWithPrintingError(&scope,
                                                       R"(({
  start(controller) {
    return controller;
  }
}))");
  ASSERT_TRUE(underlying_value.IsObject());
  auto underlying_object = underlying_value.V8Value().As<v8::Object>();
  // In a real stream, |controller| is never a promise, but nothing in
  // CreateStartAlgorithm() requires this. By making it a promise, we can verify
  // that a promise returned from start is passed through as-is.
  v8::Local<v8::Value> controller =
      v8::Promise::Resolver::New(scope.GetContext())
          .ToLocalChecked()
          ->GetPromise();
  auto* algo = CreateStartAlgorithm(scope.GetScriptState(), underlying_object,
                                    "underlyingSink.start", controller);
  ASSERT_TRUE(algo);
  auto result = algo->Run(scope.GetScriptState());
  EXPECT_FALSE(result.IsEmpty());
  ASSERT_EQ(result.V8Promise(), controller);
}

TEST(MiscellaneousOperationsTest, CallOrNoop1NoMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto underlying_object = v8::Object::New(scope.GetIsolate());
  v8::Local<v8::Value> arg0 = v8::Number::New(scope.GetIsolate(), 0);
  auto maybe_result =
      CallOrNoop1(scope.GetScriptState(), underlying_object, "transform",
                  "transformer.transform", arg0, ASSERT_NO_EXCEPTION);
  ASSERT_FALSE(maybe_result.IsEmpty());
  EXPECT_TRUE(maybe_result.ToLocalChecked()->IsUndefined());
}

TEST(MiscellaneousOperationsTest, CallOrNoop1NullMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto underlying_object = v8::Object::New(scope.GetIsolate());
  v8::Local<v8::Value> arg0 = v8::Number::New(scope.GetIsolate(), 0);
  underlying_object
      ->Set(scope.GetContext(), V8String(scope.GetIsolate(), "transform"),
            v8::Null(scope.GetIsolate()))
      .Check();
  ExceptionState exception_state(scope.GetIsolate(),
                                 v8::ExceptionContext::kOperation, "", "");
  auto maybe_result =
      CallOrNoop1(scope.GetScriptState(), underlying_object, "transform",
                  "transformer.transform", arg0, exception_state);
  ASSERT_TRUE(maybe_result.IsEmpty());
  ASSERT_TRUE(exception_state.HadException());
}

TEST(MiscellaneousOperationsTest, CallOrNoop1CheckCalled) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptValue underlying_value = EvalWithPrintingError(&scope,
                                                       R"(({
  transform(...args) {
    return args.length === 1 && args[0] === 17;
  }
}))");
  ASSERT_TRUE(underlying_value.IsObject());
  auto underlying_object = underlying_value.V8Value().As<v8::Object>();
  v8::Local<v8::Value> arg0 = v8::Number::New(scope.GetIsolate(), 17);
  auto maybe_result =
      CallOrNoop1(scope.GetScriptState(), underlying_object, "transform",
                  "transformer.transform", arg0, ASSERT_NO_EXCEPTION);
  ASSERT_FALSE(maybe_result.IsEmpty());
  auto result = maybe_result.ToLocalChecked();
  ASSERT_TRUE(result->IsBoolean());
  EXPECT_TRUE(result.As<v8::Boolean>()->Value());
}

TEST(MiscellaneousOperationsTest, CallOrNoop1ThrowingMethod) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptValue underlying_value = EvalWithPrintingError(&scope,
                                                       R"(({
  transform(...args) {
    throw false;
  }
}))");
  ASSERT_TRUE(underlying_value.IsObject());
  auto underlying_object = underlying_value.V8Value().As<v8::Object>();
  v8::Local<v8::Value> arg0 = v8::Number::New(scope.GetIsolate(), 17);
  v8::TryCatch try_catch(scope.GetIsolate());
  auto maybe_result = CallOrNoop1(scope.GetScriptState(), underlying_object,
                                  "transform", "transformer.transform", arg0,
                                  PassThroughException(scope.GetIsolate()));
  ASSERT_TRUE(try_catch.HasCaught());
  EXPECT_TRUE(maybe_result.IsEmpty());
  EXPECT_TRUE(try_catch.Exception()->IsBoolean());
}

ScriptPromise<IDLUndefined> PromiseCallFromText(V8TestingScope* scope,
                                                const char* function_definition,
                                                const char* object_definition,
                                                int argc,
                                                v8::Local<v8::Value> argv[]) {
  ScriptValue function_value =
      EvalWithPrintingError(scope, function_definition);
  EXPECT_TRUE(function_value.IsFunction());
  ScriptValue object_value = EvalWithPrintingError(scope, object_definition);
  EXPECT_TRUE(object_value.IsObject());
  return PromiseCall(scope->GetScriptState(),
                     function_value.V8Value().As<v8::Function>(),
                     object_value.V8Value().As<v8::Object>(), argc, argv);
}

TEST(MiscellaneousOperationsTest, PromiseCalledWithObject) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptPromise<IDLUndefined> promise =
      PromiseCallFromText(&scope, "(function() { return this.value === 15; })",
                          "({ value: 15 })", 0, nullptr);
  ASSERT_EQ(promise.V8Promise()->State(), v8::Promise::kFulfilled);
  ASSERT_TRUE(promise.V8Promise()->Result()->IsBoolean());
  EXPECT_TRUE(promise.V8Promise()->Result().As<v8::Boolean>()->Value());
}

TEST(MiscellaneousOperationsTest, PromiseCallThrowing) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptPromise<IDLUndefined> promise = PromiseCallFromText(
      &scope, "(function() { throw new TypeError(); })", "({})", 0, nullptr);
  ASSERT_EQ(promise.V8Promise()->State(), v8::Promise::kRejected);
  EXPECT_TRUE(promise.V8Promise()->Result()->IsNativeError());
}

TEST(MiscellaneousOperationsTest, PromiseCallRejecting) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptPromise<IDLUndefined> promise = PromiseCallFromText(
      &scope, "(function() { return Promise.reject(16) })", "({})", 0, nullptr);
  ASSERT_EQ(promise.V8Promise()->State(), v8::Promise::kRejected);
  ASSERT_TRUE(promise.V8Promise()->Result()->IsNumber());
  EXPECT_EQ(promise.V8Promise()->Result().As<v8::Number>()->Value(), 16);
}

TEST(MiscellaneousOperationsTest, ValidatePositiveHighWaterMark) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  EXPECT_EQ(ValidateAndNormalizeHighWaterMark(23, ASSERT_NO_EXCEPTION), 23.0);
}

TEST(MiscellaneousOperationsTest, ValidateInfiniteHighWaterMark) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  EXPECT_FALSE(isfinite(ValidateAndNormalizeHighWaterMark(
      std::numeric_limits<double>::infinity(), ASSERT_NO_EXCEPTION)));
}

TEST(MiscellaneousOperationsTest, NegativeHighWaterMarkInvalid) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ExceptionState exception_state(scope.GetIsolate(),
                                 v8::ExceptionContext::kOperation, "", "");
  ValidateAndNormalizeHighWaterMark(-1, exception_state);
  EXPECT_TRUE(exception_state.HadException());
}

TEST(MiscellaneousOperationsTest, NaNHighWaterMarkInvalid) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ExceptionState exception_state(scope.GetIsolate(),
                                 v8::ExceptionContext::kOperation, "", "");
  ValidateAndNormalizeHighWaterMark(std::numeric_limits<double>::quiet_NaN(),
                                    exception_state);
  EXPECT_TRUE(exception_state.HadException());
}

TEST(MiscellaneousOperationsTest, UndefinedSizeFunction) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* algo = MakeSizeAlgorithmFromSizeFunction(
      scope.GetScriptState(), v8::Undefined(scope.GetIsolate()),
      ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(algo);
  auto optional = algo->Run(scope.GetScriptState(),
                            v8::Number::New(scope.GetIsolate(), 97));
  ASSERT_TRUE(optional.has_value());
  EXPECT_EQ(optional.value(), 1.0);
}

TEST(MiscellaneousOperationsTest, NullSizeFunction) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ExceptionState exception_state(scope.GetIsolate(),
                                 v8::ExceptionContext::kOperation, "", "");
  EXPECT_EQ(MakeSizeAlgorithmFromSizeFunction(scope.GetScriptState(),
                                              v8::Null(scope.GetIsolate()),

                                              exception_state),
            nullptr);
  EXPECT_TRUE(exception_state.HadException());
}

StrategySizeAlgorithm* IdentitySizeAlgorithm(V8TestingScope* scope) {
  ScriptValue function_value = EvalWithPrintingError(scope, "i => i");
  EXPECT_TRUE(function_value.IsFunction());
  return MakeSizeAlgorithmFromSizeFunction(
      scope->GetScriptState(), function_value.V8Value(), ASSERT_NO_EXCEPTION);
}

TEST(MiscellaneousOperationsTest, SizeAlgorithmWorks) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* algo = IdentitySizeAlgorithm(&scope);
  ASSERT_TRUE(algo);
  auto optional = algo->Run(scope.GetScriptState(),
                            v8::Number::New(scope.GetIsolate(), 41));
  ASSERT_TRUE(optional.has_value());
  EXPECT_EQ(optional.value(), 41.0);
}

TEST(MiscellaneousOperationsTest, SizeAlgorithmConvertsToNumber) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* algo = IdentitySizeAlgorithm(&scope);
  ASSERT_TRUE(algo);
  auto optional =
      algo->Run(scope.GetScriptState(), V8String(scope.GetIsolate(), "79"));
  ASSERT_TRUE(optional.has_value());
  EXPECT_EQ(optional.value(), 79.0);
}

TEST(MiscellaneousOperationsTest, ThrowingSizeAlgorithm) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptValue function_value =
      EvalWithPrintingError(&scope, "() => { throw new TypeError(); }");
  EXPECT_TRUE(function_value.IsFunction());
  auto* algo = MakeSizeAlgorithmFromSizeFunction(
      scope.GetScriptState(), function_value.V8Value(), ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(algo);
  v8::TryCatch try_catch(scope.GetIsolate());
  auto optional =
      algo->Run(scope.GetScriptState(), V8String(scope.GetIsolate(), "79"));

  ASSERT_FALSE(optional.has_value());
  EXPECT_TRUE(try_catch.HasCaught());
}

TEST(MiscellaneousOperationsTest, UnconvertibleSize) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* algo = IdentitySizeAlgorithm(&scope);
  ASSERT_TRUE(algo);
  ScriptValue unconvertible_value =
      EvalWithPrintingError(&scope, "({ toString() { throw new Error(); }})");
  EXPECT_TRUE(unconvertible_value.IsObject());
  v8::TryCatch try_catch(scope.GetIsolate());
  auto optional =
      algo->Run(scope.GetScriptState(), unconvertible_value.V8Value());

  ASSERT_FALSE(optional.has_value());
}

TEST(MiscellaneousOperationsTest, PromiseResolve) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto promise = PromiseResolve(scope.GetScriptState(),
                                v8::Number::New(scope.GetIsolate(), 19));
  ASSERT_EQ(promise->State(), v8::Promise::kFulfilled);
  ASSERT_TRUE(promise->Result()->IsNumber());
  EXPECT_EQ(promise->Result().As<v8::Number>()->Value(), 19);
}

TEST(MiscellaneousOperationsTest, PromiseResolveWithPromise) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto original_promise = v8::Promise::Resolver::New(scope.GetContext())
                              .ToLocalChecked()
                              ->GetPromise();
  auto resolved_promise =
      PromiseResolve(scope.GetScriptState(), original_promise);
  EXPECT_EQ(original_promise, resolved_promise);
}

TEST(MiscellaneousOperationsTest, PromiseResolveWithUndefined) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto promise = PromiseResolveWithUndefined(scope.GetScriptState());
  ASSERT_EQ(promise->State(), v8::Promise::kFulfilled);
  EXPECT_TRUE(promise->Result()->IsUndefined());
}

TEST(MiscellaneousOperationsTest, PromiseReject) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto promise = PromiseReject(scope.GetScriptState(),
                               v8::Number::New(scope.GetIsolate(), 43));
  ASSERT_EQ(promise->State(), v8::Promise::kRejected);
  ASSERT_TRUE(promise->Result()->IsNumber());
  EXPECT_EQ(promise->Result().As<v8::Number>()->Value(), 43);
}

}  // namespace

}  // namespace blink

"""

```