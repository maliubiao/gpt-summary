Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The request is to understand the functionality of `model_execution_responder_test.cc`. This immediately suggests it's testing something related to model execution and how it interacts with the browser environment, specifically within the Blink rendering engine. The request also asks for connections to JavaScript, HTML, CSS, logical reasoning, common errors, and debugging context.

**2. Initial Scan and Keyword Identification:**

I start by quickly scanning the code, looking for keywords and patterns. I notice:

* **`TEST(...)`**: This is a strong indicator of unit tests using the Google Test framework. Each `TEST` block represents a specific scenario being tested.
* **`CreateModelExecutionResponder` and `CreateModelExecutionStreamingResponder`**: These function names are central and suggest the core functionality being tested. The "Streaming" variant likely handles responses delivered in chunks.
* **`mojom::blink::ModelStreamingResponder`**:  This points to a Mojo interface, meaning communication across process boundaries is involved (likely between the renderer and some backend service).
* **`ScriptPromiseResolver` and `ScriptPromise`**: These indicate the test interacts with JavaScript promises, suggesting asynchronous operations are being handled.
* **`ReadableStreamDefaultReader`**: This confirms the "StreamingResponder" indeed produces a readable stream, a JavaScript concept for handling asynchronous data.
* **`AbortController`**:  This is a standard web API for cancelling asynchronous operations.
* **`DOMException`**:  This signals error handling within the web platform.
* **`AIMetrics`**: This hints at tracking and measuring the performance or usage of these AI features.
* **`V8TestingScope`**: This confirms the tests are running within a V8 JavaScript engine context.

**3. Analyzing Individual Tests:**

Now, I go through each `TEST` block, understanding what it's verifying:

* **`CreateModelExecutionResponder, Simple`**: This tests a basic successful scenario. It sends a "result" and checks if the promise resolves with that result, and the completion callback is executed.
* **`CreateModelExecutionResponder, ErrorPermissionDenied`**:  This tests error handling. It simulates a "permission denied" error from the backend and verifies the promise is rejected with the correct `NotAllowedError` DOM exception.
* **`CreateModelExecutionResponder, AbortWithoutResponse` and `AbortAfterResponse`**: These test the behavior when an `AbortController` is used. They check if the promise is rejected with an `AbortError` in both cases (before and after receiving data).
* **`CreateModelExecutionStreamingResponder, Simple`**: This tests the streaming case. It verifies that data chunks are delivered through the readable stream and the stream eventually closes.
* **`CreateModelExecutionStreamingResponder, ErrorPermissionDenied`**: Similar to the non-streaming version, this checks if a "permission denied" error propagates to the readable stream as a `NotAllowedError`.
* **`CreateModelExecutionStreamingResponder, AbortWithoutResponse` and `AbortAfterResponse`**: These mirror the abort tests for the non-streaming version but verify the `AbortError` is signaled through the readable stream.

**4. Identifying Connections to Web Technologies:**

Based on the analysis of the tests, the connections to JavaScript, HTML, and CSS become clear:

* **JavaScript:** The tests directly use JavaScript promise and readable stream APIs. The `AbortController` is also a JavaScript API. The code is testing how C++ code interacts with and fulfills JavaScript expectations.
* **HTML:** While not directly manipulated in *this* test file, the underlying functionality is likely triggered by JavaScript code within a web page. For instance, a button click might initiate a request that uses these AI model execution mechanisms.
* **CSS:**  CSS is less directly related here, as the focus is on the logic of data processing and error handling. However, the *results* of the AI model execution (e.g., generated text) might eventually influence the styling or content of an HTML element, which is styled by CSS.

**5. Logical Reasoning and Assumptions:**

For the logical reasoning section, I consider the basic flow of the tests:

* **Assumption:** The backend service (communicated with via Mojo) is responsible for the actual model execution. The C++ code acts as an intermediary and handles the asynchronous communication.
* **Input (for a simple case):**  A request to execute a model (implicitly represented by the `CreateModelExecutionResponder` call). The backend sends the string "result" and a completion signal.
* **Output:** The JavaScript promise resolves with the string "result". The completion callback is executed with token information.

**6. Identifying Potential User/Programming Errors:**

I think about how a developer might misuse these APIs:

* **Forgetting to handle promise rejections:**  If a developer doesn't attach a `.catch()` to the promise, unhandled errors will occur.
* **Not properly handling stream errors:**  In the streaming case, developers need to listen for errors on the readable stream.
* **Misunderstanding the AbortController:**  Failing to correctly associate an `AbortController` with an operation can lead to requests continuing even after they should be cancelled.

**7. Debugging Scenario:**

I consider how a developer might end up investigating this code:

* A user reports an error when using an AI feature on a website.
* The developer suspects the error occurs during the model execution phase.
* They might set breakpoints in the JavaScript code that initiates the request.
* They would then trace the execution into the Blink rendering engine, potentially landing in the C++ code related to `CreateModelExecutionResponder`.
* Examining the Mojo messages and the state of the promises/streams would be crucial for debugging.

**8. Structuring the Response:**

Finally, I organize the information logically, starting with the core functionality and then expanding to related areas as requested by the prompt. I use clear headings and examples to make the explanation easy to understand. I ensure to address each specific point raised in the prompt.
这个C++源代码文件 `model_execution_responder_test.cc` 的主要功能是**测试** Blink 渲染引擎中用于处理 AI 模型执行响应的两个核心类：`ModelExecutionResponder` 和 `CreateModelExecutionStreamingResponder` 返回的对象。

更具体地说，它测试了以下场景：

**针对 `CreateModelExecutionResponder` (返回一个 Promise):**

* **成功场景:** 测试当模型执行成功并返回结果时，返回的 JavaScript Promise 是否能正确地 fulfilled，并且其 value 是预期的结果字符串。同时，测试完成回调函数是否被正确调用，并接收到预期的上下文信息（例如，已处理的 token 数量）。
* **错误处理:** 测试当模型执行发生错误（例如，权限被拒绝）时，返回的 Promise 是否能正确地 rejected，并且 rejection 的原因是预期的 `DOMException` (例如，`NotAllowedError`)。
* **中止 (Abort) 场景:**
    * 测试当在没有收到模型响应之前调用 `AbortController` 中止操作时，返回的 Promise 是否能正确地 rejected，并且 rejection 的原因是 `AbortError`。
    * 测试当在收到部分模型响应之后调用 `AbortController` 中止操作时，返回的 Promise 是否能正确地 rejected，并且 rejection 的原因是 `AbortError`。

**针对 `CreateModelExecutionStreamingResponder` (返回一个 ReadableStream):**

* **成功场景:** 测试当模型执行成功并流式返回结果时，返回的 JavaScript `ReadableStream` 是否能正确地读取到所有的结果片段，并且最终的状态是 `done`。
* **错误处理:** 测试当模型执行发生错误（例如，权限被拒绝）时，错误是否能正确地传递到 `ReadableStream`，并且通过读取 stream 导致 Promise rejected，其 rejection 原因是预期的 `DOMException` (例如，`NotAllowedError`)。
* **中止 (Abort) 场景:**
    * 测试当在没有收到模型响应之前调用 `AbortController` 中止操作时，中止信号是否能正确地传递到 `ReadableStream`，并且通过读取 stream 导致 Promise rejected，其 rejection 原因是 `AbortError`。
    * 测试当在收到部分模型响应之后调用 `AbortController` 中止操作时，中止信号是否能正确地传递到 `ReadableStream`，并且通过读取 stream 导致 Promise rejected，其 rejection 原因是 `AbortError`。

**与 Javascript, HTML, CSS 的关系:**

这个测试文件本身是 C++ 代码，用于测试 Blink 引擎中与 JavaScript 交互的部分。它的功能直接关系到如何将 AI 模型执行的结果传递给 JavaScript 代码。

* **JavaScript:**
    * `CreateModelExecutionResponder` 返回的 Promise 对象可以直接在 JavaScript 中使用 `.then()` 和 `.catch()` 来处理成功和失败的情况。
    * `CreateModelExecutionStreamingResponder` 返回的 `ReadableStream` 对象是 JavaScript 中用于处理流式数据的标准 API。JavaScript 代码可以使用 `ReadableStreamDefaultReader` 来逐步读取模型生成的文本或其他数据。
    * `AbortController` 也是 JavaScript 的 API，用于取消异步操作，这里测试了从 JavaScript 发起的中止操作如何影响 C++ 层的模型执行流程。

    **举例说明:**

    ```javascript
    // 使用 CreateModelExecutionResponder
    navigator.ai.executeModel(modelName, inputData)
      .then(result => {
        console.log("模型执行结果:", result);
      })
      .catch(error => {
        console.error("模型执行出错:", error);
      });

    // 使用 CreateModelExecutionStreamingResponder
    const stream = navigator.ai.executeModelStreaming(modelName, inputData);
    const reader = stream.getReader();
    let result = '';
    reader.read().then(function processText({ done, value }) {
      if (done) {
        console.log("流式数据读取完成:", result);
        return;
      }
      result += value;
      console.log("接收到数据片段:", value);
      return reader.read().then(processText);
    });

    const controller = new AbortController();
    const signal = controller.signal;
    navigator.ai.executeModelStreaming(modelName, inputData, { signal })
      .then(...)
      .catch(error => {
        if (error.name === 'AbortError') {
          console.log("模型执行被用户取消");
        }
      });
    controller.abort();
    ```

* **HTML:** HTML 本身不直接与这个测试文件交互。但是，HTML 页面中的 JavaScript 代码会调用相关的 AI API，从而触发 Blink 引擎中 `ModelExecutionResponder` 或 `CreateModelExecutionStreamingResponder` 的使用。模型执行的结果可能会被 JavaScript 代码用来更新 HTML 页面的内容。

    **举例说明:** 用户在网页上点击一个按钮，触发 JavaScript 代码调用 AI 模型生成一段文本，然后将生成的文本插入到页面上的一个 `<div>` 元素中。

* **CSS:** CSS 同样不直接与这个测试文件交互。但是，模型生成的内容（例如，文本）最终会通过 HTML 渲染到页面上，并可以使用 CSS 进行样式化。

**逻辑推理 (假设输入与输出):**

**场景 1: `CreateModelExecutionResponder, Simple`**

* **假设输入 (Mojo 层):**
    * `OnStreaming("result")` 被调用一次。
    * `OnCompletion(mojom::blink::ModelExecutionContextInfo::New(1u, false))` 被调用。
* **预期输出 (JavaScript 层):**
    * 返回的 Promise 将会 fulfilled。
    * Promise 的 value 将会是字符串 `"result"`。
    * 传递给 `CreateModelExecutionResponder` 的 `complete_callback` 将会被调用，并且其 `context_info` 参数的 `current_tokens` 字段值为 `1u`。

**场景 2: `CreateModelExecutionStreamingResponder, Simple`**

* **假设输入 (Mojo 层):**
    * `OnStreaming("result")` 被调用一次。
    * `OnCompletion(mojom::blink::ModelExecutionContextInfo::New(1u, false))` 被调用。
* **预期输出 (JavaScript 层):**
    * 返回的 `ReadableStream` 可以被读取。
    * 第一次 `reader.read()` 返回的 value 是字符串 `"result"`，`done` 是 `false`。
    * 第二次 `reader.read()` 返回的 value 是 `null` 或 `undefined` (取决于具体的实现)，`done` 是 `true`。

**用户或者编程常见的使用错误:**

* **忘记处理 Promise 的 rejection:** 如果 JavaScript 代码没有使用 `.catch()` 或 `.then(null, ...)` 来处理 `CreateModelExecutionResponder` 返回的 Promise 的 rejection，当模型执行出错时可能会导致未捕获的错误。
    ```javascript
    // 错误示例：未处理 rejection
    navigator.ai.executeModel(modelName, inputData)
      .then(result => {
        console.log("结果:", result);
      });
    ```
* **没有正确处理 ReadableStream 的错误:** 对于 `CreateModelExecutionStreamingResponder` 返回的流，如果 JavaScript 代码没有监听 stream 上的错误事件或者在读取过程中处理可能的错误，可能会导致程序异常。
    ```javascript
    // 错误示例：未处理 stream 错误
    const stream = navigator.ai.executeModelStreaming(modelName, inputData);
    const reader = stream.getReader();
    reader.read().then(function processText({ done, value }) { ... }); // 缺少错误处理
    ```
* **在不需要中止的时候调用 AbortController.abort():**  如果错误地调用了 `abort()`, 会意外地取消正在进行的模型执行。
* **在模型执行已经完成或出错后尝试读取 ReadableStream:**  尝试读取一个已经关闭或发生错误的 `ReadableStream` 会导致 Promise rejected。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中与一个使用了 AI 功能的网页进行交互：

1. **用户操作:** 用户在网页上点击了一个“生成文本”的按钮。
2. **JavaScript 代码触发:** 按钮的点击事件监听器被触发，执行相应的 JavaScript 代码。
3. **调用 AI API:** JavaScript 代码调用了浏览器的 AI API，例如 `navigator.ai.executeModel()` 或 `navigator.ai.executeModelStreaming()`。
4. **Blink 引擎处理:** 浏览器接收到 API 调用，Blink 引擎开始处理这个请求。
5. **创建 Responder 对象:**  Blink 引擎内部会创建 `ModelExecutionResponder` 或 `CreateModelExecutionStreamingResponder` 的实例，并返回相应的 Promise 或 ReadableStream 给 JavaScript。同时，会通过 Mojo 与浏览器进程或外部服务通信，请求执行 AI 模型。
6. **模型执行 (可能在其他进程):**  AI 模型的执行可能发生在浏览器进程的其他部分，或者甚至是一个独立的外部服务。
7. **Mojo 消息传递:** 模型执行的结果（成功或失败，以及数据）通过 Mojo 消息传递回 Blink 引擎。
8. **Responder 对象接收消息:** `ModelExecutionResponder` 或 `CreateModelExecutionStreamingResponder` 接收到来自 Mojo 的消息（例如，`OnStreaming`, `OnCompletion`, `OnError`）。
9. **更新 Promise 或 Stream 状态:**  根据接收到的 Mojo 消息，Responder 对象会更新其关联的 JavaScript Promise 的状态（resolve 或 reject），或者向 ReadableStream 中写入数据或发送错误信号。

**调试线索:**

* **JavaScript 错误信息:** 如果模型执行出错，浏览器的开发者工具的控制台可能会显示相关的 JavaScript 错误信息，例如 Promise 的 rejection 原因。
* **网络请求:** 开发者可以使用浏览器的网络面板查看是否有相关的网络请求发送到 AI 模型服务，以及请求和响应的状态和内容。
* **Mojo 接口监控:** Chromium 的开发者可以使用内部工具（例如 `chrome://tracing` 或 `about:tracing`) 来监控 Mojo 接口的调用和消息传递，查看 `ModelStreamingResponder` 接口上的方法调用和数据。
* **Blink 渲染引擎调试:**  如果需要深入了解 Blink 引擎内部的运行情况，可以使用 C++ 调试器 (例如 gdb 或 lldb) attach 到渲染进程，并在 `model_execution_responder_test.cc` 中测试的代码路径上设置断点，例如在 `CreateModelExecutionResponder` 和 `CreateModelExecutionStreamingResponder` 函数内部，以及 `OnStreaming`, `OnCompletion`, `OnError` 等方法中，来跟踪代码的执行流程和变量的值。
* **日志输出:** Blink 引擎中可能包含相关的日志输出，可以帮助开发者了解模型执行的状态和错误信息。

总而言之，`model_execution_responder_test.cc` 是一个非常重要的测试文件，它确保了 Blink 引擎能够正确地将 AI 模型执行的结果和状态传递给 JavaScript，并且能够处理各种成功、错误和中止的情况，保证了 Web 平台上 AI 功能的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/modules/ai/model_execution_responder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ai/model_execution_responder.h"

#include <optional>
#include <tuple>

#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/functional/callback_helpers.h"
#include "base/run_loop.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/ai/model_streaming_responder.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/core/dom/abort_controller.h"
#include "third_party/blink/renderer/core/fetch/readable_stream_bytes_consumer.h"
#include "third_party/blink/renderer/modules/ai/ai_metrics.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {
namespace {

std::tuple<String, bool> ReadString(ReadableStreamDefaultReader* reader,
                                    V8TestingScope& scope) {
  String result;
  bool done = false;
  auto read_promise = reader->read(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(scope.GetScriptState(), read_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  v8::Local<v8::Value> v8value;
  EXPECT_TRUE(V8UnpackIterationResult(scope.GetScriptState(),
                                      tester.Value().V8Value().As<v8::Object>(),
                                      &v8value, &done));
  if (v8value->IsString()) {
    result = ToCoreString(scope.GetIsolate(), v8value.As<v8::String>());
  }
  return std::make_tuple(result, done);
}

}  // namespace

TEST(CreateModelExecutionResponder, Simple) {
  uint64_t kTestTokenNumber = 1u;
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  base::RunLoop callback_runloop;
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto promise = resolver->Promise();
  auto pending_remote = CreateModelExecutionResponder(
      script_state, /*signal=*/nullptr, resolver,
      blink::scheduler::GetSequencedTaskRunnerForTesting(),
      AIMetrics::AISessionType::kLanguageModel,
      base::BindOnce(
          [](uint64_t expected_tokens, base::RunLoop* runloop,
             mojom::blink::ModelExecutionContextInfoPtr context_info) {
            EXPECT_TRUE(context_info);
            EXPECT_EQ(context_info->current_tokens, expected_tokens);
            runloop->Quit();
          },
          kTestTokenNumber, &callback_runloop));

  base::RunLoop runloop;
  mojo::Remote<blink::mojom::blink::ModelStreamingResponder> responder(
      std::move(pending_remote));
  responder.set_disconnect_handler(runloop.QuitClosure());
  responder->OnStreaming("result");
  responder->OnCompletion(mojom::blink::ModelExecutionContextInfo::New(
      kTestTokenNumber, /*did_overflow=*/false));
  // Check that the promise will be resolved with the "result" string.
  ScriptPromiseTester tester(scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_TRUE(tester.Value().V8Value()->IsString());
  EXPECT_EQ("result", ToCoreString(scope.GetIsolate(),
                                   tester.Value().V8Value().As<v8::String>()));

  // Check that the callback is run.
  callback_runloop.Run();
  // Check that the Mojo handle will be disconnected.
  runloop.Run();
}

TEST(CreateModelExecutionResponder, ErrorPermissionDenied) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto promise = resolver->Promise();
  auto pending_remote = CreateModelExecutionResponder(
      script_state, /*signal=*/nullptr, resolver,
      blink::scheduler::GetSequencedTaskRunnerForTesting(),
      AIMetrics::AISessionType::kLanguageModel,
      /*complete_callback=*/base::DoNothing());

  mojo::Remote<blink::mojom::blink::ModelStreamingResponder> responder(
      std::move(pending_remote));
  base::RunLoop runloop;
  responder.set_disconnect_handler(runloop.QuitClosure());
  responder->OnError(
      blink::mojom::ModelStreamingResponseStatus::kErrorPermissionDenied);

  // Check that the promise will be rejected with an ErrorInvalidRequest.
  ScriptPromiseTester tester(scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
  auto* dom_exception = V8DOMException::ToWrappable(script_state->GetIsolate(),
                                                    tester.Value().V8Value());
  ASSERT_TRUE(dom_exception);
  EXPECT_EQ(DOMException(DOMExceptionCode::kNotAllowedError).name(),
            dom_exception->name());

  // Check that the Mojo handle will be disconnected.
  runloop.Run();
}

TEST(CreateModelExecutionResponder, AbortWithoutResponse) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  auto* controller = AbortController::Create(scope.GetScriptState());
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto promise = resolver->Promise();
  auto pending_remote = CreateModelExecutionResponder(
      script_state, controller->signal(), resolver,
      blink::scheduler::GetSequencedTaskRunnerForTesting(),
      AIMetrics::AISessionType::kLanguageModel,
      /*complete_callback=*/base::DoNothing());

  controller->abort(scope.GetScriptState());

  mojo::Remote<blink::mojom::blink::ModelStreamingResponder> responder(
      std::move(pending_remote));
  base::RunLoop runloop;
  responder.set_disconnect_handler(runloop.QuitClosure());

  // Check that the promise will be rejected with an AbortError.
  ScriptPromiseTester tester(scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
  auto* dom_exception = V8DOMException::ToWrappable(script_state->GetIsolate(),
                                                    tester.Value().V8Value());
  ASSERT_TRUE(dom_exception);
  EXPECT_EQ(DOMException(DOMExceptionCode::kAbortError).name(),
            dom_exception->name());

  // Check that the Mojo handle will be disconnected.
  runloop.Run();
}

TEST(CreateModelExecutionResponder, AbortAfterResponse) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  auto* controller = AbortController::Create(scope.GetScriptState());
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto promise = resolver->Promise();
  auto pending_remote = CreateModelExecutionResponder(
      script_state, controller->signal(), resolver,
      blink::scheduler::GetSequencedTaskRunnerForTesting(),
      AIMetrics::AISessionType::kLanguageModel,
      /*complete_callback=*/base::DoNothing());

  mojo::Remote<blink::mojom::blink::ModelStreamingResponder> responder(
      std::move(pending_remote));
  base::RunLoop runloop;
  responder.set_disconnect_handler(runloop.QuitClosure());
  responder->OnStreaming("result");
  responder->OnCompletion(mojom::blink::ModelExecutionContextInfo::New(
      /*current_tokens=*/1u, /*did_overflow=*/false));

  controller->abort(scope.GetScriptState());

  // Check that the promise will be rejected with an AbortError.
  ScriptPromiseTester tester(scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
  auto* dom_exception = V8DOMException::ToWrappable(script_state->GetIsolate(),
                                                    tester.Value().V8Value());
  ASSERT_TRUE(dom_exception);
  EXPECT_EQ(DOMException(DOMExceptionCode::kAbortError).name(),
            dom_exception->name());

  // Check that the Mojo handle will be disconnected.
  runloop.Run();
}

TEST(CreateModelExecutionStreamingResponder, Simple) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  auto [stream, pending_remote] = CreateModelExecutionStreamingResponder(
      script_state, /*signal=*/nullptr,
      blink::scheduler::GetSequencedTaskRunnerForTesting(),
      AIMetrics::AISessionType::kLanguageModel,
      /*complete_callback=*/base::DoNothing());

  mojo::Remote<blink::mojom::blink::ModelStreamingResponder> responder(
      std::move(pending_remote));
  base::RunLoop runloop;
  responder.set_disconnect_handler(runloop.QuitClosure());
  responder->OnStreaming("result");
  responder->OnCompletion(mojom::blink::ModelExecutionContextInfo::New(
      /*current_tokens=*/1u, /*did_overflow=*/false));

  // Check that we can read the stream.
  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  String result;
  bool done;
  std::tie(result, done) = ReadString(reader, scope);
  EXPECT_EQ("result", result);
  EXPECT_FALSE(done);
  std::tie(result, done) = ReadString(reader, scope);
  EXPECT_TRUE(result.IsNull());
  EXPECT_TRUE(done);

  // Check that the Mojo handle will be disconnected.
  runloop.Run();
}

TEST(CreateModelExecutionStreamingResponder, ErrorPermissionDenied) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  auto [stream, pending_remote] = CreateModelExecutionStreamingResponder(
      script_state, /*signal=*/nullptr,
      blink::scheduler::GetSequencedTaskRunnerForTesting(),
      AIMetrics::AISessionType::kLanguageModel,
      /*complete_callback=*/base::DoNothing());

  mojo::Remote<blink::mojom::blink::ModelStreamingResponder> responder(
      std::move(pending_remote));
  base::RunLoop runloop;
  responder.set_disconnect_handler(runloop.QuitClosure());
  responder->OnError(
      blink::mojom::ModelStreamingResponseStatus::kErrorPermissionDenied);

  // Check that the NotAllowedError is passed to the stream.
  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(scope.GetScriptState(), read_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
  auto* dom_exception = V8DOMException::ToWrappable(script_state->GetIsolate(),
                                                    tester.Value().V8Value());
  ASSERT_TRUE(dom_exception);
  EXPECT_EQ(DOMException(DOMExceptionCode::kNotAllowedError).name(),
            dom_exception->name());

  // Check that the Mojo handle will be disconnected.
  runloop.Run();
}

TEST(CreateModelExecutionStreamingResponder, AbortWithoutResponse) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  auto* controller = AbortController::Create(scope.GetScriptState());
  auto [stream, pending_remote] = CreateModelExecutionStreamingResponder(
      script_state, controller->signal(),
      blink::scheduler::GetSequencedTaskRunnerForTesting(),
      AIMetrics::AISessionType::kLanguageModel,
      /*complete_callback=*/base::DoNothing());

  controller->abort(scope.GetScriptState());

  mojo::Remote<blink::mojom::blink::ModelStreamingResponder> responder(
      std::move(pending_remote));
  base::RunLoop runloop;
  responder.set_disconnect_handler(runloop.QuitClosure());

  // Check that the AbortError is passed to the stream.
  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(scope.GetScriptState(), read_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
  auto* dom_exception = V8DOMException::ToWrappable(script_state->GetIsolate(),
                                                    tester.Value().V8Value());
  ASSERT_TRUE(dom_exception);
  EXPECT_EQ(DOMException(DOMExceptionCode::kAbortError).name(),
            dom_exception->name());

  // Check that the Mojo handle will be disconnected.
  runloop.Run();
}

TEST(CreateModelExecutionStreamingResponder, AbortAfterResponse) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  auto* controller = AbortController::Create(scope.GetScriptState());
  auto [stream, pending_remote] = CreateModelExecutionStreamingResponder(
      script_state, controller->signal(),
      blink::scheduler::GetSequencedTaskRunnerForTesting(),
      AIMetrics::AISessionType::kLanguageModel,
      /*complete_callback=*/base::DoNothing());

  controller->abort(scope.GetScriptState());

  mojo::Remote<blink::mojom::blink::ModelStreamingResponder> responder(
      std::move(pending_remote));
  base::RunLoop runloop;
  responder.set_disconnect_handler(runloop.QuitClosure());
  responder->OnStreaming("result");
  responder->OnCompletion(
      mojom::blink::ModelExecutionContextInfo::New(1u, /*did_overflow=*/false));

  // Check that the AbortError is passed to the stream.
  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(scope.GetScriptState(), read_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
  auto* dom_exception = V8DOMException::ToWrappable(script_state->GetIsolate(),
                                                    tester.Value().V8Value());
  ASSERT_TRUE(dom_exception);
  EXPECT_EQ(DOMException(DOMExceptionCode::kAbortError).name(),
            dom_exception->name());

  // Check that the Mojo handle will be disconnected.
  runloop.Run();
}

}  // namespace blink
```