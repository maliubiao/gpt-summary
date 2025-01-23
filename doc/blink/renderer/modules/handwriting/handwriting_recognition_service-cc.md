Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the functionality of `handwriting_recognition_service.cc` within the Chromium Blink rendering engine. This involves identifying its purpose, how it interacts with other parts of the system (especially JavaScript/web APIs), potential errors, and how a user might trigger this code.

**2. Initial Code Scan - High-Level Understanding:**

First, a quick scan reveals key keywords and concepts:

* **`HandwritingRecognitionService`**: This is the central class, so it's likely responsible for managing handwriting recognition.
* **`Navigator`**: The service is associated with the `Navigator` object, a core browser API available in JavaScript. This strongly suggests a web API connection.
* **`HandwritingRecognizer`**:  Another class, probably representing an individual handwriting recognition session or engine.
* **`HandwritingModelConstraint`**:  This likely defines the parameters for handwriting recognition (e.g., language).
* **`ScriptPromise`**:  Promises are a common way to handle asynchronous operations in JavaScript and are used here, confirming an interaction with the JavaScript layer.
* **`mojo`**:  Keywords like `mojo::PendingRemote` and `remote_service_` point to the use of Mojo, Chromium's inter-process communication system. This means this code likely interacts with a browser process component responsible for the actual handwriting recognition.
* **`CreateHandwritingRecognizer` and `QueryHandwritingRecognizer`**: These function names clearly indicate the primary actions the service performs.
* **Error Handling (`DOMException`)**: The code explicitly handles different error scenarios.

**3. Deeper Dive into Functionality:**

Now, let's analyze the key functions and their roles:

* **`HandwritingRecognitionService::From(Navigator& navigator)`**: This is a typical Chromium "supplement" pattern. It ensures a single instance of the service exists per `Navigator`.
* **`createHandwritingRecognizer(ScriptState*, Navigator&, const HandwritingModelConstraint*, ExceptionState&)`**:  This static method acts as an entry point, delegating to the instance method. The parameters (especially `ScriptState` and `ExceptionState`) confirm the interaction with the JavaScript engine.
* **`BootstrapMojoConnectionIfNeeded(ScriptState*, ExceptionState&)`**: This function establishes the Mojo connection to the browser process if it hasn't already been done. It's crucial for communicating with the handwriting recognition backend. The checks for `ContextIsValid()` are important for handling detached frames.
* **`CreateHandwritingRecognizer(ScriptState*, const HandwritingModelConstraint*, ExceptionState&)`**: This is the core logic for initiating handwriting recognition. It involves:
    * Checking for a valid Mojo connection.
    * Creating a JavaScript Promise.
    * Converting the `HandwritingModelConstraint` to a Mojo type.
    * Making a Mojo call to the browser process (`remote_service_->CreateHandwritingRecognizer`).
    * Using a callback (`OnCreateHandwritingRecognizer`) to handle the result of the Mojo call and resolve or reject the JavaScript Promise.
* **`queryHandwritingRecognizer(...)`**: Similar to `createHandwritingRecognizer`, but it's for querying available handwriting recognition capabilities.
* **`OnCreateHandwritingRecognizer(...)` and `OnQueryHandwritingRecognizer(...)`**: These callback functions handle the responses from the browser process via Mojo. They translate the Mojo results into JavaScript Promise resolutions (either resolving with a `HandwritingRecognizer` or `HandwritingRecognizerQueryResult`, or rejecting with a `DOMException`).

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Based on the function signatures and the use of Promises, it's clear this C++ code provides the backend implementation for a JavaScript API. The names of the classes and methods strongly suggest the existence of a corresponding JavaScript API. We can infer the following:

* **JavaScript API:**  There's likely a JavaScript API on the `Navigator` object (e.g., `navigator.createHandwritingRecognizer(...)`) that maps to the C++ `createHandwritingRecognizer`.
* **HTML:**  HTML provides the user interface where the handwriting input would occur (e.g., a `<canvas>` element for drawing).
* **CSS:** CSS would style the user interface elements related to handwriting input.

**5. Logic and Assumptions:**

The logic revolves around:

* **Assumption:** The browser process has a separate component responsible for the actual handwriting recognition using machine learning models.
* **Input (for `CreateHandwritingRecognizer`):**  A `HandwritingModelConstraint` object specifying the desired language(s).
* **Output (for `CreateHandwritingRecognizer`):** A JavaScript Promise that resolves with a `HandwritingRecognizer` object if successful, or rejects with an error if not.
* **Input (for `QueryHandwritingRecognizer`):** A `HandwritingModelConstraint` object to query for matching recognizers.
* **Output (for `QueryHandwritingRecognizer`):** A JavaScript Promise that resolves with a `HandwritingRecognizerQueryResult` (potentially null) indicating available recognizers.

**6. User and Programming Errors:**

Consider common mistakes:

* **Unsupported Language:** The user might request recognition for a language not supported by the available models. This is handled by the `kNotSupported` error.
* **Invalid State:** Calling the API when the execution context is invalid (e.g., after navigating away from the page).
* **Internal Error:**  A generic error on the backend side.

**7. User Steps and Debugging:**

To understand how a user reaches this code, trace the typical flow:

1. **User interacts with a web page:** The page contains JavaScript code that uses the Handwriting Recognition API.
2. **JavaScript calls `navigator.createHandwritingRecognizer(...)`:**  This is the entry point from the web page.
3. **Blink (C++) handles the call:** The JavaScript call is routed to the `HandwritingRecognitionService::createHandwritingRecognizer` method.
4. **Mojo communication:** The C++ code uses Mojo to communicate with the browser process.
5. **Browser process performs recognition:** The browser process handles the actual handwriting recognition.
6. **Response via Mojo:** The result is sent back to the renderer process.
7. **C++ callback handles the response:** `OnCreateHandwritingRecognizer` processes the Mojo response.
8. **JavaScript Promise resolves/rejects:** The JavaScript Promise associated with the initial call is settled.

**8. Refinement and Structuring the Answer:**

Finally, organize the information into a clear and structured answer, addressing each part of the prompt with examples where needed. Use clear headings and bullet points for readability. Ensure the examples are concrete and illustrative. For instance, showing a JavaScript snippet of how the API might be used.
好的，让我们来分析一下 `blink/renderer/modules/handwriting/handwriting_recognition_service.cc` 这个文件。

**功能概述:**

`HandwritingRecognitionService` 类是 Blink 渲染引擎中用于提供手写识别服务的核心组件。它主要负责以下功能：

1. **作为 JavaScript API 的桥梁:** 它实现了 JavaScript 中 `Navigator.createHandwritingRecognizer()` 和 `Navigator.queryHandwritingRecognizer()` 方法的底层逻辑，使得网页可以通过 JavaScript 调用浏览器的手写识别功能。
2. **管理与浏览器进程的通信:**  它使用 Chromium 的 Mojo IPC 机制与浏览器进程中的手写识别后端服务进行通信。
3. **创建 `HandwritingRecognizer` 对象:**  当 JavaScript 调用 `createHandwritingRecognizer()` 时，这个服务会请求浏览器进程创建一个 `HandwritingRecognizer` 的实例，该实例用于实际的手写识别操作。
4. **查询可用的手写识别器:** 当 JavaScript 调用 `queryHandwritingRecognizer()` 时，这个服务会请求浏览器进程查询符合给定约束条件的手写识别器信息。
5. **处理异步操作:** 手写识别是一个可能耗时的操作，因此这个服务使用了 JavaScript 的 `Promise` 来处理异步结果，并在操作完成或出错时通知 JavaScript。
6. **错误处理:**  它处理来自浏览器进程的错误，并将这些错误转换为 JavaScript 可以理解的 `DOMException` 异常。

**与 JavaScript, HTML, CSS 的关系及举例:**

这个文件是 Web API 的底层实现，直接与 JavaScript 交互，间接影响 HTML 和 CSS 的功能，因为手写识别功能可以增强网页的交互性。

* **JavaScript:**
    * **调用 API:** JavaScript 代码会调用 `navigator.createHandwritingRecognizer(constraints)` 或 `navigator.queryHandwritingRecognizer(constraints)` 来使用手写识别服务。
        ```javascript
        navigator.createHandwritingRecognizer({ languages: ['zh-CN'] })
          .then(recognizer => {
            console.log('手写识别器创建成功', recognizer);
          })
          .catch(error => {
            console.error('创建手写识别器失败', error);
          });

        navigator.queryHandwritingRecognizer({ languages: ['en-US'] })
          .then(queryResult => {
            if (queryResult) {
              console.log('找到匹配的手写识别器', queryResult);
            } else {
              console.log('没有找到匹配的手写识别器');
            }
          });
        ```
    * **接收结果:** JavaScript 通过 `Promise` 接收 `HandwritingRecognizer` 对象或 `HandwritingRecognizerQueryResult` 对象。

* **HTML:**
    * **提供输入区域:** HTML 可以使用 `<canvas>` 或其他元素作为用户手写的输入区域。
    * **事件监听:** JavaScript 会监听 HTML 元素的鼠标或触摸事件，来获取用户的手写轨迹数据。

* **CSS:**
    * **样式控制:** CSS 用于控制手写输入区域的样式，例如边框、大小等。
    * **反馈可视化:** CSS 可以用于可视化手写识别的中间或最终结果。

**逻辑推理、假设输入与输出:**

**假设输入 (对于 `createHandwritingRecognizer`):**

* **JavaScript 调用:** `navigator.createHandwritingRecognizer({ languages: ['ja-JP', 'en-US'] })`
* **C++ 接收到的 `HandwritingModelConstraint`:**  包含一个语言代码数组 `["ja-JP", "en-US"]`。

**逻辑推理:**

1. `HandwritingRecognitionService` 接收到 JavaScript 的请求。
2. 它会检查是否已与浏览器进程建立 Mojo 连接，如果没有则建立连接。
3. 它将 JavaScript 的 `HandwritingModelConstraint` 对象转换为 Mojo 接口定义的类型。
4. 它通过 Mojo 向浏览器进程发送创建手写识别器的请求，并附带转换后的约束条件。
5. 浏览器进程的手写识别服务会尝试创建一个支持日语和英语的手写识别器。
6. **可能的结果:**
    * **成功:** 浏览器进程成功创建识别器，并通过 Mojo 返回一个 `HandwritingRecognizer` 的远程接口。`OnCreateHandwritingRecognizer` 回调函数被调用，创建一个 `HandwritingRecognizer` Blink 对象，并将 JavaScript 的 `Promise` 解析为该对象。
    * **部分支持:**  可能只支持其中一种语言。代码中当前的逻辑是，如果 `CreateHandwritingRecognizerResult` 不是 `kOk`，则会拒绝 Promise。
    * **不支持:** 浏览器进程无法找到或创建符合约束的识别器，例如操作系统或硬件不支持。Mojo 返回一个错误状态 (`kNotSupported` 或 `kError`)。`OnCreateHandwritingRecognizer` 回调函数会根据错误状态拒绝 JavaScript 的 `Promise`，并抛出相应的 `DOMException`。

**假设输出 (对于 `createHandwritingRecognizer`):**

* **成功:** JavaScript 的 `Promise` 被解析为一个 `HandwritingRecognizer` 对象。
* **失败 (不支持):** JavaScript 的 `Promise` 被拒绝，并抛出一个 `NotSupportedError` 类型的 `DOMException`，消息为 "The provided model constraints aren't supported."
* **失败 (内部错误):** JavaScript 的 `Promise` 被拒绝，并抛出一个 `UnknownError` 类型的 `DOMException`，消息为 "Internal error."

**假设输入 (对于 `queryHandwritingRecognizer`):**

* **JavaScript 调用:** `navigator.queryHandwritingRecognizer({ languages: ['ko-KR'] })`
* **C++ 接收到的 `HandwritingModelConstraint`:** 包含语言代码 `"ko-KR"`。

**假设输出 (对于 `queryHandwritingRecognizer`):**

* **找到匹配:** JavaScript 的 `Promise` 被解析为一个 `HandwritingRecognizerQueryResult` 对象，该对象可能包含关于匹配的手写识别器的信息。
* **未找到匹配:** JavaScript 的 `Promise` 被解析为一个 `null` 值的 `HandwritingRecognizerQueryResult`。

**用户或编程常见的使用错误:**

1. **在不支持手写识别的浏览器或平台上调用 API:**  此时 `createHandwritingRecognizer` 或 `queryHandwritingRecognizer` 可能会返回被拒绝的 Promise，并抛出 `NotSupportedError`。
    ```javascript
    navigator.createHandwritingRecognizer({ languages: ['zh-CN'] })
      .catch(error => {
        if (error.name === 'NotSupportedError') {
          console.error('当前环境不支持手写识别');
        }
      });
    ```
2. **传递无效的语言代码:**  虽然代码中似乎没有对语言代码进行严格的校验（校验可能发生在浏览器进程），但如果传递了格式错误的语言代码，可能会导致后端无法识别，从而返回错误。
3. **在不合法的 ExecutionContext 中调用:**  例如，在 Frame 被 detached 后尝试调用 API，可能会导致 `BootstrapMojoConnectionIfNeeded` 抛出 `InvalidStateError`。
    ```javascript
    // 假设在一个 iframe 中
    const iframe = document.querySelector('iframe');
    iframe.src = 'about:blank'; // Detach iframe

    // 稍后尝试调用
    iframe.contentWindow.navigator.createHandwritingRecognizer({ languages: ['en-US'] })
      .catch(error => {
        if (error.name === 'InvalidStateError') {
          console.error('ExecutionContext 无效');
        }
      });
    ```
4. **假设手写识别 API 一定存在:**  在某些老旧的浏览器中，手写识别 API 可能不存在。开发者应该在使用前进行特性检测。
    ```javascript
    if ('createHandwritingRecognizer' in navigator) {
      navigator.createHandwritingRecognizer({ languages: ['zh-CN'] });
    } else {
      console.log('手写识别 API 不可用');
    }
    ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户与网页交互:** 用户在一个包含手写识别功能的网页上进行操作。
2. **网页 JavaScript 代码执行:** 网页的 JavaScript 代码需要启动手写识别，因此会调用 `navigator.createHandwritingRecognizer(constraints)` 或 `navigator.queryHandwritingRecognizer(constraints)`。
3. **Blink 接收 JavaScript 调用:** 浏览器内核的 Blink 渲染引擎接收到 JavaScript 的 API 调用。具体来说，会路由到 `modules/handwriting/handwriting_recognition_service.cc` 文件中的静态方法 `createHandwritingRecognizer` 或 `queryHandwritingRecognizer`。
4. **创建 `HandwritingRecognitionService` 实例 (如果需要):**  `HandwritingRecognitionService::From(navigator)` 方法确保每个 `Navigator` 对象只有一个 `HandwritingRecognitionService` 实例。
5. **建立 Mojo 连接:** `BootstrapMojoConnectionIfNeeded` 方法检查并建立与浏览器进程中手写识别服务的 Mojo 连接。
6. **发送 Mojo 请求:**  `CreateHandwritingRecognizer` 或 `QueryHandwritingRecognizer` 方法将 JavaScript 的参数转换为 Mojo 消息，并通过 `remote_service_` 发送到浏览器进程。
7. **浏览器进程处理请求:** 浏览器进程中的手写识别服务接收到请求，执行相应的操作（创建识别器或查询）。
8. **浏览器进程返回结果:** 浏览器进程通过 Mojo 将结果（成功或失败，以及相关数据）返回给渲染进程。
9. **接收 Mojo 响应:** 渲染进程的 `HandwritingRecognitionService` 中的回调函数 (`OnCreateHandwritingRecognizer` 或 `OnQueryHandwritingRecognizer`) 接收到 Mojo 响应。
10. **解析结果并更新 JavaScript Promise:** 回调函数根据 Mojo 响应的结果，解析数据，并解析或拒绝之前 JavaScript 调用返回的 `Promise`。
11. **JavaScript 代码处理结果:** 网页的 JavaScript 代码接收到 `Promise` 的结果，并执行相应的逻辑（例如，开始使用 `HandwritingRecognizer` 对象，或显示查询结果）。

**调试线索:**

* **断点:** 在 `HandwritingRecognitionService` 的关键方法（如 `createHandwritingRecognizer`, `QueryHandwritingRecognizer`, `BootstrapMojoConnectionIfNeeded`, 以及 Mojo 回调函数）设置断点，可以追踪代码执行流程，查看参数和状态。
* **Mojo 日志:** 查看 Chromium 的 Mojo 日志可以了解渲染进程和浏览器进程之间的通信情况，包括发送和接收的消息内容。
* **JavaScript 控制台日志:** 在 JavaScript 代码中添加 `console.log` 或 `console.error` 可以查看 API 调用是否成功，以及错误信息。
* **网络面板 (如果涉及网络请求):** 虽然这个文件本身不直接处理网络请求，但如果手写识别模型的加载涉及到网络，可以在浏览器的网络面板中查看相关请求。
* **`chrome://tracing`:**  使用 Chromium 的 tracing 工具可以记录更底层的事件，帮助分析性能问题或复杂的交互流程。

总而言之，`handwriting_recognition_service.cc` 是 Blink 渲染引擎中实现 Web 手写识别 API 的关键 C++ 组件，它负责连接 JavaScript 前端和浏览器进程的后端手写识别功能，并处理异步操作和错误情况。理解这个文件的工作原理对于调试手写识别相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/modules/handwriting/handwriting_recognition_service.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/handwriting/handwriting_recognition_service.h"

#include <utility>

#include "base/notreached.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_handwriting_model_constraint.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_handwriting_recognizer_query_result.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/handwriting/handwriting_recognizer.h"
#include "third_party/blink/renderer/modules/handwriting/handwriting_type_converters.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

namespace {

void OnCreateHandwritingRecognizer(
    ScriptState* script_state,
    ScriptPromiseResolver<HandwritingRecognizer>* resolver,
    handwriting::mojom::blink::CreateHandwritingRecognizerResult result,
    mojo::PendingRemote<handwriting::mojom::blink::HandwritingRecognizer>
        pending_remote) {
  switch (result) {
    case handwriting::mojom::blink::CreateHandwritingRecognizerResult::kError: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kUnknownError, "Internal error."));
      return;
    }
    case handwriting::mojom::blink::CreateHandwritingRecognizerResult::
        kNotSupported: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "The provided model constraints aren't supported."));
      return;
    }
    case handwriting::mojom::blink::CreateHandwritingRecognizerResult::kOk: {
      auto* handwriting_recognizer =
          MakeGarbageCollected<HandwritingRecognizer>(
              ExecutionContext::From(script_state), std::move(pending_remote));
      resolver->Resolve(handwriting_recognizer);
      return;
    }
  }

  NOTREACHED() << "CreateHandwritingRecognizer returns an invalid result.";
}

void OnQueryHandwritingRecognizer(
    ScriptState* script_state,
    ScriptPromiseResolver<IDLNullable<HandwritingRecognizerQueryResult>>*
        resolver,
    handwriting::mojom::blink::QueryHandwritingRecognizerResultPtr
        query_result) {
  auto* result = mojo::ConvertTo<HandwritingRecognizerQueryResult*>(
      std::move(query_result));
  resolver->Resolve(result);
}

}  // namespace

const char HandwritingRecognitionService::kSupplementName[] =
    "NavigatorHandwritingRecognitionService";

HandwritingRecognitionService::HandwritingRecognitionService(
    Navigator& navigator)
    : Supplement<Navigator>(navigator),
      remote_service_(navigator.GetExecutionContext()) {}

// static
HandwritingRecognitionService& HandwritingRecognitionService::From(
    Navigator& navigator) {
  HandwritingRecognitionService* supplement =
      Supplement<Navigator>::From<HandwritingRecognitionService>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<HandwritingRecognitionService>(navigator);
    ProvideTo(navigator, supplement);
  }
  return *supplement;
}

// static
ScriptPromise<HandwritingRecognizer>
HandwritingRecognitionService::createHandwritingRecognizer(
    ScriptState* script_state,
    Navigator& navigator,
    const HandwritingModelConstraint* constraint,
    ExceptionState& exception_state) {
  return HandwritingRecognitionService::From(navigator)
      .CreateHandwritingRecognizer(script_state, constraint, exception_state);
}

bool HandwritingRecognitionService::BootstrapMojoConnectionIfNeeded(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // We need to do the following check because the execution context of this
  // navigator may be invalid (e.g. the frame is detached).
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The execution context is invalid");
    return false;
  }
  // Note that we do not use `ExecutionContext::From(script_state)` because
  // the ScriptState passed in may not be guaranteed to match the execution
  // context associated with this navigator, especially with
  // cross-browsing-context calls.
  auto* execution_context = GetSupplementable()->GetExecutionContext();
  if (!remote_service_.is_bound()) {
    execution_context->GetBrowserInterfaceBroker().GetInterface(
        remote_service_.BindNewPipeAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kInternalDefault)));
  }
  return true;
}

ScriptPromise<HandwritingRecognizer>
HandwritingRecognitionService::CreateHandwritingRecognizer(
    ScriptState* script_state,
    const HandwritingModelConstraint* blink_model_constraint,
    ExceptionState& exception_state) {
  if (!BootstrapMojoConnectionIfNeeded(script_state, exception_state)) {
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<HandwritingRecognizer>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  auto mojo_model_constraint =
      handwriting::mojom::blink::HandwritingModelConstraint::New();

  for (auto const& lang : blink_model_constraint->languages()) {
    mojo_model_constraint->languages.push_back(lang);
  }

  remote_service_->CreateHandwritingRecognizer(
      std::move(mojo_model_constraint),
      WTF::BindOnce(OnCreateHandwritingRecognizer, WrapPersistent(script_state),
                    WrapPersistent(resolver)));

  return promise;
}

// static
ScriptPromise<IDLNullable<HandwritingRecognizerQueryResult>>
HandwritingRecognitionService::queryHandwritingRecognizer(
    ScriptState* script_state,
    Navigator& navigator,
    const HandwritingModelConstraint* constraint,
    ExceptionState& exception_state) {
  return HandwritingRecognitionService::From(navigator)
      .QueryHandwritingRecognizer(script_state, constraint, exception_state);
}

ScriptPromise<IDLNullable<HandwritingRecognizerQueryResult>>
HandwritingRecognitionService::QueryHandwritingRecognizer(
    ScriptState* script_state,
    const HandwritingModelConstraint* constraint,
    ExceptionState& exception_state) {
  if (!BootstrapMojoConnectionIfNeeded(script_state, exception_state)) {
    return ScriptPromise<IDLNullable<HandwritingRecognizerQueryResult>>();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLNullable<HandwritingRecognizerQueryResult>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  remote_service_->QueryHandwritingRecognizer(
      mojo::ConvertTo<handwriting::mojom::blink::HandwritingModelConstraintPtr>(
          constraint),
      WTF::BindOnce(&OnQueryHandwritingRecognizer, WrapPersistent(script_state),
                    WrapPersistent(resolver)));

  return promise;
}

void HandwritingRecognitionService::Trace(Visitor* visitor) const {
  visitor->Trace(remote_service_);
  Supplement<Navigator>::Trace(visitor);
}

}  // namespace blink
```