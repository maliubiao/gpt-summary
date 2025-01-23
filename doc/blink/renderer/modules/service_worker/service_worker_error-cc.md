Response:
Let's break down the thought process for analyzing the provided C++ code and fulfilling the request.

**1. Understanding the Core Task:**

The fundamental goal is to understand what `service_worker_error.cc` does within the Chromium Blink engine, specifically in the context of Service Workers. The request also asks to connect it to web technologies (JavaScript, HTML, CSS), common usage errors, and debugging.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for keywords that give clues about its functionality. Keywords like:

* `ServiceWorkerError` (appears in the filename and class names) -  Clearly about handling errors related to Service Workers.
* `DOMException` -  Indicates interaction with the browser's DOM and how errors are represented in JavaScript.
* `mojom::blink::ServiceWorkerErrorType` -  Suggests a defined set of error types.
* `ScriptPromiseResolver` -  Points to asynchronous operations and how errors are propagated in Promises.
* `V8ThrowException` -  Shows how errors are converted and thrown within the V8 JavaScript engine.
* `GetExceptionParams` -  Suggests a function that maps internal error types to DOM exceptions.
* Specific error type enums like `kAbort`, `kNetwork`, `kNotFound`, etc. -  These are the concrete error scenarios being handled.

**3. Deconstructing the Code - Function by Function (or Logical Block):**

I'd then analyze the code in more detail, focusing on the purpose of each function/block:

* **`GetExceptionParams`:** This is crucial. It's a mapping function. It takes a `WebServiceWorkerError` (an internal representation) and determines the appropriate `DOMExceptionCode` and message to use. The `switch` statement is key to understanding which internal error type translates to which DOMException. This immediately tells me that this code is about converting internal Service Worker errors into standard web platform errors.

* **`ServiceWorkerError::Take`:** This function is straightforward. It calls `GetExceptionParams` and then creates a `DOMException` object. The `Take` naming convention often suggests it's consuming or taking ownership of some data (in this case, the `WebServiceWorkerError`). The first parameter `ScriptPromiseResolverBase*` suggests this is invoked when a Service Worker promise is rejected due to an error.

* **`ServiceWorkerError::GetException`:**  This is a helper function that creates a `WebServiceWorkerError` and then calls the `Take` function. It simplifies creating DOMExceptions from a specific error type and message.

* **`ServiceWorkerErrorForUpdate::Take`:** This function is interesting because it has different behavior based on the error type. For `kNetwork`, `kNotFound`, and `kScriptEvaluateFailed` during an update, it throws a `TypeError` instead of a generic `DOMException`. This hints at specific error handling logic for Service Worker updates. The "According to the spec" comment is a strong indicator of why this differentiation exists.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

With the understanding of what the code *does*, I can now connect it to the web platform:

* **JavaScript:** The `DOMException` objects created here are the *actual error objects* that JavaScript code receives when a Service Worker operation fails. The `TypeError` in `ServiceWorkerErrorForUpdate::Take` is a specific JavaScript error type. The use of `ScriptPromiseResolver` directly relates to how asynchronous Service Worker operations (which are heavily used in JavaScript) communicate errors via rejected Promises.

* **HTML:**  While this code doesn't directly manipulate HTML, the registration and lifecycle of Service Workers are initiated through JavaScript that is often embedded within `<script>` tags in HTML. A failed Service Worker registration or update (errors handled by this code) will impact the functionality of the web page as defined in the HTML.

* **CSS:**  Indirectly, if a Service Worker fails to install or activate, features it provides (like offline caching of CSS files) won't work, affecting the page's visual presentation. However, the error handling here is not directly about CSS parsing or rendering failures.

**5. Identifying User/Programming Errors:**

By looking at the different error types, I can infer common causes:

* **`kNetwork`:**  Network issues preventing the Service Worker script from being fetched.
* **`kNotFound`:**  Incorrect path to the Service Worker script.
* **`kSecurity`:**  Trying to register a Service Worker from an insecure origin (non-HTTPS).
* **`kScriptEvaluateFailed`:** Syntax errors in the Service Worker script.
* **`kTimeout`:**  Long-running operations exceeding time limits.
* **`kState`:**  Trying to perform an action on a Service Worker in the wrong lifecycle state.

**6. Illustrating with Examples (Hypothetical Input/Output):**

This involves creating scenarios where the code would be triggered.

* **Registration Failure:**  Trying to register a Service Worker with a mistyped URL in JavaScript. The input is the incorrect URL in the `navigator.serviceWorker.register()` call. The output is a `DOMException` in the rejected Promise.

* **Update Failure:** Deploying a new version of a Service Worker with a syntax error. The input is the updated Service Worker script. The output is a `TypeError` during the update process.

**7. Debugging Information (User Steps and How to Reach the Code):**

This is about tracing the user's actions that lead to these errors and how a developer might diagnose them. The key is to follow the lifecycle of a Service Worker: registration, installation, activation, and then usage (fetch events, etc.). Errors can happen at any of these stages. Developer tools (Console, Application tab) are essential for seeing these errors.

**8. Refining and Structuring the Answer:**

Finally, I would organize the information logically, using clear headings and bullet points to make it easy to understand. I'd also ensure I've addressed all parts of the original request. I would use the identified keywords and concepts to structure the explanation. For example, grouping related error types together when discussing user errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps I focus too much on the individual error codes.
* **Correction:** Realize the importance of explaining *why* these errors happen in the context of the Service Worker lifecycle and how they manifest in JavaScript Promises.
* **Initial thought:** Maybe I should describe every single error type in detail.
* **Correction:** Group similar error types and focus on the most common and illustrative examples. Avoid getting bogged down in rarely seen internal errors.
* **Initial thought:** Just listing the function names isn't enough.
* **Correction:** Explain the *purpose* of each function and its role in the overall error handling process.

By following these steps, I can systematically analyze the code, connect it to web technologies, provide relevant examples, and explain how a developer might encounter and debug these errors.
这个C++源代码文件 `service_worker_error.cc` 的主要功能是**将 Service Worker 内部的错误表示转换为 Web API 标准的 `DOMException` 对象或者 `TypeError` 对象，以便 JavaScript 代码能够捕获和处理这些错误。**  它充当了 Blink 引擎中 Service Worker 错误处理的桥梁。

以下是详细的功能分解和相关说明：

**1. 错误类型转换：**

* **功能:**  该文件定义了如何将 Blink 内部的 `WebServiceWorkerError` 结构（包含具体的错误类型 `mojom::blink::ServiceWorkerErrorType` 和错误消息）映射到标准的 DOMException 对象。
* **实现方式:**  `GetExceptionParams` 函数接收一个 `WebServiceWorkerError` 对象，根据其 `error_type` 成员，返回一个包含对应的 `DOMExceptionCode` 和错误消息的 `ExceptionParams` 结构体。
* **涉及到的 `mojom::blink::ServiceWorkerErrorType` 枚举值及其对应的 `DOMExceptionCode` (部分):**
    * `kAbort`: `DOMExceptionCode::kAbortError` (操作被中止)
    * `kNetwork`: `DOMExceptionCode::kNetworkError` (网络错误)
    * `kNotFound`: `DOMExceptionCode::kNotFoundError` (资源未找到)
    * `kSecurity`: `DOMExceptionCode::kSecurityError` (安全策略阻止操作)
    * `kState`: `DOMExceptionCode::kInvalidStateError` (状态无效)
    * `kTimeout`: `DOMExceptionCode::kAbortError` (操作超时)
    * `kScriptEvaluateFailed`:  `DOMExceptionCode::kAbortError` (脚本执行失败) - 但在 `ServiceWorkerErrorForUpdate::Take` 中特殊处理为 `TypeError`。
    * `kDisabled`: `DOMExceptionCode::kNotSupportedError` (Service Worker 被禁用)

**2. 创建 DOMException 对象:**

* **功能:** `ServiceWorkerError::Take` 静态方法接收一个 `WebServiceWorkerError` 对象，调用 `GetExceptionParams` 获取错误参数，然后创建一个 `DOMException` 对象。
* **用途:**  当 Service Worker 的操作（通常是一个返回 Promise 的操作）失败时，这个方法被调用来创建一个可以传递给 Promise 的 reject 回调函数的错误对象。

**3. 特殊处理 Service Worker 更新时的错误:**

* **功能:** `ServiceWorkerErrorForUpdate::Take` 静态方法专门处理 Service Worker 更新过程中发生的错误。
* **区别:** 对于某些特定的错误类型（如 `kNetwork`, `kNotFound`, `kScriptEvaluateFailed`），在更新过程中会抛出 `TypeError` 而不是通用的 `DOMException`。
* **原因:**  这是根据 Service Worker 规范的要求，在更新失败时使用 `TypeError` 来指示脚本错误或网络问题。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **直接关系:**  该文件生成的 `DOMException` 和 `TypeError` 对象最终会被传递到 JavaScript 的 Promise 的 `reject` 回调中。开发者可以使用 `catch` 方法捕获这些错误并进行处理。
    * **举例说明:**
        ```javascript
        navigator.serviceWorker.register('/sw.js')
          .then(registration => {
            console.log('Service Worker registered:', registration);
          })
          .catch(error => {
            // error 变量将会是这里创建的 DOMException 或 TypeError 对象
            console.error('Service Worker registration failed:', error);
            if (error.name === 'NotFoundError') {
              console.error('Service Worker 文件路径错误');
            } else if (error.name === 'SecurityError') {
              console.error('Service Worker 必须部署在 HTTPS 环境下');
            }
          });
        ```
        在这个例子中，如果 `/sw.js` 文件不存在，Blink 引擎内部会生成一个 `WebServiceWorkerError`，其 `error_type` 为 `kNotFound`。`ServiceWorkerError::Take` 会将其转换为一个 `NotFoundError` 类型的 `DOMException`，最终被 JavaScript 的 `catch` 捕获。

* **HTML:**
    * **间接关系:**  HTML 文件中通过 `<script>` 标签引入的 JavaScript 代码会调用 Service Worker 相关的 API (如 `navigator.serviceWorker.register`)。如果注册或后续操作失败，这里生成的错误会影响网页的功能。
    * **举例说明:**  如果 HTML 中引用的 `/sw.js` 文件内容有语法错误，在 Service Worker 更新时，`ServiceWorkerErrorForUpdate::Take` 会生成一个 `TypeError`，导致更新失败，网页可能继续使用旧的 Service Worker 或者完全失去 Service Worker 的功能。

* **CSS:**
    * **间接关系:**  Service Worker 可以拦截网络请求，包括 CSS 文件的请求，并提供缓存或其他自定义的处理。如果 Service Worker 安装失败（例如由于脚本错误导致 `kScriptEvaluateFailed`），它可能无法正确缓存 CSS 文件，导致页面样式加载异常。
    * **举例说明:**  开发者编写的 Service Worker 代码尝试缓存网站的 CSS 文件。如果在 Service Worker 脚本中有语法错误，导致安装阶段失败，用户在离线状态下访问网站时，可能无法加载 CSS 样式，因为 Service Worker 没有成功启动并缓存资源。

**逻辑推理 (假设输入与输出):**

* **假设输入 (C++):** 一个 `WebServiceWorkerError` 对象，其 `error_type` 为 `mojom::blink::ServiceWorkerErrorType::kNetwork`，`message` 为 "Failed to fetch service worker script."。
* **输出 (JavaScript):**  当 Promise 被 reject 时，会产生一个 `DOMException` 对象，其 `name` 属性为 "NetworkError"， `message` 属性为 "The Service Worker failed by network. Failed to fetch service worker script."。

* **假设输入 (C++，Service Worker 更新):** 一个 `WebServiceWorkerError` 对象，其 `error_type` 为 `mojom::blink::ServiceWorkerErrorType::kScriptEvaluateFailed`，`message` 为 "SyntaxError: Unexpected token )"。
* **输出 (JavaScript):** 当 Service Worker 更新失败时，会产生一个 `TypeError` 对象，其 `name` 属性为 "TypeError"， `message` 属性为 "The Service Worker script failed to evaluate. SyntaxError: Unexpected token )"。

**用户或编程常见的使用错误及举例说明:**

1. **Service Worker 文件路径错误 (导致 `kNotFound`):**
   * **用户操作:** 开发者在 JavaScript 中调用 `navigator.serviceWorker.register('/sw.js')`，但实际上网站根目录下没有 `sw.js` 文件，或者文件路径写错了。
   * **错误:** JavaScript Promise 的 `reject` 回调会收到一个 `NotFoundError` 类型的 `DOMException`，消息类似 "The specified Service Worker resource was not found."。

2. **在非 HTTPS 环境下注册 Service Worker (导致 `kSecurity`):**
   * **用户操作:** 开发者在 HTTP 网站上尝试注册 Service Worker。
   * **错误:** JavaScript Promise 的 `reject` 回调会收到一个 `SecurityError` 类型的 `DOMException`，消息类似 "The Service Worker security policy prevented an action."。

3. **Service Worker 脚本存在语法错误 (导致 `kScriptEvaluateFailed`):**
   * **用户操作:** 开发者编写的 `sw.js` 文件包含 JavaScript 语法错误。
   * **错误:**  在 Service Worker 注册或更新阶段，如果脚本解析失败，会产生相应的错误。注册时会产生 `AbortError` (默认行为)，更新时会产生 `TypeError`。

4. **网络问题导致 Service Worker 脚本下载失败 (导致 `kNetwork`):**
   * **用户操作:** 用户网络不稳定，或者 Service Worker 文件所在的服务器暂时不可用。
   * **错误:** JavaScript Promise 的 `reject` 回调会收到一个 `NetworkError` 类型的 `DOMException`，消息类似 "The Service Worker failed by network."。

5. **尝试在 Service Worker 状态不正确时执行操作 (导致 `kState`):**
   * **用户操作:** 开发者尝试在 Service Worker 尚未激活或已注销的情况下调用某些需要特定状态的 API。
   * **错误:** JavaScript Promise 的 `reject` 回调会收到一个 `InvalidStateError` 类型的 `DOMException`，消息会指示当前状态不允许该操作。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问网页:**  用户在浏览器中打开一个包含 Service Worker 的网页。
2. **浏览器解析 HTML:** 浏览器开始解析 HTML 文档。
3. **JavaScript 执行:**  浏览器执行 HTML 中 `<script>` 标签内的 JavaScript 代码。
4. **尝试注册 Service Worker:** JavaScript 代码调用 `navigator.serviceWorker.register('/sw.js')`。
5. **Blink 引擎处理注册请求:** Blink 引擎接收到注册请求，并尝试下载和解析 `/sw.js` 文件。
6. **发生错误:**
   * **情况 1 (文件未找到):** Blink 引擎无法找到 `/sw.js` 文件，生成一个 `WebServiceWorkerError`，其 `error_type` 为 `kNotFound`。
   * **情况 2 (网络错误):** 下载 `/sw.js` 文件时发生网络错误，生成一个 `WebServiceWorkerError`，其 `error_type` 为 `kNetwork`。
   * **情况 3 (安全错误):** 当前页面不是 HTTPS，生成一个 `WebServiceWorkerError`，其 `error_type` 为 `kSecurity`。
   * **情况 4 (脚本解析错误):**  `sw.js` 文件内容有语法错误，Blink 引擎解析脚本失败，生成一个 `WebServiceWorkerError`，其 `error_type` 为 `kScriptEvaluateFailed`。
7. **`service_worker_error.cc` 介入:** 相应的 `ServiceWorkerError::Take` 或 `ServiceWorkerErrorForUpdate::Take` 方法被调用，将 `WebServiceWorkerError` 转换为 `DOMException` 或 `TypeError`。
8. **Promise 被 reject:**  注册操作返回的 Promise 被 reject，并将生成的错误对象传递给 `catch` 回调函数。
9. **JavaScript 处理错误:** 开发者编写的 JavaScript 代码中的 `catch` 块捕获到错误，可以记录日志、显示错误信息等。

**调试线索:**

* **浏览器开发者工具 (Console):**  如果 Service Worker 注册或更新失败，浏览器控制台通常会显示详细的错误信息，包括 `DOMException` 或 `TypeError` 的名称和消息，这能直接指向 `service_worker_error.cc` 中定义的错误类型和消息模板。
* **浏览器开发者工具 (Application -> Service Workers):**  可以查看 Service Worker 的状态，例如是否成功注册、是否处于激活状态等，以及查看可能发生的错误信息。
* **网络请求 (Network tab):** 检查 Service Worker 脚本的下载请求是否成功，如果失败，可以查看 HTTP 状态码和错误信息，这有助于诊断 `kNetwork` 类型的错误。
* **断点调试:**  在 Blink 引擎的源代码中设置断点，可以跟踪错误是如何从底层传递到 JavaScript 的，理解 `service_worker_error.cc` 在其中的作用。

总而言之，`service_worker_error.cc` 是 Blink 引擎中处理 Service Worker 错误的关键组件，它负责将内部的错误表示转换为 Web 标准的异常对象，使得开发者能够使用标准的 JavaScript 错误处理机制来处理 Service Worker 相关的错误。

### 提示词
```
这是目录为blink/renderer/modules/service_worker/service_worker_error.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/service_worker/service_worker_error.h"

#include "third_party/blink/public/mojom/service_worker/service_worker_error_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

using blink::WebServiceWorkerError;

namespace blink {

namespace {

struct ExceptionParams {
  ExceptionParams(DOMExceptionCode code,
                  const String& default_message = String(),
                  const String& message = String())
      : code(code), message(message.empty() ? default_message : message) {}

  DOMExceptionCode code;
  String message;
};

ExceptionParams GetExceptionParams(const WebServiceWorkerError& web_error) {
  switch (web_error.error_type) {
    case mojom::blink::ServiceWorkerErrorType::kAbort:
      return ExceptionParams(DOMExceptionCode::kAbortError,
                             "The Service Worker operation was aborted.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kActivate:
      // Not currently returned as a promise rejection.
      // TODO: Introduce new ActivateError type to ExceptionCodes?
      return ExceptionParams(DOMExceptionCode::kAbortError,
                             "The Service Worker activation failed.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kDisabled:
      return ExceptionParams(DOMExceptionCode::kNotSupportedError,
                             "Service Worker support is disabled.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kInstall:
      // TODO: Introduce new InstallError type to ExceptionCodes?
      return ExceptionParams(DOMExceptionCode::kAbortError,
                             "The Service Worker installation failed.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kScriptEvaluateFailed:
      return ExceptionParams(DOMExceptionCode::kAbortError,
                             "The Service Worker script failed to evaluate.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kNavigation:
      // ErrorTypeNavigation should have bailed out before calling this.
      NOTREACHED();
    case mojom::blink::ServiceWorkerErrorType::kNetwork:
      return ExceptionParams(DOMExceptionCode::kNetworkError,
                             "The Service Worker failed by network.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kNotFound:
      return ExceptionParams(
          DOMExceptionCode::kNotFoundError,
          "The specified Service Worker resource was not found.",
          web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kSecurity:
      return ExceptionParams(
          DOMExceptionCode::kSecurityError,
          "The Service Worker security policy prevented an action.",
          web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kState:
      return ExceptionParams(DOMExceptionCode::kInvalidStateError,
                             "The Service Worker state was not valid.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kTimeout:
      return ExceptionParams(DOMExceptionCode::kAbortError,
                             "The Service Worker operation timed out.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kUnknown:
      return ExceptionParams(DOMExceptionCode::kUnknownError,
                             "An unknown error occurred within Service Worker.",
                             web_error.message);
    case mojom::blink::ServiceWorkerErrorType::kNone:
    case mojom::blink::ServiceWorkerErrorType::kType:
      // ErrorTypeType should have been handled before reaching this point.
      NOTREACHED();
  }
  NOTREACHED();
}

}  // namespace

// static
DOMException* ServiceWorkerError::Take(ScriptPromiseResolverBase*,
                                       const WebServiceWorkerError& web_error) {
  ExceptionParams params = GetExceptionParams(web_error);
  return MakeGarbageCollected<DOMException>(params.code, params.message);
}

// static
DOMException* ServiceWorkerError::GetException(
    ScriptPromiseResolverBase* resolver,
    mojom::blink::ServiceWorkerErrorType error,
    const String& error_msg) {
  return Take(resolver, WebServiceWorkerError(error, error_msg));
}

// static
v8::Local<v8::Value> ServiceWorkerErrorForUpdate::Take(
    ScriptPromiseResolverBase* resolver,
    const WebServiceWorkerError& web_error) {
  ScriptState* script_state = resolver->GetScriptState();
  switch (web_error.error_type) {
    case mojom::blink::ServiceWorkerErrorType::kNetwork:
    case mojom::blink::ServiceWorkerErrorType::kNotFound:
    case mojom::blink::ServiceWorkerErrorType::kScriptEvaluateFailed:
      // According to the spec, these errors during update should result in
      // a TypeError.
      return V8ThrowException::CreateTypeError(
          script_state->GetIsolate(), GetExceptionParams(web_error).message);
    case mojom::blink::ServiceWorkerErrorType::kType:
      return V8ThrowException::CreateTypeError(script_state->GetIsolate(),
                                               web_error.message);
    default:
      return ToV8Traits<DOMException>::ToV8(
          script_state, ServiceWorkerError::Take(resolver, web_error));
  }
}

}  // namespace blink
```