Response:
Let's break down the thought process to analyze the given C++ source code and generate the comprehensive explanation.

**1. Understanding the Goal:**

The request asks for a detailed explanation of the `WebAssociatedURLLoaderImpl.cc` file in the Chromium Blink engine. The explanation needs to cover functionality, relationships with web technologies (JavaScript, HTML, CSS), logical reasoning, potential user errors, and debugging clues.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd quickly scan the `#include` directives and the class name `WebAssociatedURLLoaderImpl`. This immediately tells me it's part of the networking/loading system in Blink. The inclusion of platform headers (`web_url_request.h`, `web_url_error.h`, etc.) confirms this. The presence of `WebAssociatedURLLoaderClient.h` suggests this class *implements* something that a client interacts with for loading URLs.

**3. Deconstructing the Class Structure:**

Next, I'd analyze the class definition and its nested classes:

* **`HTTPRequestHeaderValidator`:**  This looks like a helper class to validate HTTP headers based on safety and CORS rules. This immediately links to the concept of web security and how browsers handle requests.
* **`ClientAdapter`:** This class acts as a bridge between `ThreadableLoaderClient` (Blink's internal loading mechanism) and `WebAssociatedURLLoaderClient` (the public API). This pattern is common for adapting internal implementations to public interfaces.
* **`Observer`:** This class observes the lifecycle of an `ExecutionContext`. This hints at the context in which these loaders operate, likely within a frame or worker.

**4. Analyzing Key Methods:**

I'd focus on the core methods of `WebAssociatedURLLoaderImpl`:

* **`LoadAsynchronously`:** This is clearly the main entry point for initiating a URL load. The parameters (`WebURLRequest`, `WebAssociatedURLLoaderClient`) confirm its role. The logic inside this method needs careful examination.
* **`Cancel`:**  This is expected for any load operation to stop it.
* **`ClientAdapterDone`:**  This seems like a callback from the `ClientAdapter` to signal completion.
* **`SetDefersLoading`:** This relates to controlling the loading process (pausing/resuming).
* **`ContextDestroyed`:** This handles the cleanup when the associated context is destroyed.

**5. Tracing the `LoadAsynchronously` Logic (The Core Functionality):**

This method is the heart of the class. I'd break down the steps:

* **Assertions:** Checks for internal consistency.
* **Client Assignment:** Stores the provided client.
* **Observer Check:** Verifies the context is still valid.
* **Request Validation (if `options_.untrusted_http`):**  Crucially, this section validates HTTP method and headers, connecting it to potential security issues and user-provided input. This is where the `HTTPRequestHeaderValidator` comes into play.
* **`ClientAdapter` Creation:** Instantiates the bridge object.
* **Conditional Loading (`allow_load`):**  Only proceeds if validation passes.
* **`ResourceLoaderOptions`:**  Configures how the underlying loader will work (buffering, initiator info).
* **`grant_universal_access` handling:** Special case for scenarios where access restrictions need to be relaxed (like Flash).
* **`RequestContextType` adjustments:**  Sets the context of the request, potentially influencing its behavior.
* **`ThreadableLoader` Creation and Start:**  This is the actual mechanism that performs the network request.
* **Error Handling:**  If loading fails for various reasons, the client is notified.
* **`EnableErrorNotifications`:** This ensures asynchronous error reporting after the initial call returns.

**6. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This requires understanding *how* these loading mechanisms are triggered in a browser:

* **JavaScript:**  `fetch()`, `XMLHttpRequest`, dynamic `<script>` or `<img>` tags are all JavaScript APIs that trigger network requests. This code is involved in the *underlying implementation* of those APIs. I'd look for clues within the code that relate to request modes (CORS) and security implications, as these are heavily relevant to JavaScript's interaction with the network.
* **HTML:**  `<link>`, `<script>`, `<img>`, `<iframe>`, `<video>`, `<audio>` tags in HTML all initiate resource loading. This class handles the loading aspect *after* the HTML parser identifies these resources.
* **CSS:** `@import`, `url()` within CSS properties trigger resource fetching for stylesheets and assets. Again, this class is part of the lower-level implementation.

**7. Identifying Logical Reasoning and Assumptions:**

* **Assumption:** The code assumes a valid `ExecutionContext` is available. The `Observer` and the checks in `LoadAsynchronously` enforce this.
* **Reasoning:** The validation of HTTP headers is based on security principles to prevent malicious requests. The use of `ClientAdapter` is a common design pattern for decoupling. The delayed error notification is to prevent re-entrancy issues.

**8. Considering User/Programming Errors:**

* **User Error:**  A user might write JavaScript code with invalid headers or methods in a `fetch()` request. This code would *detect* such errors (if `untrusted_http` is enabled) and prevent the request from being sent.
* **Programming Error:** A developer using the Blink API might misuse `WebAssociatedURLLoaderOptions` or provide an invalid `WebURLRequest`. The assertions in the code help catch some of these errors. Failing to handle asynchronous errors reported by the client is another potential programming error.

**9. Debugging Clues and User Actions:**

To reach this code during debugging:

* **User Action:**  A user clicks a link, submits a form, or a webpage loads a resource (image, script, stylesheet).
* **Blink Flow:** The HTML parser encounters a resource, JavaScript executes a fetch, or similar. This triggers a request.
* **Navigation:**  The request likely goes through various stages in Blink's networking stack. Setting breakpoints in `WebAssociatedURLLoaderImpl::LoadAsynchronously` or within the `ThreadableLoader` would be crucial. Looking at network logs in the browser's developer tools can confirm that a request was made and potentially show the request headers.

**10. Structuring the Output:**

Finally, I'd organize the information logically, addressing each part of the original request:

* **Functionality:** Describe the core purpose and how it fits into the larger Blink architecture.
* **Relationship to Web Technologies:** Provide concrete examples of how JavaScript, HTML, and CSS interactions lead to this code being executed.
* **Logical Reasoning:** Explain the "why" behind certain design choices and assumptions.
* **User/Programming Errors:** Illustrate common mistakes and how the code might react.
* **Debugging Clues:** Detail the sequence of user actions and code execution that would lead a developer to this specific file.

This iterative process of code examination, pattern recognition, and understanding the surrounding context is key to generating a comprehensive and accurate explanation.
好的，让我们详细分析一下 `blink/renderer/core/loader/web_associated_url_loader_impl.cc` 这个文件。

**文件功能概述：**

`WebAssociatedURLLoaderImpl.cc` 实现了 `WebAssociatedURLLoader` 接口。`WebAssociatedURLLoader` 的主要功能是**代表网页或其一部分（如 Service Worker）加载与当前文档关联的资源**。 这里的“关联”通常意味着加载操作需要遵循特定的安全策略和上下文环境，例如，可能需要携带特定的凭据，或者受到同源策略的限制。

**核心功能点：**

1. **发起网络请求:**  它使用 Blink 内部的 `ThreadableLoader` 来实际执行网络请求。`ThreadableLoader` 是一个更底层的类，负责处理网络通信的细节。
2. **处理请求选项:**  它接收 `WebURLRequest` 对象，该对象包含了请求的 URL、HTTP 方法、头部信息等。它还接收 `WebAssociatedURLLoaderOptions`，用于配置加载行为，例如是否允许不安全的 HTTP 请求、CORS 预检策略等。
3. **作为 `WebAssociatedURLLoaderClient` 的桥梁:**  它使用 `ClientAdapter` 内部类，将 `ThreadableLoaderClient` 的回调（例如，接收到响应、数据、加载完成或失败）转换为 `WebAssociatedURLLoaderClient` 的回调，从而将加载状态通知给调用者。
4. **处理安全策略:**  它会根据 `WebAssociatedURLLoaderOptions` 和请求的上下文，应用一些安全策略。例如，`untrusted_http` 选项会限制请求方法和头部，防止发送恶意请求。
5. **处理 CORS:**  它会根据请求模式 (`RequestMode`) 和凭据模式 (`CredentialsMode`)，以及响应头部的 `Access-Control-Expose-Headers`，来决定哪些响应头部应该暴露给 JavaScript。
6. **管理生命周期:**  它通过 `Observer` 内部类观察关联的 `ExecutionContext` 的生命周期，并在 `ExecutionContext` 被销毁时取消加载。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件位于 Blink 引擎的底层加载模块，它直接参与了浏览器如何获取网页资源的过程。 因此，它与 JavaScript, HTML, CSS 的功能都有着密切的关系。

**1. JavaScript:**

* **`fetch()` API:** 当 JavaScript 代码中使用 `fetch()` API 发起网络请求时，Blink 引擎最终会调用到类似的加载机制。`WebAssociatedURLLoaderImpl` 可以被用于处理某些 `fetch()` 请求，特别是那些与特定上下文关联的请求。
    * **假设输入:** JavaScript 代码 `fetch('/api/data', {credentials: 'include'})` 发起了一个请求。
    * **逻辑推理:**  由于 `credentials: 'include'`，浏览器需要携带 Cookie 等凭据。`WebAssociatedURLLoaderImpl` 可能会被用来加载这个 URL，因为它需要处理凭据相关的安全策略。
    * **输出:**  `WebAssociatedURLLoaderImpl` 会创建一个 `WebURLRequest` 对象，设置 `credentialsMode` 为 `kInclude`，并通过 `ThreadableLoader` 发送请求。服务器的响应（包括头部）会通过 `ClientAdapter` 回调到 JavaScript 中。
* **`XMLHttpRequest` (XHR):** 类似于 `fetch()`，当 JavaScript 使用 XHR 对象发起请求时，底层也会使用类似的加载机制。
    * **用户操作:** 用户在网页上点击一个按钮，触发 JavaScript 代码使用 XHR 向服务器发送数据。
    * **到达这里:**  XHR 对象会创建一个请求，Blink 的网络层可能会使用 `WebAssociatedURLLoaderImpl` 来执行这个请求。
* **动态脚本加载:**  当 JavaScript 代码动态创建 `<script>` 标签并添加到 DOM 中时，浏览器会发起对脚本文件的请求。
    * **假设输入:** JavaScript 代码 `const script = document.createElement('script'); script.src = '/js/app.js'; document.body.appendChild(script);`
    * **逻辑推理:** 浏览器需要加载 `/js/app.js` 这个脚本文件。
    * **输出:**  `WebAssociatedURLLoaderImpl` 可能会被用来加载这个脚本，特别是当这个脚本的加载与当前文档的上下文有关时。

**2. HTML:**

* **`<link>` 标签加载 CSS:** 当 HTML 中包含 `<link rel="stylesheet" href="style.css">` 时，浏览器需要加载 CSS 文件。
    * **用户操作:** 用户访问一个包含 CSS 文件的网页。
    * **到达这里:**  HTML 解析器遇到 `<link>` 标签，创建加载请求，Blink 可能会使用 `WebAssociatedURLLoaderImpl` 来下载 `style.css`。
* **`<img>`, `<video>`, `<audio>` 等媒体资源加载:**  HTML 中的这些标签都需要加载外部资源。
    * **假设输入:** HTML 代码 `<img src="image.png">`
    * **逻辑推理:** 浏览器需要加载 `image.png` 文件。
    * **输出:**  `WebAssociatedURLLoaderImpl` 可能会被用于加载这个图片资源.
* **`<iframe>` 加载子文档:**  `<iframe>` 标签会加载一个新的 HTML 文档。
    * **用户操作:** 用户访问一个包含 `<iframe>` 的网页。
    * **到达这里:**  HTML 解析器遇到 `<iframe>` 标签，创建加载子文档的请求，Blink 可能会使用 `WebAssociatedURLLoaderImpl` 来加载子文档的 HTML 内容.

**3. CSS:**

* **`@import` 规则加载 CSS:**  在 CSS 文件中使用 `@import url("other.css");` 会导致浏览器加载额外的 CSS 文件。
    * **假设输入:** CSS 文件 `style.css` 包含 `@import url("base.css");`
    * **逻辑推理:** 当浏览器加载 `style.css` 时，会发现 `@import` 规则，并需要加载 `base.css`。
    * **输出:**  `WebAssociatedURLLoaderImpl` 可能会被用来加载 `base.css`。
* **`url()` 函数引用资源:** CSS 属性中可以使用 `url()` 函数引用图片、字体等资源，例如 `background-image: url("bg.png");`。
    * **用户操作:** 网页使用了包含 `url()` 引用的 CSS 样式。
    * **到达这里:**  当浏览器渲染页面并遇到这些 CSS 规则时，会创建加载对应资源的请求，Blink 可能会使用 `WebAssociatedURLLoaderImpl` 来加载 `bg.png`。

**逻辑推理的假设输入与输出：**

* **假设输入:**  `WebAssociatedURLLoaderImpl` 收到一个 `WebURLRequest`，请求方法是 "GET"，URL 是 "https://example.com/data.json"，并且 `WebAssociatedURLLoaderOptions` 设置了 `untrusted_http = true`。
* **逻辑推理:** 由于 `untrusted_http` 为 true，`LoadAsynchronously` 方法会检查 HTTP 方法是否安全（GET 是安全的）。它还会遍历请求头部，确保没有被禁止的头部。
* **输出:** 如果请求方法和头部都安全，`WebAssociatedURLLoaderImpl` 将会创建一个 `ThreadableLoader` 并启动加载。如果方法或头部不安全，加载将会被取消，并通过 `WebAssociatedURLLoaderClient` 通知失败。

**用户或编程常见的使用错误及举例说明：**

1. **发送不安全的 HTTP 请求 (当 `untrusted_http = true`):**
    * **错误代码 (JavaScript):**
      ```javascript
      fetch('/api/data', {
        method: 'CUSTOM-METHOD', // 假设 CUSTOM-METHOD 被认为是 "不安全" 的
        headers: {
          'X-Custom-Header': 'some-value'
        }
      });
      ```
    * **说明:** 如果 `WebAssociatedURLLoaderImpl` 被配置为 `untrusted_http = true`，并且 "CUSTOM-METHOD" 或 "X-Custom-Header" 被认为是危险的，加载将会失败。
2. **CORS 配置错误:**
    * **错误场景:**  JavaScript 代码尝试通过 `fetch()` 或 XHR 从另一个域名请求数据，但服务器没有设置正确的 CORS 头部（例如，缺少 `Access-Control-Allow-Origin`）。
    * **说明:**  `WebAssociatedURLLoaderImpl` 会根据 CORS 策略检查响应头部。如果 CORS 检查失败，响应数据将不会传递给 JavaScript 代码，导致跨域请求失败。
3. **错误的凭据设置:**
    * **错误代码 (JavaScript):**
      ```javascript
      fetch('/api/protected', {credentials: 'omit'}); // 应该发送凭据，但错误地设置为 omit
      ```
    * **说明:** 如果服务器需要身份验证，但客户端错误地设置了 `credentials: 'omit'`，服务器可能会拒绝请求。`WebAssociatedURLLoaderImpl` 会按照客户端的指示发送请求，但服务器的响应可能会指示认证失败。
4. **WebAssociatedURLLoaderClient 实现不当:**
    * **错误场景:**  开发者实现了 `WebAssociatedURLLoaderClient` 接口，但其中的回调方法（例如 `DidReceiveData`, `DidFinishLoading`, `DidFail`) 没有正确处理数据或错误，导致程序行为异常。
    * **说明:**  `WebAssociatedURLLoaderImpl` 依赖于 `WebAssociatedURLLoaderClient` 来处理加载结果。如果客户端实现有 bug，可能会导致数据丢失、程序崩溃或其他不可预测的行为。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并按下回车键:**
   * 浏览器开始解析输入的 URL。
   * DNS 查询解析域名。
   * 浏览器发起对 HTML 文档的请求，这可能涉及 `WebAssociatedURLLoaderImpl`。
   * HTML 文档被下载，解析器开始解析 HTML。
   * 当解析器遇到需要加载外部资源的标签（如 `<script>`, `<link>`, `<img>`）时，会创建相应的加载请求。
   * 这些请求可能会通过 `WebAssociatedURLLoaderImpl` 来执行。

2. **用户点击网页上的链接:**
   * 浏览器接收到点击事件。
   * 确定目标 URL。
   * 发起对新 URL 的请求，这可能会使用 `WebAssociatedURLLoaderImpl`。

3. **网页上的 JavaScript 代码发起网络请求 (通过 `fetch()` 或 `XMLHttpRequest`):**
   * JavaScript 代码执行 `fetch()` 或 XHR 调用。
   * 浏览器接收到 JavaScript 的请求。
   * 根据请求的性质和上下文，Blink 引擎可能会使用 `WebAssociatedURLLoaderImpl` 来处理这个请求。

**调试线索：**

* **设置断点:** 在 `WebAssociatedURLLoaderImpl::LoadAsynchronously` 方法的开头设置断点，可以观察哪些请求正在被这个类处理，以及请求的详细信息（URL, 头部, 选项）。
* **查看网络面板:**  浏览器开发者工具的网络面板可以显示所有发出的网络请求，包括请求头和响应头。这可以帮助你了解请求是否被发送、服务器的响应是什么，以及是否存在 CORS 错误。
* **使用 `//TRACE_EVENT`:** 在 `WebAssociatedURLLoaderImpl` 的关键路径上添加 `TRACE_EVENT` 宏，可以记录加载过程中的事件，并使用 Chromium 的 tracing 工具进行分析。
* **检查 `WebAssociatedURLLoaderOptions`:**  确认创建 `WebAssociatedURLLoaderImpl` 时传递的选项是否正确，例如 `untrusted_http` 和预检策略。
* **分析 `WebURLRequest` 对象:**  查看传递给 `LoadAsynchronously` 的 `WebURLRequest` 对象，确认其 URL、HTTP 方法、头部和凭据设置是否符合预期。
* **查看调用栈:** 当断点命中 `WebAssociatedURLLoaderImpl` 的代码时，查看调用栈可以帮助你理解这个加载请求是如何被触发的，以及调用者是谁。

希望这个详细的解释能够帮助你理解 `blink/renderer/core/loader/web_associated_url_loader_impl.cc` 的功能和在浏览器中的作用。

### 提示词
```
这是目录为blink/renderer/core/loader/web_associated_url_loader_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010, 2011, 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/loader/web_associated_url_loader_impl.h"

#include <limits>
#include <memory>
#include <optional>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "services/network/public/cpp/request_destination.h"
#include "services/network/public/cpp/request_mode.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/resource_request_blocked_reason.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_http_header_visitor.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/web_associated_url_loader_client.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/core/loader/threadable_loader_client.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

class HTTPRequestHeaderValidator : public WebHTTPHeaderVisitor {
 public:
  HTTPRequestHeaderValidator() : is_safe_(true) {}
  HTTPRequestHeaderValidator(const HTTPRequestHeaderValidator&) = delete;
  HTTPRequestHeaderValidator& operator=(const HTTPRequestHeaderValidator&) =
      delete;
  ~HTTPRequestHeaderValidator() override = default;

  void VisitHeader(const WebString& name, const WebString& value) override;
  bool IsSafe() const { return is_safe_; }

 private:
  bool is_safe_;
};

void HTTPRequestHeaderValidator::VisitHeader(const WebString& name,
                                             const WebString& value) {
  is_safe_ = is_safe_ && IsValidHTTPToken(name) &&
             !cors::IsForbiddenRequestHeader(name, value) &&
             IsValidHTTPHeaderValue(value);
}

}  // namespace

// This class bridges the interface differences between WebCore and WebKit
// loader clients.
// It forwards its ThreadableLoaderClient notifications to a
// WebAssociatedURLLoaderClient.
class WebAssociatedURLLoaderImpl::ClientAdapter final
    : public GarbageCollected<ClientAdapter>,
      public ThreadableLoaderClient {
 public:
  ClientAdapter(WebAssociatedURLLoaderImpl*,
                WebAssociatedURLLoaderClient*,
                const WebAssociatedURLLoaderOptions&,
                network::mojom::RequestMode,
                network::mojom::CredentialsMode,
                scoped_refptr<base::SingleThreadTaskRunner>);
  ClientAdapter(const ClientAdapter&) = delete;
  ClientAdapter& operator=(const ClientAdapter&) = delete;

  // ThreadableLoaderClient
  void DidSendData(uint64_t /*bytesSent*/,
                   uint64_t /*totalBytesToBeSent*/) override;
  void DidReceiveResponse(uint64_t, const ResourceResponse&) override;
  void DidDownloadData(uint64_t /*dataLength*/) override;
  void DidReceiveData(base::span<const char> /*data*/) override;
  void DidFinishLoading(uint64_t /*identifier*/) override;
  void DidFail(uint64_t /*identifier*/, const ResourceError&) override;
  void DidFailRedirectCheck(uint64_t /*identifier*/) override;

  // ThreadableLoaderClient
  bool WillFollowRedirect(
      uint64_t /*identifier*/,
      const KURL& /*new_url*/,
      const ResourceResponse& /*redirect_response*/) override;

  // Sets an error to be reported back to the client, asynchronously.
  void SetDelayedError(const ResourceError&);

  // Enables forwarding of error notifications to the
  // WebAssociatedURLLoaderClient. These
  // must be deferred until after the call to
  // WebAssociatedURLLoader::loadAsynchronously() completes.
  void EnableErrorNotifications();

  // Stops loading and releases the ThreadableLoader as early as
  // possible.
  WebAssociatedURLLoaderClient* ReleaseClient() {
    WebAssociatedURLLoaderClient* client = client_;
    client_ = nullptr;
    return client;
  }

  void Trace(Visitor* visitor) const final {
    visitor->Trace(error_timer_);
    ThreadableLoaderClient::Trace(visitor);
  }

 private:
  void NotifyError(TimerBase*);

  WebAssociatedURLLoaderImpl* loader_;
  WebAssociatedURLLoaderClient* client_;
  WebAssociatedURLLoaderOptions options_;
  network::mojom::RequestMode request_mode_;
  network::mojom::CredentialsMode credentials_mode_;
  std::optional<WebURLError> error_;

  HeapTaskRunnerTimer<ClientAdapter> error_timer_;
  bool enable_error_notifications_;
  bool did_fail_;
};

WebAssociatedURLLoaderImpl::ClientAdapter::ClientAdapter(
    WebAssociatedURLLoaderImpl* loader,
    WebAssociatedURLLoaderClient* client,
    const WebAssociatedURLLoaderOptions& options,
    network::mojom::RequestMode request_mode,
    network::mojom::CredentialsMode credentials_mode,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : loader_(loader),
      client_(client),
      options_(options),
      request_mode_(request_mode),
      credentials_mode_(credentials_mode),
      error_timer_(std::move(task_runner), this, &ClientAdapter::NotifyError),
      enable_error_notifications_(false),
      did_fail_(false) {
  DCHECK(loader_);
  DCHECK(client_);
}

bool WebAssociatedURLLoaderImpl::ClientAdapter::WillFollowRedirect(
    uint64_t identifier,
    const KURL& new_url,
    const ResourceResponse& redirect_response) {
  if (!client_)
    return true;

  WebURL wrapped_new_url(new_url);
  WrappedResourceResponse wrapped_redirect_response(redirect_response);
  return client_->WillFollowRedirect(wrapped_new_url,
                                     wrapped_redirect_response);
}

void WebAssociatedURLLoaderImpl::ClientAdapter::DidSendData(
    uint64_t bytes_sent,
    uint64_t total_bytes_to_be_sent) {
  if (!client_)
    return;

  client_->DidSendData(bytes_sent, total_bytes_to_be_sent);
}

void WebAssociatedURLLoaderImpl::ClientAdapter::DidReceiveResponse(
    uint64_t,
    const ResourceResponse& response) {
  if (!client_)
    return;

  if (options_.expose_all_response_headers ||
      (request_mode_ != network::mojom::RequestMode::kCors &&
       request_mode_ !=
           network::mojom::RequestMode::kCorsWithForcedPreflight)) {
    // Use the original ResourceResponse.
    client_->DidReceiveResponse(WrappedResourceResponse(response));
    return;
  }

  HTTPHeaderSet exposed_headers =
      cors::ExtractCorsExposedHeaderNamesList(credentials_mode_, response);
  HTTPHeaderSet blocked_headers;
  for (const auto& header : response.HttpHeaderFields()) {
    if (FetchUtils::IsForbiddenResponseHeaderName(header.key) ||
        (!cors::IsCorsSafelistedResponseHeader(header.key) &&
         exposed_headers.find(header.key.Ascii()) == exposed_headers.end()))
      blocked_headers.insert(header.key.Ascii());
  }

  if (blocked_headers.empty()) {
    // Use the original ResourceResponse.
    client_->DidReceiveResponse(WrappedResourceResponse(response));
    return;
  }

  // If there are blocked headers, copy the response so we can remove them.
  WebURLResponse validated_response = WrappedResourceResponse(response);
  for (const auto& header : blocked_headers)
    validated_response.ClearHttpHeaderField(WebString::FromASCII(header));
  client_->DidReceiveResponse(validated_response);
}

void WebAssociatedURLLoaderImpl::ClientAdapter::DidDownloadData(
    uint64_t data_length) {
  if (!client_)
    return;

  client_->DidDownloadData(data_length);
}

void WebAssociatedURLLoaderImpl::ClientAdapter::DidReceiveData(
    base::span<const char> data) {
  if (!client_) {
    return;
  }

  client_->DidReceiveData(data);
}

void WebAssociatedURLLoaderImpl::ClientAdapter::DidFinishLoading(
    uint64_t identifier) {
  if (!client_)
    return;

  loader_->ClientAdapterDone();

  ReleaseClient()->DidFinishLoading();
  // |this| may be dead here.
}

void WebAssociatedURLLoaderImpl::ClientAdapter::DidFail(
    uint64_t,
    const ResourceError& error) {
  if (!client_)
    return;

  loader_->ClientAdapterDone();

  did_fail_ = true;
  error_ = static_cast<WebURLError>(error);
  if (enable_error_notifications_)
    NotifyError(&error_timer_);
}

void WebAssociatedURLLoaderImpl::ClientAdapter::DidFailRedirectCheck(
    uint64_t identifier) {
  DidFail(identifier, ResourceError::Failure(NullURL()));
}

void WebAssociatedURLLoaderImpl::ClientAdapter::EnableErrorNotifications() {
  enable_error_notifications_ = true;
  // If an error has already been received, start a timer to report it to the
  // client after WebAssociatedURLLoader::loadAsynchronously has returned to the
  // caller.
  if (did_fail_)
    error_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void WebAssociatedURLLoaderImpl::ClientAdapter::NotifyError(TimerBase* timer) {
  DCHECK_EQ(timer, &error_timer_);

  if (client_) {
    DCHECK(error_);
    ReleaseClient()->DidFail(*error_);
  }
  // |this| may be dead here.
}

class WebAssociatedURLLoaderImpl::Observer final
    : public GarbageCollected<Observer>,
      public ExecutionContextLifecycleObserver {
 public:
  Observer(WebAssociatedURLLoaderImpl* parent, ExecutionContext* context)
      : ExecutionContextLifecycleObserver(context), parent_(parent) {}

  void Dispose() {
    parent_ = nullptr;
    // TODO(keishi): Remove IsIteratingOverObservers() check when
    // HeapObserverList() supports removal while iterating.
    if (!GetExecutionContext()
             ->ContextLifecycleObserverSet()
             .IsIteratingOverObservers()) {
      SetExecutionContext(nullptr);
    }
  }

  void ContextDestroyed() override {
    if (parent_)
      parent_->ContextDestroyed();
  }

  void Trace(Visitor* visitor) const override {
    ExecutionContextLifecycleObserver::Trace(visitor);
  }

  WebAssociatedURLLoaderImpl* parent_;
};

WebAssociatedURLLoaderImpl::WebAssociatedURLLoaderImpl(
    ExecutionContext* context,
    const WebAssociatedURLLoaderOptions& options)
    : client_(nullptr),
      options_(options),
      observer_(MakeGarbageCollected<Observer>(this, context)) {}

WebAssociatedURLLoaderImpl::~WebAssociatedURLLoaderImpl() {
  Cancel();
}

void WebAssociatedURLLoaderImpl::LoadAsynchronously(
    const WebURLRequest& request,
    WebAssociatedURLLoaderClient* client) {
  DCHECK(!client_);
  DCHECK(!loader_);
  DCHECK(!client_adapter_);

  DCHECK(client);
  client_ = client;

  if (!observer_) {
    ReleaseClient()->DidFail(
        WebURLError(ResourceError::CancelledError(KURL())));
    return;
  }

  bool allow_load = true;
  WebURLRequest new_request;
  new_request.CopyFrom(request);
  if (options_.untrusted_http) {
    WebString method = new_request.HttpMethod();
    allow_load =
        IsValidHTTPToken(method) && !FetchUtils::IsForbiddenMethod(method);
    if (allow_load) {
      new_request.SetHttpMethod(FetchUtils::NormalizeMethod(method));
      HTTPRequestHeaderValidator validator;
      new_request.VisitHttpHeaderFields(&validator);

      // The request's referrer string is not stored as a header, so we must
      // consult it separately, if set.
      if (request.ReferrerString() !=
          blink::WebString(Referrer::ClientReferrerString())) {
        DCHECK(cors::IsForbiddenRequestHeader("Referer", ""));
        // `Referer` is a forbidden header name, so we must disallow this to
        // load.
        allow_load = false;
      }

      allow_load = allow_load && validator.IsSafe();
    }
  }
  new_request.ToMutableResourceRequest().SetCorsPreflightPolicy(
      options_.preflight_policy);

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      observer_->GetExecutionContext()->GetTaskRunner(
          TaskType::kInternalLoading);
  client_adapter_ = MakeGarbageCollected<ClientAdapter>(
      this, client, options_, request.GetMode(), request.GetCredentialsMode(),
      std::move(task_runner));

  if (allow_load) {
    ResourceLoaderOptions resource_loader_options(
        observer_->GetExecutionContext()->GetCurrentWorld());
    resource_loader_options.data_buffering_policy = kDoNotBufferData;

    if (options_.grant_universal_access) {
      const auto request_mode = new_request.GetMode();
      DCHECK(request_mode == network::mojom::RequestMode::kNoCors ||
             request_mode == network::mojom::RequestMode::kNavigate);
      // Some callers, notablly flash, with |grant_universal_access| want to
      // have an origin matching with referrer.
      KURL referrer(request.ToResourceRequest().ReferrerString());
      scoped_refptr<SecurityOrigin> origin = SecurityOrigin::Create(referrer);
      origin->GrantUniversalAccess();
      new_request.ToMutableResourceRequest().SetRequestorOrigin(origin);
    }

    ResourceRequest& webcore_request = new_request.ToMutableResourceRequest();
    mojom::blink::RequestContextType context =
        webcore_request.GetRequestContext();
    if (context == mojom::blink::RequestContextType::UNSPECIFIED) {
      // TODO(yoav): We load URLs without setting a TargetType (and therefore a
      // request context) in several places in content/
      // (P2PPortAllocatorSession::AllocateLegacyRelaySession, for example).
      // Remove this once those places are patched up.
      new_request.SetRequestContext(mojom::blink::RequestContextType::INTERNAL);
      new_request.SetRequestDestination(
          network::mojom::RequestDestination::kEmpty);
    } else if (context == mojom::blink::RequestContextType::VIDEO) {
      resource_loader_options.initiator_info.name =
          fetch_initiator_type_names::kVideo;
    } else if (context == mojom::blink::RequestContextType::AUDIO) {
      resource_loader_options.initiator_info.name =
          fetch_initiator_type_names::kAudio;
    }

    loader_ = MakeGarbageCollected<ThreadableLoader>(
        *observer_->GetExecutionContext(), client_adapter_,
        resource_loader_options);
    loader_->Start(std::move(webcore_request));
  }

  if (!loader_) {
    client_adapter_->DidFail(
        0 /* identifier */,
        ResourceError::CancelledDueToAccessCheckError(
            request.Url(), ResourceRequestBlockedReason::kOther));
  }
  client_adapter_->EnableErrorNotifications();
}

void WebAssociatedURLLoaderImpl::Cancel() {
  DisposeObserver();
  CancelLoader();
  ReleaseClient();
}

void WebAssociatedURLLoaderImpl::ClientAdapterDone() {
  DisposeObserver();
  ReleaseClient();
}

void WebAssociatedURLLoaderImpl::CancelLoader() {
  if (!client_adapter_)
    return;

  // Prevent invocation of the WebAssociatedURLLoaderClient methods.
  client_adapter_->ReleaseClient();

  if (loader_) {
    loader_->Cancel();
    loader_ = nullptr;
  }
  client_adapter_ = nullptr;
}

void WebAssociatedURLLoaderImpl::SetDefersLoading(bool defers_loading) {
  if (loader_)
    loader_->SetDefersLoading(defers_loading);
}

void WebAssociatedURLLoaderImpl::SetLoadingTaskRunner(
    base::SingleThreadTaskRunner*) {
  // TODO(alexclarke): Maybe support this one day if it proves worthwhile.
}

void WebAssociatedURLLoaderImpl::ContextDestroyed() {
  DisposeObserver();
  CancelLoader();

  if (!client_)
    return;

  ReleaseClient()->DidFail(WebURLError(ResourceError::CancelledError(KURL())));
  // |this| may be dead here.
}

void WebAssociatedURLLoaderImpl::DisposeObserver() {
  if (!observer_)
    return;

  // TODO(tyoshino): Remove this assert once Document is fixed so that
  // contextDestroyed() is invoked for all kinds of Documents.
  //
  // Currently, the method of detecting Document destruction implemented here
  // doesn't work for all kinds of Documents. In case we reached here after
  // the Oilpan is destroyed, we just crash the renderer process to prevent
  // UaF.
  //
  // We could consider just skipping the rest of code in case
  // ThreadState::current() is null. However, the fact we reached here
  // without cancelling the loader means that it's possible there're some
  // non-Blink non-on-heap objects still facing on-heap Blink objects. E.g.
  // there could be a URLLoader instance behind the ThreadableLoader instance.
  // So, for safety, we chose to just crash here.
  CHECK(ThreadState::Current());

  observer_->Dispose();
  observer_ = nullptr;
}

}  // namespace blink
```