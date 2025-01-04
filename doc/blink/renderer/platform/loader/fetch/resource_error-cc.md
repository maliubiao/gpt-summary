Response:
Let's break down the request and the provided code to arrive at the comprehensive answer.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the `resource_error.cc` file within the Blink rendering engine. Specifically, the request asks for:

* **Functionality Listing:** A clear description of what the code does.
* **Relationship to Web Technologies (JS/HTML/CSS):** How errors handled by this code manifest in the context of these technologies.
* **Logic and Examples:**  Illustrative scenarios with inputs and outputs, demonstrating how error conditions are represented.
* **Common User/Programming Errors:** How incorrect usage might lead to these errors.

**2. Initial Code Analysis (Skimming and Identifying Key Elements):**

I started by quickly scanning the code for keywords and patterns:

* **Copyright Notices:** Indicates core ownership and licensing.
* **Includes:**  `resource_error.h`, `net/base/net_errors.h`, `services/network/...`, `third_party/blink/public/platform/...`, `third_party/blink/renderer/platform/...`. This immediately tells me it's about network-related errors within the Blink platform.
* **Namespaces:** `blink` - confirms it's a Blink component.
* **`ResourceError` Class:** This is the central entity. The focus is on creating and manipulating `ResourceError` objects.
* **Static Factory Methods:**  `CancelledError`, `CancelledDueToAccessCheckError`, `BlockedByResponse`, `CacheMissError`, `TimeoutError`, `Failure`, `HttpError`. These suggest different ways errors are categorized and instantiated.
* **Constructors:** Multiple constructors accepting error codes, URLs, and `CorsErrorStatus`. This implies flexibility in how errors are reported.
* **Conversion Operators:**  `operator WebURLError()`. This is crucial, showing how Blink's internal `ResourceError` maps to the public `WebURLError` used in the Chromium API.
* **Comparison Function:** `Compare`. Useful for testing and debugging.
* **`Is*` Methods:**  `IsTimeout`, `IsCancellation`, etc. Provide ways to check the *type* of error.
* **`GetResourceRequestBlockedReason` and `GetBlockedByResponseReason`:** Focus on errors related to blocking, hinting at security and policy enforcement.
* **`InitializeDescription`:**  Generates user-friendly error messages.
* **Output Stream Operator:**  `operator<<`. Helpful for logging and debugging.
* **Error Codes from `net::`:**  References to `net::ERR_...`  This is a strong indication of the underlying network error codes being used.

**3. Deeper Dive and Functional Grouping:**

I then went through the code more carefully, grouping related functionalities:

* **Error Creation:** The static factory methods and constructors are all about creating `ResourceError` objects. I realized the static methods provide convenient, semantically meaningful ways to create common error types.
* **Error Classification:** The `Is*` methods and the `GetResourceRequestBlockedReason` function help categorize errors. This is important for handling errors differently based on their nature.
* **Error Information:**  The various member variables (e.g., `error_code_`, `failing_url_`, `localized_description_`, `cors_error_status_`) store the details of an error.
* **Error Conversion:** The conversion to `WebURLError` is a key bridge to the outside world.
* **Error Comparison:** The `Compare` function is for equality checks.
* **Error Description:**  `InitializeDescription` generates human-readable descriptions, taking into account specific error types (like throttling).

**4. Connecting to Web Technologies (JS/HTML/CSS):**

This required thinking about how these backend error representations surface in the browser's interaction with web content:

* **JavaScript:**  `fetch()` API rejections, `XMLHttpRequest` errors (status codes, network errors), `<img>` `onerror` events, `<script>` `onerror` events.
* **HTML:**  Failed resource loading (images, scripts, stylesheets). This manifests as broken images, missing scripts, and unstyled pages. Specific error messages might appear in the developer console.
* **CSS:**  Failed loading of external stylesheets or resources referenced in CSS (e.g., `url()` for backgrounds or fonts). Can lead to unstyled elements or missing visual elements.

I needed to make concrete examples, linking specific `ResourceError` types to these web technologies.

**5. Logic and Examples (Hypothetical Scenarios):**

For the logic and examples, I focused on:

* **Input:** What actions trigger the creation of a `ResourceError`?  (e.g., a failed network request, a blocked request).
* **Processing:** How does the `ResourceError` object get created and populated? Which constructor or static method is likely used?
* **Output:** How is the `ResourceError` information exposed (e.g., as a `WebURLError`, through browser developer tools)?

This is where the "assumed input and output" part of the request came in. I created scenarios that illustrate different error types.

**6. Common Errors:**

This involved thinking about common mistakes developers make:

* Incorrect URLs.
* CORS issues.
* Network connectivity problems.
* Content Security Policy (CSP) violations.
* Mixed content issues (HTTPS page loading HTTP resources).
* Browser blocking due to extensions or settings.

**7. Structuring the Answer:**

Finally, I organized the information into a clear and structured format:

* **Concise Summary:** A high-level overview of the file's purpose.
* **Detailed Functionality List:**  Breaking down the code into logical components.
* **Relationship to Web Technologies:** Providing specific examples of how `ResourceError` instances manifest in JavaScript, HTML, and CSS.
* **Logic and Examples:**  Illustrative scenarios with inputs and outputs.
* **Common Errors:**  Listing typical developer mistakes that lead to these errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on individual methods in isolation.
* **Correction:** Realized the importance of grouping functionalities (creation, classification, etc.) for a better understanding.
* **Initial thought:** Listing all possible `net::ERR_...` codes.
* **Correction:**  Focusing on the most common and relevant ones, and explaining that the code handles a broader range.
* **Initial thought:**  Describing the code technically.
* **Correction:**  Emphasizing the *user-facing* implications and how developers encounter these errors in their web development workflow.

By following these steps of understanding the request, analyzing the code, connecting it to web technologies, creating examples, and structuring the answer, I could generate a comprehensive and informative response.
好的，让我们来分析一下 `blink/renderer/platform/loader/fetch/resource_error.cc` 这个文件。

**功能概要：**

`resource_error.cc` 文件的核心功能是定义和实现 `ResourceError` 类，这个类用于封装在资源加载过程中发生的各种错误信息。 这些错误可能源自网络层 (network stack)，也可能源自浏览器自身的策略检查或其他原因。 `ResourceError` 对象包含了描述错误的各种属性，例如错误代码、失败的 URL、本地化描述、是否是访问检查错误等等。

**详细功能列表：**

1. **错误信息封装:** `ResourceError` 类充当一个数据容器，用于存储和传递资源加载失败的相关信息。
2. **标准网络错误代码映射:** 它使用 `net/base/net_errors.h` 中定义的标准网络错误代码（例如 `net::ERR_ABORTED`, `net::ERR_TIMED_OUT` 等）来表示底层的网络错误。
3. **特定类型的错误创建:**  提供了一系列静态工厂方法，方便创建特定类型的 `ResourceError` 对象，例如：
    * `CancelledError`:  表示请求被取消。
    * `CancelledDueToAccessCheckError`: 表示由于访问权限检查失败而被取消（例如，CORS 错误）。
    * `BlockedByResponse`: 表示请求被服务器响应头阻止（例如，COEP/COOP/CORP 策略）。
    * `CacheMissError`: 表示缓存未命中。
    * `TimeoutError`: 表示请求超时。
    * `Failure`: 表示请求失败。
    * `HttpError`: 表示发生了 HTTP 错误（但具体状态码可能不是错误代码本身，而是需要进一步检查 HTTP 响应）。
4. **CORS (跨域资源共享) 错误处理:**  包含了 `cors_error_status_` 成员，用于存储更详细的 CORS 错误信息。
5. **Trust Token 错误处理:** 包含了 `trust_token_operation_error_` 成员，用于存储 Privacy Pass (Trust Token) 相关的错误信息。
6. **错误类型判断:** 提供了一系列 `Is*` 方法，用于判断错误是否属于特定类型，例如 `IsTimeout()`, `IsCancellation()`, `IsCacheMiss()` 等。
7. **错误信息本地化:**  `InitializeDescription()` 方法根据错误代码和扩展错误代码生成本地化的错误描述信息，方便用户理解。对于特定的错误（例如限流），会提供更友好的提示信息。
8. **与 `WebURLError` 的互操作性:**  提供了到 `third_party/blink/public/platform/web_url_error.h` 中定义的 `WebURLError` 的转换操作符 (`operator WebURLError() const`)。`WebURLError` 是 Blink 对外暴露的更通用的 URL 加载错误表示。
9. **错误比较:** 提供了 `Compare` 静态方法，用于比较两个 `ResourceError` 对象是否相等。
10. **获取更细致的阻塞原因:**  提供了 `GetResourceRequestBlockedReason()` 和 `GetBlockedByResponseReason()` 方法，用于获取更详细的资源请求被阻塞的原因，例如由于 CSP 策略、混合内容、CORS 策略等。

**与 JavaScript, HTML, CSS 的功能关系及举例说明：**

`ResourceError` 的实例最终会影响到浏览器如何处理加载的资源，从而影响到 JavaScript、HTML 和 CSS 的行为。

* **JavaScript:**
    * **`fetch()` API:** 当 `fetch()` 请求失败时，Promise 会被 reject，并且 reject 的原因可能包含一个 `WebURLError` 对象，这个对象内部可能就是从 `ResourceError` 转换而来。
        * **假设输入：** JavaScript 代码尝试使用 `fetch('https://example.com/image.jpg')` 加载一个不存在的图片资源，服务器返回 404 错误。
        * **输出：** `fetch()` 返回的 Promise 会被 reject，reject 的原因可能是一个 `WebURLError` 对象，其 `reason()` 方法返回对应的网络错误码（例如，如果配置了报告 HTTP 错误为取消，则可能是 `net::ERR_ABORTED`），`url()` 方法返回 `https://example.com/image.jpg`。开发者可以通过 catch 捕获这个错误并处理。
    * **`XMLHttpRequest` (XHR):**  当 XHR 请求失败时，`onerror` 事件会被触发，并且可以通过 XHR 对象的属性（例如 `status`, `statusText`，以及可能的底层网络错误信息）获取错误信息。这些底层网络错误信息在 Blink 内部就可能由 `ResourceError` 来表示。
        * **假设输入：** JavaScript 代码发起一个到被 CORS 策略阻止的 API 端点的 XHR 请求。
        * **输出：** XHR 请求失败，`onerror` 事件触发。开发者可以通过检查 XHR 对象的 `status` 是否为 0 以及可能的底层错误信息来判断是 CORS 错误。在 Blink 内部，会创建一个 `ResourceError` 对象，其 `is_access_check_` 为 true，并且可能包含 `cors_error_status_`。
    * **`<script>` 标签加载失败：** 当 `<script src="...">` 加载失败时，会触发 `onerror` 事件。
        * **假设输入：** HTML 中包含 `<script src="https://example.com/nonexistent.js"></script>`。
        * **输出：** 浏览器尝试加载脚本但失败（例如，DNS 解析失败，对应 `net::ERR_NAME_NOT_RESOLVED`）。Blink 内部会创建一个 `ResourceError` 对象来表示这个错误。脚本的 `onerror` 事件会被触发。

* **HTML:**
    * **`<img>` 标签加载失败：** 当 `<img>` 标签的 `src` 属性指向的图片资源加载失败时，会触发 `onerror` 事件，并且图片会显示为占位符或不显示。
        * **假设输入：** HTML 中包含 `<img src="https://example.com/broken.png">`，该 URL 返回 404 错误。
        * **输出：** 浏览器尝试加载图片失败。Blink 内部会创建一个 `ResourceError` 对象，其 `error_code_` 可能对应 HTTP 错误或者网络错误。`<img>` 标签会触发 `onerror` 事件。
    * **`<link>` 标签加载失败 (CSS)：** 当 `<link rel="stylesheet" href="...">` 加载失败时，CSS 样式不会被应用。
        * **假设输入：** HTML 中包含 `<link rel="stylesheet" href="https://example.com/nonexistent.css">`。
        * **输出：** 浏览器尝试加载 CSS 文件失败（例如，连接超时，对应 `net::ERR_TIMED_OUT`）。Blink 内部会创建一个 `ResourceError` 对象。页面可能显示为无样式。

* **CSS:**
    * **`url()` 加载失败 (例如 `background-image`, `font-face`)：** 当 CSS 中使用 `url()` 引用的资源加载失败时，对应的样式效果可能不会显示。
        * **假设输入：** CSS 文件中包含 `background-image: url('https://example.com/missing_bg.jpg');`，该 URL 返回 500 错误。
        * **输出：** 浏览器尝试加载背景图片失败。Blink 内部会创建一个 `ResourceError` 对象。元素的背景图片可能不会显示。

**逻辑推理 (假设输入与输出):**

假设我们发起一个跨域的 `fetch()` 请求，但服务器没有设置正确的 CORS 头信息。

* **假设输入：**
    * JavaScript 代码： `fetch('https://api.another-domain.com/data')`
    * 服务器 `https://api.another-domain.com` 没有返回 `Access-Control-Allow-Origin` 头，或者返回的值与当前页面的 origin 不匹配。

* **处理过程 (Blink 内部):**
    1. Blink 的网络层检测到这是一个跨域请求。
    2. 浏览器发送预检请求 (OPTIONS)，如果需要的话。
    3. 如果预检失败或者主请求的响应头缺少必要的 CORS 头信息，Blink 会阻止该请求。
    4. Blink 会创建一个 `ResourceError` 对象，并将 `is_access_check_` 设置为 `true`，同时设置 `cors_error_status_` 以包含更详细的 CORS 错误信息。
    5. 这个 `ResourceError` 对象会被转换为 `WebURLError`。

* **输出：**
    * `fetch()` 返回的 Promise 会被 reject。
    * reject 的原因是一个 `TypeError`，其消息可能类似于 "Failed to fetch" 或包含更详细的 CORS 错误信息，这取决于浏览器的实现细节。
    * 在开发者工具的控制台中，可能会显示 CORS 相关的错误信息，这些信息来源于内部的 `ResourceError` 或 `WebURLError`。

**涉及用户或编程常见的使用错误及举例说明：**

1. **错误的 URL：**  用户在 HTML、CSS 或 JavaScript 中输入了错误的资源 URL，导致请求无法到达目标服务器或请求的资源不存在。
    * **例子：** `<img src="htps://example.com/image.jpg">` (拼写错误 "https" 为 "htps")。这会导致 DNS 解析失败，对应 `net::ERR_NAME_NOT_RESOLVED`。
2. **CORS 配置错误：**  开发者没有在服务器端配置正确的 CORS 头信息，导致跨域请求被浏览器阻止。
    * **例子：** 前端 JavaScript 代码 `fetch('https://api.another-domain.com/data')`，但 `https://api.another-domain.com` 的响应头中缺少 `Access-Control-Allow-Origin`。
3. **混合内容 (Mixed Content)：**  在 HTTPS 页面中加载 HTTP 资源，这会被浏览器阻止以提高安全性。
    * **例子：** 一个 HTTPS 网页中包含 `<img src="http://example.com/image.jpg">`。这会导致 `net::ERR_BLOCKED_BY_RESPONSE`，并且 `blocked_by_response_reason_` 可能设置为 `kCorpNotSameOriginAfterDefaultedToSameOriginByCoep` 或类似的。
4. **Content Security Policy (CSP) 违规：**  网页的 CSP 策略禁止加载某些来源的资源，或者禁止执行内联脚本/样式。
    * **例子：** 网页的 CSP 头设置为 `Content-Security-Policy: script-src 'self'`，但 HTML 中包含 `<script src="https://cdn.example.com/script.js"></script>`。这会导致资源加载被阻止，`error_code_` 为 `net::ERR_BLOCKED_BY_CLIENT`，`extended_error_code_` 会映射到 `ResourceRequestBlockedReason::kCSP`。
5. **网络连接问题：**  用户的网络连接不稳定或者断开，导致资源加载失败。
    * **例子：** 用户在没有网络连接的情况下尝试访问一个网页，网页上的图片资源无法加载，可能会出现 `net::ERR_INTERNET_DISCONNECTED`。
6. **请求被浏览器扩展或设置阻止：**  用户的浏览器安装了广告拦截器或其他类型的扩展，这些扩展可能会阻止某些资源的加载。
    * **例子：** 广告拦截器阻止加载特定的广告脚本，导致 `error_code_` 为 `net::ERR_BLOCKED_BY_CLIENT`，`extended_error_code_` 可能对应 `ResourceRequestBlockedReason::kInspector` 或其他扩展相关的理由。

总而言之，`resource_error.cc` 文件在 Blink 渲染引擎中扮演着至关重要的角色，它负责统一、规范地表示资源加载过程中出现的各种错误，并将这些错误信息传递给上层模块，最终影响到 Web 开发者在 JavaScript、HTML 和 CSS 中所能观察到的行为和错误信息。 了解 `ResourceError` 的工作原理有助于开发者更好地理解和调试 Web 应用程序中的资源加载问题。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/resource_error.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2006 Apple Computer, Inc.  All rights reserved.
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"

#include "base/strings/string_number_conversions.h"
#include "net/base/net_errors.h"
#include "services/network/public/mojom/trust_tokens.mojom-blink-forward.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/resource_request_blocked_reason.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/trust_token_params_conversion.h"

namespace blink {

namespace {
constexpr char kThrottledErrorDescription[] =
    "Request throttled. Visit https://dev.chromium.org/throttling for more "
    "information.";
}  // namespace

ResourceError ResourceError::CancelledError(const KURL& url) {
  return ResourceError(net::ERR_ABORTED, url, std::nullopt);
}

ResourceError ResourceError::CancelledDueToAccessCheckError(
    const KURL& url,
    ResourceRequestBlockedReason blocked_reason) {
  ResourceError error = CancelledError(url);
  error.is_access_check_ = true;
  error.should_collapse_inititator_ =
      blocked_reason == ResourceRequestBlockedReason::kSubresourceFilter;
  return error;
}

ResourceError ResourceError::CancelledDueToAccessCheckError(
    const KURL& url,
    ResourceRequestBlockedReason blocked_reason,
    const String& localized_description) {
  ResourceError error = CancelledDueToAccessCheckError(url, blocked_reason);
  error.localized_description_ = localized_description;
  return error;
}

ResourceError ResourceError::BlockedByResponse(
    const KURL& url,
    network::mojom::BlockedByResponseReason blocked_by_response_reason) {
  ResourceError error(net::ERR_BLOCKED_BY_RESPONSE, url, std::nullopt);
  error.blocked_by_response_reason_ = blocked_by_response_reason;
  return error;
}

ResourceError ResourceError::CacheMissError(const KURL& url) {
  return ResourceError(net::ERR_CACHE_MISS, url, std::nullopt);
}

ResourceError ResourceError::TimeoutError(const KURL& url) {
  return ResourceError(net::ERR_TIMED_OUT, url, std::nullopt);
}

ResourceError ResourceError::Failure(const KURL& url) {
  return ResourceError(net::ERR_FAILED, url, std::nullopt);
}

ResourceError ResourceError::HttpError(const KURL& url) {
  ResourceError error = CancelledError(url);
  error.is_cancelled_from_http_error_ = true;
  return error;
}

ResourceError::ResourceError(
    int error_code,
    const KURL& url,
    std::optional<network::CorsErrorStatus> cors_error_status)
    : error_code_(error_code),
      failing_url_(url),
      is_access_check_(cors_error_status.has_value()),
      cors_error_status_(cors_error_status) {
  DCHECK_NE(error_code_, 0);
  InitializeDescription();
}

ResourceError::ResourceError(const KURL& url,
                             const network::CorsErrorStatus& cors_error_status)
    : ResourceError(net::ERR_FAILED, url, cors_error_status) {}

ResourceError::ResourceError(const WebURLError& error)
    : error_code_(error.reason()),
      extended_error_code_(error.extended_reason()),
      resolve_error_info_(error.resolve_error_info()),
      failing_url_(error.url()),
      is_access_check_(error.is_web_security_violation()),
      has_copy_in_cache_(error.has_copy_in_cache()),
      cors_error_status_(error.cors_error_status()),
      should_collapse_inititator_(error.should_collapse_initiator()),
      blocked_by_response_reason_(error.blocked_by_response_reason()),
      trust_token_operation_error_(error.trust_token_operation_error()) {
  DCHECK_NE(error_code_, 0);
  InitializeDescription();
}

ResourceError::operator WebURLError() const {
  WebURLError::HasCopyInCache has_copy_in_cache =
      has_copy_in_cache_ ? WebURLError::HasCopyInCache::kTrue
                         : WebURLError::HasCopyInCache::kFalse;

  if (cors_error_status_) {
    DCHECK_EQ(net::ERR_FAILED, error_code_);
    return WebURLError(*cors_error_status_, has_copy_in_cache, failing_url_);
  }

  if (trust_token_operation_error_ !=
      network::mojom::blink::TrustTokenOperationStatus::kOk) {
    return WebURLError(error_code_, trust_token_operation_error_, failing_url_);
  }

  return WebURLError(
      error_code_, extended_error_code_, resolve_error_info_, has_copy_in_cache,
      is_access_check_ ? WebURLError::IsWebSecurityViolation::kTrue
                       : WebURLError::IsWebSecurityViolation::kFalse,
      failing_url_,
      should_collapse_inititator_
          ? WebURLError::ShouldCollapseInitiator::kTrue
          : WebURLError::ShouldCollapseInitiator::kFalse);
}

bool ResourceError::Compare(const ResourceError& a, const ResourceError& b) {
  if (a.ErrorCode() != b.ErrorCode())
    return false;

  if (a.FailingURL() != b.FailingURL())
    return false;

  if (a.LocalizedDescription() != b.LocalizedDescription())
    return false;

  if (a.IsAccessCheck() != b.IsAccessCheck())
    return false;

  if (a.HasCopyInCache() != b.HasCopyInCache())
    return false;

  if (a.CorsErrorStatus() != b.CorsErrorStatus())
    return false;

  if (a.extended_error_code_ != b.extended_error_code_)
    return false;

  if (a.resolve_error_info_ != b.resolve_error_info_)
    return false;

  if (a.trust_token_operation_error_ != b.trust_token_operation_error_)
    return false;

  if (a.should_collapse_inititator_ != b.should_collapse_inititator_)
    return false;

  return true;
}

bool ResourceError::IsTimeout() const {
  return error_code_ == net::ERR_TIMED_OUT;
}

bool ResourceError::IsCancellation() const {
  return error_code_ == net::ERR_ABORTED;
}

bool ResourceError::IsTrustTokenCacheHit() const {
  return error_code_ ==
         net::ERR_TRUST_TOKEN_OPERATION_SUCCESS_WITHOUT_SENDING_REQUEST;
}

bool ResourceError::IsUnactionableTrustTokensStatus() const {
  return IsTrustTokenCacheHit() ||
         (error_code_ == net::ERR_TRUST_TOKEN_OPERATION_FAILED &&
          trust_token_operation_error_ ==
              network::mojom::TrustTokenOperationStatus::kUnauthorized);
}

bool ResourceError::IsCacheMiss() const {
  return error_code_ == net::ERR_CACHE_MISS;
}

bool ResourceError::WasBlockedByResponse() const {
  return error_code_ == net::ERR_BLOCKED_BY_RESPONSE;
}

bool ResourceError::WasBlockedByORB() const {
  return error_code_ == net::ERR_BLOCKED_BY_ORB;
}

namespace {
blink::ResourceRequestBlockedReason
BlockedByResponseReasonToResourceRequestBlockedReason(
    network::mojom::BlockedByResponseReason reason) {
  switch (reason) {
    case network::mojom::BlockedByResponseReason::
        kCoepFrameResourceNeedsCoepHeader:
      return blink::ResourceRequestBlockedReason::
          kCoepFrameResourceNeedsCoepHeader;
    case network::mojom::BlockedByResponseReason::
        kCoopSandboxedIFrameCannotNavigateToCoopPage:
      return blink::ResourceRequestBlockedReason::
          kCoopSandboxedIFrameCannotNavigateToCoopPage;
    case network::mojom::BlockedByResponseReason::kCorpNotSameOrigin:
      return blink::ResourceRequestBlockedReason::kCorpNotSameOrigin;
    case network::mojom::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoep:
      return blink::ResourceRequestBlockedReason::
          kCorpNotSameOriginAfterDefaultedToSameOriginByCoep;
    case network::mojom::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByDip:
      return blink::ResourceRequestBlockedReason::
          kCorpNotSameOriginAfterDefaultedToSameOriginByDip;
    case network::mojom::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip:
      return blink::ResourceRequestBlockedReason::
          kCorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip;
    case network::mojom::BlockedByResponseReason::kCorpNotSameSite:
      return blink::ResourceRequestBlockedReason::kCorpNotSameSite;
  }
  NOTREACHED();
}
}  // namespace

std::optional<ResourceRequestBlockedReason>
ResourceError::GetResourceRequestBlockedReason() const {
  if (error_code_ != net::ERR_BLOCKED_BY_CLIENT &&
      error_code_ != net::ERR_BLOCKED_BY_RESPONSE) {
    return std::nullopt;
  }
  if (blocked_by_response_reason_) {
    return BlockedByResponseReasonToResourceRequestBlockedReason(
        *blocked_by_response_reason_);
  }

  if (extended_error_code_ <=
      static_cast<int>(ResourceRequestBlockedReason::kMax)) {
    return static_cast<ResourceRequestBlockedReason>(extended_error_code_);
  }

  return std::nullopt;
}

std::optional<network::mojom::BlockedByResponseReason>
ResourceError::GetBlockedByResponseReason() const {
  if (error_code_ != net::ERR_BLOCKED_BY_CLIENT &&
      error_code_ != net::ERR_BLOCKED_BY_RESPONSE) {
    return std::nullopt;
  }
  return blocked_by_response_reason_;
}

namespace {
String DescriptionForBlockedByClientOrResponse(
    int error,
    const std::optional<blink::ResourceRequestBlockedReason>& reason) {
  if (!reason || *reason == ResourceRequestBlockedReason::kOther)
    return WebString::FromASCII(net::ErrorToString(error));
  std::string detail;
  switch (*reason) {
    case ResourceRequestBlockedReason::kOther:
      NOTREACHED();  // handled above
    case ResourceRequestBlockedReason::kCSP:
      detail = "CSP";
      break;
    case ResourceRequestBlockedReason::kMixedContent:
      detail = "MixedContent";
      break;
    case ResourceRequestBlockedReason::kOrigin:
      detail = "Origin";
      break;
    case ResourceRequestBlockedReason::kInspector:
      detail = "Inspector";
      break;
    case ResourceRequestBlockedReason::kSubresourceFilter:
      detail = "SubresourceFilter";
      break;
    case ResourceRequestBlockedReason::kContentType:
      detail = "ContentType";
      break;
    case ResourceRequestBlockedReason::kCoepFrameResourceNeedsCoepHeader:
      detail = "ResponseNeedsCrossOriginEmbedderPolicy";
      break;
    case ResourceRequestBlockedReason::
        kCoopSandboxedIFrameCannotNavigateToCoopPage:
      detail = "SandboxedIFrameCannotNavigateToOriginIsolatedPage";
      break;
    case ResourceRequestBlockedReason::kCorpNotSameOrigin:
      detail = "NotSameOrigin";
      break;
    case ResourceRequestBlockedReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoep:
      detail = "NotSameOriginAfterDefaultedToSameOriginByCoep";
      break;
    case ResourceRequestBlockedReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByDip:
      detail = "NotSameOriginAfterDefaultedToSameOriginByDip";
      break;
    case ResourceRequestBlockedReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip:
      detail = "NotSameOriginAfterDefaultedToSameOriginByCoepAndDip";
      break;
    case ResourceRequestBlockedReason::kCorpNotSameSite:
      detail = "NotSameSite";
      break;
    case ResourceRequestBlockedReason::kConversionRequest:
      detail = "ConversionRequest";
      break;
  }
  return WebString::FromASCII(net::ErrorToString(error) + "." + detail);
}
}  // namespace

void ResourceError::InitializeDescription() {
  if (error_code_ == net::ERR_TEMPORARILY_THROTTLED) {
    localized_description_ = WebString::FromASCII(kThrottledErrorDescription);
  } else if (error_code_ == net::ERR_BLOCKED_BY_CLIENT ||
             error_code_ == net::ERR_BLOCKED_BY_RESPONSE) {
    std::optional<ResourceRequestBlockedReason> reason =
        GetResourceRequestBlockedReason();
    localized_description_ =
        DescriptionForBlockedByClientOrResponse(error_code_, reason);
  } else {
    localized_description_ = WebString::FromASCII(
        net::ExtendedErrorToString(error_code_, extended_error_code_));
  }
}

std::ostream& operator<<(std::ostream& os, const ResourceError& error) {
  return os << ", ErrorCode = " << error.ErrorCode()
            << ", FailingURL = " << error.FailingURL()
            << ", LocalizedDescription = " << error.LocalizedDescription()
            << ", IsCancellation = " << error.IsCancellation()
            << ", IsAccessCheck = " << error.IsAccessCheck()
            << ", IsTimeout = " << error.IsTimeout()
            << ", HasCopyInCache = " << error.HasCopyInCache()
            << ", IsCacheMiss = " << error.IsCacheMiss()
            << ", TrustTokenOperationError = "
            << String::FromUTF8(base::NumberToString(
                   static_cast<int32_t>(error.TrustTokenOperationError())));
}

}  // namespace blink

"""

```