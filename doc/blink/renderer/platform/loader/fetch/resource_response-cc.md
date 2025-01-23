Response:
Let's break down the thought process for analyzing this `ResourceResponse.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of this file, its relationship to web technologies (JS, HTML, CSS), examples with assumptions, and potential user/programming errors.

2. **Identify the Core Class:** The file name `resource_response.cc` and the presence of the `ResourceResponse` class definition immediately indicate that this file is about representing and managing the *response* received from a network request.

3. **Analyze the Includes:** Examining the included headers provides clues about the class's responsibilities:
    * `third_party/blink/renderer/platform/loader/fetch/resource_response.h`: The corresponding header file, likely containing the class declaration.
    * `<string>`: Basic string manipulation.
    * `base/memory/scoped_refptr.h`:  Indicates the use of reference counting for memory management, suggesting potential shared ownership of `ResourceResponse` objects.
    * `net/http/structured_headers.h`, `net/ssl/ssl_info.h`:  Points to handling HTTP headers and SSL/TLS information, crucial for web communication.
    * `services/network/public/cpp/cors/cors.h`, `services/network/public/mojom/fetch_api.mojom-blink.h`:  Shows involvement with Cross-Origin Resource Sharing (CORS) and the Fetch API, both fundamental for web security and data access.
    * `third_party/blink/public/common/features.h`:  Feature flags, allowing for experimental or conditional behavior.
    * `third_party/blink/public/mojom/timing/resource_timing.mojom-blink.h`:  Resource Timing API, used to collect performance metrics for web resources.
    * `third_party/blink/public/platform/web_url_response.h`:  Integration with Blink's public API for representing URL responses.
    * `third_party/blink/renderer/platform/instrumentation/use_counter.h`: Tracking usage of features.
    * `third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h`:  Related to the loading process and timing.
    * `third_party/blink/renderer/platform/loader/fetch/service_worker_router_info.h`: Interaction with Service Workers.
    * `third_party/blink/renderer/platform/network/http_names.h`, `third_party/blink/renderer/platform/network/http_parsers.h`: Handling HTTP-specific data.
    * `third_party/blink/renderer/platform/wtf/...`:  WTF (Web Template Framework) utilities, like assertions, strings, etc.

4. **Examine the Class Members and Methods:**  This is the core of the analysis. Go through the class definition and the implemented methods. Categorize them by functionality:

    * **Basic Response Information:** URL, status code, status text, MIME type, encoding, content length. These are fundamental attributes of an HTTP response.
    * **Headers:**  Methods for getting, setting, adding, and clearing HTTP headers. Pay attention to how headers are parsed and cached (e.g., `cache_control_header_`).
    * **Caching:**  Flags and methods related to caching behavior (`was_cached_`, `CacheControlContainsNoCache`, `Expires`, `Age`, etc.).
    * **Security:** SSL information, CORS checks, Cross-Origin Embedder Policy (COEP).
    * **Service Workers:** Flags and data related to responses fetched via service workers.
    * **Timing:** Resource Timing information.
    * **Connection Information:** Connection reuse, ID, ALPN.
    * **Data Lengths:** Encoded and decoded body lengths.
    * **Flags:** Various boolean flags indicating aspects of the response (e.g., `is_null_`, `has_range_requested_`).
    * **Constructors and Destructor:**  Basic object lifecycle management.

5. **Connect to Web Technologies:**  Think about how the information managed by `ResourceResponse` relates to JavaScript, HTML, and CSS:

    * **JavaScript:**  JavaScript's `fetch` API or `XMLHttpRequest` receives a response object. This `ResourceResponse` class is part of how Blink represents that response internally. The headers, status, and body information are all accessible to JavaScript.
    * **HTML:**  When the browser fetches an HTML document, the `ResourceResponse` object associated with that fetch determines how the browser interprets the content (MIME type), whether to cache it, etc. Headers like `Content-Type` influence rendering.
    * **CSS:** Similar to HTML, when fetching CSS stylesheets, `ResourceResponse` dictates caching and interpretation. The `Content-Type` header is crucial for identifying it as CSS.

6. **Develop Examples with Assumptions:**  Create concrete scenarios to illustrate how `ResourceResponse` is used. For each scenario:
    * **Assume an Input:**  This will be a hypothetical HTTP response (status code, headers, etc.).
    * **Describe the Processing:** Explain how the `ResourceResponse` object would store and manage this information.
    * **Predict the Output/Behavior:** What would be the values of key properties (`WasCached`, `CacheControlContainsNoCache`, etc.)? How might this affect the browser's behavior?

7. **Identify Potential Errors:** Think about common mistakes developers make related to HTTP responses and how the `ResourceResponse` class might be involved:

    * **Incorrect MIME type:**  Leading to incorrect rendering or interpretation.
    * **Incorrect caching headers:**  Causing excessive network requests or serving stale content.
    * **CORS issues:**  Problems with cross-origin requests due to missing or incorrect CORS headers.

8. **Structure the Answer:** Organize the information logically, using clear headings and bullet points. Start with a general overview of the file's purpose, then delve into specific functionalities and their relation to web technologies. Provide clear examples and error scenarios.

9. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, double-check the interpretation of specific header parsing logic.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the methods.
* **Correction:** Realize the importance of understanding the *data* the class holds (member variables) and how the includes provide context.
* **Initial thought:**  Just list the methods.
* **Refinement:**  Group methods by functionality (caching, security, etc.) for better organization.
* **Initial thought:**  Generic examples.
* **Refinement:**  Create specific examples with concrete header values to illustrate the parsing logic and the impact on flags like `WasCached`.
* **Initial thought:**  Only developer errors.
* **Refinement:** Include scenarios where the *server* might send incorrect headers, which the browser (using `ResourceResponse`) needs to handle.

By following these steps and constantly refining the understanding, we can generate a comprehensive and accurate analysis of the `ResourceResponse.cc` file.
好的，让我们来分析一下 `blink/renderer/platform/loader/fetch/resource_response.cc` 这个文件。

**文件功能概述**

`resource_response.cc` 文件定义了 `ResourceResponse` 类，这个类在 Chromium Blink 引擎中用于**表示从网络请求中获得的响应**。它封装了 HTTP 响应的各种信息，例如：

* **基本信息:**  请求的 URL、响应的 URL、HTTP 状态码、状态文本、MIME 类型、文本编码、预期内容长度等。
* **HTTP 头部:**  存储了响应头部的键值对。
* **缓存控制信息:**  解析并存储了与缓存相关的头部信息，如 `Cache-Control`, `Expires`, `Pragma`, `Age`, `Last-Modified`, `ETag` 等。
* **安全性信息:**  包括 SSL 连接信息、CORS (跨域资源共享) 相关信息、COEP (跨域嵌入策略) 等。
* **Service Worker 信息:**  记录了响应是否来自 Service Worker，以及相关的 Service Worker 信息。
* **性能信息:**  关联了 `ResourceLoadTiming` 对象，用于记录资源加载的各个阶段的时间。
* **其他标志:**  例如，是否来自缓存、连接是否复用、是否通过 SPDY/HTTP2/HTTP3 获取、是否是预加载缓存等。

**与 JavaScript, HTML, CSS 的关系及举例**

`ResourceResponse` 类在 Blink 引擎中扮演着非常核心的角色，它直接影响着浏览器如何处理从网络加载的各种资源，包括 JavaScript, HTML 和 CSS 文件。

**1. JavaScript:**

* **功能关系:** 当 JavaScript 代码通过 `fetch()` API 或 `XMLHttpRequest` 发起网络请求时，服务器返回的响应信息会被封装成 `ResourceResponse` 对象。JavaScript 可以通过这些 API 访问响应的状态码、头部等信息。
* **举例说明:**
    * **假设输入 (HTTP 响应):**
        ```
        HTTP/1.1 200 OK
        Content-Type: application/javascript
        Cache-Control: public, max-age=3600
        ```
    * **`ResourceResponse` 处理:**  `ResourceResponse` 对象会存储状态码 `200`，MIME 类型 `application/javascript`，以及缓存控制指令 `public, max-age=3600`。
    * **JavaScript 访问:**  JavaScript 代码可以使用 `response.status` 获取状态码，`response.headers.get('Content-Type')` 获取 MIME 类型等。浏览器会根据 `Content-Type` 来解析和执行 JavaScript 代码，并根据 `Cache-Control` 决定是否缓存该脚本。

**2. HTML:**

* **功能关系:** 当浏览器请求一个 HTML 文档时，服务器返回的 `ResourceResponse` 对象决定了浏览器如何解析和渲染该 HTML。`Content-Type` 头部决定了浏览器将其视为 HTML，缓存头影响后续导航的加载速度。
* **举例说明:**
    * **假设输入 (HTTP 响应):**
        ```
        HTTP/1.1 200 OK
        Content-Type: text/html; charset=utf-8
        ```
    * **`ResourceResponse` 处理:** `ResourceResponse` 会记录状态码 `200` 和 MIME 类型 `text/html`，以及字符编码 `utf-8`。
    * **HTML 处理:** 浏览器根据 `Content-Type` 识别为 HTML，并使用 `utf-8` 编码解析文档。

**3. CSS:**

* **功能关系:** 加载 CSS 样式表的过程与 HTML 类似，`ResourceResponse` 包含了 CSS 文件的元信息，如 MIME 类型（`text/css`）和缓存策略。
* **举例说明:**
    * **假设输入 (HTTP 响应):**
        ```
        HTTP/1.1 200 OK
        Content-Type: text/css
        Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT
        ```
    * **`ResourceResponse` 处理:** `ResourceResponse` 会存储 MIME 类型 `text/css` 和 `Last-Modified` 时间。
    * **CSS 处理:** 浏览器根据 `Content-Type` 知道这是一个 CSS 文件，并解析其中的样式规则。`Last-Modified` 可以用于缓存验证，判断是否需要重新下载 CSS 文件。

**逻辑推理 (假设输入与输出)**

假设我们有一个 `ResourceResponse` 对象，其 HTTP 头部包含以下信息：

* **假设输入:**
    * `Content-Type: image/png`
    * `Cache-Control: max-age=600, public`
    * `Date: Tue, 23 Apr 2024 10:00:00 GMT`

* **逻辑推理:**
    * `ResourceResponse::HttpContentType()` 将返回 `"image/png"`。
    * `ResourceResponse::CacheControlContainsNoCache()` 将返回 `false`，因为 `Cache-Control` 中没有 `no-cache` 指令。
    * `ResourceResponse::CacheControlMaxAge()` 将返回一个 `base::TimeDelta` 对象，表示 600 秒。
    * `ResourceResponse::Date()` 将尝试解析 `Date` 头部，并返回一个 `base::Time` 对象，表示 `Tue, 23 Apr 2024 10:00:00 GMT`。

**用户或编程常见的使用错误**

虽然用户通常不直接操作 `ResourceResponse` 对象，但服务端配置错误或前端代码处理不当会导致与 `ResourceResponse` 相关的错误：

* **服务端配置错误的 MIME 类型:**
    * **错误示例:** 服务器将 JavaScript 文件配置为 `text/plain` 的 MIME 类型。
    * **后果:** 浏览器可能不会将其识别为 JavaScript，导致脚本无法执行。
* **服务端缓存控制不当:**
    * **错误示例:**  静态资源设置了 `Cache-Control: no-store`，导致浏览器每次都重新请求，影响性能。或者设置了过长的缓存时间，导致更新没有及时生效。
* **前端代码错误处理响应状态码或头部:**
    * **错误示例:**  前端 JavaScript 代码发起 `fetch` 请求后，没有正确检查 `response.ok` 或 `response.status`，导致在请求失败时没有进行错误处理。
    * **后果:**  页面可能显示错误信息或者功能不正常。
* **CORS 配置错误:**
    * **错误示例:**  当 JavaScript 从一个源请求另一个源的资源时，服务器没有设置正确的 CORS 头部（例如 `Access-Control-Allow-Origin`）。
    * **后果:** 浏览器会阻止跨域请求，并报错。

**总结**

`resource_response.cc` 中定义的 `ResourceResponse` 类是 Blink 引擎处理网络响应的核心组件。它负责存储和管理响应的各种元数据，并直接影响着浏览器如何解析、渲染和缓存从网络加载的资源。理解 `ResourceResponse` 的功能对于理解浏览器的工作原理以及排查与网络加载相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_response.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2008 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"

#include <string>

#include "base/memory/scoped_refptr.h"
#include "net/http/structured_headers.h"
#include "net/ssl/ssl_info.h"
#include "services/network/public/cpp/cors/cors.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/service_worker_router_info.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

template <typename Interface>
Vector<Interface> IsolatedCopy(const Vector<Interface>& src) {
  Vector<Interface> result;
  result.reserve(src.size());
  for (const auto& timestamp : src) {
    result.push_back(timestamp.IsolatedCopy());
  }
  return result;
}

}  // namespace

ResourceResponse::ResourceResponse()
    : was_cached_(false),
      connection_reused_(false),
      is_null_(true),
      have_parsed_age_header_(false),
      have_parsed_date_header_(false),
      have_parsed_expires_header_(false),
      have_parsed_last_modified_header_(false),
      has_major_certificate_errors_(false),
      has_range_requested_(false),
      timing_allow_passed_(false),
      was_fetched_via_spdy_(false),
      was_fetched_via_service_worker_(false),
      did_service_worker_navigation_preload_(false),
      did_use_shared_dictionary_(false),
      async_revalidation_requested_(false),
      is_signed_exchange_inner_response_(false),
      is_web_bundle_inner_response_(false),
      was_in_prefetch_cache_(false),
      was_cookie_in_request_(false),
      network_accessed_(false),
      from_archive_(false),
      was_alternate_protocol_available_(false),
      was_alpn_negotiated_(false),
      has_authorization_covered_by_wildcard_on_preflight_(false),
      is_validated_(false),
      request_include_credentials_(true),
      should_use_source_hash_for_js_code_cache_(false) {}

ResourceResponse::ResourceResponse(const KURL& current_request_url)
    : ResourceResponse() {
  SetCurrentRequestUrl(current_request_url);
}

ResourceResponse::ResourceResponse(const ResourceResponse&) = default;
ResourceResponse& ResourceResponse::operator=(const ResourceResponse&) =
    default;

ResourceResponse::~ResourceResponse() = default;

bool ResourceResponse::IsHTTP() const {
  return current_request_url_.ProtocolIsInHTTPFamily();
}

bool ResourceResponse::ShouldPopulateResourceTiming() const {
  return IsHTTP() || is_web_bundle_inner_response_;
}

const KURL& ResourceResponse::CurrentRequestUrl() const {
  return current_request_url_;
}

void ResourceResponse::SetCurrentRequestUrl(const KURL& url) {
  is_null_ = false;

  current_request_url_ = url;
}

KURL ResourceResponse::ResponseUrl() const {
  // Ideally ResourceResponse would have a |url_list_| to match Fetch
  // specification's URL list concept
  // (https://fetch.spec.whatwg.org/#concept-response-url-list), and its
  // last element would be returned here.
  //
  // Instead it has |url_list_via_service_worker_| which is only populated when
  // the response came from a service worker, and that response was not created
  // through `new Response()`. Use it when available.
  if (!url_list_via_service_worker_.empty()) {
    DCHECK(WasFetchedViaServiceWorker());
    return url_list_via_service_worker_.back();
  }

  // Otherwise, use the current request URL. This is OK because the Fetch
  // specification's "main fetch" algorithm[1] sets the response URL list to the
  // request's URL list when the list isn't present. That step can't be
  // implemented now because there is no |url_list_| memeber, but effectively
  // the same thing happens by returning CurrentRequestUrl() here.
  //
  // [1] "If internalResponse’s URL list is empty, then set it to a clone of
  // request’s URL list." at
  // https://fetch.spec.whatwg.org/#ref-for-concept-response-url-list%E2%91%A4
  return CurrentRequestUrl();
}

bool ResourceResponse::IsServiceWorkerPassThrough() const {
  return cache_storage_cache_name_.empty() &&
         !url_list_via_service_worker_.empty() &&
         ResponseUrl() == CurrentRequestUrl();
}

const AtomicString& ResourceResponse::MimeType() const {
  return mime_type_;
}

void ResourceResponse::SetMimeType(const AtomicString& mime_type) {
  is_null_ = false;

  // FIXME: MIME type is determined by HTTP Content-Type header. We should
  // update the header, so that it doesn't disagree with m_mimeType.
  mime_type_ = mime_type;
}

int64_t ResourceResponse::ExpectedContentLength() const {
  return expected_content_length_;
}

void ResourceResponse::SetExpectedContentLength(
    int64_t expected_content_length) {
  is_null_ = false;

  // FIXME: Content length is determined by HTTP Content-Length header. We
  // should update the header, so that it doesn't disagree with
  // m_expectedContentLength.
  expected_content_length_ = expected_content_length;
}

const AtomicString& ResourceResponse::TextEncodingName() const {
  return text_encoding_name_;
}

void ResourceResponse::SetTextEncodingName(const AtomicString& encoding_name) {
  is_null_ = false;

  // FIXME: Text encoding is determined by HTTP Content-Type header. We should
  // update the header, so that it doesn't disagree with m_textEncodingName.
  text_encoding_name_ = encoding_name;
}

int ResourceResponse::HttpStatusCode() const {
  return http_status_code_;
}

void ResourceResponse::SetHttpStatusCode(int status_code) {
  http_status_code_ = status_code;
}

const AtomicString& ResourceResponse::HttpStatusText() const {
  return http_status_text_;
}

void ResourceResponse::SetHttpStatusText(const AtomicString& status_text) {
  http_status_text_ = status_text;
}

const AtomicString& ResourceResponse::HttpHeaderField(
    const AtomicString& name) const {
  return http_header_fields_.Get(name);
}

void ResourceResponse::UpdateHeaderParsedState(const AtomicString& name) {
  if (EqualIgnoringASCIICase(name, http_names::kLowerAge)) {
    have_parsed_age_header_ = false;
  } else if (EqualIgnoringASCIICase(name, http_names::kLowerCacheControl) ||
             EqualIgnoringASCIICase(name, http_names::kLowerPragma)) {
    cache_control_header_ = CacheControlHeader();
  } else if (EqualIgnoringASCIICase(name, http_names::kLowerDate)) {
    have_parsed_date_header_ = false;
  } else if (EqualIgnoringASCIICase(name, http_names::kLowerExpires)) {
    have_parsed_expires_header_ = false;
  } else if (EqualIgnoringASCIICase(name, http_names::kLowerLastModified)) {
    have_parsed_last_modified_header_ = false;
  }
}

void ResourceResponse::SetSSLInfo(const net::SSLInfo& ssl_info) {
  DCHECK_NE(security_style_, SecurityStyle::kUnknown);
  DCHECK_NE(security_style_, SecurityStyle::kNeutral);
  ssl_info_ = ssl_info;
}

void ResourceResponse::SetServiceWorkerRouterInfo(
    scoped_refptr<ServiceWorkerRouterInfo> value) {
  service_worker_router_info_ = std::move(value);
}

bool ResourceResponse::IsCorsSameOrigin() const {
  return network::cors::IsCorsSameOriginResponseType(response_type_);
}

bool ResourceResponse::IsCorsCrossOrigin() const {
  return network::cors::IsCorsCrossOriginResponseType(response_type_);
}

void ResourceResponse::SetHttpHeaderField(const AtomicString& name,
                                          const AtomicString& value) {
  UpdateHeaderParsedState(name);

  http_header_fields_.Set(name, value);
}

void ResourceResponse::AddHttpHeaderField(const AtomicString& name,
                                          const AtomicString& value) {
  UpdateHeaderParsedState(name);

  HTTPHeaderMap::AddResult result = http_header_fields_.Add(name, value);
  if (!result.is_new_entry)
    result.stored_value->value = result.stored_value->value + ", " + value;
}

void ResourceResponse::AddHttpHeaderFieldWithMultipleValues(
    const AtomicString& name,
    const Vector<AtomicString>& values) {
  if (values.empty())
    return;

  UpdateHeaderParsedState(name);

  StringBuilder value_builder;
  const auto it = http_header_fields_.Find(name);
  if (it != http_header_fields_.end())
    value_builder.Append(it->value);
  for (const auto& value : values) {
    if (!value_builder.empty())
      value_builder.Append(", ");
    value_builder.Append(value);
  }
  http_header_fields_.Set(name, value_builder.ToAtomicString());
}

void ResourceResponse::ClearHttpHeaderField(const AtomicString& name) {
  http_header_fields_.Remove(name);
}

const HTTPHeaderMap& ResourceResponse::HttpHeaderFields() const {
  return http_header_fields_;
}

bool ResourceResponse::CacheControlContainsNoCache() const {
  if (!cache_control_header_.parsed) {
    cache_control_header_ = ParseCacheControlDirectives(
        http_header_fields_.Get(http_names::kLowerCacheControl),
        http_header_fields_.Get(http_names::kLowerPragma));
  }
  return cache_control_header_.contains_no_cache;
}

bool ResourceResponse::CacheControlContainsNoStore() const {
  if (!cache_control_header_.parsed) {
    cache_control_header_ = ParseCacheControlDirectives(
        http_header_fields_.Get(http_names::kLowerCacheControl),
        http_header_fields_.Get(http_names::kLowerPragma));
  }
  return cache_control_header_.contains_no_store;
}

bool ResourceResponse::CacheControlContainsMustRevalidate() const {
  if (!cache_control_header_.parsed) {
    cache_control_header_ = ParseCacheControlDirectives(
        http_header_fields_.Get(http_names::kLowerCacheControl),
        http_header_fields_.Get(http_names::kLowerPragma));
  }
  return cache_control_header_.contains_must_revalidate;
}

bool ResourceResponse::HasCacheValidatorFields() const {
  return !http_header_fields_.Get(http_names::kLowerLastModified).empty() ||
         !http_header_fields_.Get(http_names::kLowerETag).empty();
}

std::optional<base::TimeDelta> ResourceResponse::CacheControlMaxAge() const {
  if (!cache_control_header_.parsed) {
    cache_control_header_ = ParseCacheControlDirectives(
        http_header_fields_.Get(http_names::kLowerCacheControl),
        http_header_fields_.Get(http_names::kLowerPragma));
  }
  return cache_control_header_.max_age;
}

base::TimeDelta ResourceResponse::CacheControlStaleWhileRevalidate() const {
  if (!cache_control_header_.parsed) {
    cache_control_header_ = ParseCacheControlDirectives(
        http_header_fields_.Get(http_names::kLowerCacheControl),
        http_header_fields_.Get(http_names::kLowerPragma));
  }
  if (!cache_control_header_.stale_while_revalidate ||
      cache_control_header_.stale_while_revalidate.value() <
          base::TimeDelta()) {
    return base::TimeDelta();
  }
  return cache_control_header_.stale_while_revalidate.value();
}

static std::optional<base::Time> ParseDateValueInHeader(
    const HTTPHeaderMap& headers,
    const AtomicString& header_name,
    UseCounter& use_counter) {
  const AtomicString& header_value = headers.Get(header_name);
  if (header_value.empty())
    return std::nullopt;

  // In case of parsing the Expires header value, an invalid string 0 should be
  // treated as expired according to the RFC 9111 section 5.3 as below:
  //
  // > A cache recipient MUST interpret invalid date formats, especially the
  // > value "0", as representing a time in the past (i.e., "already expired").
  if (base::FeatureList::IsEnabled(
          blink::features::kTreatHTTPExpiresHeaderValueZeroAsExpiredInBlink) &&
      header_name == http_names::kLowerExpires && header_value == "0") {
    return base::Time::Min();
  }

  // This handles all date formats required by RFC2616:
  // Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
  // Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
  // Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format
  std::optional<base::Time> date = ParseDate(header_value, use_counter);

  if (date && date.value().is_max())
    return std::nullopt;
  return date;
}

std::optional<base::Time> ResourceResponse::Date(
    UseCounter& use_counter) const {
  if (!have_parsed_date_header_) {
    date_ = ParseDateValueInHeader(http_header_fields_, http_names::kLowerDate,
                                   use_counter);
    have_parsed_date_header_ = true;
  }
  return date_;
}

std::optional<base::TimeDelta> ResourceResponse::Age() const {
  if (!have_parsed_age_header_) {
    const AtomicString& header_value =
        http_header_fields_.Get(http_names::kLowerAge);
    bool ok;
    double seconds = header_value.ToDouble(&ok);
    if (!ok) {
      age_ = std::nullopt;
    } else {
      age_ = base::Seconds(seconds);
    }
    have_parsed_age_header_ = true;
  }
  return age_;
}

std::optional<base::Time> ResourceResponse::Expires(
    UseCounter& use_counter) const {
  if (!have_parsed_expires_header_) {
    expires_ = ParseDateValueInHeader(http_header_fields_,
                                      http_names::kLowerExpires, use_counter);
    have_parsed_expires_header_ = true;
  }
  return expires_;
}

std::optional<base::Time> ResourceResponse::LastModified(
    UseCounter& use_counter) const {
  if (!have_parsed_last_modified_header_) {
    last_modified_ = ParseDateValueInHeader(
        http_header_fields_, http_names::kLowerLastModified, use_counter);
    have_parsed_last_modified_header_ = true;
  }
  return last_modified_;
}

bool ResourceResponse::IsAttachment() const {
  static const char kAttachmentString[] = "attachment";
  String value = http_header_fields_.Get(http_names::kContentDisposition);
  wtf_size_t loc = value.find(';');
  if (loc != kNotFound)
    value = value.Left(loc);
  value = value.StripWhiteSpace();
  return EqualIgnoringASCIICase(value, kAttachmentString);
}

AtomicString ResourceResponse::HttpContentType() const {
  return ExtractMIMETypeFromMediaType(
      HttpHeaderField(http_names::kContentType).LowerASCII());
}

bool ResourceResponse::WasCached() const {
  return was_cached_;
}

void ResourceResponse::SetWasCached(bool value) {
  was_cached_ = value;
}

bool ResourceResponse::ConnectionReused() const {
  return connection_reused_;
}

void ResourceResponse::SetConnectionReused(bool connection_reused) {
  connection_reused_ = connection_reused;
}

unsigned ResourceResponse::ConnectionID() const {
  return connection_id_;
}

void ResourceResponse::SetConnectionID(unsigned connection_id) {
  connection_id_ = connection_id;
}

ResourceLoadTiming* ResourceResponse::GetResourceLoadTiming() const {
  return resource_load_timing_.get();
}

void ResourceResponse::SetResourceLoadTiming(
    scoped_refptr<ResourceLoadTiming> resource_load_timing) {
  resource_load_timing_ = std::move(resource_load_timing);
}

AtomicString ResourceResponse::ConnectionInfoString() const {
  std::string_view connection_info_string =
      net::HttpConnectionInfoToString(connection_info_);
  return AtomicString(base::as_byte_span(connection_info_string));
}

mojom::blink::CacheState ResourceResponse::CacheState() const {
  return is_validated_
             ? mojom::blink::CacheState::kValidated
             : (!encoded_data_length_ ? mojom::blink::CacheState::kLocal
                                      : mojom::blink::CacheState::kNone);
}

void ResourceResponse::SetIsValidated(bool is_validated) {
  is_validated_ = is_validated;
}

void ResourceResponse::SetEncodedDataLength(int64_t value) {
  encoded_data_length_ = value;
}

void ResourceResponse::SetEncodedBodyLength(uint64_t value) {
  encoded_body_length_ = value;
}

void ResourceResponse::SetDecodedBodyLength(int64_t value) {
  decoded_body_length_ = value;
}

network::mojom::CrossOriginEmbedderPolicyValue
ResourceResponse::GetCrossOriginEmbedderPolicy() const {
  const std::string value =
      HttpHeaderField(http_names::kLowerCrossOriginEmbedderPolicy).Utf8();
  using Item = net::structured_headers::Item;
  const auto item = net::structured_headers::ParseItem(value);
  if (!item || item->item.Type() != Item::kTokenType) {
    return network::mojom::CrossOriginEmbedderPolicyValue::kNone;
  }
  if (item->item.GetString() == "require-corp") {
    return network::mojom::CrossOriginEmbedderPolicyValue::kRequireCorp;
  } else if (item->item.GetString() == "credentialless") {
    return network::mojom::CrossOriginEmbedderPolicyValue::kCredentialless;
  } else {
    return network::mojom::CrossOriginEmbedderPolicyValue::kNone;
  }
}

STATIC_ASSERT_ENUM(WebURLResponse::kHTTPVersionUnknown,
                   ResourceResponse::kHTTPVersionUnknown);
STATIC_ASSERT_ENUM(WebURLResponse::kHTTPVersion_0_9,
                   ResourceResponse::kHTTPVersion_0_9);
STATIC_ASSERT_ENUM(WebURLResponse::kHTTPVersion_1_0,
                   ResourceResponse::kHTTPVersion_1_0);
STATIC_ASSERT_ENUM(WebURLResponse::kHTTPVersion_1_1,
                   ResourceResponse::kHTTPVersion_1_1);
STATIC_ASSERT_ENUM(WebURLResponse::kHTTPVersion_2_0,
                   ResourceResponse::kHTTPVersion_2_0);
}  // namespace blink
```