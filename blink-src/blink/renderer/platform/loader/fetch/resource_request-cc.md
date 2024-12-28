Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understand the Goal:** The primary goal is to explain the functionality of `resource_request.cc` (even though the provided content is actually the header file `resource_request.h`). We need to identify its purpose, connections to web technologies (JavaScript, HTML, CSS), and common usage errors.

2. **Initial Scan and Keyword Identification:** Read through the code, looking for key terms and concepts. Some immediate takeaways:
    * `ResourceRequestHead`, `ResourceRequest`, `ResourceRequestBody`: These are clearly core classes.
    * `KURL`:  Likely represents URLs.
    * `HTTPHeaderMap`:  Deals with HTTP headers.
    * `FetchCacheMode`, `CredentialsMode`, `RequestMode`, `ReferrerPolicy`: These seem related to web request configuration.
    * `PermissionsPolicy`:  Indicates something about browser permissions.
    * `mojom::blink::*`:  Suggests communication with other parts of Chromium using Mojo.
    * `net::*`:  Likely interacts with the networking stack.
    * Methods like `SetUrl`, `SetHttpMethod`, `SetHttpHeaderField`: These are setters, indicating configuration of requests.
    * Methods like `CreateRedirectRequest`:  This hints at handling redirects.

3. **Focus on the Core Classes:**  Examine `ResourceRequestHead` and `ResourceRequest` in detail.

    * **`ResourceRequestHead`:**  This class seems to hold the *attributes* of a request. Think of it as the configuration object. Notice the various data members: URL, HTTP method, headers, cache mode, credentials, etc. It also has methods for manipulating these attributes.

    * **`ResourceRequest`:** This class *inherits* from `ResourceRequestHead`. This suggests it *is* a `ResourceRequestHead` and might add additional functionality (though in this snippet, it largely delegates to the `head`). The `CopyHeadFrom` method confirms this.

    * **`ResourceRequestBody`:**  This class seems to represent the *body* of an HTTP request, if there is one. It can hold either `EncodedFormData` (for form submissions) or a `ChunkedDataPipeGetter` (for streaming bodies).

4. **Identify Connections to Web Technologies:**  Consider how these classes relate to the browser's interaction with web content:

    * **URLs (HTML, JavaScript):**  The `KURL` and the `SetUrl` method are directly related to how web browsers identify resources. HTML `<a>` tags, `<script src="...">`, `<link href="...">`, and JavaScript's `fetch()` API all involve URLs.

    * **HTTP Methods (HTML, JavaScript):**  Methods like `SetHttpMethod` relate to how browsers make requests (GET for simple links and resource loading, POST for form submissions, etc.). HTML forms use the `method` attribute. JavaScript's `fetch()` allows specifying the method.

    * **HTTP Headers (HTML, JavaScript, CSS):**  The `HTTPHeaderMap` and related methods are crucial. Examples:
        * `Cache-Control` headers affect caching (related to `<meta>` tags in HTML, and general browser behavior).
        * `Origin` header is vital for CORS (relevant to JavaScript's `fetch()` and cross-origin requests).
        * `Content-Type` header (though not explicitly shown being *set* here, it's often related to request bodies) is crucial for how the server interprets data (forms, JSON, etc.).
        * `Referer` header (represented by `referrer_string_`) is important for server-side analytics and security.

    * **Fetch API (JavaScript):** The presence of `is_fetch_like_api_` and `is_fetch_later_api_` strongly suggests a direct relationship with the JavaScript Fetch API. The `credentials_mode_`, `mode_`, and `redirect_mode_` also map closely to Fetch API options.

    * **Forms (HTML):**  The `EncodedFormData` in `ResourceRequestBody` directly connects to HTML `<form>` elements and how their data is submitted.

    * **Permissions Policy (HTML):** The `PermissionsPolicy` mentions features like "browsing topics" and "shared storage," which are controlled by the Permissions Policy, often set via HTTP headers or `<iframe>` attributes in HTML.

5. **Infer Logic and Create Examples:** Think about how these classes are used.

    * **Redirects:** The `CreateRedirectRequest` method provides a clear example of how the browser handles server-side redirects. Imagine an initial request and then a 302 response.

    * **Setting Headers:**  Consider how JavaScript might add custom headers using `fetch()` or how the browser itself might add headers based on the request type.

    * **Caching:**  The `CacheMode` and cache-related header checks illustrate how the browser manages its cache.

6. **Identify Potential User/Programming Errors:** Consider common mistakes developers make:

    * **Incorrect HTTP Method:** Using GET when a POST is needed for form submission.
    * **Missing or Incorrect CORS Headers:** Leading to failed `fetch()` requests.
    * **Misunderstanding Caching:** Not setting appropriate `Cache-Control` headers, leading to unexpected caching behavior.
    * **Incorrect Referrer Policy:**  Leaking sensitive information or breaking functionality.
    * **Confusing `SiteForCookies`:**  Not understanding its implications for cross-site requests and cookies.

7. **Structure the Explanation:** Organize the findings logically:

    * Start with a general overview of the file's purpose.
    * Explain the core classes and their roles.
    * Provide concrete examples of how the functionality relates to JavaScript, HTML, and CSS.
    * Illustrate logical inference with input/output scenarios.
    * Highlight common usage errors with examples.

8. **Refine and Elaborate:**  Review the explanation for clarity and completeness. Add more detail where needed. For instance, explaining *why* certain headers are important for CORS or caching.

By following this process, we can systematically analyze the C++ header file and generate a comprehensive and informative explanation of its functionality and relevance to web development. The key is to connect the code constructs to the practical realities of building web applications.
这个文件 `resource_request.cc` (更准确地说，根据内容应该是 `resource_request.h`，因为内容是头文件) 定义了 Blink 渲染引擎中用于表示资源请求的类和相关结构。它的核心功能是**封装发起网络请求所需的所有信息**。

以下是其主要功能点的详细说明：

**1. 定义资源请求的数据结构:**

* **`ResourceRequestHead`:**  这个类包含了资源请求的头部信息，例如：
    * **URL (`KURL url_`)**:  请求的目标地址。
    * **HTTP 方法 (`AtomicString http_method_`)**:  GET, POST, PUT, DELETE 等。
    * **HTTP 头部 (`HTTPHeaderMap http_header_fields_`)**:  请求头部的键值对，例如 `User-Agent`, `Content-Type`, `Cache-Control` 等。
    * **缓存模式 (`mojom::blink::FetchCacheMode cache_mode_`)**:  控制缓存行为，例如 `kDefault`, `kNoCache`, `kReload` 等。
    * **超时时间 (`base::TimeDelta timeout_interval_`)**:  请求的超时时间。
    * **Cookie 相关信息 (`net::SiteForCookies site_for_cookies_`)**:  控制 Cookie 的发送策略。
    * **发起者的安全来源 (`scoped_refptr<const SecurityOrigin> top_frame_origin_`)**:  用于安全策略判断。
    * **优先级 (`ResourceLoadPriority priority_`, `int intra_priority_value_`)**:  影响资源加载的顺序。
    * **请求上下文 (`mojom::blink::RequestContextType request_context_`)**:  指示请求的类型，例如主框架、脚本、样式表等。
    * **目标类型 (`network::mojom::RequestDestination destination_`)**:  请求资源的类型，例如文档、脚本、图像等。
    * **CORS 模式 (`network::mojom::RequestMode mode_`)**:  控制跨域请求的行为。
    * **凭据模式 (`network::mojom::CredentialsMode credentials_mode_`)**:  控制是否发送 Cookie 和 HTTP 认证信息。
    * **重定向模式 (`network::mojom::RedirectMode redirect_mode_`)**:  控制如何处理重定向。
    * **引用 (`String referrer_string_`, `network::mojom::ReferrerPolicy referrer_policy_`)**:  指示请求的来源页面。
    * **用户手势 (`bool has_user_gesture_`)**:  表示请求是否由用户操作触发。
    * **是否下载到 Blob (`bool download_to_blob_`)**:  指示是否将响应下载为 Blob 对象。
    * **是否使用流式响应 (`bool use_stream_on_response_`)**:  指示是否以流的方式处理响应。
    * **Keep-Alive (`bool keepalive_`)**:  指示是否保持连接。
    * **Permissions Policy 相关信息**: 用于控制浏览器特性的权限。
    * **以及其他控制请求行为的标志和参数。**

* **`ResourceRequestBody`:**  这个类表示请求的 body 部分，对于 POST 或 PUT 请求，它包含了要发送的数据。可以包含以下两种类型的数据：
    * **`scoped_refptr<EncodedFormData> form_body_`**:  用于表示 `application/x-www-form-urlencoded` 或 `multipart/form-data` 类型的表单数据。
    * **`mojo::PendingRemote<network::mojom::blink::ChunkedDataPipeGetter> stream_body_`**:  用于表示流式数据。

* **`ResourceRequest`:**  继承自 `ResourceRequestHead`，代表一个完整的资源请求。它组合了头部信息和 body 信息。

**2. 提供创建和修改资源请求的方法:**

* 提供了构造函数来创建 `ResourceRequest` 和 `ResourceRequestHead` 对象。
* 提供了 `Set` 开头的方法来设置各种请求属性，例如 `SetUrl`, `SetHttpMethod`, `SetHttpHeaderField` 等。
* 提供了 `AddHttpHeaderField` 和 `AddHTTPHeaderFields` 方法来添加 HTTP 头部。
* 提供了 `ClearHttpHeaderField` 方法来移除 HTTP 头部。
* 提供了 `CreateRedirectRequest` 方法，用于在处理 HTTP 重定向时创建新的请求。

**3. 提供访问请求属性的方法:**

* 提供了 `Get` 开头的方法来获取请求的各种属性，例如 `Url`, `HttpMethod`, `HttpHeaderFields` 等。

**与 JavaScript, HTML, CSS 的功能关系和举例说明:**

`ResourceRequest` 类在 Blink 引擎中扮演着核心角色，它连接了前端的 JavaScript, HTML, CSS 代码与底层的网络请求。

* **JavaScript:**
    * **`fetch()` API**: 当 JavaScript 代码使用 `fetch()` API 发起网络请求时，Blink 引擎会创建一个 `ResourceRequest` 对象来封装请求信息。`fetch()` 的参数，如 URL, method, headers, body, mode, credentials 等，都会被映射到 `ResourceRequest` 对象的相应属性上。
        * **假设输入 (JavaScript):**
          ```javascript
          fetch('https://example.com/data', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ key: 'value' }),
            mode: 'cors',
            credentials: 'include'
          });
          ```
        * **输出 (推断的 `ResourceRequest` 对象属性):**
          * `url_`: `https://example.com/data`
          * `http_method_`: `"POST"`
          * `http_header_fields_`:  包含了 `{"Content-Type": "application/json"}`
          * `body_`:  一个包含 `JSON.stringify({ key: 'value' })` 数据的 `ResourceRequestBody` 对象
          * `mode_`: `network::mojom::RequestMode::kCors`
          * `credentials_mode_`: `network::mojom::CredentialsMode::kInclude`
    * **XMLHttpRequest (XHR)**:  类似于 `fetch()`，当使用 XHR 对象发起请求时，也会创建一个 `ResourceRequest` 对象。XHR 的属性和方法，如 `open()`, `setRequestHeader()`, `send()`，都会影响 `ResourceRequest` 对象的构建。

* **HTML:**
    * **`<form>` 提交**: 当 HTML 表单被提交时，浏览器会根据表单的 `action` 属性和 `method` 属性创建一个 `ResourceRequest` 对象。表单的数据会被编码并存储在 `ResourceRequestBody` 中。
        * **假设输入 (HTML):**
          ```html
          <form action="/submit" method="post">
            <input type="text" name="name" value="John">
            <button type="submit">Submit</button>
          </form>
          ```
        * **输出 (推断的 `ResourceRequest` 对象属性):**
          * `url_`: 当前页面 URL + `/submit`
          * `http_method_`: `"POST"`
          * `body_`:  一个包含 `name=John` 的 `EncodedFormData` 对象的 `ResourceRequestBody` 对象
          * `is_form_submission_`: `true`
    * **`<a>` 标签**: 点击链接时，会创建一个 `ResourceRequest` 对象，其 HTTP 方法默认为 GET。
    * **`<script src="...">`, `<link href="...">`, `<img> src="..."` 等**:  这些标签用于加载外部资源，浏览器会为每个资源创建一个 `ResourceRequest` 对象。请求上下文 (`request_context_`) 会根据标签类型进行设置（例如，脚本、样式表、图像）。

* **CSS:**
    * **`url()` 函数**: 在 CSS 中使用 `url()` 函数引用外部资源（例如背景图片、字体）时，Blink 引擎会创建一个 `ResourceRequest` 对象来加载这些资源。
        * **假设输入 (CSS):**
          ```css
          body {
            background-image: url('image.png');
          }
          ```
        * **输出 (推断的 `ResourceRequest` 对象属性):**
          * `url_`: 当前 CSS 文件 URL + `image.png`
          * `http_method_`: `"GET"`
          * `request_context_`:  可能为 `mojom::blink::RequestContextType::kImage`

**逻辑推理的假设输入与输出:**

* **假设输入:** 一个 JavaScript 发起的 `fetch()` 请求，需要携带特定的 Cookie。
* **推断的 `ResourceRequest` 对象属性:** `credentials_mode_` 将被设置为 `network::mojom::CredentialsMode::kInclude`，以便在请求中包含 Cookie。

* **假设输入:**  用户点击了一个指向 HTTPS 地址的 HTTP 链接。
* **推断的 `ResourceRequest` 对象属性:**  如果启用了 HTTP 严格传输安全 (HSTS)，或者浏览器内部有升级机制，`upgrade_if_insecure_` 可能会被设置为 `true`，并且请求的 URL 可能会被升级到 HTTPS。

**涉及用户或编程常见的使用错误:**

* **CORS 问题:**  如果 JavaScript 代码尝试从与当前页面不同源的地址请求资源，并且服务器没有设置正确的 CORS 头部，浏览器会阻止该请求。开发者可能会遇到控制台报错，提示 CORS 策略阻止了该请求。
    * **错误示例:** JavaScript 代码从 `http://example.com` 请求 `http://api.another.com` 的数据，但 `http://api.another.com` 的响应头中缺少 `Access-Control-Allow-Origin`。
* **混合内容 (Mixed Content):**  在 HTTPS 页面中加载 HTTP 资源（例如脚本、样式表、图片）会导致安全风险。浏览器通常会阻止或警告这种行为。
    * **错误示例:**  一个 HTTPS 页面引用了一个 HTTP 的 JavaScript 文件 `<script src="http://insecure.com/script.js">`。
* **缓存控制不当:**  如果服务器或开发者没有设置合适的缓存控制头部 (`Cache-Control`)，可能导致浏览器缓存了过期的资源，或者频繁地重新请求资源，影响用户体验和性能。
    * **错误示例:**  静态资源（例如图片）没有设置 `Cache-Control: max-age=...`，导致浏览器每次都重新请求。
* **Referrer Policy 设置不当:**  错误的 `Referrer-Policy` 设置可能导致服务器端无法正确获取来源信息，或者泄露敏感信息。
    * **错误示例:**  将 `Referrer-Policy` 设置为 `unsafe-url` 可能会将来源页面的完整 URL 发送到第三方网站，即使该网站是通过 HTTPS 访问的。
* **HTTP 方法误用:**  例如，使用 GET 请求来发送敏感数据，或者使用 POST 请求来获取应该使用 GET 请求的数据。
    * **错误示例:**  使用 GET 请求来提交包含密码的表单数据，这会将密码暴露在 URL 中。

总而言之，`resource_request.cc` (或 `.h`) 文件定义了 Blink 引擎中网络请求的核心数据结构，它将前端的 Web 技术与底层的网络通信连接起来，是理解浏览器如何发起和处理网络请求的关键。开发者在使用 JavaScript, HTML, CSS 进行网络交互时，实际上是在幕后操作着这些 `ResourceRequest` 对象。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/resource_request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2003, 2006 Apple Computer, Inc.  All rights reserved.
 * Copyright (C) 2009, 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"

#include <memory>

#include "base/unguessable_token.h"
#include "net/base/request_priority.h"
#include "services/network/public/mojom/ip_address_space.mojom-blink.h"
#include "services/network/public/mojom/web_bundle_handle.mojom-blink.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"

namespace blink {

ResourceRequestHead::WebBundleTokenParams&
ResourceRequestHead::WebBundleTokenParams::operator=(
    const WebBundleTokenParams& other) {
  bundle_url = other.bundle_url;
  token = other.token;
  handle = other.CloneHandle();
  return *this;
}

ResourceRequestHead::WebBundleTokenParams::WebBundleTokenParams(
    const WebBundleTokenParams& other) {
  *this = other;
}

ResourceRequestHead::WebBundleTokenParams::WebBundleTokenParams(
    const KURL& bundle_url,
    const base::UnguessableToken& web_bundle_token,
    mojo::PendingRemote<network::mojom::blink::WebBundleHandle>
        web_bundle_handle)
    : bundle_url(bundle_url),
      token(web_bundle_token),
      handle(std::move(web_bundle_handle)) {}

mojo::PendingRemote<network::mojom::blink::WebBundleHandle>
ResourceRequestHead::WebBundleTokenParams::CloneHandle() const {
  if (!handle)
    return mojo::NullRemote();
  mojo::Remote<network::mojom::blink::WebBundleHandle> remote(std::move(
      const_cast<mojo::PendingRemote<network::mojom::blink::WebBundleHandle>&>(
          handle)));
  mojo::PendingRemote<network::mojom::blink::WebBundleHandle> new_remote;
  remote->Clone(new_remote.InitWithNewPipeAndPassReceiver());
  const_cast<mojo::PendingRemote<network::mojom::blink::WebBundleHandle>&>(
      handle) = remote.Unbind();
  return new_remote;
}

const base::TimeDelta ResourceRequestHead::default_timeout_interval_ =
    base::TimeDelta::Max();

ResourceRequestHead::ResourceRequestHead() : ResourceRequestHead(NullURL()) {}

ResourceRequestHead::ResourceRequestHead(const KURL& url)
    : url_(url),
      timeout_interval_(default_timeout_interval_),
      http_method_(http_names::kGET),
      report_upload_progress_(false),
      has_user_gesture_(false),
      has_text_fragment_token_(false),
      download_to_blob_(false),
      use_stream_on_response_(false),
      keepalive_(false),
      browsing_topics_(false),
      ad_auction_headers_(false),
      shared_storage_writable_opted_in_(false),
      shared_storage_writable_eligible_(false),
      allow_stale_response_(false),
      skip_service_worker_(false),
      download_to_cache_only_(false),
      site_for_cookies_set_(false),
      is_form_submission_(false),
      priority_incremental_(net::kDefaultPriorityIncremental),
      is_ad_resource_(false),
      upgrade_if_insecure_(false),
      is_revalidating_(false),
      is_automatic_upgrade_(false),
      is_from_origin_dirty_style_sheet_(false),
      is_fetch_like_api_(false),
      is_fetch_later_api_(false),
      is_favicon_(false),
      prefetch_maybe_for_top_level_navigation_(false),
      shared_dictionary_writer_enabled_(false),
      requires_upgrade_for_loader_(false),
      cache_mode_(mojom::blink::FetchCacheMode::kDefault),
      initial_priority_(ResourceLoadPriority::kUnresolved),
      priority_(ResourceLoadPriority::kUnresolved),
      intra_priority_value_(0),
      request_context_(mojom::blink::RequestContextType::UNSPECIFIED),
      destination_(network::mojom::RequestDestination::kEmpty),
      mode_(network::mojom::RequestMode::kNoCors),
      fetch_priority_hint_(mojom::blink::FetchPriorityHint::kAuto),
      credentials_mode_(network::mojom::CredentialsMode::kInclude),
      redirect_mode_(network::mojom::RedirectMode::kFollow),
      referrer_string_(Referrer::ClientReferrerString()),
      referrer_policy_(network::mojom::ReferrerPolicy::kDefault),
      cors_preflight_policy_(
          network::mojom::CorsPreflightPolicy::kConsiderPreflight),
      target_address_space_(network::mojom::IPAddressSpace::kUnknown) {}

ResourceRequestHead::ResourceRequestHead(const ResourceRequestHead&) = default;

ResourceRequestHead& ResourceRequestHead::operator=(
    const ResourceRequestHead&) = default;

ResourceRequestHead::ResourceRequestHead(ResourceRequestHead&&) = default;

ResourceRequestHead& ResourceRequestHead::operator=(ResourceRequestHead&&) =
    default;

ResourceRequestHead::~ResourceRequestHead() = default;

ResourceRequestBody::ResourceRequestBody() : ResourceRequestBody(nullptr) {}

ResourceRequestBody::ResourceRequestBody(
    scoped_refptr<EncodedFormData> form_body)
    : form_body_(form_body) {}

ResourceRequestBody::ResourceRequestBody(
    mojo::PendingRemote<network::mojom::blink::ChunkedDataPipeGetter>
        stream_body)
    : stream_body_(std::move(stream_body)) {}

ResourceRequestBody::ResourceRequestBody(ResourceRequestBody&& src)
    : form_body_(std::move(src.form_body_)),
      stream_body_(std::move(src.stream_body_)) {}

ResourceRequestBody& ResourceRequestBody::operator=(ResourceRequestBody&& src) =
    default;

ResourceRequestBody::~ResourceRequestBody() = default;

void ResourceRequestBody::SetStreamBody(
    mojo::PendingRemote<network::mojom::blink::ChunkedDataPipeGetter>
        stream_body) {
  stream_body_ = std::move(stream_body);
}

ResourceRequest::ResourceRequest() : ResourceRequestHead(NullURL()) {}

ResourceRequest::ResourceRequest(const String& url_string)
    : ResourceRequestHead(KURL(url_string)) {}

ResourceRequest::ResourceRequest(const KURL& url) : ResourceRequestHead(url) {}

ResourceRequest::ResourceRequest(const ResourceRequestHead& head)
    : ResourceRequestHead(head) {}

ResourceRequest::ResourceRequest(ResourceRequest&&) = default;

ResourceRequest& ResourceRequest::operator=(ResourceRequest&&) = default;

ResourceRequest::~ResourceRequest() = default;

void ResourceRequest::CopyHeadFrom(const ResourceRequestHead& src) {
  this->ResourceRequestHead::operator=(src);
}

std::unique_ptr<ResourceRequest> ResourceRequestHead::CreateRedirectRequest(
    const KURL& new_url,
    const AtomicString& new_method,
    const net::SiteForCookies& new_site_for_cookies,
    const String& new_referrer,
    network::mojom::ReferrerPolicy new_referrer_policy,
    bool skip_service_worker) const {
  std::unique_ptr<ResourceRequest> request =
      std::make_unique<ResourceRequest>(new_url);
  request->SetRequestorOrigin(RequestorOrigin());
  request->SetIsolatedWorldOrigin(IsolatedWorldOrigin());
  request->SetHttpMethod(new_method);
  request->SetSiteForCookies(new_site_for_cookies);
  String referrer =
      new_referrer.empty() ? Referrer::NoReferrer() : String(new_referrer);
  request->SetReferrerString(referrer);
  request->SetReferrerPolicy(new_referrer_policy);
  request->SetSkipServiceWorker(skip_service_worker);
  request->redirect_info_ = RedirectInfo(
      redirect_info_ ? redirect_info_->original_url : Url(), Url());

  // Copy from parameters for |this|.
  request->SetDownloadToBlob(DownloadToBlob());
  request->SetUseStreamOnResponse(UseStreamOnResponse());
  request->SetRequestContext(GetRequestContext());
  request->SetMode(GetMode());
  request->SetTargetAddressSpace(GetTargetAddressSpace());
  request->SetCredentialsMode(GetCredentialsMode());
  request->SetKeepalive(GetKeepalive());
  request->SetBrowsingTopics(GetBrowsingTopics());
  request->SetAdAuctionHeaders(GetAdAuctionHeaders());
  request->SetSharedStorageWritableOptedIn(GetSharedStorageWritableOptedIn());
  request->SetPriority(Priority());
  request->SetPriorityIncremental(PriorityIncremental());

  request->SetCorsPreflightPolicy(CorsPreflightPolicy());
  if (IsAdResource())
    request->SetIsAdResource();
  request->SetUpgradeIfInsecure(UpgradeIfInsecure());
  request->SetIsAutomaticUpgrade(IsAutomaticUpgrade());
  request->SetRequestedWithHeader(GetRequestedWithHeader());
  request->SetClientDataHeader(GetClientDataHeader());
  request->SetPurposeHeader(GetPurposeHeader());
  request->SetUkmSourceId(GetUkmSourceId());
  request->SetInspectorId(InspectorId());
  request->SetFromOriginDirtyStyleSheet(IsFromOriginDirtyStyleSheet());
  request->SetRecursivePrefetchToken(RecursivePrefetchToken());
  request->SetFetchLikeAPI(IsFetchLikeAPI());
  request->SetFetchLaterAPI(IsFetchLaterAPI());
  request->SetFavicon(IsFavicon());
  request->SetAttributionReportingSupport(GetAttributionReportingSupport());
  request->SetAttributionReportingEligibility(
      GetAttributionReportingEligibility());
  request->SetAttributionReportingSrcToken(GetAttributionSrcToken());

  return request;
}

bool ResourceRequestHead::IsNull() const {
  return url_.IsNull();
}

const KURL& ResourceRequestHead::Url() const {
  return url_;
}

void ResourceRequestHead::SetUrl(const KURL& url) {
  // Loading consists of a number of phases. After cache lookup the url should
  // not change (otherwise checks would not be valid). This DCHECK verifies
  // that.
#if DCHECK_IS_ON()
  DCHECK(is_set_url_allowed_);
#endif
  url_ = url;
}

void ResourceRequestHead::RemoveUserAndPassFromURL() {
  if (url_.User().empty() && url_.Pass().empty())
    return;

  url_.SetUser(String());
  url_.SetPass(String());
}

mojom::blink::FetchCacheMode ResourceRequestHead::GetCacheMode() const {
  return cache_mode_;
}

void ResourceRequestHead::SetCacheMode(
    mojom::blink::FetchCacheMode cache_mode) {
  cache_mode_ = cache_mode;
}

base::TimeDelta ResourceRequestHead::TimeoutInterval() const {
  return timeout_interval_;
}

void ResourceRequestHead::SetTimeoutInterval(
    base::TimeDelta timout_interval_seconds) {
  timeout_interval_ = timout_interval_seconds;
}

const net::SiteForCookies& ResourceRequestHead::SiteForCookies() const {
  return site_for_cookies_;
}

void ResourceRequestHead::SetSiteForCookies(
    const net::SiteForCookies& site_for_cookies) {
  site_for_cookies_ = site_for_cookies;
  site_for_cookies_set_ = true;
}

const SecurityOrigin* ResourceRequestHead::TopFrameOrigin() const {
  return top_frame_origin_.get();
}

void ResourceRequestHead::SetTopFrameOrigin(
    scoped_refptr<const SecurityOrigin> origin) {
  top_frame_origin_ = std::move(origin);
}

const AtomicString& ResourceRequestHead::HttpMethod() const {
  return http_method_;
}

void ResourceRequestHead::SetHttpMethod(const AtomicString& http_method) {
  http_method_ = http_method;
}

const HTTPHeaderMap& ResourceRequestHead::HttpHeaderFields() const {
  return http_header_fields_;
}

const AtomicString& ResourceRequestHead::HttpHeaderField(
    const AtomicString& name) const {
  return http_header_fields_.Get(name);
}

void ResourceRequestHead::SetHttpHeaderField(const AtomicString& name,
                                             const AtomicString& value) {
  http_header_fields_.Set(name, value);
}

void ResourceRequestHead::SetHTTPOrigin(const SecurityOrigin* origin) {
  SetHttpHeaderField(http_names::kOrigin, origin->ToAtomicString());
}

void ResourceRequestHead::ClearHTTPOrigin() {
  http_header_fields_.Remove(http_names::kOrigin);
}

void ResourceRequestHead::SetHttpOriginIfNeeded(const SecurityOrigin* origin) {
  if (NeedsHTTPOrigin())
    SetHTTPOrigin(origin);
}

void ResourceRequestHead::SetHTTPOriginToMatchReferrerIfNeeded() {
  if (NeedsHTTPOrigin()) {
    SetHTTPOrigin(SecurityOrigin::CreateFromString(ReferrerString()).get());
  }
}

void ResourceRequestHead::ClearHTTPUserAgent() {
  http_header_fields_.Remove(http_names::kUserAgent);
}

void ResourceRequestBody::SetFormBody(
    scoped_refptr<EncodedFormData> form_body) {
  form_body_ = std::move(form_body);
}

const scoped_refptr<EncodedFormData>& ResourceRequest::HttpBody() const {
  return body_.FormBody();
}

void ResourceRequest::SetHttpBody(scoped_refptr<EncodedFormData> http_body) {
  body_.SetFormBody(std::move(http_body));
}

ResourceLoadPriority ResourceRequestHead::InitialPriority() const {
  return initial_priority_;
}

ResourceLoadPriority ResourceRequestHead::Priority() const {
  return priority_;
}

int ResourceRequestHead::IntraPriorityValue() const {
  return intra_priority_value_;
}

bool ResourceRequestHead::PriorityHasBeenSet() const {
  return priority_ != ResourceLoadPriority::kUnresolved;
}

void ResourceRequestHead::SetPriority(ResourceLoadPriority priority,
                                      int intra_priority_value) {
  if (!PriorityHasBeenSet())
    initial_priority_ = priority;
  priority_ = priority;
  intra_priority_value_ = intra_priority_value;
}

bool ResourceRequestHead::PriorityIncremental() const {
  return priority_incremental_;
}

void ResourceRequestHead::SetPriorityIncremental(bool priority_incremental) {
  priority_incremental_ = priority_incremental;
}

void ResourceRequestHead::AddHttpHeaderField(const AtomicString& name,
                                             const AtomicString& value) {
  HTTPHeaderMap::AddResult result = http_header_fields_.Add(name, value);
  if (!result.is_new_entry)
    result.stored_value->value = result.stored_value->value + ", " + value;
}

void ResourceRequestHead::AddHTTPHeaderFields(
    const HTTPHeaderMap& header_fields) {
  HTTPHeaderMap::const_iterator end = header_fields.end();
  for (HTTPHeaderMap::const_iterator it = header_fields.begin(); it != end;
       ++it)
    AddHttpHeaderField(it->key, it->value);
}

void ResourceRequestHead::ClearHttpHeaderField(const AtomicString& name) {
  http_header_fields_.Remove(name);
}

bool ResourceRequestHead::IsConditional() const {
  return (http_header_fields_.Contains(http_names::kIfMatch) ||
          http_header_fields_.Contains(http_names::kIfModifiedSince) ||
          http_header_fields_.Contains(http_names::kIfNoneMatch) ||
          http_header_fields_.Contains(http_names::kIfRange) ||
          http_header_fields_.Contains(http_names::kIfUnmodifiedSince));
}

void ResourceRequestHead::SetHasUserGesture(bool has_user_gesture) {
  has_user_gesture_ |= has_user_gesture;
}

void ResourceRequestHead::SetHasTextFragmentToken(
    bool has_text_fragment_token) {
  has_text_fragment_token_ = has_text_fragment_token;
}

bool ResourceRequestHead::CanDisplay(const KURL& url) const {
  if (RequestorOrigin()->CanDisplay(url))
    return true;

  if (IsolatedWorldOrigin() && IsolatedWorldOrigin()->CanDisplay(url))
    return true;

  return false;
}

const CacheControlHeader& ResourceRequestHead::GetCacheControlHeader() const {
  if (!cache_control_header_cache_.parsed) {
    cache_control_header_cache_ = ParseCacheControlDirectives(
        http_header_fields_.Get(http_names::kCacheControl),
        http_header_fields_.Get(http_names::kPragma));
  }
  return cache_control_header_cache_;
}

bool ResourceRequestHead::CacheControlContainsNoCache() const {
  return GetCacheControlHeader().contains_no_cache;
}

bool ResourceRequestHead::CacheControlContainsNoStore() const {
  return GetCacheControlHeader().contains_no_store;
}

bool ResourceRequestHead::HasCacheValidatorFields() const {
  return !http_header_fields_.Get(http_names::kLastModified).empty() ||
         !http_header_fields_.Get(http_names::kETag).empty();
}

bool ResourceRequestHead::NeedsHTTPOrigin() const {
  if (!HttpOrigin().empty())
    return false;  // Request already has an Origin header.

  // Don't send an Origin header for GET or HEAD to avoid privacy issues.
  // For example, if an intranet page has a hyperlink to an external web
  // site, we don't want to include the Origin of the request because it
  // will leak the internal host name. Similar privacy concerns have lead
  // to the widespread suppression of the Referer header at the network
  // layer.
  if (HttpMethod() == http_names::kGET || HttpMethod() == http_names::kHEAD)
    return false;

  // For non-GET and non-HEAD methods, always send an Origin header so the
  // server knows we support this feature.
  return true;
}

bool ResourceRequest::IsFeatureEnabledForSubresourceRequestAssumingOptIn(
    const PermissionsPolicy* policy,
    mojom::blink::PermissionsPolicyFeature feature,
    const url::Origin& origin) {
  if (!policy) {
    return false;
  }

  bool browsing_topics_opted_in =
      (feature == mojom::blink::PermissionsPolicyFeature::kBrowsingTopics ||
       feature == mojom::blink::PermissionsPolicyFeature::
                      kBrowsingTopicsBackwardCompatible) &&
      GetBrowsingTopics();
  bool shared_storage_opted_in =
      feature == mojom::blink::PermissionsPolicyFeature::kSharedStorage &&
      GetSharedStorageWritableOptedIn();

  if (!browsing_topics_opted_in && !shared_storage_opted_in) {
    return false;
  }

  return policy->IsFeatureEnabledForSubresourceRequestAssumingOptIn(feature,
                                                                    origin);
}

}  // namespace blink

"""

```