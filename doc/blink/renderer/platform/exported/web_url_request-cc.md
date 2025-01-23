Response:
Let's break down the thought process for analyzing the `web_url_request.cc` file and generating the comprehensive response.

**1. Understanding the Goal:**

The primary goal is to understand the *purpose* of this file within the Chromium Blink rendering engine. We need to identify its main functionalities and how it interacts with other parts of the browser, especially JavaScript, HTML, and CSS. We also need to think about potential user and programmer errors related to its use.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for prominent keywords and patterns. This gives a high-level overview. Some immediate observations:

* **`WebURLRequest`:**  The class name itself is a huge clue. It strongly suggests handling URL requests within the web rendering process.
* **`ResourceRequest`:** This appears frequently, often in a one-to-one relationship with `WebURLRequest`. This suggests `WebURLRequest` might be a higher-level, "exported" (as the directory name suggests) interface over the internal `ResourceRequest`.
* **`SetUrl`, `HttpMethod`, `HttpHeaderField`, `HttpBody`, etc.:** These methods clearly indicate the ability to configure the properties of an HTTP request.
* **`Priority`, `CacheMode`, `CredentialsMode`, `ReferrerPolicy`, etc.:**  These suggest fine-grained control over how the request is made and handled.
* **`WebString`, `WebURL`, `WebSecurityOrigin`, `WebHTTPBody`, `WebHTTPHeaderVisitor`:** The "Web" prefix indicates these are Blink's platform-agnostic representations of web-related concepts.
* **`mojom::FetchCacheMode`, `network::mojom::RequestMode`, etc.:** The "mojom" namespace points to Mojo interfaces, hinting at communication between different processes (likely the renderer and the network service).
* **`// This is complementary to ConvertRequestPriorityToResourceLoadPriority...`:**  Comments like this are gold. They explicitly state relationships with other parts of the codebase.
* **Copyright notice:** Indicates Google's involvement and the open-source nature.
* **Include statements:**  Show dependencies on other Blink components and external libraries (like `net`).

**3. Deeper Dive and Function Grouping:**

After the initial scan, the next step is to examine the methods in more detail and group them by functionality:

* **Core Request Properties:**  `SetUrl`, `HttpMethod`, `SetHttpMethod`, `HttpContentType`, `IsFormSubmission`. These are fundamental to any HTTP request.
* **Headers:** `SetHttpHeaderField`, `AddHttpHeaderField`, `ClearHttpHeaderField`, `VisitHttpHeaderFields`. These manipulate HTTP headers.
* **Body:** `HttpBody`, `SetHttpBody`. Handles the request body.
* **Request Context and Mode:** `GetRequestContext`, `SetRequestContext`, `GetRequestDestination`, `SetRequestDestination`, `GetMode`, `SetMode`. These relate to the *type* of request being made (e.g., for an image, a script, a navigation).
* **Caching:** `GetCacheMode`, `SetCacheMode`. Controls how the browser's cache is used.
* **Security and Origin:** `SetSiteForCookies`, `SetTopFrameOrigin`, `SetRequestorOrigin`, `SetHttpOriginIfNeeded`, `GetCredentialsMode`, `SetCredentialsMode`. Crucial for web security.
* **Referrer Policy:** `SetReferrerString`, `SetReferrerPolicy`, `ReferrerString`, `GetReferrerPolicy`. Controls how the referrer is sent.
* **User Interaction:** `HasUserGesture`, `SetHasUserGesture`. Indicates if the request was initiated by a user action.
* **Service Workers:** `GetSkipServiceWorker`, `SetSkipServiceWorker`. Allows bypassing service workers.
* **Priority:** `GetPriority`, `SetPriority`. Influences the order in which requests are processed.
* **Prefetching:**  Mentions of `LOAD_PREFETCH`, `PrefetchMaybeForTopLevelNavigation`, `is_for_no_state_prefetch`.
* **Trust Tokens and Web Bundles:**  `TrustTokenParams`, `WebBundleUrl`, `WebBundleToken`. These are more advanced features.
* **Internal Conversion:** `ConvertToNetPriority`, `ToMutableResourceRequest`, `ToResourceRequest`, `GetLoadFlagsForWebUrlRequest`. These deal with converting the `WebURLRequest` into its underlying representations or flags used by the network stack.

**4. Identifying Relationships with JavaScript, HTML, and CSS:**

Now, the key is to connect the functionalities of `WebURLRequest` to how these web technologies operate:

* **JavaScript:** The primary way JavaScript interacts with `WebURLRequest` is through the Fetch API and XMLHttpRequest. Every `fetch()` call and `XMLHttpRequest` object ultimately uses something like `WebURLRequest` under the hood. Examples include: fetching data with `fetch('/api/data')`, submitting forms using `XMLHttpRequest`, or loading scripts/images dynamically.
* **HTML:**  HTML elements trigger URL requests. `<img>` tags, `<link>` tags for CSS, `<script>` tags, `<a>` tags, and `<form>` submissions all lead to the creation of `WebURLRequest` objects internally.
* **CSS:**  CSS can trigger requests for external stylesheets (`<link rel="stylesheet">`) and for resources referenced within stylesheets (e.g., `url()` in `background-image`).

**5. Constructing Examples and Logical Reasoning:**

For each connection to JavaScript, HTML, and CSS, concrete examples are essential. This clarifies the relationship. The logical reasoning involves thinking about the steps involved when a browser fetches a resource:

1. The browser encounters an HTML tag or JavaScript code that requires a resource.
2. A `WebURLRequest` object is created and configured.
3. The `WebURLRequest` (or its underlying `ResourceRequest`) is passed to the network stack.
4. The network stack fetches the resource.
5. The response is handled by the browser.

**6. Identifying User and Programmer Errors:**

Think about common mistakes developers make when dealing with web requests:

* **Incorrect URLs:**  Typos, wrong paths.
* **Missing/Incorrect Headers:**  CORS errors, authentication failures.
* **Incorrect HTTP Methods:** Using GET when POST is required, or vice-versa.
* **Cache-related issues:**  Not understanding or correctly using cache control headers.
* **Security vulnerabilities:**  Not setting proper referrer policies or handling credentials correctly.
* **Misunderstanding Asynchronous Operations:**  Trying to access data from a request before it has completed.

**7. Structuring the Response:**

Finally, organize the information clearly and logically, using headings and bullet points for readability. Address each part of the prompt (functionality, relationships, examples, logical reasoning, common errors).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just creates URL requests."  **Correction:** It's more about *configuring* and *representing* URL requests in a way that Blink understands before they are sent to the network layer.
* **Focusing too much on low-level details:**  **Correction:** Keep the focus on the *purpose* and the high-level interaction with web technologies.
* **Not enough concrete examples:** **Correction:**  Add specific code snippets to illustrate the connections.
* **Overlapping functionalities:** **Correction:** Group related methods logically to avoid repetition.

By following these steps, combining code analysis with an understanding of web development principles, and iteratively refining the analysis, we arrive at a comprehensive and accurate description of the `web_url_request.cc` file's role.
这是 `blink/renderer/platform/exported/web_url_request.cc` 文件的功能分析：

**主要功能：**

`WebURLRequest` 类是 Blink 渲染引擎中用于表示和配置 **URL 请求** 的核心类。它提供了一个平台无关的接口，供 Blink 的其他组件（例如网络加载器、Fetch API 实现等）使用，来描述需要发起的网络请求的各种属性。  可以将它看作是一个蓝图或配置对象，定义了如何发起一个 HTTP(S) 请求。

**具体功能点：**

1. **URL 管理:**
   - 存储和管理请求的 URL (`SetUrl`, `Url`).
   - 允许设置用于 Cookie 的站点 (`SetSiteForCookies`, `SiteForCookies`).

2. **HTTP 方法:**
   - 设置和获取 HTTP 请求方法 (GET, POST, PUT, DELETE 等) (`SetHttpMethod`, `HttpMethod`).

3. **HTTP 头部:**
   - 设置、添加、清除和访问 HTTP 请求头 (`SetHttpHeaderField`, `AddHttpHeaderField`, `ClearHttpHeaderField`, `VisitHttpHeaderFields`).

4. **HTTP 请求体 (Body):**
   - 设置和获取请求体数据 (`SetHttpBody`, `HttpBody`)，通常用于 POST 或 PUT 请求。

5. **缓存控制:**
   - 设置请求的缓存模式 (`SetCacheMode`, `GetCacheMode`)，例如是否使用缓存、强制刷新缓存等。

6. **超时设置:**
   - 获取请求的超时时间间隔 (`TimeoutInterval`).

7. **Referrer 控制:**
   - 设置 Referrer URL 字符串和策略 (`SetReferrerString`, `SetReferrerPolicy`, `ReferrerString`, `GetReferrerPolicy`).

8. **Origin 信息:**
   - 设置和获取请求的发起者 Origin (`SetRequestorOrigin`, `RequestorOrigin`).
   - 设置 Top Frame 的 Origin (`SetTopFrameOrigin`, `TopFrameOrigin`).
   - 设置 Isolated World 的 Origin (`IsolatedWorldOrigin`).
   - 根据需要设置 `Origin` HTTP 头 (`SetHttpOriginIfNeeded`).

9. **用户手势:**
   - 标记请求是否由用户手势触发 (`SetHasUserGesture`, `HasUserGesture`).

10. **请求上下文和目标:**
   - 设置和获取请求的上下文类型 (例如 `Document`, `Image`, `Script`) (`SetRequestContext`, `GetRequestContext`).
   - 设置和获取请求的目标类型 (例如 `Document`, `Image`, `Font`) (`SetRequestDestination`, `GetRequestDestination`).

11. **流式响应:**
   - 设置是否希望使用流式响应 (`SetUseStreamOnResponse`, `UseStreamOnResponse`).

12. **Keep-Alive:**
   - 设置是否使用 Keep-Alive 连接 (`SetKeepalive`, `GetKeepalive`).

13. **Service Worker:**
   - 设置是否跳过 Service Worker (`SetSkipServiceWorker`, `GetSkipServiceWorker`).

14. **请求模式 (Mode):**
   - 设置请求的模式 (例如 `cors`, `no-cors`, `same-origin`) (`SetMode`, `GetMode`).

15. **凭据模式 (Credentials Mode):**
   - 设置请求的凭据模式 (例如 `omit`, `same-origin`, `include`) (`SetCredentialsMode`, `GetCredentialsMode`).

16. **重定向模式 (Redirect Mode):**
   - 设置请求的重定向模式 (例如 `follow`, `error`, `manual`) (`SetRedirectMode`, `GetRedirectMode`).

17. **额外数据:**
   - 关联额外的请求数据 (`SetURLRequestExtraData`, `GetURLRequestExtraData`).

18. **下载到网络缓存:**
   - 设置是否仅下载到网络缓存 (`SetDownloadToNetworkCacheOnly`, `IsDownloadToNetworkCacheOnly`).

19. **优先级:**
   - 设置和获取请求的优先级 (`SetPriority`, `GetPriority`).

20. **CORS 预检策略:**
   - 获取 CORS 预检策略 (`GetCorsPreflightPolicy`).

21. **建议的文件名:**
   - 获取服务器建议的文件名 (`GetSuggestedFilename`).

22. **广告资源标记:**
   - 标记请求是否为广告资源 (`IsAdResource`).

23. **不安全链接升级:**
   - 设置是否升级不安全的链接 (`SetUpgradeIfInsecure`, `UpgradeIfInsecure`).

24. **异步再验证支持:**
   - 查询是否支持异步再验证 (`SupportsAsyncRevalidation`, `IsRevalidating`).

25. **开发者工具令牌:**
   - 获取与请求关联的开发者工具令牌 (`GetDevToolsToken`).

26. **`Requested-With` 头部:**
   - 设置和获取 `Requested-With` 头部 (`SetRequestedWithHeader`, `GetRequestedWithHeader`).

27. **`Purpose` 头部:**
   - 获取 `Purpose` 头部 (`GetPurposeHeader`).

28. **Fetch Window ID:**
   - 设置和获取 Fetch Window 的 ID (`SetFetchWindowId`, `GetFetchWindowId`).

29. **Load Flags:**
   - 根据 `WebURLRequest` 的属性生成用于 `net::URLRequest` 的加载标志 (`GetLoadFlagsForWebUrlRequest`).

30. **转换为内部表示:**
   - 提供访问内部 `ResourceRequest` 对象的方法 (`ToMutableResourceRequest`, `ToResourceRequest`).

31. **开发者工具 ID:**
   - 获取开发者工具 ID (`GetDevToolsId`).

32. **Origin-Dirty 样式表:**
   - 标记请求是否来自 Origin-Dirty 的样式表 (`IsFromOriginDirtyStyleSheet`).

33. **递归预取令牌:**
   - 获取递归预取令牌 (`RecursivePrefetchToken`).

34. **Trust Token 参数:**
   - 获取 Trust Token 参数 (`TrustTokenParams`).

35. **Web Bundle 相关:**
   - 获取 Web Bundle 的 URL 和 Token (`WebBundleUrl`, `WebBundleToken`).

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`WebURLRequest` 是 Blink 引擎处理所有网络请求的基础，因此与 JavaScript, HTML, CSS 的功能息息相关。

**JavaScript:**

- **Fetch API:** 当 JavaScript 代码使用 `fetch()` API 发起网络请求时，Blink 内部会创建一个 `WebURLRequest` 对象来配置这个请求。
  ```javascript
  fetch('https://example.com/data.json', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json'
    },
    cache: 'no-store'
  }).then(response => response.json());
  ```
  在这个例子中，`method`, `headers`, `cache` 等选项会被转换为 `WebURLRequest` 对象的相应设置。

- **XMLHttpRequest (XHR):**  类似于 Fetch API，当使用 `XMLHttpRequest` 对象发起请求时，也会使用 `WebURLRequest`。
  ```javascript
  const xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://example.com/submit');
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.send('name=John&age=30');
  ```
  `open()` 方法对应设置 URL 和 HTTP 方法，`setRequestHeader()` 设置 HTTP 头部，`send()` 方法结合请求体信息来配置 `WebURLRequest`。

**HTML:**

- **`<link>` 标签加载 CSS:** 当浏览器解析到 `<link rel="stylesheet" href="style.css">` 时，会创建一个 `WebURLRequest` 来请求 `style.css` 文件。请求的 URL、优先级等信息都会在 `WebURLRequest` 中设置。

- **`<img>` 标签加载图片:**  `<img src="image.png">` 会触发一个 `WebURLRequest` 来获取图片资源。

- **`<script>` 标签加载 JavaScript 文件:**  `<script src="script.js"></script>` 同样会创建一个 `WebURLRequest`。

- **`<a>` 标签导航:** 点击 `<a href="newpage.html">` 链接会创建一个 `WebURLRequest` 来请求新的页面。

- **`<form>` 提交:**  当用户提交 HTML 表单时，浏览器会创建一个 `WebURLRequest`，根据表单的 `method` 和 `action` 属性以及表单数据来配置请求。

**CSS:**

- **`url()` 函数引用资源:** 在 CSS 中使用 `background-image: url('image.png')` 或 `@import 'style.css'` 时，浏览器会创建 `WebURLRequest` 来加载这些资源。

**逻辑推理及假设输入与输出：**

假设输入一个 `WebURLRequest` 对象，并设置了一些属性：

**假设输入:**

```c++
WebURLRequest request(WebURL::FromString("https://api.example.com/users"));
request.SetHttpMethod("POST");
request.AddHttpHeaderField("Authorization", "Bearer my_token");
WebHTTPBody body;
body.Append("{\"name\": \"New User\"}");
request.SetHttpBody(body);
request.SetCacheMode(blink::mojom::FetchCacheMode::kNoStore);
```

**逻辑推理:**

当 Blink 引擎需要发起这个请求时，会读取 `WebURLRequest` 对象中的信息，并将其转换为底层的网络请求操作。`GetLoadFlagsForWebUrlRequest()` 方法会根据 `GetCacheMode()` 的返回值生成相应的 `net::LOAD_DISABLE_CACHE` 加载标志，指示网络层不要使用缓存。

**可能的输出 (在网络层):**

- 请求方法: `POST`
- 请求 URL: `https://api.example.com/users`
- 请求头:
  - `Authorization: Bearer my_token`
  - 其他浏览器默认头部...
- 请求体: `{"name": "New User"}`
- 加载标志中包含 `net::LOAD_DISABLE_CACHE`

**用户或编程常见的使用错误举例说明：**

1. **忘记设置请求方法:**  如果创建一个 `WebURLRequest` 对象，但没有调用 `SetHttpMethod()`，那么请求方法可能默认为 "GET"，导致 POST 请求失败或行为不符合预期。

   ```c++
   WebURLRequest request(WebURL::FromString("/submit"));
   // 忘记设置 request.SetHttpMethod("POST");
   // ... 设置请求体 ...
   ```

2. **错误设置 Content-Type 头部:**  对于包含请求体的 POST 或 PUT 请求，必须正确设置 `Content-Type` 头部，服务端才能正确解析请求体。如果 `Content-Type` 与请求体格式不匹配，会导致服务端解析错误。

   ```c++
   WebURLRequest request(WebURL::FromString("/data"));
   request.SetHttpMethod("POST");
   WebHTTPBody body;
   body.Append("name=value"); // 假设要发送 form data
   request.SetHttpBody(body);
   // 错误地设置 Content-Type
   request.SetHttpHeaderField("Content-Type", "application/json");
   ```

3. **在不应该设置的情况下设置了某些头部:**  例如，尝试手动设置 `Content-Length` 头部通常是不必要的，因为 Blink 会根据请求体自动计算。手动设置可能会导致不一致。

4. **混淆 `SetHttpHeaderField` 和 `AddHttpHeaderField`:**  `SetHttpHeaderField` 会覆盖已存在的同名头部，而 `AddHttpHeaderField` 会添加新的同名头部。错误地使用可能导致头部信息丢失或重复。

5. **不理解缓存模式的影响:**  错误地设置 `CacheMode` 可能导致非预期的缓存行为，例如应该从网络获取最新数据的请求使用了缓存，或者不应该缓存的数据被缓存了。

6. **Referrer Policy 设置不当:**  错误的 Referrer Policy 设置可能导致安全问题或功能失效，例如某些网站依赖 Referrer 信息进行统计或安全验证。

7. **在需要用户手势的场景下发起没有用户手势的请求:** 某些浏览器功能或 API 可能要求请求必须由用户手势触发。如果没有正确设置 `SetHasUserGesture(true)`，请求可能会被阻止。

总而言之，`WebURLRequest` 类是 Blink 引擎中构建和配置网络请求的关键，理解其各种属性和方法对于理解浏览器如何发起和处理网络请求至关重要。正确使用 `WebURLRequest` 可以避免很多常见的网络请求错误。

### 提示词
```
这是目录为blink/renderer/platform/exported/web_url_request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#include "third_party/blink/public/platform/web_url_request.h"

#include <memory>

#include "base/time/time.h"
#include "net/base/load_flags.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/optional_trust_token_params.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/url_conversion.h"
#include "third_party/blink/public/platform/web_http_body.h"
#include "third_party/blink/public/platform/web_http_header_visitor.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/trust_token_params_conversion.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"

using blink::mojom::FetchCacheMode;

namespace blink {

// This is complementary to ConvertRequestPriorityToResourceLoadPriority,
// defined in third_party/blink/renderer/core/fetch/fetch_request_data.cc.
net::RequestPriority WebURLRequest::ConvertToNetPriority(
    WebURLRequest::Priority priority) {
  switch (priority) {
    case WebURLRequest::Priority::kVeryHigh:
      return net::HIGHEST;

    case WebURLRequest::Priority::kHigh:
      return net::MEDIUM;

    case WebURLRequest::Priority::kMedium:
      return net::LOW;

    case WebURLRequest::Priority::kLow:
      return net::LOWEST;

    case WebURLRequest::Priority::kVeryLow:
      return net::IDLE;

    case WebURLRequest::Priority::kUnresolved:
    default:
      NOTREACHED();
  }
}

WebURLRequest::~WebURLRequest() = default;

WebURLRequest::WebURLRequest()
    : owned_resource_request_(std::make_unique<ResourceRequest>()),
      resource_request_(owned_resource_request_.get()) {}

WebURLRequest::WebURLRequest(WebURLRequest&& src) {
  *this = std::move(src);
}

WebURLRequest& WebURLRequest::operator=(WebURLRequest&& src) {
  if (this == &src) {
    return *this;
  }
  if (src.owned_resource_request_) {
    owned_resource_request_ = std::move(src.owned_resource_request_);
    resource_request_ = owned_resource_request_.get();
  } else {
    owned_resource_request_ = std::make_unique<ResourceRequest>();
    resource_request_ = owned_resource_request_.get();
    CopyFrom(src);
  }
  src.resource_request_ = nullptr;
  return *this;
}

WebURLRequest::WebURLRequest(const WebURL& url) : WebURLRequest() {
  SetUrl(url);
}

void WebURLRequest::CopyFrom(const WebURLRequest& r) {
  // Copying subclasses that have different m_resourceRequest ownership
  // semantics via this operator is just not supported.
  DCHECK(owned_resource_request_);
  DCHECK_EQ(owned_resource_request_.get(), resource_request_);
  DCHECK(owned_resource_request_->IsNull());
  DCHECK(this != &r);
  resource_request_->CopyHeadFrom(*r.resource_request_);
  resource_request_->SetHttpBody(r.resource_request_->HttpBody());
}

bool WebURLRequest::IsNull() const {
  return resource_request_->IsNull();
}

WebURL WebURLRequest::Url() const {
  return resource_request_->Url();
}

void WebURLRequest::SetUrl(const WebURL& url) {
  resource_request_->SetUrl(url);
}

const net::SiteForCookies& WebURLRequest::SiteForCookies() const {
  return resource_request_->SiteForCookies();
}

void WebURLRequest::SetSiteForCookies(
    const net::SiteForCookies& site_for_cookies) {
  resource_request_->SetSiteForCookies(site_for_cookies);
}

std::optional<WebSecurityOrigin> WebURLRequest::TopFrameOrigin() const {
  const SecurityOrigin* origin = resource_request_->TopFrameOrigin();
  return origin ? std::optional<WebSecurityOrigin>(origin)
                : std::optional<WebSecurityOrigin>();
}

void WebURLRequest::SetTopFrameOrigin(const WebSecurityOrigin& origin) {
  resource_request_->SetTopFrameOrigin(origin);
}

WebSecurityOrigin WebURLRequest::RequestorOrigin() const {
  return resource_request_->RequestorOrigin();
}

WebSecurityOrigin WebURLRequest::IsolatedWorldOrigin() const {
  return resource_request_->IsolatedWorldOrigin();
}

void WebURLRequest::SetRequestorOrigin(
    const WebSecurityOrigin& requestor_origin) {
  resource_request_->SetRequestorOrigin(requestor_origin);
}

mojom::FetchCacheMode WebURLRequest::GetCacheMode() const {
  return resource_request_->GetCacheMode();
}

void WebURLRequest::SetCacheMode(mojom::FetchCacheMode cache_mode) {
  resource_request_->SetCacheMode(cache_mode);
}

base::TimeDelta WebURLRequest::TimeoutInterval() const {
  return resource_request_->TimeoutInterval();
}

WebString WebURLRequest::HttpMethod() const {
  return resource_request_->HttpMethod();
}

void WebURLRequest::SetHttpMethod(const WebString& http_method) {
  resource_request_->SetHttpMethod(http_method);
}

WebString WebURLRequest::HttpContentType() const {
  return resource_request_->HttpContentType();
}

bool WebURLRequest::IsFormSubmission() const {
  return resource_request_->IsFormSubmission();
}

WebString WebURLRequest::HttpHeaderField(const WebString& name) const {
  return resource_request_->HttpHeaderField(name);
}

void WebURLRequest::SetHttpHeaderField(const WebString& name,
                                       const WebString& value) {
  CHECK(!EqualIgnoringASCIICase(name, "referer"));
  resource_request_->SetHttpHeaderField(name, value);
}

void WebURLRequest::AddHttpHeaderField(const WebString& name,
                                       const WebString& value) {
  resource_request_->AddHttpHeaderField(name, value);
}

void WebURLRequest::ClearHttpHeaderField(const WebString& name) {
  resource_request_->ClearHttpHeaderField(name);
}

void WebURLRequest::VisitHttpHeaderFields(WebHTTPHeaderVisitor* visitor) const {
  const HTTPHeaderMap& map = resource_request_->HttpHeaderFields();
  for (HTTPHeaderMap::const_iterator it = map.begin(); it != map.end(); ++it)
    visitor->VisitHeader(it->key, it->value);
}

WebHTTPBody WebURLRequest::HttpBody() const {
  return WebHTTPBody(resource_request_->HttpBody());
}

void WebURLRequest::SetHttpBody(const WebHTTPBody& http_body) {
  resource_request_->SetHttpBody(http_body);
}

bool WebURLRequest::ReportUploadProgress() const {
  return resource_request_->ReportUploadProgress();
}

void WebURLRequest::SetReportUploadProgress(bool report_upload_progress) {
  resource_request_->SetReportUploadProgress(report_upload_progress);
}

mojom::blink::RequestContextType WebURLRequest::GetRequestContext() const {
  return resource_request_->GetRequestContext();
}

network::mojom::RequestDestination WebURLRequest::GetRequestDestination()
    const {
  return resource_request_->GetRequestDestination();
}

void WebURLRequest::SetReferrerString(const WebString& referrer) {
  resource_request_->SetReferrerString(referrer);
}

void WebURLRequest::SetReferrerPolicy(
    network::mojom::ReferrerPolicy referrer_policy) {
  resource_request_->SetReferrerPolicy(referrer_policy);
}

WebString WebURLRequest::ReferrerString() const {
  return resource_request_->ReferrerString();
}

network::mojom::ReferrerPolicy WebURLRequest::GetReferrerPolicy() const {
  return resource_request_->GetReferrerPolicy();
}

void WebURLRequest::SetHttpOriginIfNeeded(const WebSecurityOrigin& origin) {
  resource_request_->SetHttpOriginIfNeeded(origin.Get());
}

bool WebURLRequest::HasUserGesture() const {
  return resource_request_->HasUserGesture();
}

bool WebURLRequest::HasTextFragmentToken() const {
  return resource_request_->HasTextFragmentToken();
}

void WebURLRequest::SetHasUserGesture(bool has_user_gesture) {
  resource_request_->SetHasUserGesture(has_user_gesture);
}

void WebURLRequest::SetRequestContext(
    mojom::blink::RequestContextType request_context) {
  resource_request_->SetRequestContext(request_context);
}

void WebURLRequest::SetRequestDestination(
    network::mojom::RequestDestination destination) {
  resource_request_->SetRequestDestination(destination);
}

bool WebURLRequest::UseStreamOnResponse() const {
  return resource_request_->UseStreamOnResponse();
}

void WebURLRequest::SetUseStreamOnResponse(bool use_stream_on_response) {
  resource_request_->SetUseStreamOnResponse(use_stream_on_response);
}

bool WebURLRequest::GetKeepalive() const {
  return resource_request_->GetKeepalive();
}

void WebURLRequest::SetKeepalive(bool keepalive) {
  resource_request_->SetKeepalive(keepalive);
}

bool WebURLRequest::GetSkipServiceWorker() const {
  return resource_request_->GetSkipServiceWorker();
}

void WebURLRequest::SetSkipServiceWorker(bool skip_service_worker) {
  resource_request_->SetSkipServiceWorker(skip_service_worker);
}

network::mojom::RequestMode WebURLRequest::GetMode() const {
  return resource_request_->GetMode();
}

void WebURLRequest::SetMode(network::mojom::RequestMode mode) {
  return resource_request_->SetMode(mode);
}

bool WebURLRequest::GetFavicon() const {
  return resource_request_->IsFavicon();
}

void WebURLRequest::SetFavicon(bool) {
  resource_request_->SetFavicon(true);
}

network::mojom::CredentialsMode WebURLRequest::GetCredentialsMode() const {
  return resource_request_->GetCredentialsMode();
}

void WebURLRequest::SetCredentialsMode(network::mojom::CredentialsMode mode) {
  return resource_request_->SetCredentialsMode(mode);
}

network::mojom::RedirectMode WebURLRequest::GetRedirectMode() const {
  return resource_request_->GetRedirectMode();
}

void WebURLRequest::SetRedirectMode(network::mojom::RedirectMode redirect) {
  return resource_request_->SetRedirectMode(redirect);
}

const scoped_refptr<WebURLRequestExtraData>&
WebURLRequest::GetURLRequestExtraData() const {
  return resource_request_->GetURLRequestExtraData();
}

void WebURLRequest::SetURLRequestExtraData(
    scoped_refptr<WebURLRequestExtraData> extra_data) {
  resource_request_->SetURLRequestExtraData(std::move(extra_data));
}

bool WebURLRequest::IsDownloadToNetworkCacheOnly() const {
  return resource_request_->IsDownloadToNetworkCacheOnly();
}

void WebURLRequest::SetDownloadToNetworkCacheOnly(bool download_to_cache_only) {
  resource_request_->SetDownloadToNetworkCacheOnly(download_to_cache_only);
}

ResourceRequest& WebURLRequest::ToMutableResourceRequest() {
  DCHECK(resource_request_);
  return *resource_request_;
}

WebURLRequest::Priority WebURLRequest::GetPriority() const {
  return static_cast<WebURLRequest::Priority>(resource_request_->Priority());
}

void WebURLRequest::SetPriority(WebURLRequest::Priority priority) {
  resource_request_->SetPriority(static_cast<ResourceLoadPriority>(priority));
}

network::mojom::CorsPreflightPolicy WebURLRequest::GetCorsPreflightPolicy()
    const {
  return resource_request_->CorsPreflightPolicy();
}

std::optional<WebString> WebURLRequest::GetSuggestedFilename() const {
  if (!resource_request_->GetSuggestedFilename().has_value())
    return std::optional<WebString>();
  return static_cast<WebString>(
      resource_request_->GetSuggestedFilename().value());
}

bool WebURLRequest::IsAdResource() const {
  return resource_request_->IsAdResource();
}

void WebURLRequest::SetUpgradeIfInsecure(bool upgrade_if_insecure) {
  resource_request_->SetUpgradeIfInsecure(upgrade_if_insecure);
}

bool WebURLRequest::UpgradeIfInsecure() const {
  return resource_request_->UpgradeIfInsecure();
}

bool WebURLRequest::SupportsAsyncRevalidation() const {
  return resource_request_->AllowsStaleResponse();
}

bool WebURLRequest::IsRevalidating() const {
  return resource_request_->IsRevalidating();
}

const std::optional<base::UnguessableToken>& WebURLRequest::GetDevToolsToken()
    const {
  return resource_request_->GetDevToolsToken();
}

const WebString WebURLRequest::GetRequestedWithHeader() const {
  return resource_request_->GetRequestedWithHeader();
}

void WebURLRequest::SetRequestedWithHeader(const WebString& value) {
  resource_request_->SetRequestedWithHeader(value);
}

const WebString WebURLRequest::GetPurposeHeader() const {
  return resource_request_->GetPurposeHeader();
}

const base::UnguessableToken& WebURLRequest::GetFetchWindowId() const {
  return resource_request_->GetFetchWindowId();
}
void WebURLRequest::SetFetchWindowId(const base::UnguessableToken& id) {
  resource_request_->SetFetchWindowId(id);
}

int WebURLRequest::GetLoadFlagsForWebUrlRequest() const {
  int load_flags = net::LOAD_NORMAL;

  switch (resource_request_->GetCacheMode()) {
    case FetchCacheMode::kNoStore:
      load_flags |= net::LOAD_DISABLE_CACHE;
      break;
    case FetchCacheMode::kValidateCache:
      load_flags |= net::LOAD_VALIDATE_CACHE;
      break;
    case FetchCacheMode::kBypassCache:
      load_flags |= net::LOAD_BYPASS_CACHE;
      break;
    case FetchCacheMode::kForceCache:
      load_flags |= net::LOAD_SKIP_CACHE_VALIDATION;
      break;
    case FetchCacheMode::kOnlyIfCached:
      load_flags |= net::LOAD_ONLY_FROM_CACHE | net::LOAD_SKIP_CACHE_VALIDATION;
      break;
    case FetchCacheMode::kUnspecifiedOnlyIfCachedStrict:
      load_flags |= net::LOAD_ONLY_FROM_CACHE;
      break;
    case FetchCacheMode::kDefault:
      break;
    case FetchCacheMode::kUnspecifiedForceCacheMiss:
      load_flags |= net::LOAD_ONLY_FROM_CACHE | net::LOAD_BYPASS_CACHE;
      break;
  }

  if (resource_request_->GetRequestContext() ==
      blink::mojom::blink::RequestContextType::PREFETCH)
    load_flags |= net::LOAD_PREFETCH;

  if (resource_request_->GetURLRequestExtraData()) {
    if (resource_request_->GetURLRequestExtraData()->is_for_no_state_prefetch())
      load_flags |= net::LOAD_PREFETCH;
  }
  if (resource_request_->AllowsStaleResponse()) {
    load_flags |= net::LOAD_SUPPORT_ASYNC_REVALIDATION;
  }
  if (resource_request_->PrefetchMaybeForTopLevelNavigation()) {
    CHECK_EQ(resource_request_->GetRequestContext(),
             blink::mojom::blink::RequestContextType::PREFETCH);
    if (!resource_request_->RequestorOrigin()->IsSameOriginWith(
            SecurityOrigin::Create(resource_request_->Url()).get())) {
      load_flags |= net::LOAD_RESTRICTED_PREFETCH_FOR_MAIN_FRAME;
    }
  }

  return load_flags;
}

const ResourceRequest& WebURLRequest::ToResourceRequest() const {
  DCHECK(resource_request_);
  return *resource_request_;
}

std::optional<WebString> WebURLRequest::GetDevToolsId() const {
  return resource_request_->GetDevToolsId();
}

bool WebURLRequest::IsFromOriginDirtyStyleSheet() const {
  return resource_request_->IsFromOriginDirtyStyleSheet();
}

std::optional<base::UnguessableToken> WebURLRequest::RecursivePrefetchToken()
    const {
  return resource_request_->RecursivePrefetchToken();
}

network::OptionalTrustTokenParams WebURLRequest::TrustTokenParams() const {
  return ConvertTrustTokenParams(resource_request_->TrustTokenParams());
}

std::optional<WebURL> WebURLRequest::WebBundleUrl() const {
  if (resource_request_->GetWebBundleTokenParams()) {
    return resource_request_->GetWebBundleTokenParams()->bundle_url;
  }
  return std::nullopt;
}

std::optional<base::UnguessableToken> WebURLRequest::WebBundleToken() const {
  if (resource_request_->GetWebBundleTokenParams()) {
    return resource_request_->GetWebBundleTokenParams()->token;
  }
  return std::nullopt;
}

WebURLRequest::WebURLRequest(ResourceRequest& r) : resource_request_(&r) {}

}  // namespace blink
```