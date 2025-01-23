Response:
Let's break down the thought process for analyzing the provided `cookie_store.cc` file.

**1. Initial Skim and Keyword Identification:**

The first step is to quickly read through the code, looking for prominent keywords and patterns. Some immediately stand out:

* `CookieStore` (obviously the central class)
* `getAll`, `get`, `set`, `delete` (common data manipulation operations)
* `CookieListItem`, `CookieInit`, `CookieStoreGetOptions`, `CookieStoreDeleteOptions` (data structures related to cookies)
* `ScriptPromise` (asynchronous operations)
* `ExecutionContext`, `LocalDOMWindow`, `ServiceWorkerGlobalScope` (different contexts where this code runs)
* `network::mojom::blink::RestrictedCookieManager` (interaction with the network layer)
* `CookieChangeEvent` (events related to cookie changes)
* `ExceptionState` (error handling)
* `ToCanonicalCookie`, `ToBackendOptions` (data conversion functions)
* `StartsWith`, `EndsWith`, `Contains` (string manipulation for validation)
* `default_cookie_url_`, `default_site_for_cookies_`, `default_top_frame_origin_` (contextual information)

**2. Core Functionality - Mapping Methods to Actions:**

Based on the method names, it's clear the core functionality revolves around:

* **Reading Cookies:** `getAll`, `get`. These methods likely fetch cookies from the underlying storage.
* **Writing Cookies:** `set`. This method is for creating or modifying cookies.
* **Deleting Cookies:** `Delete`. This removes cookies.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, the key is to understand *how* this code interacts with the web.

* **JavaScript API:** The `CookieStore` class is clearly exposed to JavaScript. The methods like `getAll`, `get`, `set`, and `delete` are the direct counterparts of the JavaScript `CookieStore` API. The `ScriptPromise` return types confirm asynchronous interactions initiated by JavaScript.

* **HTML and Context:** The presence of `LocalDOMWindow` and `ServiceWorkerGlobalScope` indicates this code operates in the context of web pages and service workers. This suggests the `CookieStore` API is accessible from both. The code references `document->CookieURL()` and `serviceWorker()->scriptURL()`, showing how the context determines the default cookie scope.

* **No Direct CSS Interaction:**  While cookies influence how a website appears (e.g., through personalized content), this specific C++ code doesn't directly manipulate CSS. The interaction is indirect – JavaScript using this API affects the cookies, which can then influence the server's response and ultimately the CSS applied.

**4. Logical Reasoning and Assumptions:**

Here's where the analysis becomes more detailed:

* **`ToBackendOptions`:**  This function takes `CookieStoreGetOptions` and converts them to a backend representation. The assumption is that the backend requires a specific format for querying cookies. The logic about `match_type` and the handling of the `name` property are important.

* **`ToCanonicalCookie`:** This function converts the `CookieInit` data (provided by JavaScript) into a `net::CanonicalCookie`. This involves significant validation. Assumptions here are:
    * The backend expects a `CanonicalCookie` object.
    * Certain cookie attributes (domain, path, secure, etc.) have specific rules that must be enforced.
    * The code explicitly handles prefixes like `__Host-`.

* **Cookie Scope and Context:** The logic in `CookieUrlForRead` demonstrates how the context (window vs. service worker) affects the permissible URLs for cookie operations. The assumption is that security and scope restrictions are crucial.

* **Asynchronous Operations:** The use of `ScriptPromise` signals asynchronous operations. The `DoRead` and `DoWrite` methods initiate actions that don't immediately return, and callbacks (`GetAllForUrlToGetAllResult`, `OnSetCanonicalCookieResult`) handle the results.

**5. Common Usage Errors and Debugging:**

By understanding the validation logic in `ToCanonicalCookie` and the context handling, we can infer common errors:

* **Invalid Cookie Attributes:** Providing incorrect domain, path, or trying to set a `__Host-` cookie with a domain or non-"/" path.
* **Setting Secure Cookies on Insecure Origins:**  The code explicitly checks for this.
* **URL Mismatches:** Trying to get cookies for a URL different from the document URL (in a window context) or outside the service worker scope.
* **Empty Options:** The `get` method requires either a name or a URL.

**6. User Actions and Debugging Trace:**

To understand how a user might reach this code, consider the typical steps involved in using the `CookieStore` API:

1. **JavaScript Code:** The user writes JavaScript code that uses `navigator.cookieStore.get()`, `navigator.cookieStore.getAll()`, `navigator.cookieStore.set()`, or `navigator.cookieStore.delete()`.
2. **Browser Invocation:** The browser's JavaScript engine executes this code.
3. **Blink Binding:** The JavaScript calls are translated into calls to the C++ `CookieStore` methods (the V8 bindings handle this).
4. **Backend Interaction:** The C++ code interacts with the `RestrictedCookieManager` (likely in the network service) to perform the actual cookie operations.
5. **Callbacks and Promises:** Asynchronous operations use promises to return results to the JavaScript.

**Debugging Trace:**

If a developer encounters an issue (e.g., a cookie not being set), they might:

1. **Set Breakpoints in JavaScript:** Inspect the arguments passed to `navigator.cookieStore.set()`.
2. **Set Breakpoints in C++:** Set breakpoints in the `CookieStore::set` method and in functions like `ToCanonicalCookie` to see the intermediate values and where validation might be failing.
3. **Network Panel:** Observe the network requests and responses, particularly the `Set-Cookie` headers.
4. **Console Logs:** Use `console.log` in JavaScript to track the flow and the results of promise resolutions.

**Self-Correction/Refinement During Analysis:**

Initially, I might have focused too much on the individual methods. Realizing the importance of the context (window vs. service worker) and the validation logic in `ToCanonicalCookie` was crucial for a deeper understanding. Also, understanding the asynchronous nature of the API and the role of `ScriptPromise` is vital. Recognizing the interaction with the network service via `RestrictedCookieManager` adds another layer to the analysis.
这个文件 `blink/renderer/modules/cookie_store/cookie_store.cc` 是 Chromium Blink 渲染引擎中实现 **Cookie Store API** 的核心代码。Cookie Store API 是一个 JavaScript API，它提供了一种更现代、更强大的方式来访问和操作 HTTP Cookies，相较于传统的 `document.cookie` API。

以下是该文件的主要功能：

**1. 实现 JavaScript Cookie Store API：**

* **`getAll()`:**  允许 JavaScript 获取当前作用域下所有匹配指定条件（如名称）的 Cookie。
* **`get()`:** 允许 JavaScript 获取当前作用域下第一个匹配指定条件（如名称）的 Cookie。
* **`set()`:** 允许 JavaScript 创建或更新 Cookie。
* **`delete()`:** 允许 JavaScript 删除 Cookie。
* **事件监听 (`change` 事件):** 提供一个事件，当 Cookie 发生变化时（添加、删除、修改），会触发该事件。

**2. 与 Chromium 网络层交互：**

* 该文件通过 `network::mojom::blink::RestrictedCookieManager` Mojo 接口与 Chromium 的网络服务进行通信，以执行实际的 Cookie 读取、写入和删除操作。
* 它负责将 JavaScript API 的请求转换为网络层能够理解的格式。

**3. Cookie 的管理和操作：**

* **Cookie 的创建和解析：**  使用 `net::CanonicalCookie::CreateSanitizedCookie` 来创建和验证 Cookie。
* **Cookie 的过滤和匹配：**  根据 JavaScript 提供的选项（如名称、URL）来过滤和匹配 Cookie。
* **SameSite 属性的处理：**  支持 `SameSite` Cookie 属性，并根据其值进行相应的处理。
* **Partitioned Cookies 的处理：** 支持 Partitioned Cookies，并处理其相关的逻辑。
* **安全性和权限控制：** 检查当前上下文是否允许访问 Cookie (例如，是否是安全上下文)。

**4. 事件处理：**

* 监听来自网络层的 Cookie 变化通知。
* 创建并分发 `CookieChangeEvent` 事件给 JavaScript，通知 Cookie 的变化。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**  `CookieStore` 类是 JavaScript `navigator.cookieStore` 对象的 C++ 实现。JavaScript 代码可以直接调用 `navigator.cookieStore` 上的 `getAll()`, `get()`, `set()`, `delete()` 方法以及监听 `change` 事件。

   ```javascript
   // JavaScript 示例
   navigator.cookieStore.getAll().then(cookies => {
     console.log("All cookies:", cookies);
   });

   navigator.cookieStore.get("myCookie").then(cookie => {
     if (cookie) {
       console.log("Value of myCookie:", cookie.value);
     } else {
       console.log("myCookie not found");
     }
   });

   navigator.cookieStore.set({
     name: "newUserCookie",
     value: "someValue",
     expires: Date.now() + 3600000, // 一小时后过期
     path: "/",
     secure: true,
     sameSite: "Strict"
   }).then(() => {
     console.log("newUserCookie set successfully");
   });

   navigator.cookieStore.addEventListener('change', event => {
     console.log("Cookie changed!", event);
   });
   ```

* **HTML:**  HTML 本身不直接与 `cookie_store.cc` 交互。但是，HTML 中加载的 JavaScript 代码可以使用 Cookie Store API 来管理 Cookie，从而影响网站的行为和内容。例如，根据 Cookie 的值来显示不同的用户界面元素。

* **CSS:** CSS 也不直接与 `cookie_store.cc` 交互。然而，JavaScript 可以使用 Cookie Store API 读取 Cookie，并根据 Cookie 的值来动态修改 HTML 元素的 CSS 类或样式，从而改变页面的外观。

   ```javascript
   // JavaScript 示例
   navigator.cookieStore.get("theme").then(cookie => {
     if (cookie && cookie.value === "dark") {
       document.body.classList.add("dark-theme");
     }
   });
   ```

**逻辑推理、假设输入与输出：**

**假设输入 (JavaScript 调用 `getAll()`):**

```javascript
navigator.cookieStore.getAll({ name: "user_id" }).then(cookies => {
  // 处理 cookies
});
```

**逻辑推理:**

1. JavaScript 调用 `navigator.cookieStore.getAll({ name: "user_id" })`。
2. Blink 的 JavaScript 引擎会将这个调用转发到 `cookie_store.cc` 的 `CookieStore::getAll()` 方法。
3. `CookieStore::getAll()` 将 `CookieStoreGetOptions` 转换为网络层需要的 `network::mojom::blink::CookieManagerGetOptionsPtr`。
4. 它会调用 `backend_->GetAllForUrl()`，向网络服务请求所有 URL 下的匹配 `name` 为 "user_id" 的 Cookie。
5. 网络服务返回匹配的 Cookie 列表。
6. `CookieStore::GetAllForUrlToGetAllResult()` 将网络层返回的 `network::mojom::blink::CookieWithAccessResultPtr` 列表转换为 JavaScript 可以理解的 `CookieListItem` 对象数组。
7. Promise resolve，JavaScript 的 `.then()` 回调函数被调用，接收到包含匹配 Cookie 的数组。

**假设输出 (如果存在名为 "user_id" 的 Cookie):**

```javascript
// cookies 变量可能包含类似以下的对象
[
  {
    "name": "user_id",
    "value": "12345",
    "domain": "example.com",
    "path": "/",
    "expires": 1678886400000, // 时间戳
    "secure": true,
    "httpOnly": false,
    "sameSite": "strict"
  }
]
```

**如果不存在名为 "user_id" 的 Cookie，输出将是一个空数组 `[]`。**

**涉及用户或编程常见的使用错误及举例说明：**

1. **尝试在不安全的上下文中使用 `set()` 修改 secure Cookie：**

   ```javascript
   // 如果当前页面不是 HTTPS
   navigator.cookieStore.set({
     name: "secureCookie",
     value: "test",
     secure: true
   }); // 这可能会失败，并抛出 TypeError
   ```

   **错误说明:**  `ToCanonicalCookie` 函数会检查当前 URL 是否是安全来源。如果尝试在一个非安全来源设置 `secure: true` 的 Cookie，会抛出 `TypeError`。

2. **设置无效的 Cookie 属性：**

   ```javascript
   navigator.cookieStore.set({
     name: "invalidDomain",
     value: "test",
     domain: ".example.com" // domain 不能以 "." 开头
   }); // 抛出 TypeError
   ```

   **错误说明:** `ToCanonicalCookie` 函数会验证 Cookie 的属性。例如，`domain` 不能以 "." 开头。如果验证失败，会抛出 `TypeError`。

3. **在 Service Worker 中尝试获取超出其作用域的 Cookie：**

   ```javascript
   // 在 Service Worker 中
   navigator.cookieStore.getAll({ url: 'https://other-domain.com' }); // 抛出 TypeError
   ```

   **错误说明:** `CookieUrlForRead` 函数会检查在 Service Worker 上下文中提供的 URL 是否在其作用域内。如果 URL 超出 Service Worker 的作用域，会抛出 `TypeError`。

4. **忘记处理 Promise 的 rejected 状态：**

   ```javascript
   navigator.cookieStore.set({ name: "test", value: "value" })
     // .then(() => { ... }) // 忘记添加 .catch() 处理错误
   ```

   **错误说明:** 虽然 `set()` 方法通常会成功，但在某些情况下（例如，存储配额已满），操作可能会失败。开发者应该始终使用 `.then()` 和 `.catch()` 来处理 Promise 的成功和失败情况。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个网页。**
2. **网页的 JavaScript 代码调用了 `navigator.cookieStore` API 的方法，例如 `set()`, `get()`, `getAll()`, 或 `delete()`。**
3. **浏览器的 JavaScript 引擎 (V8) 执行这段 JavaScript 代码。**
4. **V8 引擎会将对 `navigator.cookieStore` API 的调用桥接到 Blink 渲染引擎中对应的 C++ 代码，即 `cookie_store.cc` 文件中的 `CookieStore` 类的方法。**
5. **`CookieStore` 类的方法会：**
   * **解析 JavaScript 传递的参数 (例如，Cookie 的名称、值、选项)。**
   * **进行必要的验证 (例如，检查安全上下文，验证 Cookie 属性)。**
   * **构建与 Chromium 网络层通信的请求。**
   * **通过 `RestrictedCookieManager` Mojo 接口将请求发送到网络服务。**
6. **Chromium 的网络服务会执行实际的 Cookie 操作 (读取、写入、删除)。**
7. **网络服务将操作结果返回给 `cookie_store.cc` 中的回调函数。**
8. **回调函数会将结果转换为 JavaScript Promise 的 resolve 或 reject 状态。**
9. **JavaScript 代码中的 `.then()` 或 `.catch()` 方法会被调用，处理 Cookie 操作的结果。**

**作为调试线索：**

* 如果开发者发现 Cookie 的行为不符合预期，他们可以：
    * **在 JavaScript 代码中设置断点**，查看传递给 `navigator.cookieStore` API 的参数。
    * **在 `cookie_store.cc` 文件的关键方法中设置断点**，例如 `ToCanonicalCookie`, `DoWrite`, `DoRead`，查看 C++ 层的处理逻辑和数据。
    * **使用 Chrome 的开发者工具 (Application -> Cookies)** 查看当前页面的 Cookie 状态，确认浏览器中实际存储的 Cookie 是否与预期一致。
    * **检查控制台的错误信息**，查看是否有 `TypeError` 或其他异常抛出。
    * **使用网络面板** 查看 HTTP 请求和响应头中的 `Cookie` 和 `Set-Cookie` 头，了解浏览器发送和接收的 Cookie 信息。
    * **如果涉及到 Cookie 的跨域问题**，需要检查 SameSite 属性、Partitioned 属性以及 Storage Access API 的状态。

通过以上分析，可以更深入地理解 `cookie_store.cc` 文件的作用以及它在 Web 技术栈中的位置和交互方式。

### 提示词
```
这是目录为blink/renderer/modules/cookie_store/cookie_store.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/cookie_store/cookie_store.h"

#include <optional>
#include <utility>

#include "base/containers/contains.h"
#include "net/base/features.h"
#include "net/cookies/canonical_cookie.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "services/network/public/mojom/restricted_cookie_manager.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_cookie_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_cookie_list_item.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_cookie_store_delete_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_cookie_store_get_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/cookie_store/cookie_change_event.h"
#include "third_party/blink/renderer/modules/event_modules.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_registration.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

// Returns null if and only if an exception is thrown.
network::mojom::blink::CookieManagerGetOptionsPtr ToBackendOptions(
    const CookieStoreGetOptions* options,
    ExceptionState& exception_state) {
  auto backend_options = network::mojom::blink::CookieManagerGetOptions::New();

  // TODO(crbug.com/1124499): Cleanup matchType after evaluation.
  backend_options->match_type = network::mojom::blink::CookieMatchType::EQUALS;

  if (options->hasName()) {
    backend_options->name = options->name();
  } else {
    // No name provided. Use a filter that matches all cookies. This overrides
    // a user-provided matchType.
    backend_options->match_type =
        network::mojom::blink::CookieMatchType::STARTS_WITH;
    backend_options->name = g_empty_string;
  }

  return backend_options;
}

// Returns no value if and only if an exception is thrown.
std::unique_ptr<net::CanonicalCookie> ToCanonicalCookie(
    const KURL& cookie_url,
    const CookieInit* options,
    ExceptionState& exception_state,
    net::CookieInclusionStatus& status_out) {
  const String& name = options->name();
  const String& value = options->value();
  if (name.empty() && value.Contains('=')) {
    exception_state.ThrowTypeError(
        "Cookie value cannot contain '=' if the name is empty");
    return nullptr;
  }
  if (name.empty() && value.empty()) {
    exception_state.ThrowTypeError(
        "Cookie name and value both cannot be empty");
    return nullptr;
  }

  base::Time expires = options->hasExpiresNonNull()
                           ? base::Time::FromMillisecondsSinceUnixEpoch(
                                 options->expiresNonNull())
                           : base::Time();

  String cookie_url_host = cookie_url.Host().ToString();
  String domain;
  if (!options->domain().IsNull()) {
    if (name.StartsWith("__Host-")) {
      exception_state.ThrowTypeError(
          "Cookies with \"__Host-\" prefix cannot have a domain");
      return nullptr;
    }
    // The leading dot (".") from the domain attribute is stripped in the
    // Set-Cookie header, for compatibility. This API doesn't have compatibility
    // constraints, so reject the edge case outright.
    if (options->domain().StartsWith(".")) {
      exception_state.ThrowTypeError("Cookie domain cannot start with \".\"");
      return nullptr;
    }

    domain = String(".") + options->domain();
    if (!cookie_url_host.EndsWith(domain) &&
        cookie_url_host != options->domain()) {
      exception_state.ThrowTypeError(
          "Cookie domain must domain-match current host");
      return nullptr;
    }
  }

  String path = options->path();
  if (!path.empty()) {
    if (name.StartsWith("__Host-") && path != "/") {
      exception_state.ThrowTypeError(
          "Cookies with \"__Host-\" prefix cannot have a non-\"/\" path");
      return nullptr;
    }
    if (!path.StartsWith("/")) {
      exception_state.ThrowTypeError("Cookie path must start with \"/\"");
      return nullptr;
    }
    if (!path.EndsWith("/")) {
      path = path + String("/");
    }
  }

  // The Cookie Store API will only write secure cookies but will read insecure
  // cookies. As a result,
  // cookieStore.get("name", "value") can get an insecure cookie, but when
  // modifying a retrieved insecure cookie via the Cookie Store API, it will
  // automatically turn it into a secure cookie without any warning.
  //
  // The Cookie Store API can only set secure cookies, so it is unusable on
  // insecure origins. file:// are excluded too for consistency with
  // document.cookie.
  if (!network::IsUrlPotentiallyTrustworthy(GURL(cookie_url)) ||
      base::Contains(url::GetLocalSchemes(), cookie_url.Protocol().Ascii())) {
    exception_state.ThrowTypeError(
        "Cannot modify a secure cookie on insecure origin");
    return nullptr;
  }

  net::CookieSameSite same_site;
  if (options->sameSite() == "strict") {
    same_site = net::CookieSameSite::STRICT_MODE;
  } else if (options->sameSite() == "lax") {
    same_site = net::CookieSameSite::LAX_MODE;
  } else {
    DCHECK_EQ(options->sameSite(), "none");
    same_site = net::CookieSameSite::NO_RESTRICTION;
  }

  std::optional<net::CookiePartitionKey> cookie_partition_key = std::nullopt;
  if (options->partitioned()) {
    // We don't trust the renderer to determine the cookie partition key, so we
    // use this factory to indicate we are using a temporary value here.
    cookie_partition_key = net::CookiePartitionKey::FromScript();
  }

  std::unique_ptr<net::CanonicalCookie> cookie =
      net::CanonicalCookie::CreateSanitizedCookie(
          GURL(cookie_url), name.Utf8(), value.Utf8(), domain.Utf8(),
          path.Utf8(), base::Time() /*creation*/, expires,
          base::Time() /*last_access*/, true /*secure*/, false /*http_only*/,
          same_site, net::CookiePriority::COOKIE_PRIORITY_DEFAULT,
          cookie_partition_key, &status_out);

  // TODO(crbug.com/1310444): Improve serialization validation comments and
  // associate them with ExceptionState codes.
  if (!status_out.IsInclude()) {
    exception_state.ThrowTypeError(
        "Cookie was malformed and could not be stored, due to problem(s) while "
        "parsing.");
  }

  return cookie;
}

const KURL DefaultCookieURL(ExecutionContext* execution_context) {
  DCHECK(execution_context);

  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context))
    return window->document()->CookieURL();

  return KURL(To<ServiceWorkerGlobalScope>(execution_context)
                  ->serviceWorker()
                  ->scriptURL());
}

// Return empty KURL if and only if an exception is thrown.
KURL CookieUrlForRead(const CookieStoreGetOptions* options,
                      const KURL& default_cookie_url,
                      ScriptState* script_state,
                      ExceptionState& exception_state) {
  ExecutionContext* context = ExecutionContext::From(script_state);

  if (!options->hasUrl())
    return default_cookie_url;

  KURL cookie_url = KURL(default_cookie_url, options->url());

  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    DCHECK_EQ(default_cookie_url, window->document()->CookieURL());

    if (cookie_url.GetString() != default_cookie_url.GetString()) {
      exception_state.ThrowTypeError("URL must match the document URL");
      return KURL();
    }
  } else {
    DCHECK(context->IsServiceWorkerGlobalScope());
    DCHECK_EQ(
        default_cookie_url.GetString(),
        To<ServiceWorkerGlobalScope>(context)->serviceWorker()->scriptURL());

    if (!cookie_url.GetString().StartsWith(default_cookie_url.GetString())) {
      exception_state.ThrowTypeError("URL must be within Service Worker scope");
      return KURL();
    }
  }

  return cookie_url;
}

net::SiteForCookies DefaultSiteForCookies(ExecutionContext* execution_context) {
  DCHECK(execution_context);

  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context))
    return window->document()->SiteForCookies();

  auto* scope = To<ServiceWorkerGlobalScope>(execution_context);
  const blink::BlinkStorageKey& key = scope->storage_key();
  if (key.IsFirstPartyContext()) {
    return net::SiteForCookies::FromUrl(GURL(scope->Url()));
  }
  return net::SiteForCookies();
}

const scoped_refptr<const SecurityOrigin> DefaultTopFrameOrigin(
    ExecutionContext* execution_context) {
  DCHECK(execution_context);

  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    // Can we avoid the copy? TopFrameOrigin is returned as const& but we need
    // a scoped_refptr.
    return window->document()->TopFrameOrigin()->IsolatedCopy();
  }

  const BlinkStorageKey& key =
      To<ServiceWorkerGlobalScope>(execution_context)->storage_key();
  if (key.IsFirstPartyContext()) {
    return key.GetSecurityOrigin();
  }
  return SecurityOrigin::CreateFromUrlOrigin(
      url::Origin::Create(net::SchemefulSite(key.GetTopLevelSite()).GetURL()));
}

}  // namespace

CookieStore::CookieStore(
    ExecutionContext* execution_context,
    HeapMojoRemote<network::mojom::blink::RestrictedCookieManager> backend)
    : ExecutionContextClient(execution_context),
      backend_(std::move(backend)),
      change_listener_receiver_(this, execution_context),
      default_cookie_url_(DefaultCookieURL(execution_context)),
      default_site_for_cookies_(DefaultSiteForCookies(execution_context)),
      default_top_frame_origin_(DefaultTopFrameOrigin(execution_context)) {
  DCHECK(backend_);
}

CookieStore::~CookieStore() = default;

ScriptPromise<IDLSequence<CookieListItem>> CookieStore::getAll(
    ScriptState* script_state,
    const String& name,
    ExceptionState& exception_state) {
  CookieStoreGetOptions* options = CookieStoreGetOptions::Create();
  options->setName(name);
  return getAll(script_state, options, exception_state);
}

ScriptPromise<IDLSequence<CookieListItem>> CookieStore::getAll(
    ScriptState* script_state,
    const CookieStoreGetOptions* options,
    ExceptionState& exception_state) {
  UseCounter::Count(CurrentExecutionContext(script_state->GetIsolate()),
                    WebFeature::kCookieStoreAPI);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<CookieListItem>>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  DoRead(script_state, options,
         WTF::BindOnce(&CookieStore::GetAllForUrlToGetAllResult,
                       WrapPersistent(resolver)),
         exception_state);
  if (exception_state.HadException()) {
    resolver->Detach();
    return EmptyPromise();
  }
  return promise;
}

ScriptPromise<IDLNullable<CookieListItem>> CookieStore::get(
    ScriptState* script_state,
    const String& name,
    ExceptionState& exception_state) {
  CookieStoreGetOptions* options = CookieStoreGetOptions::Create();
  options->setName(name);
  return get(script_state, options, exception_state);
}

ScriptPromise<IDLNullable<CookieListItem>> CookieStore::get(
    ScriptState* script_state,
    const CookieStoreGetOptions* options,
    ExceptionState& exception_state) {
  UseCounter::Count(CurrentExecutionContext(script_state->GetIsolate()),
                    WebFeature::kCookieStoreAPI);

  if (!options->hasName() && !options->hasUrl()) {
    exception_state.ThrowTypeError("CookieStoreGetOptions must not be empty");
    return ScriptPromise<IDLNullable<CookieListItem>>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<CookieListItem>>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  DoRead(script_state, options,
         WTF::BindOnce(&CookieStore::GetAllForUrlToGetResult,
                       WrapPersistent(resolver)),
         exception_state);
  if (exception_state.HadException()) {
    resolver->Detach();
    return EmptyPromise();
  }
  return promise;
}

ScriptPromise<IDLUndefined> CookieStore::set(ScriptState* script_state,
                                             const String& name,
                                             const String& value,
                                             ExceptionState& exception_state) {
  CookieInit* set_options = CookieInit::Create();
  set_options->setName(name);
  set_options->setValue(value);
  return set(script_state, set_options, exception_state);
}

ScriptPromise<IDLUndefined> CookieStore::set(ScriptState* script_state,
                                             const CookieInit* options,
                                             ExceptionState& exception_state) {
  UseCounter::Count(CurrentExecutionContext(script_state->GetIsolate()),
                    WebFeature::kCookieStoreAPI);

  return DoWrite(script_state, options, exception_state);
}

ScriptPromise<IDLUndefined> CookieStore::Delete(
    ScriptState* script_state,
    const String& name,
    ExceptionState& exception_state) {
  UseCounter::Count(CurrentExecutionContext(script_state->GetIsolate()),
                    WebFeature::kCookieStoreAPI);

  CookieInit* set_options = CookieInit::Create();
  set_options->setName(name);
  set_options->setValue("deleted");
  set_options->setExpires(0);
  return DoWrite(script_state, set_options, exception_state);
}

ScriptPromise<IDLUndefined> CookieStore::Delete(
    ScriptState* script_state,
    const CookieStoreDeleteOptions* options,
    ExceptionState& exception_state) {
  CookieInit* set_options = CookieInit::Create();
  set_options->setName(options->name());
  set_options->setValue("deleted");
  set_options->setExpires(0);
  set_options->setDomain(options->domain());
  set_options->setPath(options->path());
  set_options->setSameSite("strict");
  set_options->setPartitioned(options->partitioned());
  return DoWrite(script_state, set_options, exception_state);
}

void CookieStore::Trace(Visitor* visitor) const {
  visitor->Trace(change_listener_receiver_);
  visitor->Trace(backend_);
  EventTarget::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

const AtomicString& CookieStore::InterfaceName() const {
  return event_target_names::kCookieStore;
}

ExecutionContext* CookieStore::GetExecutionContext() const {
  return ExecutionContextClient::GetExecutionContext();
}

void CookieStore::RemoveAllEventListeners() {
  EventTarget::RemoveAllEventListeners();
  DCHECK(!HasEventListeners());
  StopObserving();
}

void CookieStore::OnCookieChange(
    network::mojom::blink::CookieChangeInfoPtr change) {
  HeapVector<Member<CookieListItem>> changed, deleted;
  CookieChangeEvent::ToEventInfo(change, changed, deleted);
  if (changed.empty() && deleted.empty()) {
    // The backend only reported OVERWRITE events, which are dropped.
    return;
  }
  DispatchEvent(*CookieChangeEvent::Create(
      event_type_names::kChange, std::move(changed), std::move(deleted)));
}

void CookieStore::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  EventTarget::AddedEventListener(event_type, registered_listener);
  StartObserving();
}

void CookieStore::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {
  EventTarget::RemovedEventListener(event_type, registered_listener);
  if (!HasEventListeners())
    StopObserving();
}

void CookieStore::DoRead(ScriptState* script_state,
                         const CookieStoreGetOptions* options,
                         GetAllForUrlCallback backend_result_converter,
                         ExceptionState& exception_state) {
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context->GetSecurityOrigin()->CanAccessCookies()) {
    exception_state.ThrowSecurityError(
        "Access to the CookieStore API is denied in this context.");
    return;
  }

  network::mojom::blink::CookieManagerGetOptionsPtr backend_options =
      ToBackendOptions(options, exception_state);
  KURL cookie_url = CookieUrlForRead(options, default_cookie_url_, script_state,
                                     exception_state);
  if (backend_options.is_null() || cookie_url.IsNull()) {
    DCHECK(exception_state.HadException());
    return;
  }

  if (!backend_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "CookieStore backend went away");
    return;
  }

  bool is_ad_tagged = false;
  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    if (auto* local_frame = window->GetFrame()) {
      is_ad_tagged = local_frame->IsAdFrame();
    }
  }
  backend_->GetAllForUrl(cookie_url, default_site_for_cookies_,
                         default_top_frame_origin_,
                         context->GetStorageAccessApiStatus(),
                         std::move(backend_options), is_ad_tagged,
                         /*force_disable_third_party_cookies=*/false,
                         std::move(backend_result_converter));
}

// static
void CookieStore::GetAllForUrlToGetAllResult(
    ScriptPromiseResolver<IDLSequence<CookieListItem>>* resolver,
    const Vector<network::mojom::blink::CookieWithAccessResultPtr>
        backend_cookies) {
  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid())
    return;
  ScriptState::Scope scope(script_state);

  HeapVector<Member<CookieListItem>> cookies;
  cookies.ReserveInitialCapacity(backend_cookies.size());
  for (const auto& backend_cookie : backend_cookies) {
    cookies.push_back(CookieChangeEvent::ToCookieListItem(
        backend_cookie->cookie,
        backend_cookie->access_result->effective_same_site,
        false /* is_deleted */));
  }

  resolver->Resolve(std::move(cookies));
}

// static
void CookieStore::GetAllForUrlToGetResult(
    ScriptPromiseResolver<IDLNullable<CookieListItem>>* resolver,
    const Vector<network::mojom::blink::CookieWithAccessResultPtr>
        backend_cookies) {
  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid())
    return;
  ScriptState::Scope scope(script_state);

  if (backend_cookies.empty()) {
    resolver->Resolve(nullptr);
    return;
  }

  const auto& backend_cookie = backend_cookies.front();
  CookieListItem* cookie = CookieChangeEvent::ToCookieListItem(
      backend_cookie->cookie,
      backend_cookie->access_result->effective_same_site,
      false /* is_deleted */);
  resolver->Resolve(cookie);
}

ScriptPromise<IDLUndefined> CookieStore::DoWrite(
    ScriptState* script_state,
    const CookieInit* options,
    ExceptionState& exception_state) {
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context->GetSecurityOrigin()->CanAccessCookies()) {
    exception_state.ThrowSecurityError(
        "Access to the CookieStore API is denied in this context.");
    return EmptyPromise();
  }

  net::CookieInclusionStatus status;
  std::unique_ptr<net::CanonicalCookie> canonical_cookie =
      ToCanonicalCookie(default_cookie_url_, options, exception_state, status);

  if (!canonical_cookie) {
    DCHECK(exception_state.HadException());
    return EmptyPromise();
  }
  // Since a canonical cookie exists, the status should have no exclusion
  // reasons associated with it.
  DCHECK(status.IsInclude());

  if (!backend_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "CookieStore backend went away");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  backend_->SetCanonicalCookie(
      *std::move(canonical_cookie), default_cookie_url_,
      default_site_for_cookies_, default_top_frame_origin_,
      context->GetStorageAccessApiStatus(), status,
      WTF::BindOnce(&CookieStore::OnSetCanonicalCookieResult,
                    WrapPersistent(resolver)));
  return resolver->Promise();
}

// static
void CookieStore::OnSetCanonicalCookieResult(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool backend_success) {
  if (!backend_success) {
    resolver->RejectWithDOMException(
        DOMExceptionCode::kUnknownError,
        "An unknown error occurred while writing the cookie.");
    return;
  }
  resolver->Resolve();
}

void CookieStore::StartObserving() {
  if (change_listener_receiver_.is_bound() || !backend_)
    return;

  // See https://bit.ly/2S0zRAS for task types.
  auto task_runner =
      GetExecutionContext()->GetTaskRunner(TaskType::kDOMManipulation);
  backend_->AddChangeListener(
      default_cookie_url_, default_site_for_cookies_, default_top_frame_origin_,
      GetExecutionContext()->GetStorageAccessApiStatus(),
      change_listener_receiver_.BindNewPipeAndPassRemote(task_runner), {});
}

void CookieStore::StopObserving() {
  if (!change_listener_receiver_.is_bound())
    return;
  change_listener_receiver_.reset();
}

}  // namespace blink
```