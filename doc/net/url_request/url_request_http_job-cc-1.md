Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/url_request/url_request_http_job.cc`. This is part 2 of a 3-part request.

Here's a breakdown of the code's key actions and how to structure the answer:

1. **Cookie Handling:** The code deals extensively with sending and receiving cookies. This includes:
    * Retrieving cookies from the store.
    * Checking cookie permissions and settings.
    * Setting cookies based on `Set-Cookie` headers.
    * Handling partitioned cookies and related deprecation headers.
    * Interacting with `NetworkDelegate` for cookie blocking.
    * Logging cookie inclusion/exclusion decisions.

2. **Device-Bound Sessions:**  The code interacts with a device-bound sessions service. This involves:
    * Checking for required device-bound session cookies.
    * Deferring requests if session refresh is needed.
    * Registering bound sessions and setting challenges based on response headers.

3. **HTTP Headers Processing:**  The code processes various HTTP headers:
    * `Strict-Transport-Security` (HSTS) to enforce HTTPS.
    * `Clear-Site-Data` to clear cookies.
    * `Content-Encoding` to handle compressed responses.
    * `Set-Cookie` for storing cookies.
    * Potential interaction with `Sec-Cookie-Deprecation` and TPC-related headers.
    * Storage Access API related headers for retries.

4. **Network Delegate Interaction:**  The code integrates with the `NetworkDelegate` for:
    * Checking cookie permissions (`AnnotateAndMoveUserBlockedCookies`).
    * Notifying about received headers (`NotifyHeadersReceived`).

5. **Error Handling and Retries:** The code handles various network errors, including:
    * SSL certificate errors.
    * Client authentication requests.
    * Handling `DNS_NAME_HTTPS_ONLY` by synthesizing redirects.
    * Supporting authentication challenges (401 and 407 responses).
    * Allowing retries based on storage access grants.

6. **Data Reading and Processing:**  The code deals with reading the response body and handling content encoding.

7. **Redirection Handling:** The code manages redirects, including checking for safe redirects and handling fragment preservation.

8. **Logging and Metrics:**  The code uses UMA histograms for tracking cookie usage and other metrics. It also uses the `NetLog` for debugging.

**Relation to JavaScript:**

* Cookies are fundamental to web development and directly impact JavaScript's ability to manage user sessions, track preferences, etc. JavaScript can read and write cookies using the `document.cookie` API. The code here handles the backend logic of setting these cookies.
* Device-bound sessions, while backend focused, influence how web applications using JavaScript can interact with authentication and authorization mechanisms.
* HSTS directly impacts the security of web pages accessed via JavaScript, ensuring HTTPS connections.
* The Storage Access API, which this code interacts with, affects JavaScript's ability to access cookies in cross-site contexts.

**Logical Inference (Example):**

* **Assumption:** A server sends a `Set-Cookie` header with the `Secure` attribute on an HTTPS connection.
* **Output:** The code will likely attempt to store this cookie.

**User/Programming Errors:**

* Users might block cookies in their browser settings, which will be reflected in the `NetworkDelegate`'s decisions.
* Developers might incorrectly set cookie attributes (e.g., `Secure` on an HTTP site), leading to cookies being rejected.

**User Operation Trace (Example):**

* User types a URL in the address bar and hits Enter.
* The browser initiates a network request.
* The network stack reaches `URLRequestHttpJob` to handle the HTTP/HTTPS request.
* This code snippet is involved in processing the response headers, especially `Set-Cookie` headers, as part of handling the server's response.

**Structure of the Answer:**

The answer should be structured around the core functionalities listed above, providing explanations and examples where appropriate. For the "歸納一下它的功能" (summarize its function) part, it should synthesize the individual functionalities into a concise overview of the code's role.
好的，我们来归纳一下这段代码的功能。

这段代码主要负责处理 HTTP 响应中与 Cookie 相关的逻辑，并与设备的绑定会话（Device Bound Sessions）以及 HSTS (HTTP Strict Transport Security) 处理相关。

**核心功能归纳:**

1. **处理 Set-Cookie 头部:**
   - 遍历响应头中的 `Set-Cookie` 字段。
   - 解析 `Set-Cookie` 字符串，创建 `CanonicalCookie` 对象。
   - 检查 Cookie 的可访问性，包括 `Secure` 属性、`HttpOnly` 属性、以及是否被用户设置阻止。
   - 判断是否需要设置 `Sec-Cookie-Deprecation` 头部 (与 partitioned cookie 和实验性功能相关)。
   - 异步地将解析后的 Cookie 存储到 CookieStore 中。
   - 记录 Cookie 存储的结果 (成功或失败)。
   - 考虑 `Clear-Site-Data` 头部的影响，如果指定清除 cookies，则不存储新的 cookies。

2. **处理 Cookie 发送:**
   - 在请求发送前，从 CookieStore 中检索相关的 Cookie。
   - 根据请求是否安全 (HTTPS) 以及 Cookie 的 `Secure` 属性，决定发送哪些 Cookie。
   - 记录 Cookie 的包含或排除状态，并通过 `NetLog` 记录详细信息。
   - 调用 `NetworkDelegate` 来检查和移动用户阻止的 Cookie。

3. **处理设备绑定会话 (Device Bound Sessions):**
   - 检查响应头中是否包含设备绑定会话相关的头部 (例如用于注册或质询)。
   - 如果存在，调用 `device_bound_sessions::SessionService` 来处理这些头部，例如注册绑定会话或设置会话质询。
   - 在请求开始时，检查是否需要等待设备绑定会话刷新，如果需要，则延迟事务的开始。

4. **处理 HSTS (HTTP Strict Transport Security) 头部:**
   - 检查响应头中是否存在 `Strict-Transport-Security` 头部。
   - 如果存在，并且满足 HSTS 生效的条件 (HTTPS 连接，无证书错误，非 IP 地址，非 localhost - 根据 Feature Flag)，则将 HSTS 信息添加到 `TransportSecurityState` 中，以便后续强制使用 HTTPS。

5. **与 NetworkDelegate 交互:**
   - 调用 `NetworkDelegate` 的 `AnnotateAndMoveUserBlockedCookies` 方法来获取用户阻止的 Cookie。
   - 调用 `NetworkDelegate` 的 `NotifyHeadersReceived` 方法，允许 `NetworkDelegate` 修改响应头或取消请求。

**与 JavaScript 的关系:**

- **Cookie 的读取和设置:** JavaScript 可以通过 `document.cookie` API 来读取和设置 Cookie。这段 C++ 代码负责接收服务器通过 `Set-Cookie` 头部发送的指示，并将 Cookie 存储在浏览器本地。当 JavaScript 需要读取 Cookie 时，浏览器会根据存储的 Cookie 信息提供。这段代码中关于 Cookie 的各种规则和策略（例如 `Secure` 属性，`HttpOnly` 属性，SameSite 属性等）直接影响了 JavaScript 对 Cookie 的访问和操作。
    - **举例:**  如果服务器发送了一个带有 `HttpOnly` 属性的 Cookie，那么这段 C++ 代码会成功存储它。但是，JavaScript 代码将无法通过 `document.cookie` 读取到这个 Cookie，因为它只能由 HTTP 请求头发送回服务器。

- **设备绑定会话:** 虽然设备绑定会话的底层实现是在网络栈中，但它可能影响到 Web 应用的认证和授权流程，进而影响到 JavaScript 的行为。例如，如果一个请求需要特定的设备绑定会话，而 JavaScript 发起的请求没有满足条件，服务器可能会返回错误，导致 JavaScript 需要处理这些错误情况。

- **HSTS:** HSTS 机制确保浏览器对于特定的域名总是使用 HTTPS 连接。当这段 C++ 代码处理了 `Strict-Transport-Security` 头部并将其记录下来后，即使 JavaScript 代码尝试使用 `http://` 发起请求到该域名，浏览器也会自动将其升级为 `https://`。这增强了 Web 应用的安全性，并对 JavaScript 发起的网络请求有直接的影响。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **请求 URL:** `https://example.com/page`
2. **响应头:**
   ```
   HTTP/1.1 200 OK
   Set-Cookie: session_id=123; Secure; HttpOnly
   Set-Cookie: user_pref=dark_mode; Path=/
   ```

**输出:**

- `session_id=123; Secure; HttpOnly` 这个 Cookie 将会被存储，并且由于 `Secure` 属性，只会在 HTTPS 连接中发送。由于 `HttpOnly` 属性，JavaScript 无法通过 `document.cookie` 读取它。
- `user_pref=dark_mode; Path=/` 这个 Cookie 将会被存储，可以在 `example.com` 域名下路径为 `/` 或其子路径的页面中被 JavaScript 读取和发送。

**用户或编程常见的使用错误:**

1. **用户阻止 Cookie:** 用户可以在浏览器设置中阻止网站设置 Cookie。在这种情况下，即使服务器发送了 `Set-Cookie` 头部，这段代码在尝试存储 Cookie 时也会受到影响，最终可能导致 Cookie 存储失败。
   - **例子:** 用户在 Chrome 浏览器的 "隐私设置和安全性" 中选择了 "阻止所有 Cookie"。当访问任何网站时，即使服务器尝试设置 Cookie，这段代码也会因为用户设置而无法成功存储。

2. **开发者在 HTTP 页面设置 Secure Cookie:** 开发者可能会错误地在非 HTTPS 的页面上设置带有 `Secure` 属性的 Cookie。这段代码会根据 `request_is_secure` 的状态来判断，如果请求不是 HTTPS，则不会为 `net::CookieSourceScheme::kSecure` 的 Cookie 设置 `CookieRequestScheme::kSecureSetSecureRequest`，从而可能导致 Cookie 无法被正确设置。
   - **例子:**  一个网站使用 HTTP 协议 (`http://example.com`)，服务器尝试发送 `Set-Cookie: session_id=123; Secure`。由于连接不是 HTTPS，这段代码处理后，该 Cookie 将不会被浏览器存储，因为 `Secure` 属性要求在安全的连接下才能设置。

**用户操作到达此处的调试线索:**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。** 这会触发一个网络请求。
2. **浏览器网络栈开始处理该请求，并建立与服务器的连接。**
3. **服务器返回 HTTP 响应，其中包含响应头。**
4. **这段 `URLRequestHttpJob::SaveCookiesAndNotifyHeadersComplete` 函数会被调用，开始处理响应头。**
5. **在 `SaveCookiesAndNotifyHeadersComplete` 函数中，代码会遍历响应头中的 `Set-Cookie` 字段。**
6. **对于每个 `Set-Cookie` 字段，会调用 `net::CanonicalCookie::Create` 来解析 Cookie 字符串。**
7. **接着会调用 `URLRequestHttpJob::OnSetCookieResult` 来处理每个 Cookie 的存储结果。**
8. **如果响应头中包含 `Strict-Transport-Security` 头部，`URLRequestHttpJob::ProcessStrictTransportSecurityHeader` 会被调用。**
9. **如果涉及到设备绑定会话，可能会在 `URLRequestHttpJob::OnStartCompleted` 中检查并处理相关的头部。**

通过在网络请求的生命周期中设置断点，例如在 `URLRequestHttpJob::SaveCookiesAndNotifyHeadersComplete` 函数的入口，或者在 `net::CanonicalCookie::Create` 函数中，可以观察到这段代码的执行情况，并检查 Cookie 的解析和存储过程。还可以通过 Chrome 的 `chrome://net-export/` 功能导出网络日志，查看 Cookie 的发送和接收情况，以及 HSTS 的状态变化。

总而言之，这段代码在 Chromium 网络栈中扮演着至关重要的角色，它负责处理 HTTP 响应中与 Cookie 和安全相关的关键逻辑，并与浏览器的其他组件（如 CookieStore，TransportSecurityState，NetworkDelegate）进行交互，确保用户能够安全有效地浏览网页。

### 提示词
```
这是目录为net/url_request/url_request_http_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
me cookie_request_schemes;

      switch (cookie_scheme) {
        case net::CookieSourceScheme::kSecure:
          cookie_request_schemes =
              request_is_secure
                  ? CookieRequestScheme::kSecureSetSecureRequest
                  : CookieRequestScheme::kSecureSetNonsecureRequest;
          break;

        case net::CookieSourceScheme::kNonSecure:
          cookie_request_schemes =
              request_is_secure
                  ? CookieRequestScheme::kNonsecureSetSecureRequest
                  : CookieRequestScheme::kNonsecureSetNonsecureRequest;
          break;

        case net::CookieSourceScheme::kUnset:
          cookie_request_schemes = CookieRequestScheme::kUnsetCookieScheme;
          break;
      }

      UMA_HISTOGRAM_ENUMERATION("Cookie.CookieSchemeRequestScheme",
                                cookie_request_schemes);
      if (c.cookie.IsPartitioned()) {
        ++n_partitioned_cookies;

        if (may_set_sec_cookie_deprecation_header &&
            c.cookie.Name() == "receive-cookie-deprecation" &&
            c.cookie.IsHttpOnly() && c.cookie.SecureAttribute()) {
          request_info_.extra_headers.SetHeader(
              "Sec-Cookie-Deprecation",
              *request_->context()->cookie_deprecation_label());
          may_set_sec_cookie_deprecation_header = false;
        }
      }
    }

    if (ShouldRecordPartitionedCookieUsage()) {
      base::UmaHistogramCounts100("Cookie.PartitionedCookiesInRequest",
                                  n_partitioned_cookies);
    }
  }
  if (cookie_deprecation_testing_enabled) {
    if (!cookie_deprecation_testing_has_label) {
      RecordTpcdHeaderStatus(TpcdHeaderStatus::kNoLabel);
    } else if (may_set_sec_cookie_deprecation_header) {
      RecordTpcdHeaderStatus(TpcdHeaderStatus::kNoCookie);
    } else {
      RecordTpcdHeaderStatus(TpcdHeaderStatus::kSet);
    }
  }

  CookieAccessResultList maybe_sent_cookies = std::move(excluded_cookies);
  maybe_sent_cookies.insert(
      maybe_sent_cookies.end(),
      std::make_move_iterator(maybe_included_cookies.begin()),
      std::make_move_iterator(maybe_included_cookies.end()));
  maybe_included_cookies.clear();

  if (request_->net_log().IsCapturing()) {
    for (const auto& cookie_with_access_result : maybe_sent_cookies) {
      request_->net_log().AddEvent(
          NetLogEventType::COOKIE_INCLUSION_STATUS,
          [&](NetLogCaptureMode capture_mode) {
            return CookieInclusionStatusNetLogParams(
                "send", cookie_with_access_result.cookie.Name(),
                cookie_with_access_result.cookie.Domain(),
                cookie_with_access_result.cookie.Path(),
                cookie_with_access_result.cookie.PartitionKey(),
                cookie_with_access_result.access_result.status, capture_mode);
          });
    }
  }

  request_->set_maybe_sent_cookies(std::move(maybe_sent_cookies));

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
  // Check if the right device bound cookies are set for the request, see
  // https://wicg.github.io/dbsc/ for specification.
  device_bound_sessions::SessionService* service =
      request_->context()->device_bound_session_service();
  if (service) {
    std::optional<device_bound_sessions::Session::Id> id =
        service->GetAnySessionRequiringDeferral(request_);
    // If the request needs to be deferred while waiting for refresh,
    // do not start the transaction at this time.
    if (id) {
      service->DeferRequestForRefresh(
          request_, *id,
          // restart with new cookies callback
          base::BindOnce(&URLRequestHttpJob::RestartTransactionForRefresh,
                         weak_factory_.GetWeakPtr()),
          // continue callback
          base::BindOnce(&URLRequestHttpJob::StartTransaction,
                         weak_factory_.GetWeakPtr()));
      return;
    }
  }
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

  StartTransaction();
}

void URLRequestHttpJob::AnnotateAndMoveUserBlockedCookies(
    CookieAccessResultList& maybe_included_cookies,
    CookieAccessResultList& excluded_cookies) const {
  DCHECK(!ShouldBlockAllCookies(request_info_.privacy_mode))
      << request_info_.privacy_mode;

  bool can_get_cookies = URLRequest::DefaultCanUseCookies();
  if (request()->network_delegate()) {
    can_get_cookies =
        request()->network_delegate()->AnnotateAndMoveUserBlockedCookies(
            *request(), first_party_set_metadata_, maybe_included_cookies,
            excluded_cookies);
  }

  if (!can_get_cookies) {
    request()->net_log().AddEvent(
        NetLogEventType::COOKIE_GET_BLOCKED_BY_NETWORK_DELEGATE);
  }
}

void URLRequestHttpJob::SaveCookiesAndNotifyHeadersComplete(int result) {
  DCHECK(set_cookie_access_result_list_.empty());
  // TODO(crbug.com/40753971): Turn this CHECK into DCHECK once the
  // investigation is done.
  CHECK_EQ(0, num_cookie_lines_left_);

  // End of the call started in OnStartCompleted.
  OnCallToDelegateComplete();

  if (result != OK) {
    request_->net_log().AddEventWithStringParams(NetLogEventType::CANCELLED,
                                                 "source", "delegate");
    NotifyStartError(result);
    return;
  }

  CookieStore* cookie_store = request_->context()->cookie_store();

  if ((request_info_.load_flags & LOAD_DO_NOT_SAVE_COOKIES) || !cookie_store) {
    NotifyHeadersComplete();
    return;
  }

  HttpResponseHeaders* headers = GetResponseHeaders();

  // If we're clearing the cookies as part of a clear-site-data header we must
  // not also write new ones in the same response.
  bool clear_site_data_prevents_cookies_from_being_stored = false;
  std::string clear_site_data_header =
      headers->GetNormalizedHeader(kClearSiteDataHeader)
          .value_or(std::string());
  std::vector<std::string> clear_site_data_types =
      ClearSiteDataHeaderContents(clear_site_data_header);
  std::set<std::string> clear_site_data_set(clear_site_data_types.begin(),
                                            clear_site_data_types.end());
  if (clear_site_data_set.find(kDatatypeCookies) != clear_site_data_set.end() ||
      clear_site_data_set.find(kDatatypeWildcard) !=
          clear_site_data_set.end()) {
    clear_site_data_prevents_cookies_from_being_stored = true;
  }

  std::optional<base::Time> server_time = GetResponseHeaders()->GetDateValue();

  bool force_ignore_site_for_cookies =
      request_->force_ignore_site_for_cookies();
  if (cookie_store->cookie_access_delegate() &&
      cookie_store->cookie_access_delegate()->ShouldIgnoreSameSiteRestrictions(
          request_->url(), request_->site_for_cookies())) {
    force_ignore_site_for_cookies = true;
  }
  bool is_main_frame_navigation =
      IsolationInfo::RequestType::kMainFrame ==
          request_->isolation_info().request_type() ||
      request_->force_main_frame_for_same_site_cookies();
  CookieOptions::SameSiteCookieContext same_site_context =
      net::cookie_util::ComputeSameSiteContextForResponse(
          request_->url_chain(), request_->site_for_cookies(),
          request_->initiator(), is_main_frame_navigation,
          force_ignore_site_for_cookies);

  CookieOptions options = CreateCookieOptions(same_site_context);

  // Set all cookies, without waiting for them to be set. Any subsequent
  // read will see the combined result of all cookie operation.
  const std::string_view name("Set-Cookie");
  std::optional<std::string_view> cookie_string_view;
  size_t iter = 0;

  // NotifyHeadersComplete needs to be called once and only once after the
  // list has been fully processed, and it can either be called in the
  // callback or after the loop is called, depending on how the last element
  // was handled. |num_cookie_lines_left_| keeps track of how many async
  // callbacks are currently out (starting from 1 to make sure the loop runs
  // all the way through before trying to exit). If there are any callbacks
  // still waiting when the loop ends, then NotifyHeadersComplete will be
  // called when it reaches 0 in the callback itself.
  num_cookie_lines_left_ = 1;
  while ((cookie_string_view = headers->EnumerateHeader(&iter, name))) {
    // Will need a copy of the string on all paths, so go ahead and make on now.
    std::string cookie_string(*cookie_string_view);
    CookieInclusionStatus returned_status;

    num_cookie_lines_left_++;

    std::unique_ptr<CanonicalCookie> cookie = net::CanonicalCookie::Create(
        request_->url(), cookie_string, base::Time::Now(), server_time,
        request_->cookie_partition_key(), net::CookieSourceType::kHTTP,
        &returned_status);

    std::optional<CanonicalCookie> cookie_to_return = std::nullopt;
    if (returned_status.IsInclude()) {
      DCHECK(cookie);
      // Make a copy of the cookie if we successfully made one.
      cookie_to_return = *cookie;
    }

    // Check cookie accessibility with cookie_settings.
    if (cookie && !CanSetCookie(*cookie, &options, first_party_set_metadata_,
                                &returned_status)) {
      // Cookie allowed by cookie_settings checks could be blocked explicitly,
      // e.g. via Android Webview APIs, we need to manually add exclusion reason
      // in this case.
      if (returned_status.IsInclude()) {
        returned_status.AddExclusionReason(
            net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES);
      }
    }
    if (clear_site_data_prevents_cookies_from_being_stored) {
      returned_status.AddExclusionReason(
          CookieInclusionStatus::EXCLUDE_FAILURE_TO_STORE);
    }
    if (!returned_status.IsInclude()) {
      OnSetCookieResult(options, cookie_to_return, std::move(cookie_string),
                        CookieAccessResult(returned_status));
      continue;
    }
    CookieAccessResult cookie_access_result(returned_status);
    cookie_store->SetCanonicalCookieAsync(
        std::move(cookie), request_->url(), options,
        base::BindOnce(&URLRequestHttpJob::OnSetCookieResult,
                       weak_factory_.GetWeakPtr(), options, cookie_to_return,
                       std::move(cookie_string)),
        std::move(cookie_access_result));
  }
  // Removing the 1 that |num_cookie_lines_left| started with, signifing that
  // loop has been exited.
  num_cookie_lines_left_--;

  if (num_cookie_lines_left_ == 0)
    NotifyHeadersComplete();
}

void URLRequestHttpJob::OnSetCookieResult(const CookieOptions& options,
                                          std::optional<CanonicalCookie> cookie,
                                          std::string cookie_string,
                                          CookieAccessResult access_result) {
  if (request_->net_log().IsCapturing()) {
    request_->net_log().AddEvent(
        NetLogEventType::COOKIE_INCLUSION_STATUS,
        [&](NetLogCaptureMode capture_mode) {
          return CookieInclusionStatusNetLogParams(
              "store", cookie ? cookie.value().Name() : "",
              cookie ? cookie.value().Domain() : "",
              cookie ? cookie.value().Path() : "",
              cookie ? cookie.value().PartitionKey() : std::nullopt,
              access_result.status, capture_mode);
        });
  }

  set_cookie_access_result_list_.emplace_back(
      std::move(cookie), std::move(cookie_string), access_result);

  num_cookie_lines_left_--;

  // If all the cookie lines have been handled, |set_cookie_access_result_list_|
  // now reflects the result of all Set-Cookie lines, and the request can be
  // continued.
  if (num_cookie_lines_left_ == 0)
    NotifyHeadersComplete();
}

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
void URLRequestHttpJob::ProcessDeviceBoundSessionsHeader() {
  device_bound_sessions::SessionService* service =
      request_->context()->device_bound_session_service();
  if (!service) {
    return;
  }

  const auto& request_url = request_->url();
  auto* headers = GetResponseHeaders();
  std::vector<device_bound_sessions::RegistrationFetcherParam> params =
      device_bound_sessions::RegistrationFetcherParam::CreateIfValid(
          request_url, headers);
  for (auto& param : params) {
    service->RegisterBoundSession(
        request_->device_bound_session_access_callback(), std::move(param),
        request_->isolation_info());
  }

  std::vector<device_bound_sessions::SessionChallengeParam> challenge_params =
      device_bound_sessions::SessionChallengeParam::CreateIfValid(request_url,
                                                                  headers);
  for (auto& param : challenge_params) {
    service->SetChallengeForBoundSession(
        request_->device_bound_session_access_callback(), request_url,
        std::move(param));
  }
}
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

void URLRequestHttpJob::ProcessStrictTransportSecurityHeader() {
  DCHECK(response_info_);
  TransportSecurityState* security_state =
      request_->context()->transport_security_state();
  const SSLInfo& ssl_info = response_info_->ssl_info;

  // Only accept HSTS headers on HTTPS connections that have no
  // certificate errors.
  if (!ssl_info.is_valid() || IsCertStatusError(ssl_info.cert_status) ||
      !security_state) {
    return;
  }

  // Don't accept HSTS headers when the hostname is an IP address.
  if (request_info_.url.HostIsIPAddress())
    return;

  // Don't accept HSTS headers for localhost. (crbug.com/41251622)
  if (net::IsLocalHostname(request_info_.url.host()) &&
      base::FeatureList::IsEnabled(features::kIgnoreHSTSForLocalhost)) {
    return;
  }

  // http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec:
  //
  //   If a UA receives more than one STS header field in a HTTP response
  //   message over secure transport, then the UA MUST process only the
  //   first such header field.
  HttpResponseHeaders* headers = GetResponseHeaders();
  std::optional<std::string_view> value;
  if ((value =
           headers->EnumerateHeader(nullptr, "Strict-Transport-Security"))) {
    security_state->AddHSTSHeader(request_info_.url.host(), *value);
  }
}

void URLRequestHttpJob::OnStartCompleted(int result) {
  TRACE_EVENT0(NetTracingCategory(), "URLRequestHttpJob::OnStartCompleted");
  RecordTimer();

  // If the job is done (due to cancellation), can just ignore this
  // notification.
  if (done_)
    return;

  receive_headers_end_ = base::TimeTicks::Now();

  const URLRequestContext* context = request_->context();

  if (transaction_ && transaction_->GetResponseInfo()) {
    const SSLInfo& ssl_info = transaction_->GetResponseInfo()->ssl_info;
    if (!IsCertificateError(result)) {
      LogTrustAnchor(ssl_info.public_key_hashes);
    }
  }

  if (transaction_ && transaction_->GetResponseInfo()) {
    SetProxyChain(transaction_->GetResponseInfo()->proxy_chain);
  }

  if (result == OK) {
    scoped_refptr<HttpResponseHeaders> headers = GetResponseHeaders();

    NetworkDelegate* network_delegate = request()->network_delegate();
    if (network_delegate) {
      // Note that |this| may not be deleted until
      // |URLRequestHttpJob::OnHeadersReceivedCallback()| or
      // |NetworkDelegate::URLRequestDestroyed()| has been called.
      OnCallToDelegate(NetLogEventType::NETWORK_DELEGATE_HEADERS_RECEIVED);
      preserve_fragment_on_redirect_url_ = std::nullopt;
      IPEndPoint endpoint;
      if (transaction_)
        transaction_->GetRemoteEndpoint(&endpoint);
      // The NetworkDelegate must watch for OnRequestDestroyed and not modify
      // any of the arguments after it's called.
      // TODO(mattm): change the API to remove the out-params and take the
      // results as params of the callback.
      int error = network_delegate->NotifyHeadersReceived(
          request_,
          base::BindOnce(&URLRequestHttpJob::OnHeadersReceivedCallback,
                         weak_factory_.GetWeakPtr()),
          headers.get(), &override_response_headers_, endpoint,
          &preserve_fragment_on_redirect_url_);
      if (error != OK) {
        if (error == ERR_IO_PENDING) {
          awaiting_callback_ = true;
        } else {
          request_->net_log().AddEventWithStringParams(
              NetLogEventType::CANCELLED, "source", "delegate");
          OnCallToDelegateComplete();
          NotifyStartError(error);
        }
        return;
      }
    }

    SaveCookiesAndNotifyHeadersComplete(OK);
  } else if (IsCertificateError(result)) {
    // We encountered an SSL certificate error.
    // Maybe overridable, maybe not. Ask the delegate to decide.
    TransportSecurityState* state = context->transport_security_state();
    NotifySSLCertificateError(
        result, transaction_->GetResponseInfo()->ssl_info,
        state->ShouldSSLErrorsBeFatal(request_info_.url.host()) &&
            result != ERR_CERT_KNOWN_INTERCEPTION_BLOCKED);
  } else if (result == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
    NotifyCertificateRequested(
        transaction_->GetResponseInfo()->cert_request_info.get());
  } else if (result == ERR_DNS_NAME_HTTPS_ONLY) {
    // If DNS indicated the name is HTTPS-only, synthesize a redirect to either
    // HTTPS or WSS.
    DCHECK(!request_->url().SchemeIsCryptographic());

    base::Time request_time =
        transaction_ && transaction_->GetResponseInfo()
            ? transaction_->GetResponseInfo()->request_time
            : base::Time::Now();
    DestroyTransaction();
    override_response_info_ = std::make_unique<HttpResponseInfo>();
    override_response_info_->request_time = request_time;

    override_response_info_->headers = RedirectUtil::SynthesizeRedirectHeaders(
        UpgradeSchemeToCryptographic(request_->url()),
        RedirectUtil::ResponseCode::REDIRECT_307_TEMPORARY_REDIRECT, "DNS",
        request_->extra_request_headers());
    NetLogResponseHeaders(
        request_->net_log(),
        NetLogEventType::URL_REQUEST_FAKE_RESPONSE_HEADERS_CREATED,
        override_response_info_->headers.get());

    NotifyHeadersComplete();
  } else {
    // Even on an error, there may be useful information in the response
    // info (e.g. whether there's a cached copy).
    if (transaction_.get())
      response_info_ = transaction_->GetResponseInfo();
    NotifyStartError(result);
  }
}

void URLRequestHttpJob::OnHeadersReceivedCallback(int result) {
  // The request should not have been cancelled or have already completed.
  DCHECK(!is_done());

  awaiting_callback_ = false;

  SaveCookiesAndNotifyHeadersComplete(result);
}

void URLRequestHttpJob::OnReadCompleted(int result) {
  TRACE_EVENT0(NetTracingCategory(), "URLRequestHttpJob::OnReadCompleted");
  read_in_progress_ = false;

  DCHECK_NE(ERR_IO_PENDING, result);

  if (ShouldFixMismatchedContentLength(result))
    result = OK;

  // EOF or error, done with this job.
  if (result <= 0)
    DoneWithRequest(FINISHED);

  ReadRawDataComplete(result);
}

void URLRequestHttpJob::RestartTransaction() {
  DCHECK(!override_response_info_);

  // These will be reset in OnStartCompleted.
  response_info_ = nullptr;
  override_response_headers_ = nullptr;  // See https://crbug.com/801237.
  receive_headers_end_ = base::TimeTicks();

  ResetTimer();

  // Update the cookies, since the cookie store may have been updated from the
  // headers in the 401/407. Since cookies were already appended to
  // extra_headers, we need to strip them out before adding them again.
  request_info_.extra_headers.RemoveHeader(HttpRequestHeaders::kCookie);

  // TODO(https://crbug.com/968327/): This is weird, as all other clearing is at
  // the URLRequest layer. Should this call into URLRequest so it can share
  // logic at that layer with SetAuth()?
  request_->set_maybe_sent_cookies({});
  request_->set_maybe_stored_cookies({});

  if (ShouldAddCookieHeader()) {
    // Since `request_->isolation_info()` hasn't changed, we don't need to
    // recompute the cookie partition key.
    AddCookieHeaderAndStart();
  } else {
    StartTransaction();
  }
}

void URLRequestHttpJob::RestartTransactionForRefresh() {
  RestartTransaction();
}

void URLRequestHttpJob::RestartTransactionWithAuth(
    const AuthCredentials& credentials) {
  auth_credentials_ = credentials;
  RestartTransaction();
}

void URLRequestHttpJob::SetUpload(UploadDataStream* upload) {
  DCHECK(!transaction_.get() && !override_response_info_)
      << "cannot change once started";
  request_info_.upload_data_stream = upload;
}

void URLRequestHttpJob::SetExtraRequestHeaders(
    const HttpRequestHeaders& headers) {
  DCHECK(!transaction_.get() && !override_response_info_)
      << "cannot change once started";
  request_info_.extra_headers = headers;
}

LoadState URLRequestHttpJob::GetLoadState() const {
  return transaction_.get() ?
      transaction_->GetLoadState() : LOAD_STATE_IDLE;
}

bool URLRequestHttpJob::GetMimeType(std::string* mime_type) const {
  DCHECK(transaction_.get() || override_response_info_);

  if (!response_info_)
    return false;

  HttpResponseHeaders* headers = GetResponseHeaders();
  if (!headers)
    return false;
  return headers->GetMimeType(mime_type);
}

bool URLRequestHttpJob::GetCharset(std::string* charset) {
  DCHECK(transaction_.get() || override_response_info_);

  if (!response_info_)
    return false;

  return GetResponseHeaders()->GetCharset(charset);
}

void URLRequestHttpJob::GetResponseInfo(HttpResponseInfo* info) {
  if (override_response_info_) {
    DCHECK(!transaction_.get());
    *info = *override_response_info_;
    return;
  }

  if (response_info_) {
    DCHECK(transaction_.get());

    *info = *response_info_;
    if (override_response_headers_.get())
      info->headers = override_response_headers_;
  }
}

void URLRequestHttpJob::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  // If haven't made it far enough to receive any headers, don't return
  // anything. This makes for more consistent behavior in the case of errors.
  if (!transaction_ || receive_headers_end_.is_null())
    return;
  if (transaction_->GetLoadTimingInfo(load_timing_info))
    load_timing_info->receive_headers_end = receive_headers_end_;
}

bool URLRequestHttpJob::GetTransactionRemoteEndpoint(
    IPEndPoint* endpoint) const {
  if (!transaction_)
    return false;

  return transaction_->GetRemoteEndpoint(endpoint);
}

int URLRequestHttpJob::GetResponseCode() const {
  DCHECK(transaction_.get());

  if (!response_info_)
    return -1;

  return GetResponseHeaders()->response_code();
}

void URLRequestHttpJob::PopulateNetErrorDetails(
    NetErrorDetails* details) const {
  if (!transaction_)
    return;
  return transaction_->PopulateNetErrorDetails(details);
}

std::unique_ptr<SourceStream> URLRequestHttpJob::SetUpSourceStream() {
  DCHECK(transaction_.get());
  if (!response_info_)
    return nullptr;

  std::unique_ptr<SourceStream> upstream = URLRequestJob::SetUpSourceStream();
  HttpResponseHeaders* headers = GetResponseHeaders();
  std::vector<SourceStream::SourceType> types;
  size_t iter = 0;
  while (std::optional<std::string_view> type =
             headers->EnumerateHeader(&iter, "Content-Encoding")) {
    SourceStream::SourceType source_type =
        FilterSourceStream::ParseEncodingType(*type);
    switch (source_type) {
      case SourceStream::TYPE_BROTLI:
      case SourceStream::TYPE_DEFLATE:
      case SourceStream::TYPE_GZIP:
      case SourceStream::TYPE_ZSTD:
        if (request_->accepted_stream_types() &&
            !request_->accepted_stream_types()->contains(source_type)) {
          // If the source type is disabled, we treat it
          // in the same way as SourceStream::TYPE_UNKNOWN.
          return upstream;
        }
        types.push_back(source_type);
        break;
      case SourceStream::TYPE_NONE:
        // Identity encoding type. Pass through raw response body.
        return upstream;
      case SourceStream::TYPE_UNKNOWN:
        // Unknown encoding type. Pass through raw response body.
        // Request will not be canceled; though
        // it is expected that user will see malformed / garbage response.
        return upstream;
    }
  }

  ContentEncodingType content_encoding_type = ContentEncodingType::kUnknown;

  for (const auto& type : base::Reversed(types)) {
    std::unique_ptr<FilterSourceStream> downstream;
    switch (type) {
      case SourceStream::TYPE_BROTLI:
        downstream = CreateBrotliSourceStream(std::move(upstream));
        content_encoding_type = ContentEncodingType::kBrotli;
        break;
      case SourceStream::TYPE_GZIP:
      case SourceStream::TYPE_DEFLATE:
        downstream = GzipSourceStream::Create(std::move(upstream), type);
        content_encoding_type = type == SourceStream::TYPE_GZIP
                                    ? ContentEncodingType::kGZip
                                    : ContentEncodingType::kDeflate;
        break;
      case SourceStream::TYPE_ZSTD:
        downstream = CreateZstdSourceStream(std::move(upstream));
        content_encoding_type = ContentEncodingType::kZstd;
        break;
      case SourceStream::TYPE_NONE:
      case SourceStream::TYPE_UNKNOWN:
        NOTREACHED();
    }
    if (downstream == nullptr)
      return nullptr;
    upstream = std::move(downstream);
  }

  // Note: If multiple encoding types were specified, this only records the last
  // encoding type.
  UMA_HISTOGRAM_ENUMERATION("Net.ContentEncodingType", content_encoding_type);

  return upstream;
}

bool URLRequestHttpJob::CopyFragmentOnRedirect(const GURL& location) const {
  // Allow modification of reference fragments by default, unless
  // |preserve_fragment_on_redirect_url_| is set and equal to the redirect URL.
  return !preserve_fragment_on_redirect_url_.has_value() ||
         preserve_fragment_on_redirect_url_ != location;
}

bool URLRequestHttpJob::IsSafeRedirect(const GURL& location) {
  // HTTP is always safe.
  // TODO(pauljensen): Remove once crbug.com/146591 is fixed.
  if (location.is_valid() &&
      (location.scheme() == "http" || location.scheme() == "https")) {
    return true;
  }
  // Query URLRequestJobFactory as to whether |location| would be safe to
  // redirect to.
  return request_->context()->job_factory() &&
      request_->context()->job_factory()->IsSafeRedirectTarget(location);
}

bool URLRequestHttpJob::NeedsAuth() {
  if (!transaction_.get()) {
    // If we synthesized a redirect (for `DNS_NAME_HTTPS_ONLY`, e.g.), we aren't
    // guaranteed to have a transaction here.
    return false;
  }
  int code = GetResponseCode();
  if (code == -1)
    return false;

  // Check if we need either Proxy or WWW Authentication. This could happen
  // because we either provided no auth info, or provided incorrect info.
  switch (code) {
    case 407:
      if (proxy_auth_state_ == AUTH_STATE_CANCELED)
        return false;
      proxy_auth_state_ = AUTH_STATE_NEED_AUTH;
      return true;
    case 401:
      if (server_auth_state_ == AUTH_STATE_CANCELED)
        return false;
      server_auth_state_ = AUTH_STATE_NEED_AUTH;
      return true;
  }
  return false;
}

bool URLRequestHttpJob::NeedsRetryWithStorageAccess() {
  // We use the Origin header's value directly, rather than
  // `request_.initiator()`, because the header may be "null" in some cases.
  if (!request_->response_headers() ||
      !request_->response_headers()->HasStorageAccessRetryHeader(
          base::OptionalToPtr(request_info_.extra_headers.GetHeader(
              HttpRequestHeaders::kOrigin)))) {
    return false;
  }

  auto determine_storage_access_retry_outcome =
      [&]() -> cookie_util::ActivateStorageAccessRetryOutcome {
    using enum cookie_util::ActivateStorageAccessRetryOutcome;
    if (!request_->network_delegate()->IsStorageAccessHeaderEnabled(
            base::OptionalToPtr(request_->isolation_info().top_frame_origin()),
            request_->url())) {
      return kFailureHeaderDisabled;
    }
    if (!ShouldAddCookieHeader() ||
        request_->storage_access_status() !=
            cookie_util::StorageAccessStatus::kInactive ||
        request_->cookie_setting_overrides().Has(
            CookieSettingOverride::kStorageAccessGrantEligible) ||
        request_->cookie_setting_overrides().Has(
            CookieSettingOverride::kStorageAccessGrantEligibleViaHeader)) {
      // We're not allowed to read cookies for this request, or this request
      // already had all the relevant settings overrides, so retrying it
      // wouldn't change anything.
      return kFailureIneffectiveRetry;
    }
    return kSuccess;
  };

  auto outcome = determine_storage_access_retry_outcome();

  base::UmaHistogramEnumeration(
      "API.StorageAccessHeader.ActivateStorageAccessRetryOutcome", outcome);
  return outcome == cookie_util::ActivateStorageAccessRetryOutcome::kSuccess;
}

void URLRequestHttpJob::SetSharedDictionaryGetter(
    SharedDictionaryGetter dictionary_getter) {
  CHECK(!request_info_.dictionary_getter);
  request_info_.dictionary_getter = std::move(dictionary_getter);
}

std::unique_ptr<AuthChallengeInfo> URLRequestHttpJob::GetAuthChallengeInfo() {
  DCHECK(transaction_.get());
  DCHECK(response_info_);

  // sanity checks:
  DCHECK(proxy_auth_state_ == AUTH_STATE_NEED_AUTH ||
         server_auth_state_ == AUTH_STATE_NEED_AUTH);
  DCHECK((GetResponseHeaders()->response_code() == HTTP_UNAUTHORIZED) ||
         (GetResponseHeaders()->response_code() ==
          HTTP_PROXY_AUTHENTICATION_REQUIRED));

  if (!response_info_->auth_challenge.has_value())
    return nullptr;
  return std::make_unique<AuthChallengeInfo>(
      response_info_->auth_challenge.value());
}

void URLRequestHttpJob::SetAuth(const AuthCredentials& credentials) {
  DCHECK(transaction_.get());

  // Proxy gets set first, then WWW.
  if (proxy_auth_state_ == AUTH_STATE_NEED_AUTH) {
    proxy_auth_state_ = AUTH_STATE_HAVE_AUTH;
  } else {
    DCHECK_EQ(server_auth_state_, AUTH_STATE_NEED_AUTH);
    server_auth_state_ = AUTH_STATE_HAVE_AUTH;
  }

  RestartTransactionWithAuth(credentials);
}

void URLRequestHttpJob::CancelAuth() {
  if (proxy_auth_state_ == AUTH_STATE_NEED_AUTH) {
    proxy_auth_state_ = AUTH_STATE_CANCELED;
  } else {
    DCHECK_EQ(server_auth_state_, AUTH_STATE_NEED_AUTH);
    server_auth_state_ = AUTH_STATE_CANCELED;
  }

  // The above lines should ensure this is the case.
  DCHECK(!NeedsAuth());

  // Let the consumer read the HTTP error page. NeedsAuth() should now return
  // false, so NotifyHeadersComplete() should not request auth from the client
  // again.
  //
  // Have to do this via PostTask to avoid re-entrantly calling into the
  // consumer.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&URLRequestHttpJob::NotifyFinalHeadersReceived,
                                weak_factory_.GetWeakPtr()));
}

void URLRequestHttpJob::ContinueWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key) {
  DCHECK(transaction_);

  DCHECK(!response_info_) << "should not have a response yet";
  DCHECK(!override_response_headers_);
  receive_headers_end_ = base::TimeTicks();

  ResetTimer();

  int rv = transaction_->RestartWithCertificate(
      std::move(client_cert), std::move(client_private_key),
      base::BindOnce(&URLRequestHttpJob::OnStartCompleted,
                     base::Unretained(this)));
  if (rv == ERR_IO_PENDING)
    return;

  // The transaction started synchronously, but we need to notify the
  // URLRequest delegate via the message loop.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&URLRequestHttpJob::OnStartCompleted,
                                weak_factory_.GetWeakPtr(), rv));
}

void URLRequestHttpJob::ContinueDespiteLastError() {
  // If the transaction was destroyed, then the job was cancelled.
  if (!transaction_.get())
    return;

  DCHECK(!response_info_) << "should not have a response yet";
  DCHECK(!override_response_headers_);
  receive_headers_end_ = base::TimeTicks();

  ResetTimer();

  int rv = transaction_->RestartIgnoringLastError(base::BindOnce(
      &URLRequestHttpJob::OnStartCompleted, base::Unretained(this)));
  if (rv == ERR_IO_PENDING)
    return;

  // The transaction started synchronously, but we need to notify the
  // URLRequest delegate via the message loop.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&URLRequestHttpJob::OnStartCompleted,
                                weak_factory_.GetWeakPtr(), rv));
}

bool URLRequestHttpJob::ShouldFixMismatchedContentLength(int rv) const {
  // Some servers send the body compressed, but specify the content length as
  // the uncompressed size. Although this violates the HTTP spec we want to
  // support it (as IE and FireFox do), but *only* for an ex
```