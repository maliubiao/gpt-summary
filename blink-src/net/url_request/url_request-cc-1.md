Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/url_request/url_request.cc` in Chromium's network stack. Specifically, they are asking for:

1. **General Functionality:** What does this code do?
2. **Relationship to JavaScript:** Does it interact with JavaScript, and if so, how?
3. **Logical Inference (with Input/Output):**  Are there logical decisions made? If so, provide example inputs and outputs.
4. **Common User/Programming Errors:** Are there common mistakes related to this code?
5. **User Operation to Reach Here (Debugging):** How does a user's action lead to this code being executed?
6. **Summary of Functionality:** A concise overview of the code's purpose.

Let's break down the code section by section and address each point:

**Code Analysis:**

The provided code snippet focuses on several key aspects of how a `URLRequest` handles redirects and retries, particularly in scenarios involving storage access.

* **`PrepareToRestart()`:** This function resets the state of a `URLRequest` in preparation for a new attempt, likely after a redirect or retry. It clears the previous job, response info, load timing, and sets the status back to `OK`.
* **`Redirect()`:** This is the core logic for handling HTTP redirects. It updates the request URL, method, headers, referrer, and other relevant attributes based on the redirect information. It also manages the redirect limit and initiates the new request with `Start()`. Crucially, it interacts with `NetworkDelegate` to notify about the redirect.
* **`RetryWithStorageAccess()`:** This function deals with retrying a request after potentially gaining storage access permissions. It sets specific cookie overrides and headers related to storage access, then restarts the request. It also updates the `url_chain_` and `redirect_limit_` similar to a redirect, to prevent infinite retry loops.
* **Getter Methods:**  Functions like `DefaultCanUseCookies()`, `context()`, `network_delegate()`, and `GetExpectedContentSize()` provide access to the `URLRequest`'s state and associated objects.
* **Setter Methods:**  Functions like `SetPriority()`, `SetPriorityIncremental()`, `SetRequestHeadersCallback()`, etc., allow modification of the `URLRequest`'s behavior and properties.
* **Notification Methods:**  Methods like `NotifyAuthRequired()`, `NotifyCertificateRequested()`, `NotifySSLCertificateError()`, and `NotifyReadCompleted()` inform the `delegate_` (typically the browser) about the progress and status of the request.
* **`OnHeadersComplete()`:** This method is called when the HTTP headers have been received. It captures load timing information.
* **`NotifyRequestCompleted()`:**  Called when the request is finished (success or failure). It notifies the `NetworkDelegate`.
* **`OnCallToDelegate()` and `OnCallToDelegateComplete()`:** These methods manage logging events around calls to the request's delegate.
* **`RecordReferrerGranularityMetrics()`:**  Collects metrics related to the referrer policy.
* **`CreateIsolationInfoFromNetworkAnonymizationKey()`:**  Creates `IsolationInfo` based on the `NetworkAnonymizationKey`.
* **`GetConnectionAttempts()`:** Returns the connection attempts made for the request.
* **Callback Setters:** Functions like `SetRequestHeadersCallback()` allow setting callbacks to be invoked at specific points in the request lifecycle.
* **`CalculateStorageAccessStatus()`:** Determines the storage access status for the request, potentially involving the `NetworkDelegate`.
* **`SetSharedDictionaryGetter()`:**  Sets a getter for shared dictionaries.
* **`GetWeakPtr()`:** Provides a weak pointer to the `URLRequest` object.

**Addressing the User's Points:**

1. **Functionality:** The code manages the lifecycle of a network request, specifically focusing on handling redirects, retries (especially for storage access), and interactions with the `NetworkDelegate`. It's responsible for updating the request's state, modifying headers, and notifying the delegate about significant events.

2. **Relationship to JavaScript:**
   * **Indirect Relationship:**  While this specific C++ code doesn't directly execute JavaScript, it's a crucial part of the network stack that underlies web browsing. When JavaScript in a web page initiates a network request (e.g., using `fetch()` or `XMLHttpRequest`), the browser's rendering engine eventually uses the Chromium network stack, including `URLRequest`, to perform the actual network communication.
   * **Example:**  If a JavaScript `fetch()` call results in a 302 redirect, this `Redirect()` function in the C++ code would be executed to handle the redirection. The new URL provided in the redirect response would be used to create a new request. Similarly, if a website attempts to access cookies in a cross-site context and needs storage access, the `RetryWithStorageAccess()` function might be invoked based on the browser's storage access policy, ultimately triggered by JavaScript's interaction with the DOM and cookies.

3. **Logical Inference (Input/Output):**
   * **`Redirect()`:**
      * **Input:** `redirect_info` containing the new URL ("https://example.com/new_page"), new method ("GET"), etc. The current `url()` is "https://original.com/old_page".
      * **Output:** The `URLRequest`'s `url()` is updated to "https://example.com/new_page". The `method_` is updated to "GET". A new network request is initiated to the new URL.
   * **`RetryWithStorageAccess()`:**
      * **Input:** The initial request to "https://some-embedded-site.com" was denied cookie access in a cross-site context.
      * **Output:** The `URLRequest`'s cookie overrides are modified to include `kStorageAccessGrantEligibleViaHeader`. The "Sec-Fetch-Storage-Access: active" header is added. The request is restarted, potentially prompting the browser to ask the user for storage access permission or automatically granting it based on policy.

4. **Common User/Programming Errors:**
   * **Incorrect Redirect Handling on the Server:**  A server might send an incorrect redirect URL or an infinite redirect loop. The `redirect_limit_` in the `URLRequest` helps prevent the browser from getting stuck in such loops.
   * **Client-Side Misconfiguration of Storage Access:** While not directly in this code, developers might misunderstand browser storage access policies and expect cookies to be available in cross-site contexts without proper configuration (e.g., using the Storage Access API). This code is involved in the *retry* mechanism after a potential storage access grant, indicating a prior failure due to access restrictions.
   * **Unexpected Network Delegate Behavior:** A custom `NetworkDelegate` could be implemented incorrectly, potentially blocking redirects or interfering with the storage access retry logic in unexpected ways.

5. **User Operation to Reach Here (Debugging):**
   * **Simple Redirect:** A user clicks a link on a webpage, or JavaScript code navigates the page to a URL that results in an HTTP redirect (e.g., a 301, 302, 307, or 308 response from the server). The browser receives this redirect response, and the `Redirect()` function in `URLRequest` is called to handle the navigation to the new URL.
   * **Storage Access Request:**
      1. A user visits `https://main-site.com`.
      2. `https://main-site.com` embeds content from `https://embedded-site.com`.
      3. JavaScript on `https://embedded-site.com` tries to access its cookies.
      4. The browser's cookie policy blocks the access because it's a cross-site request.
      5. The server for `https://embedded-site.com` might respond with a header indicating it's eligible for a storage access grant.
      6. The browser might then call `RetryWithStorageAccess()` to attempt the request again with the appropriate headers, potentially triggering a user prompt for permission or automatically granting access based on policy.

6. **Summary of Functionality:** This section of `URLRequest.cc` handles the core logic for redirecting network requests and retrying requests when storage access permissions are involved. It updates the request state, manages headers, and interacts with the `NetworkDelegate` to inform the browser about these events.

**Final Summary for Part 2:**

This part of `net/url_request/url_request.cc` primarily focuses on the mechanisms for handling redirections and retries, particularly in the context of storage access. It provides methods to prepare for a restart of a request, to process redirect information and initiate a new request, and to retry requests with modified headers when storage access is potentially granted. This functionality is crucial for the correct behavior of web navigation and for managing cross-site resource access according to browser security policies.

好的，这是对`net/url_request/url_request.cc` 文件第二部分的归纳总结：

**功能归纳:**

这段代码主要负责处理 `URLRequest` 在以下场景下的状态变更和操作：

1. **重定向 (Redirection):**
   - 提供了 `PrepareToRestart()` 方法，用于在发起新的请求之前重置 `URLRequest` 的状态，例如清除之前的 job，response info 和 load timing。
   - 实现了 `Redirect()` 方法，当收到服务器的重定向响应时被调用。它会更新 `URLRequest` 的 URL、方法、header 等信息，并根据重定向信息发起新的请求。
   - 在重定向过程中会通知 `NetworkDelegate`。
   - 考虑了跨域重定向对 Shared Dictionary 的影响。

2. **存储访问重试 (Retry with Storage Access):**
   - 实现了 `RetryWithStorageAccess()` 方法，用于在因缺乏存储访问权限而被拒绝后，尝试重新发起请求。
   - 这个方法会设置特定的 cookie 覆盖选项 (`CookieSettingOverride`)，添加 `Sec-Fetch-Storage-Access` 请求头，并重新启动请求。
   - 也会更新 `url_chain_` 和递减 `redirect_limit_`，以避免无限重试。
   - 在重试之前会通知 `NetworkDelegate`。

3. **请求属性的设置和获取:**
   - 提供了获取 `URLRequestContext` 和 `NetworkDelegate` 的方法。
   - 提供了获取期望的内容大小 (`GetExpectedContentSize()`) 的方法。
   - 提供了设置请求优先级 (`SetPriority()`) 和优先级增量 (`SetPriorityIncremental()`) 的方法。

4. **通知代理 (Delegate Notification):**
   - 提供了在需要身份验证时通知代理 (`NotifyAuthRequired()`) 的方法。
   - 提供了在需要客户端证书时通知代理 (`NotifyCertificateRequested()`) 的方法。
   - 提供了在 SSL 证书出现错误时通知代理 (`NotifySSLCertificateError()`) 的方法。
   - 提供了在读取完成时通知代理 (`NotifyReadCompleted()`) 的方法。
   - 实现了 `OnHeadersComplete()` 方法，在接收到完整的 HTTP 头部后被调用，用于记录加载时间信息。
   - 实现了 `NotifyRequestCompleted()` 方法，在请求完成时通知代理。
   - 提供了 `OnCallToDelegate()` 和 `OnCallToDelegateComplete()` 方法，用于标记和记录对代理的回调。

5. **Cookie 处理:**
   - 提供了 `CanSetCookie()` 方法，用于判断是否可以设置 Cookie，并会咨询 `NetworkDelegate`。

6. **请求完成处理:**
   - 实现了 `NotifyRequestCompleted()` 方法，标记请求完成，并通知 `NetworkDelegate`。

7. **Referrer 处理:**
   - 实现了 `RecordReferrerGranularityMetrics()` 方法，用于记录 Referrer 相关的指标。

8. **隔离信息 (Isolation Info):**
   - 提供了 `CreateIsolationInfoFromNetworkAnonymizationKey()` 方法，根据 `NetworkAnonymizationKey` 创建 `IsolationInfo` 对象。

9. **连接尝试 (Connection Attempts):**
   - 提供了 `GetConnectionAttempts()` 方法，用于获取请求的连接尝试次数。

10. **回调函数设置:**
    - 提供了设置请求头部回调 (`SetRequestHeadersCallback()`)、响应头部回调 (`SetResponseHeadersCallback()` 和 `SetEarlyResponseHeadersCallback()`)、Shared Dictionary 读取允许回调 (`SetIsSharedDictionaryReadAllowedCallback()`) 和设备绑定会话访问回调 (`SetDeviceBoundSessionAccessCallback()`) 的方法。

11. **Socket Tag 设置:**
    - 提供了设置 Socket Tag (`set_socket_tag()`) 的方法。

12. **存储访问状态计算:**
    - 提供了 `CalculateStorageAccessStatus()` 方法，用于计算存储访问状态。

13. **Shared Dictionary Getter 设置:**
    - 提供了 `SetSharedDictionaryGetter()` 方法，用于设置 Shared Dictionary 的获取器。

14. **获取 WeakPtr:**
    - 提供了 `GetWeakPtr()` 方法，用于获取指向 `URLRequest` 对象的弱指针。

**与 JavaScript 的关系举例:**

当 JavaScript 代码发起一个网络请求（例如使用 `fetch()` API）并且服务器返回一个 HTTP 重定向状态码（如 301 或 302）时，Chromium 的网络栈会调用 `URLRequest::Redirect()` 方法来处理这个重定向。

**假设输入与输出 (逻辑推理):**

**场景：处理 HTTP 重定向**

* **假设输入:**
    * 当前请求的 URL 是 `https://example.com/page1`
    * 服务器返回的重定向响应包含：
        * 状态码：302 Found
        * `Location` 头部：`https://example.com/page2`
        * 重定向方法：`GET`
* **输出:**
    * `URLRequest` 对象的内部 URL 被更新为 `https://example.com/page2`。
    * `URLRequest` 对象的方法被更新为 `GET`。
    * `url_chain_` 列表中添加了 `https://example.com/page2`。
    * 网络栈会发起一个新的请求到 `https://example.com/page2`。

**场景：尝试存储访问重试**

* **假设输入:**
    * 当前请求的 URL 是 `https://embed.example.com/resource`，嵌入在 `https://main.example.com` 中。
    * 尝试访问 `https://embed.example.com` 的 Cookie 被浏览器阻止（跨域 Cookie 访问限制）。
    * 服务器响应包含指示可以请求存储访问权限的头部 (可能需要 `NetworkDelegate` 的参与来判断)。
* **输出:**
    * `URLRequest` 的 `cookie_setting_overrides()` 会包含 `CookieSettingOverride::kStorageAccessGrantEligibleViaHeader`。
    * 请求头部会添加 `Sec-Fetch-Storage-Access: active`。
    * 网络栈会重新发起对 `https://embed.example.com/resource` 的请求，这次请求会携带存储访问相关的头部，可能会触发浏览器弹窗询问用户是否允许存储访问。

**用户或编程常见的使用错误举例:**

1. **服务器配置错误导致无限重定向:**  如果服务器配置错误，导致重定向指向自身或其他导致循环的地址，`URLRequest` 会持续调用 `Redirect()` 方法，直到达到 `redirect_limit_`，然后请求会失败。
   * **用户操作:** 点击一个错误的链接或访问一个配置错误的网站。
   * **调试线索:** 在 Network 面板中可以看到一系列相同的请求，状态码是重定向状态码 (3xx)。

2. **不理解存储访问策略导致请求失败:** 开发者可能期望在跨域情况下直接访问 Cookie，而没有意识到需要请求存储访问权限。
   * **用户操作:** 访问一个嵌入了来自其他域的内容的网站，并且该嵌入内容尝试访问其自身的 Cookie。
   * **调试线索:** 在 Network 面板中可以看到请求因为缺乏凭据而被拒绝，并且可能会看到 `RetryWithStorageAccess()` 被调用。

**用户操作如何一步步的到达这里 (调试线索):**

以一个简单的 HTTP 重定向为例：

1. **用户在浏览器地址栏输入一个 URL，或者点击网页上的一个链接。**
2. **浏览器解析 URL，并创建一个 `URLRequest` 对象。**
3. **网络栈开始处理这个 `URLRequest`，向服务器发送请求。**
4. **服务器返回一个 HTTP 重定向响应 (例如 302 Found)，并在 `Location` 头部指定了新的 URL。**
5. **网络栈接收到重定向响应，并调用 `URLRequest::Redirect()` 方法。**
6. **`Redirect()` 方法会更新 `URLRequest` 的状态，并将新的 URL 添加到请求链中。**
7. **`Redirect()` 方法会调用 `Start()` 方法来发起对新 URL 的请求。**

在开发者工具的 Network 面板中，可以看到原始请求和后续的重定向请求。点击请求可以看到详细的请求头和响应头，可以确认是否发生了重定向以及重定向的目标 URL。  使用 Chromium 的 `net-internals` 工具 (chrome://net-internals/#events) 可以更详细地追踪 `URLRequest` 的生命周期和发生的事件，包括 `URL_REQUEST_REDIRECTED` 事件。

总而言之，这段代码是 Chromium 网络栈中处理网络请求重定向和特定重试逻辑的关键部分，确保了浏览器能够正确处理服务器的重定向指令，并为跨域资源访问提供了一种受控的重试机制。

Prompt: 
```
这是目录为net/url_request/url_request.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
est::PrepareToRestart() {
  DCHECK(job_.get());

  // Close the current URL_REQUEST_START_JOB, since we will be starting a new
  // one.
  net_log_.EndEvent(NetLogEventType::URL_REQUEST_START_JOB);

  job_.reset();

  response_info_ = HttpResponseInfo();
  response_info_.request_time = base::Time::Now();

  load_timing_info_ = LoadTimingInfo();
  load_timing_info_.request_start_time = response_info_.request_time;
  load_timing_info_.request_start = base::TimeTicks::Now();

  status_ = OK;
  is_pending_ = false;
  proxy_chain_ = ProxyChain();
}

void URLRequest::Redirect(
    const RedirectInfo& redirect_info,
    const std::optional<std::vector<std::string>>& removed_headers,
    const std::optional<net::HttpRequestHeaders>& modified_headers) {
  // This method always succeeds. Whether |job_| is allowed to redirect to
  // |redirect_info| is checked in URLRequestJob::CanFollowRedirect, before
  // NotifyReceivedRedirect. This means the delegate can assume that, if it
  // accepted the redirect, future calls to OnResponseStarted correspond to
  // |redirect_info.new_url|.
  OnCallToDelegateComplete();
  if (net_log_.IsCapturing()) {
    net_log_.AddEventWithStringParams(
        NetLogEventType::URL_REQUEST_REDIRECTED, "location",
        redirect_info.new_url.possibly_invalid_spec());
  }

  if (network_delegate())
    network_delegate()->NotifyBeforeRedirect(this, redirect_info.new_url);

  if (!final_upload_progress_.position() && upload_data_stream_)
    final_upload_progress_ = upload_data_stream_->GetUploadProgress();
  PrepareToRestart();

  bool clear_body = false;
  net::RedirectUtil::UpdateHttpRequest(url(), method_, redirect_info,
                                       removed_headers, modified_headers,
                                       &extra_request_headers_, &clear_body);
  if (clear_body)
    upload_data_stream_.reset();

  method_ = redirect_info.new_method;
  referrer_ = redirect_info.new_referrer;
  referrer_policy_ = redirect_info.new_referrer_policy;
  site_for_cookies_ = redirect_info.new_site_for_cookies;
  set_isolation_info(isolation_info_.CreateForRedirect(
                         url::Origin::Create(redirect_info.new_url)),
                     redirect_info.new_url);

  if ((load_flags() & LOAD_CAN_USE_SHARED_DICTIONARY) &&
      (load_flags() &
       LOAD_DISABLE_SHARED_DICTIONARY_AFTER_CROSS_ORIGIN_REDIRECT) &&
      !url::Origin::Create(url()).IsSameOriginWith(redirect_info.new_url)) {
    partial_load_flags_ &= ~LOAD_CAN_USE_SHARED_DICTIONARY;
  }

  url_chain_.push_back(redirect_info.new_url);
  --redirect_limit_;

  Start();
}

void URLRequest::RetryWithStorageAccess() {
  CHECK(!cookie_setting_overrides().Has(
      CookieSettingOverride::kStorageAccessGrantEligibleViaHeader));
  CHECK(!cookie_setting_overrides().Has(
      CookieSettingOverride::kStorageAccessGrantEligible));

  net_log_.AddEvent(NetLogEventType::URL_REQUEST_RETRY_WITH_STORAGE_ACCESS);
  if (network_delegate()) {
    network_delegate()->NotifyBeforeRetry(this);
  }

  // TODO(https://crbug.com/366284840): this state mutation should reuse the
  // Sec- header helpers at a higher layer, not within //net.
  cookie_setting_overrides().Put(
      CookieSettingOverride::kStorageAccessGrantEligibleViaHeader);
  set_per_hop_load_flags(LOAD_BYPASS_CACHE);
  set_storage_access_status(CalculateStorageAccessStatus());
  // This code is only reachable if the status was previously "inactive", which
  // implies that the URL is "potentially trustworthy" and that adding the
  // `kStorageAccessGrantEligibleViaHeader` override is sufficient to make the
  // status "active".
  CHECK(storage_access_status());
  CHECK_EQ(static_cast<int>(storage_access_status().value()),
           static_cast<int>(cookie_util::StorageAccessStatus::kActive));
  extra_request_headers_.SetHeader("Sec-Fetch-Storage-Access", "active");
  base::UmaHistogramEnumeration(
      "API.StorageAccessHeader.SecFetchStorageAccessOutcome",
      cookie_util::SecFetchStorageAccessOutcome::kValueActive);

  if (!final_upload_progress_.position() && upload_data_stream_) {
    final_upload_progress_ = upload_data_stream_->GetUploadProgress();
  }
  PrepareToRestart();

  // This isn't really a proper redirect, but we add to the `url_chain_` and
  // count it against the redirect limit anyway, to avoid unbounded retries.
  url_chain_.push_back(url());
  --redirect_limit_;

  Start();
}

// static
bool URLRequest::DefaultCanUseCookies() {
  return g_default_can_use_cookies;
}

const URLRequestContext* URLRequest::context() const {
  return context_;
}

NetworkDelegate* URLRequest::network_delegate() const {
  return context_->network_delegate();
}

int64_t URLRequest::GetExpectedContentSize() const {
  int64_t expected_content_size = -1;
  if (job_.get())
    expected_content_size = job_->expected_content_size();

  return expected_content_size;
}

void URLRequest::SetPriority(RequestPriority priority) {
  DCHECK_GE(priority, MINIMUM_PRIORITY);
  DCHECK_LE(priority, MAXIMUM_PRIORITY);

  if ((load_flags() & LOAD_IGNORE_LIMITS) && (priority != MAXIMUM_PRIORITY)) {
    NOTREACHED();
  }

  if (priority_ == priority)
    return;

  priority_ = priority;
  net_log_.AddEventWithStringParams(NetLogEventType::URL_REQUEST_SET_PRIORITY,
                                    "priority",
                                    RequestPriorityToString(priority_));
  if (job_.get())
    job_->SetPriority(priority_);
}

void URLRequest::SetPriorityIncremental(bool priority_incremental) {
  priority_incremental_ = priority_incremental;
}

void URLRequest::NotifyAuthRequired(
    std::unique_ptr<AuthChallengeInfo> auth_info) {
  DCHECK_EQ(OK, status_);
  DCHECK(auth_info);
  // Check that there are no callbacks to already failed or cancelled requests.
  DCHECK(!failed());

  delegate_->OnAuthRequired(this, *auth_info.get());
}

void URLRequest::NotifyCertificateRequested(
    SSLCertRequestInfo* cert_request_info) {
  status_ = OK;

  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_CERTIFICATE_REQUESTED);
  delegate_->OnCertificateRequested(this, cert_request_info);
}

void URLRequest::NotifySSLCertificateError(int net_error,
                                           const SSLInfo& ssl_info,
                                           bool fatal) {
  status_ = OK;
  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_SSL_CERTIFICATE_ERROR);
  delegate_->OnSSLCertificateError(this, net_error, ssl_info, fatal);
}

bool URLRequest::CanSetCookie(
    const net::CanonicalCookie& cookie,
    CookieOptions* options,
    const net::FirstPartySetMetadata& first_party_set_metadata,
    CookieInclusionStatus* inclusion_status) const {
  DCHECK(!(load_flags() & LOAD_DO_NOT_SAVE_COOKIES));
  bool can_set_cookies = g_default_can_use_cookies;
  if (network_delegate()) {
    can_set_cookies = network_delegate()->CanSetCookie(
        *this, cookie, options, first_party_set_metadata, inclusion_status);
  }
  if (!can_set_cookies)
    net_log_.AddEvent(NetLogEventType::COOKIE_SET_BLOCKED_BY_NETWORK_DELEGATE);
  return can_set_cookies;
}

void URLRequest::NotifyReadCompleted(int bytes_read) {
  if (bytes_read > 0)
    set_status(OK);
  // Notify in case the entire URL Request has been finished.
  if (bytes_read <= 0)
    NotifyRequestCompleted();

  // When URLRequestJob notices there was an error in URLRequest's |status_|,
  // it calls this method with |bytes_read| set to -1. Set it to a real error
  // here.
  // TODO(maksims): NotifyReadCompleted take the error code as an argument on
  // failure, rather than -1.
  if (bytes_read == -1) {
    // |status_| should indicate an error.
    DCHECK(failed());
    bytes_read = status_;
  }

  delegate_->OnReadCompleted(this, bytes_read);

  // Nothing below this line as OnReadCompleted may delete |this|.
}

void URLRequest::OnHeadersComplete() {
  // The URLRequest status should still be IO_PENDING, which it was set to
  // before the URLRequestJob was started.  On error or cancellation, this
  // method should not be called.
  DCHECK_EQ(ERR_IO_PENDING, status_);
  set_status(OK);
  // Cache load timing information now, as information will be lost once the
  // socket is closed and the ClientSocketHandle is Reset, which will happen
  // once the body is complete.  The start times should already be populated.
  if (job_.get()) {
    // Keep a copy of the two times the URLRequest sets.
    base::TimeTicks request_start = load_timing_info_.request_start;
    base::Time request_start_time = load_timing_info_.request_start_time;

    // Clear load times.  Shouldn't be neded, but gives the GetLoadTimingInfo a
    // consistent place to start from.
    load_timing_info_ = LoadTimingInfo();
    job_->GetLoadTimingInfo(&load_timing_info_);

    load_timing_info_.request_start = request_start;
    load_timing_info_.request_start_time = request_start_time;

    ConvertRealLoadTimesToBlockingTimes(&load_timing_info_);
  }
}

void URLRequest::NotifyRequestCompleted() {
  // TODO(battre): Get rid of this check, according to willchan it should
  // not be needed.
  if (has_notified_completion_)
    return;

  is_pending_ = false;
  is_redirecting_ = false;
  deferred_redirect_info_.reset();
  has_notified_completion_ = true;
  if (network_delegate())
    network_delegate()->NotifyCompleted(this, job_.get() != nullptr, status_);
}

void URLRequest::OnCallToDelegate(NetLogEventType type) {
  DCHECK(!calling_delegate_);
  DCHECK(blocked_by_.empty());
  calling_delegate_ = true;
  delegate_event_type_ = type;
  net_log_.BeginEvent(type);
}

void URLRequest::OnCallToDelegateComplete(int error) {
  // This should have been cleared before resuming the request.
  DCHECK(blocked_by_.empty());
  if (!calling_delegate_)
    return;
  calling_delegate_ = false;
  net_log_.EndEventWithNetErrorCode(delegate_event_type_, error);
  delegate_event_type_ = NetLogEventType::FAILED;
}

void URLRequest::RecordReferrerGranularityMetrics(
    bool request_is_same_origin) const {
  GURL referrer_url(referrer_);
  bool referrer_more_descriptive_than_its_origin =
      referrer_url.is_valid() && referrer_url.PathForRequestPiece().size() > 1;

  // To avoid renaming the existing enum, we have to use the three-argument
  // histogram macro.
  if (request_is_same_origin) {
    UMA_HISTOGRAM_ENUMERATION(
        "Net.URLRequest.ReferrerPolicyForRequest.SameOrigin", referrer_policy_,
        static_cast<int>(ReferrerPolicy::MAX) + 1);
    UMA_HISTOGRAM_BOOLEAN(
        "Net.URLRequest.ReferrerHasInformativePath.SameOrigin",
        referrer_more_descriptive_than_its_origin);
  } else {
    UMA_HISTOGRAM_ENUMERATION(
        "Net.URLRequest.ReferrerPolicyForRequest.CrossOrigin", referrer_policy_,
        static_cast<int>(ReferrerPolicy::MAX) + 1);
    UMA_HISTOGRAM_BOOLEAN(
        "Net.URLRequest.ReferrerHasInformativePath.CrossOrigin",
        referrer_more_descriptive_than_its_origin);
  }
}

IsolationInfo URLRequest::CreateIsolationInfoFromNetworkAnonymizationKey(
    const NetworkAnonymizationKey& network_anonymization_key) {
  if (!network_anonymization_key.IsFullyPopulated()) {
    return IsolationInfo();
  }

  url::Origin top_frame_origin =
      network_anonymization_key.GetTopFrameSite()->site_as_origin_;

  std::optional<url::Origin> frame_origin;
  if (network_anonymization_key.IsCrossSite()) {
    // If we know that the origin is cross site to the top level site, create an
    // empty origin to use as the frame origin for the isolation info. This
    // should be cross site with the top level origin.
    frame_origin = url::Origin();
  } else {
    // If we don't know that it's cross site to the top level site, use the top
    // frame site to set the frame origin.
    frame_origin = top_frame_origin;
  }

  auto isolation_info = IsolationInfo::Create(
      IsolationInfo::RequestType::kOther, top_frame_origin,
      frame_origin.value(), SiteForCookies(),
      network_anonymization_key.GetNonce());
  // TODO(crbug.com/40852603): DCHECK isolation info is fully populated.
  return isolation_info;
}

ConnectionAttempts URLRequest::GetConnectionAttempts() const {
  if (job_)
    return job_->GetConnectionAttempts();
  return {};
}

void URLRequest::SetRequestHeadersCallback(RequestHeadersCallback callback) {
  DCHECK(!job_.get());
  DCHECK(request_headers_callback_.is_null());
  request_headers_callback_ = std::move(callback);
}

void URLRequest::SetResponseHeadersCallback(ResponseHeadersCallback callback) {
  DCHECK(!job_.get());
  DCHECK(response_headers_callback_.is_null());
  response_headers_callback_ = std::move(callback);
}

void URLRequest::SetEarlyResponseHeadersCallback(
    ResponseHeadersCallback callback) {
  DCHECK(!job_.get());
  DCHECK(early_response_headers_callback_.is_null());
  early_response_headers_callback_ = std::move(callback);
}

void URLRequest::SetIsSharedDictionaryReadAllowedCallback(
    base::RepeatingCallback<bool()> callback) {
  DCHECK(!job_.get());
  DCHECK(is_shared_dictionary_read_allowed_callback_.is_null());
  is_shared_dictionary_read_allowed_callback_ = std::move(callback);
}

void URLRequest::SetDeviceBoundSessionAccessCallback(
    base::RepeatingCallback<void(const device_bound_sessions::SessionKey&)>
        callback) {
  device_bound_session_access_callback_ = std::move(callback);
}

void URLRequest::set_socket_tag(const SocketTag& socket_tag) {
  DCHECK(!is_pending_);
  DCHECK(url().SchemeIsHTTPOrHTTPS());
  socket_tag_ = socket_tag;
}
std::optional<net::cookie_util::StorageAccessStatus>
URLRequest::CalculateStorageAccessStatus(
    base::optional_ref<const RedirectInfo> redirect_info) const {
  std::optional<net::cookie_util::StorageAccessStatus> storage_access_status =
      network_delegate()->GetStorageAccessStatus(*this, redirect_info);

  auto get_storage_access_value_outcome_if_omitted =
      [&]() -> std::optional<net::cookie_util::StorageAccessStatusOutcome> {
    if (!network_delegate()->IsStorageAccessHeaderEnabled(
            base::OptionalToPtr(isolation_info().top_frame_origin()), url())) {
      return net::cookie_util::StorageAccessStatusOutcome::
          kOmittedFeatureDisabled;
    }
    if (!storage_access_status) {
      return net::cookie_util::StorageAccessStatusOutcome::kOmittedSameSite;
    }
    return std::nullopt;
  };

  auto storage_access_value_outcome =
      get_storage_access_value_outcome_if_omitted();
  if (storage_access_value_outcome) {
    storage_access_status = std::nullopt;
  } else {
    storage_access_value_outcome =
        ConvertSecFetchStorageAccessHeaderValueToOutcome(
            storage_access_status.value());
  }

  base::UmaHistogramEnumeration(
      "API.StorageAccessHeader.StorageAccessStatusOutcome",
      storage_access_value_outcome.value());

  return storage_access_status;
}

void URLRequest::SetSharedDictionaryGetter(
    SharedDictionaryGetter shared_dictionary_getter) {
  CHECK(!job_.get());
  CHECK(shared_dictionary_getter_.is_null());
  shared_dictionary_getter_ = std::move(shared_dictionary_getter);
}

base::WeakPtr<URLRequest> URLRequest::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

}  // namespace net

"""


```