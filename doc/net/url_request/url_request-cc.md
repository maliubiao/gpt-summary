Response:
The user wants a summary of the functionality of the `url_request.cc` file in Chromium's network stack. I need to extract the core responsibilities and features implemented in this file based on the provided code snippet. I should also look for any connections to JavaScript, logical reasoning (and provide examples), potential user/programming errors, and how a user action leads to this code.

**Core Functionality Identification:**

- The file defines the `URLRequest` class.
- `URLRequest` represents a request for a URL.
- It manages the lifecycle of a request, including starting, redirecting, authentication, error handling, and reading data.
- It interacts with a `URLRequestJob` to handle the actual network communication.
- It uses a `URLRequestContext` to get necessary dependencies.
- It communicates with a `Delegate` to inform about request progress and decisions.
- It deals with HTTP headers, cookies, and security aspects like SSL.
- It logs events for debugging.

**JavaScript Relationship:**

- JavaScript in a web page initiates network requests (e.g., `fetch`, `XMLHttpRequest`).
- These JavaScript APIs eventually trigger the creation of `URLRequest` objects in the browser's networking stack.

**Logical Reasoning:**

- The code makes decisions based on the state of the request (e.g., handling redirects, authentication challenges).

**User/Programming Errors:**

- Incorrect usage of the `URLRequest` API can lead to errors (e.g., calling methods in the wrong order).

**User Actions:**

- Typing a URL in the address bar.
- Clicking a link.
- JavaScript making a network request.

**Plan:**

1. Summarize the main purpose of the `URLRequest` class and the `url_request.cc` file.
2. Provide a JavaScript example that triggers a `URLRequest`.
3. Give a simple logical inference example within the code.
4. Illustrate a common user or programming error.
5. Explain how a user action leads to this code.
```
这是目录为net/url_request/url_request.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**`net/url_request/url_request.cc` (第1部分) 的功能归纳:**

这个文件是 Chromium 网络栈中 `URLRequest` 类的主要实现。`URLRequest` 类是 Chromium 网络请求的核心抽象，它负责管理和协调一个网络请求的整个生命周期。

**主要功能包括:**

1. **请求的创建和配置:**
   -  允许创建指定 URL、请求方法 (GET, POST 等)、优先级、委托 (Delegate) 等属性的 `URLRequest` 对象。
   -  可以设置额外的请求头 (`SetExtraRequestHeaderByName`, `SetExtraRequestHeaders`)。
   -  支持设置上传数据 (`set_upload`)。
   -  可以设置加载标志 (`SetLoadFlags`) 来控制请求的行为，例如是否使用缓存、是否忽略限制等。
   -  支持设置安全 DNS 策略 (`SetSecureDnsPolicy`)。
   -  允许设置与 Cookie 相关的策略，如 `site_for_cookies`、`isolation_info` 等。
   -  可以设置请求的发起者 (`set_initiator`) 和 Referrer 信息 (`SetReferrer`, `set_referrer_policy`)。

2. **请求的启动和生命周期管理:**
   -  `Start()` 方法启动网络请求。
   -  管理请求的状态 (例如，是否挂起 `is_pending_`) 和错误状态 (`status_`)。
   -  处理网络委托 (`NetworkDelegate`) 的通知，例如 `NotifyBeforeURLRequest`。
   -  与 `URLRequestJob` 交互，`URLRequestJob` 负责实际的网络传输。

3. **重定向处理:**
   -  处理服务器返回的重定向响应 (`ReceivedRedirect`)。
   -  允许委托决定是否跟随重定向 (`defer_redirect`)。
   -  提供 `FollowDeferredRedirect` 方法来继续被延迟的重定向。

4. **认证处理:**
   -  处理服务器返回的认证挑战 (`OnAuthRequired`)。
   -  允许设置认证信息 (`SetAuth`) 和取消认证 (`CancelAuth`)。

5. **SSL 证书处理:**
   -  处理客户端证书请求 (`OnCertificateRequested`)。
   -  处理 SSL 证书错误 (`OnSSLCertificateError`)，并允许用户忽略错误 (`ContinueDespiteLastError`)。

6. **数据读取:**
   -  提供 `Read()` 方法从网络连接读取数据。
   -  跟踪接收到的字节数 (`GetTotalReceivedBytes`, `GetRawBodyBytes`)。

7. **响应信息获取:**
   -  可以获取响应头 (`GetResponseHeaderByName`, `response_headers`)。
   -  可以获取响应状态码 (`GetResponseCode`)。
   -  可以获取远程端点信息 (`GetResponseRemoteEndpoint`, `GetTransactionRemoteEndpoint`)。
   -  可以获取 MIME 类型和字符集 (`GetMimeType`, `GetCharset`)。
   -  可以获取加载时间信息 (`GetLoadTimingInfo`)。

8. **请求取消:**
   -  提供 `Cancel()` 和 `CancelWithError()` 方法来取消请求。

9. **NetLog 集成:**
   -  使用 `net_log_` 记录请求的各个阶段和事件，用于调试和性能分析。

10. **Cookie 管理辅助:**
    - 存储可能发送和存储的 Cookie 信息 (`set_maybe_sent_cookies`, `set_maybe_stored_cookies`)。

**与 JavaScript 的关系举例:**

当 JavaScript 代码在网页中发起一个网络请求时，例如使用 `fetch` API：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

或者使用 `XMLHttpRequest`：

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://example.com/api/items');
xhr.onload = function() {
  if (xhr.status >= 200 && xhr.status < 300) {
    console.log(xhr.responseText);
  }
};
xhr.send();
```

这些 JavaScript API 调用最终会触发 Chromium 渲染进程（Renderer Process）向浏览器进程（Browser Process）发送消息，指示需要发起一个网络请求。浏览器进程的网络服务组件会创建一个 `URLRequest` 对象来处理这个请求。`URLRequest` 对象会根据请求的 URL、方法等信息，以及浏览器自身的配置和策略，启动网络连接，接收响应数据，并将数据返回给渲染进程，最终传递给 JavaScript 代码。

**逻辑推理的假设输入与输出举例:**

**假设输入:**

- `URLRequest` 对象请求的 URL 是 `https://redirect.example.com/page1`。
- 服务器在 `https://redirect.example.com/page1` 返回一个 HTTP 302 重定向到 `https://final.example.com/page2`。

**代码中的逻辑推理（简化）：**

当 `URLRequestJob` 接收到 302 响应时，会调用 `URLRequest::ReceivedRedirect`。

**输出:**

- `URLRequest::ReceivedRedirect` 会创建一个 `RedirectInfo` 对象，包含新的 URL (`https://final.example.com/page2`) 和其他重定向信息。
- 如果委托允许重定向（`defer_redirect` 为 `false`），则会创建一个新的 `URLRequestJob` 来请求 `https://final.example.com/page2`。
- `url_chain_` 成员变量会被更新，包含原始 URL 和重定向后的 URL。

**用户或编程常见的使用错误举例:**

**错误:** 在 `URLRequest::Delegate` 的回调方法中（例如 `OnResponseStarted`）直接调用 `delete request;` 来销毁 `URLRequest` 对象。

**说明:**  `URLRequest` 的生命周期是由网络栈管理的，过早或不当的销毁会导致程序崩溃或其他未定义的行为。正确的做法是在不再需要请求时调用 `Cancel()` 方法，让网络栈安全地清理资源。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在地址栏输入 `https://example.com` 并按下回车。**
2. **浏览器 UI 进程接收到用户输入，并判断需要导航到这个 URL。**
3. **浏览器 UI 进程向渲染进程发送导航请求。**
4. **渲染进程（如果需要）执行页面脚本，并开始加载页面资源。**
5. **渲染进程中的网络模块（例如，通过 `fetch` 或资源加载器）创建一个 `URLRequest` 对象，用于请求 `https://example.com` 的 HTML 资源。**
6. **`URLRequest` 对象会被传递给浏览器进程的网络服务组件。**
7. **网络服务组件会根据 `URLRequest` 的配置，创建并启动一个 `URLRequestJob` 来处理实际的网络请求。**
8. **`net/url_request/url_request.cc` 中的代码负责管理这个 `URLRequest` 对象的生命周期，协调 `URLRequestJob` 的工作，并通知委托对象请求的进度。**

**调试线索:** 如果在网络请求过程中出现问题，例如请求失败、重定向错误、认证问题等，可以通过以下方式进行调试：

- **查看 Chrome 的 `chrome://net-export/` (网络日志导出) 或 `chrome://net-internals/#events` (网络内部事件) 来分析网络请求的详细过程。** 这些工具会记录 `URLRequest` 相关的事件，包括请求的创建、启动、重定向、错误等信息。
- **在 `net/url_request/url_request.cc` 中添加断点，跟踪 `URLRequest` 对象的状态变化和方法调用。** 特别关注 `Start()`, `ReceivedRedirect()`, `NotifyResponseStarted()`, `Cancel()` 等方法的执行流程。
- **检查 `URLRequest::Delegate` 的实现，看是否有逻辑错误导致请求处理不当。**

总而言之，`net/url_request/url_request.cc` 的这部分代码定义了网络请求的核心抽象，并负责管理请求的创建、配置、生命周期以及与网络栈其他组件的交互，是 Chromium 网络功能的基础。

### 提示词
```
这是目录为net/url_request/url_request.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request.h"

#include <utility>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_functions_internal_overloads.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/rand_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/lock.h"
#include "base/task/single_thread_task_runner.h"
#include "base/types/optional_util.h"
#include "base/types/pass_key.h"
#include "base/values.h"
#include "net/base/auth.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/base/network_change_notifier.h"
#include "net/base/network_delegate.h"
#include "net/base/upload_data_stream.h"
#include "net/cert/x509_certificate.h"
#include "net/cookies/cookie_setting_override.h"
#include "net/cookies/cookie_store.h"
#include "net/cookies/cookie_util.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_log_util.h"
#include "net/http/http_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/socket/next_proto.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/storage_access_api/status.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/redirect_util.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_error_job.h"
#include "net/url_request/url_request_job.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_netlog_params.h"
#include "net/url_request/url_request_redirect_job.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

namespace {

// True once the first URLRequest was started.
bool g_url_requests_started = false;

// True if cookies are accepted by default.
bool g_default_can_use_cookies = true;

// When the URLRequest first assempts load timing information, it has the times
// at which each event occurred.  The API requires the time which the request
// was blocked on each phase.  This function handles the conversion.
//
// In the case of reusing a SPDY session, old proxy results may have been
// reused, so proxy resolution times may be before the request was started.
//
// Due to preconnect and late binding, it is also possible for the connection
// attempt to start before a request has been started, or proxy resolution
// completed.
//
// This functions fixes both those cases.
void ConvertRealLoadTimesToBlockingTimes(LoadTimingInfo* load_timing_info) {
  DCHECK(!load_timing_info->request_start.is_null());

  // Earliest time possible for the request to be blocking on connect events.
  base::TimeTicks block_on_connect = load_timing_info->request_start;

  if (!load_timing_info->proxy_resolve_start.is_null()) {
    DCHECK(!load_timing_info->proxy_resolve_end.is_null());

    // Make sure the proxy times are after request start.
    if (load_timing_info->proxy_resolve_start < load_timing_info->request_start)
      load_timing_info->proxy_resolve_start = load_timing_info->request_start;
    if (load_timing_info->proxy_resolve_end < load_timing_info->request_start)
      load_timing_info->proxy_resolve_end = load_timing_info->request_start;

    // Connect times must also be after the proxy times.
    block_on_connect = load_timing_info->proxy_resolve_end;
  }

  if (!load_timing_info->receive_headers_start.is_null() &&
      load_timing_info->receive_headers_start < block_on_connect) {
    load_timing_info->receive_headers_start = block_on_connect;
  }
  if (!load_timing_info->receive_non_informational_headers_start.is_null() &&
      load_timing_info->receive_non_informational_headers_start <
          block_on_connect) {
    load_timing_info->receive_non_informational_headers_start =
        block_on_connect;
  }

  // Make sure connection times are after start and proxy times.

  LoadTimingInfo::ConnectTiming* connect_timing =
      &load_timing_info->connect_timing;
  if (!connect_timing->domain_lookup_start.is_null()) {
    DCHECK(!connect_timing->domain_lookup_end.is_null());
    if (connect_timing->domain_lookup_start < block_on_connect)
      connect_timing->domain_lookup_start = block_on_connect;
    if (connect_timing->domain_lookup_end < block_on_connect)
      connect_timing->domain_lookup_end = block_on_connect;
  }

  if (!connect_timing->connect_start.is_null()) {
    DCHECK(!connect_timing->connect_end.is_null());
    if (connect_timing->connect_start < block_on_connect)
      connect_timing->connect_start = block_on_connect;
    if (connect_timing->connect_end < block_on_connect)
      connect_timing->connect_end = block_on_connect;
  }

  if (!connect_timing->ssl_start.is_null()) {
    DCHECK(!connect_timing->ssl_end.is_null());
    if (connect_timing->ssl_start < block_on_connect)
      connect_timing->ssl_start = block_on_connect;
    if (connect_timing->ssl_end < block_on_connect)
      connect_timing->ssl_end = block_on_connect;
  }
}

NetLogWithSource CreateNetLogWithSource(
    NetLog* net_log,
    std::optional<net::NetLogSource> net_log_source) {
  if (net_log_source) {
    return NetLogWithSource::Make(net_log, net_log_source.value());
  }
  return NetLogWithSource::Make(net_log, NetLogSourceType::URL_REQUEST);
}

// TODO(https://crbug.com/366284840): remove this, once the "retry" header is
// handled in URLLoader.
net::cookie_util::StorageAccessStatusOutcome
ConvertSecFetchStorageAccessHeaderValueToOutcome(
    net::cookie_util::StorageAccessStatus storage_access_status) {
  using enum net::cookie_util::StorageAccessStatusOutcome;
  switch (storage_access_status) {
    case net::cookie_util::StorageAccessStatus::kInactive:
      return kValueInactive;
    case net::cookie_util::StorageAccessStatus::kActive:
      return kValueActive;
    case net::cookie_util::StorageAccessStatus::kNone:
      return kValueNone;
  }
  NOTREACHED();
}

}  // namespace

///////////////////////////////////////////////////////////////////////////////
// URLRequest::Delegate

int URLRequest::Delegate::OnConnected(URLRequest* request,
                                      const TransportInfo& info,
                                      CompletionOnceCallback callback) {
  return OK;
}

void URLRequest::Delegate::OnReceivedRedirect(URLRequest* request,
                                              const RedirectInfo& redirect_info,
                                              bool* defer_redirect) {}

void URLRequest::Delegate::OnAuthRequired(URLRequest* request,
                                          const AuthChallengeInfo& auth_info) {
  request->CancelAuth();
}

void URLRequest::Delegate::OnCertificateRequested(
    URLRequest* request,
    SSLCertRequestInfo* cert_request_info) {
  request->CancelWithError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
}

void URLRequest::Delegate::OnSSLCertificateError(URLRequest* request,
                                                 int net_error,
                                                 const SSLInfo& ssl_info,
                                                 bool is_hsts_ok) {
  request->Cancel();
}

void URLRequest::Delegate::OnResponseStarted(URLRequest* request,
                                             int net_error) {
  NOTREACHED();
}

///////////////////////////////////////////////////////////////////////////////
// URLRequest

URLRequest::~URLRequest() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  Cancel();

  if (network_delegate()) {
    network_delegate()->NotifyURLRequestDestroyed(this);
    if (job_.get())
      job_->NotifyURLRequestDestroyed();
  }

  // Delete job before |this|, since subclasses may do weird things, like depend
  // on UserData associated with |this| and poke at it during teardown.
  job_.reset();

  DCHECK_EQ(1u, context_->url_requests()->count(this));
  context_->url_requests()->erase(this);

  int net_error = OK;
  // Log error only on failure, not cancellation, as even successful requests
  // are "cancelled" on destruction.
  if (status_ != ERR_ABORTED)
    net_error = status_;
  net_log_.EndEventWithNetErrorCode(NetLogEventType::REQUEST_ALIVE, net_error);
}

void URLRequest::set_upload(std::unique_ptr<UploadDataStream> upload) {
  upload_data_stream_ = std::move(upload);
}

const UploadDataStream* URLRequest::get_upload_for_testing() const {
  return upload_data_stream_.get();
}

bool URLRequest::has_upload() const {
  return upload_data_stream_.get() != nullptr;
}

void URLRequest::SetExtraRequestHeaderByName(std::string_view name,
                                             std::string_view value,
                                             bool overwrite) {
  DCHECK(!is_pending_ || is_redirecting_);
  if (overwrite) {
    extra_request_headers_.SetHeader(name, value);
  } else {
    extra_request_headers_.SetHeaderIfMissing(name, value);
  }
}

void URLRequest::RemoveRequestHeaderByName(std::string_view name) {
  DCHECK(!is_pending_ || is_redirecting_);
  extra_request_headers_.RemoveHeader(name);
}

void URLRequest::SetExtraRequestHeaders(const HttpRequestHeaders& headers) {
  DCHECK(!is_pending_);
  extra_request_headers_ = headers;

  // NOTE: This method will likely become non-trivial once the other setters
  // for request headers are implemented.
}

int64_t URLRequest::GetTotalReceivedBytes() const {
  if (!job_.get())
    return 0;

  return job_->GetTotalReceivedBytes();
}

int64_t URLRequest::GetTotalSentBytes() const {
  if (!job_.get())
    return 0;

  return job_->GetTotalSentBytes();
}

int64_t URLRequest::GetRawBodyBytes() const {
  if (!job_.get()) {
    return 0;
  }

  if (int64_t bytes = job_->GetReceivedBodyBytes()) {
    return bytes;
  }

  // GetReceivedBodyBytes() is available only when the body was received from
  // the network. Otherwise, returns prefilter_bytes_read() instead.
  return job_->prefilter_bytes_read();
}

LoadStateWithParam URLRequest::GetLoadState() const {
  // The !blocked_by_.empty() check allows |this| to report it's blocked on a
  // delegate before it has been started.
  if (calling_delegate_ || !blocked_by_.empty()) {
    return LoadStateWithParam(LOAD_STATE_WAITING_FOR_DELEGATE,
                              use_blocked_by_as_load_param_
                                  ? base::UTF8ToUTF16(blocked_by_)
                                  : std::u16string());
  }
  return LoadStateWithParam(job_.get() ? job_->GetLoadState() : LOAD_STATE_IDLE,
                            std::u16string());
}

base::Value::Dict URLRequest::GetStateAsValue() const {
  base::Value::Dict dict;
  dict.Set("url", original_url().possibly_invalid_spec());

  if (url_chain_.size() > 1) {
    base::Value::List list;
    for (const GURL& url : url_chain_) {
      list.Append(url.possibly_invalid_spec());
    }
    dict.Set("url_chain", std::move(list));
  }

  dict.Set("load_flags", load_flags());

  LoadStateWithParam load_state = GetLoadState();
  dict.Set("load_state", load_state.state);
  if (!load_state.param.empty())
    dict.Set("load_state_param", load_state.param);
  if (!blocked_by_.empty())
    dict.Set("delegate_blocked_by", blocked_by_);

  dict.Set("method", method_);
  dict.Set("network_anonymization_key",
           isolation_info_.network_anonymization_key().ToDebugString());
  dict.Set("network_isolation_key",
           isolation_info_.network_isolation_key().ToDebugString());
  dict.Set("has_upload", has_upload());
  dict.Set("is_pending", is_pending_);

  dict.Set("traffic_annotation", traffic_annotation_.unique_id_hash_code);

  if (status_ != OK)
    dict.Set("net_error", status_);
  return dict;
}

void URLRequest::LogBlockedBy(std::string_view blocked_by) {
  DCHECK(!blocked_by.empty());

  // Only log information to NetLog during startup and certain deferring calls
  // to delegates.  For all reads but the first, do nothing.
  if (!calling_delegate_ && !response_info_.request_time.is_null())
    return;

  LogUnblocked();
  blocked_by_ = std::string(blocked_by);
  use_blocked_by_as_load_param_ = false;

  net_log_.BeginEventWithStringParams(NetLogEventType::DELEGATE_INFO,
                                      "delegate_blocked_by", blocked_by_);
}

void URLRequest::LogAndReportBlockedBy(std::string_view source) {
  LogBlockedBy(source);
  use_blocked_by_as_load_param_ = true;
}

void URLRequest::LogUnblocked() {
  if (blocked_by_.empty())
    return;

  net_log_.EndEvent(NetLogEventType::DELEGATE_INFO);
  blocked_by_.clear();
}

UploadProgress URLRequest::GetUploadProgress() const {
  if (!job_.get()) {
    // We haven't started or the request was cancelled
    return UploadProgress();
  }

  if (final_upload_progress_.position()) {
    // The first job completed and none of the subsequent series of
    // GETs when following redirects will upload anything, so we return the
    // cached results from the initial job, the POST.
    return final_upload_progress_;
  }

  if (upload_data_stream_)
    return upload_data_stream_->GetUploadProgress();

  return UploadProgress();
}

std::string URLRequest::GetResponseHeaderByName(std::string_view name) const {
  if (!response_info_.headers.get()) {
    return std::string();
  }
  return response_info_.headers->GetNormalizedHeader(name).value_or(
      std::string());
}

IPEndPoint URLRequest::GetResponseRemoteEndpoint() const {
  DCHECK(job_.get());
  return job_->GetResponseRemoteEndpoint();
}

HttpResponseHeaders* URLRequest::response_headers() const {
  return response_info_.headers.get();
}

const std::optional<AuthChallengeInfo>& URLRequest::auth_challenge_info()
    const {
  return response_info_.auth_challenge;
}

void URLRequest::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  *load_timing_info = load_timing_info_;
}

void URLRequest::PopulateNetErrorDetails(NetErrorDetails* details) const {
  if (!job_)
    return;
  return job_->PopulateNetErrorDetails(details);
}

bool URLRequest::GetTransactionRemoteEndpoint(IPEndPoint* endpoint) const {
  if (!job_)
    return false;

  return job_->GetTransactionRemoteEndpoint(endpoint);
}

void URLRequest::GetMimeType(std::string* mime_type) const {
  DCHECK(job_.get());
  job_->GetMimeType(mime_type);
}

void URLRequest::GetCharset(std::string* charset) const {
  DCHECK(job_.get());
  job_->GetCharset(charset);
}

int URLRequest::GetResponseCode() const {
  DCHECK(job_.get());
  return job_->GetResponseCode();
}

void URLRequest::set_maybe_sent_cookies(CookieAccessResultList cookies) {
  maybe_sent_cookies_ = std::move(cookies);
}

void URLRequest::set_maybe_stored_cookies(
    CookieAndLineAccessResultList cookies) {
  maybe_stored_cookies_ = std::move(cookies);
}

void URLRequest::SetLoadFlags(int flags) {
  if ((load_flags() & LOAD_IGNORE_LIMITS) != (flags & LOAD_IGNORE_LIMITS)) {
    DCHECK(!job_.get());
    DCHECK(flags & LOAD_IGNORE_LIMITS);
    DCHECK_EQ(priority_, MAXIMUM_PRIORITY);
  }
  partial_load_flags_ = flags;

  // This should be a no-op given the above DCHECKs, but do this
  // anyway for release mode.
  if ((load_flags() & LOAD_IGNORE_LIMITS) != 0) {
    SetPriority(MAXIMUM_PRIORITY);
  }
}

void URLRequest::SetSecureDnsPolicy(SecureDnsPolicy secure_dns_policy) {
  secure_dns_policy_ = secure_dns_policy;
}

// static
void URLRequest::SetDefaultCookiePolicyToBlock() {
  CHECK(!g_url_requests_started);
  g_default_can_use_cookies = false;
}

void URLRequest::SetURLChain(const std::vector<GURL>& url_chain) {
  DCHECK(!job_);
  DCHECK(!is_pending_);
  DCHECK_EQ(url_chain_.size(), 1u);

  if (url_chain.size() < 2)
    return;

  // In most cases the current request URL will match the last URL in the
  // explicitly set URL chain.  In some cases, however, a throttle will modify
  // the request URL resulting in a different request URL.  We handle this by
  // using previous values from the explicitly set URL chain, but with the
  // request URL as the final entry in the chain.
  url_chain_.insert(url_chain_.begin(), url_chain.begin(),
                    url_chain.begin() + url_chain.size() - 1);
}

void URLRequest::set_site_for_cookies(const SiteForCookies& site_for_cookies) {
  DCHECK(!is_pending_);
  site_for_cookies_ = site_for_cookies;
}

void URLRequest::set_isolation_info(const IsolationInfo& isolation_info,
                                    std::optional<GURL> redirect_info_new_url) {
  isolation_info_ = isolation_info;

  bool is_main_frame_navigation = isolation_info.IsMainFrameRequest() ||
                                  force_main_frame_for_same_site_cookies();

  cookie_partition_key_ = CookiePartitionKey::FromNetworkIsolationKey(
      isolation_info.network_isolation_key(), isolation_info.site_for_cookies(),
      net::SchemefulSite(redirect_info_new_url.has_value()
                             ? redirect_info_new_url.value()
                             : url_chain_.back()),
      is_main_frame_navigation);
}

void URLRequest::set_isolation_info_from_network_anonymization_key(
    const NetworkAnonymizationKey& network_anonymization_key) {
  set_isolation_info(URLRequest::CreateIsolationInfoFromNetworkAnonymizationKey(
      network_anonymization_key));

  is_created_from_network_anonymization_key_ = true;
}

void URLRequest::set_first_party_url_policy(
    RedirectInfo::FirstPartyURLPolicy first_party_url_policy) {
  DCHECK(!is_pending_);
  first_party_url_policy_ = first_party_url_policy;
}

void URLRequest::set_initiator(const std::optional<url::Origin>& initiator) {
  DCHECK(!is_pending_);
  DCHECK(!initiator.has_value() || initiator.value().opaque() ||
         initiator.value().GetURL().is_valid());
  initiator_ = initiator;
}

void URLRequest::set_method(std::string_view method) {
  DCHECK(!is_pending_);
  method_ = std::string(method);
}

#if BUILDFLAG(ENABLE_REPORTING)
void URLRequest::set_reporting_upload_depth(int reporting_upload_depth) {
  DCHECK(!is_pending_);
  reporting_upload_depth_ = reporting_upload_depth;
}
#endif

void URLRequest::SetReferrer(std::string_view referrer) {
  DCHECK(!is_pending_);
  GURL referrer_url(referrer);
  if (referrer_url.is_valid()) {
    referrer_ = referrer_url.GetAsReferrer().spec();
  } else {
    referrer_ = std::string(referrer);
  }
}

void URLRequest::set_referrer_policy(ReferrerPolicy referrer_policy) {
  DCHECK(!is_pending_);
  referrer_policy_ = referrer_policy;
}

void URLRequest::set_allow_credentials(bool allow_credentials) {
  allow_credentials_ = allow_credentials;
  if (allow_credentials) {
    partial_load_flags_ &= ~LOAD_DO_NOT_SAVE_COOKIES;
  } else {
    partial_load_flags_ |= LOAD_DO_NOT_SAVE_COOKIES;
  }
}

void URLRequest::Start() {
  DCHECK(delegate_);

  if (status_ != OK)
    return;

  if (context_->require_network_anonymization_key()) {
    DCHECK(!isolation_info_.IsEmpty());
  }

  // Some values can be NULL, but the job factory must not be.
  DCHECK(context_->job_factory());

  // Anything that sets |blocked_by_| before start should have cleaned up after
  // itself.
  DCHECK(blocked_by_.empty());

  g_url_requests_started = true;
  response_info_.request_time = base::Time::Now();

  load_timing_info_ = LoadTimingInfo();
  load_timing_info_.request_start_time = response_info_.request_time;
  load_timing_info_.request_start = base::TimeTicks::Now();

  if (network_delegate()) {
    OnCallToDelegate(NetLogEventType::NETWORK_DELEGATE_BEFORE_URL_REQUEST);
    int error = network_delegate()->NotifyBeforeURLRequest(
        this,
        base::BindOnce(&URLRequest::BeforeRequestComplete,
                       base::Unretained(this)),
        &delegate_redirect_url_);
    // If ERR_IO_PENDING is returned, the delegate will invoke
    // |BeforeRequestComplete| later.
    if (error != ERR_IO_PENDING)
      BeforeRequestComplete(error);
    return;
  }

  StartJob(context_->job_factory()->CreateJob(this));
}

///////////////////////////////////////////////////////////////////////////////

URLRequest::URLRequest(base::PassKey<URLRequestContext> pass_key,
                       const GURL& url,
                       RequestPriority priority,
                       Delegate* delegate,
                       const URLRequestContext* context,
                       NetworkTrafficAnnotationTag traffic_annotation,
                       bool is_for_websockets,
                       std::optional<net::NetLogSource> net_log_source)
    : context_(context),
      net_log_(CreateNetLogWithSource(context->net_log(), net_log_source)),
      url_chain_(1, url),
      method_("GET"),
      delegate_(delegate),
      is_for_websockets_(is_for_websockets),
      redirect_limit_(kMaxRedirects),
      priority_(priority),
      creation_time_(base::TimeTicks::Now()),
      traffic_annotation_(traffic_annotation) {
  // Sanity check out environment.
  DCHECK(base::SingleThreadTaskRunner::HasCurrentDefault());

  context->url_requests()->insert(this);
  net_log_.BeginEvent(NetLogEventType::REQUEST_ALIVE, [&] {
    return NetLogURLRequestConstructorParams(url, priority_,
                                             traffic_annotation_);
  });
}

void URLRequest::BeforeRequestComplete(int error) {
  DCHECK(!job_.get());
  DCHECK_NE(ERR_IO_PENDING, error);

  // Check that there are no callbacks to already failed or canceled requests.
  DCHECK(!failed());

  OnCallToDelegateComplete();

  if (error != OK) {
    net_log_.AddEventWithStringParams(NetLogEventType::CANCELLED, "source",
                                      "delegate");
    StartJob(std::make_unique<URLRequestErrorJob>(this, error));
  } else if (!delegate_redirect_url_.is_empty()) {
    GURL new_url;
    new_url.Swap(&delegate_redirect_url_);

    StartJob(std::make_unique<URLRequestRedirectJob>(
        this, new_url,
        // Use status code 307 to preserve the method, so POST requests work.
        RedirectUtil::ResponseCode::REDIRECT_307_TEMPORARY_REDIRECT,
        "Delegate"));
  } else {
    StartJob(context_->job_factory()->CreateJob(this));
  }
}

void URLRequest::StartJob(std::unique_ptr<URLRequestJob> job) {
  DCHECK(!is_pending_);
  DCHECK(!job_);
  if (is_created_from_network_anonymization_key_) {
    DCHECK(load_flags() & LOAD_DISABLE_CACHE);
    DCHECK(!allow_credentials_);
  }

  net_log_.BeginEvent(NetLogEventType::URL_REQUEST_START_JOB, [&] {
    return NetLogURLRequestStartParams(
        url(), method_, load_flags(), isolation_info_, site_for_cookies_,
        initiator_,
        upload_data_stream_ ? upload_data_stream_->identifier() : -1);
  });

  job_ = std::move(job);
  job_->SetExtraRequestHeaders(extra_request_headers_);
  job_->SetPriority(priority_);
  job_->SetRequestHeadersCallback(request_headers_callback_);
  job_->SetEarlyResponseHeadersCallback(early_response_headers_callback_);
  if (is_shared_dictionary_read_allowed_callback_) {
    job_->SetIsSharedDictionaryReadAllowedCallback(
        is_shared_dictionary_read_allowed_callback_);
  }
  job_->SetResponseHeadersCallback(response_headers_callback_);
  if (shared_dictionary_getter_) {
    job_->SetSharedDictionaryGetter(shared_dictionary_getter_);
  }

  if (upload_data_stream_.get())
    job_->SetUpload(upload_data_stream_.get());

  is_pending_ = true;
  is_redirecting_ = false;
  deferred_redirect_info_.reset();

  response_info_.was_cached = false;

  maybe_sent_cookies_.clear();
  maybe_stored_cookies_.clear();

  GURL referrer_url(referrer_);
  bool same_origin_for_metrics;

  if (referrer_url !=
      URLRequestJob::ComputeReferrerForPolicy(
          referrer_policy_, referrer_url, url(), &same_origin_for_metrics)) {
    if (!network_delegate() ||
        !network_delegate()->CancelURLRequestWithPolicyViolatingReferrerHeader(
            *this, url(), referrer_url)) {
      referrer_.clear();
    } else {
      // We need to clear the referrer anyway to avoid an infinite recursion
      // when starting the error job.
      referrer_.clear();
      net_log_.AddEventWithStringParams(NetLogEventType::CANCELLED, "source",
                                        "delegate");
      RestartWithJob(
          std::make_unique<URLRequestErrorJob>(this, ERR_BLOCKED_BY_CLIENT));
      return;
    }
  }

  RecordReferrerGranularityMetrics(same_origin_for_metrics);

  // Start() always completes asynchronously.
  //
  // Status is generally set by URLRequestJob itself, but Start() calls
  // directly into the URLRequestJob subclass, so URLRequestJob can't set it
  // here.
  // TODO(mmenke):  Make the URLRequest manage its own status.
  status_ = ERR_IO_PENDING;
  job_->Start();
}

void URLRequest::RestartWithJob(std::unique_ptr<URLRequestJob> job) {
  DCHECK(job->request() == this);
  PrepareToRestart();
  StartJob(std::move(job));
}

int URLRequest::Cancel() {
  return DoCancel(ERR_ABORTED, SSLInfo());
}

int URLRequest::CancelWithError(int error) {
  return DoCancel(error, SSLInfo());
}

void URLRequest::CancelWithSSLError(int error, const SSLInfo& ssl_info) {
  // This should only be called on a started request.
  if (!is_pending_ || !job_.get() || job_->has_response_started()) {
    NOTREACHED();
  }
  DoCancel(error, ssl_info);
}

int URLRequest::DoCancel(int error, const SSLInfo& ssl_info) {
  DCHECK_LT(error, 0);
  // If cancelled while calling a delegate, clear delegate info.
  if (calling_delegate_) {
    LogUnblocked();
    OnCallToDelegateComplete();
  }

  // If the URL request already has an error status, then canceling is a no-op.
  // Plus, we don't want to change the error status once it has been set.
  if (!failed()) {
    status_ = error;
    response_info_.ssl_info = ssl_info;

    // If the request hasn't already been completed, log a cancellation event.
    if (!has_notified_completion_) {
      // Don't log an error code on ERR_ABORTED, since that's redundant.
      net_log_.AddEventWithNetErrorCode(NetLogEventType::CANCELLED,
                                        error == ERR_ABORTED ? OK : error);
    }
  }

  if (is_pending_ && job_.get())
    job_->Kill();

  // We need to notify about the end of this job here synchronously. The
  // Job sends an asynchronous notification but by the time this is processed,
  // our |context_| is NULL.
  NotifyRequestCompleted();

  // The Job will call our NotifyDone method asynchronously.  This is done so
  // that the Delegate implementation can call Cancel without having to worry
  // about being called recursively.

  return status_;
}

int URLRequest::Read(IOBuffer* dest, int dest_size) {
  DCHECK(job_.get());
  DCHECK_NE(ERR_IO_PENDING, status_);

  // If this is the first read, end the delegate call that may have started in
  // OnResponseStarted.
  OnCallToDelegateComplete();

  // If the request has failed, Read() will return actual network error code.
  if (status_ != OK)
    return status_;

  // This handles reads after the request already completed successfully.
  // TODO(ahendrickson): DCHECK() that it is not done after
  // http://crbug.com/115705 is fixed.
  if (job_->is_done())
    return status_;

  if (dest_size == 0) {
    // Caller is not too bright.  I guess we've done what they asked.
    return OK;
  }

  // Caller should provide a buffer.
  DCHECK(dest && dest->data());

  int rv = job_->Read(dest, dest_size);
  if (rv == ERR_IO_PENDING) {
    set_status(ERR_IO_PENDING);
  } else if (rv <= 0) {
    NotifyRequestCompleted();
  }

  // If rv is not 0 or actual bytes read, the status cannot be success.
  DCHECK(rv >= 0 || status_ != OK);
  return rv;
}

void URLRequest::set_status(int status) {
  DCHECK_LE(status, 0);
  DCHECK(!failed() || (status != OK && status != ERR_IO_PENDING));
  status_ = status;
}

bool URLRequest::failed() const {
  return (status_ != OK && status_ != ERR_IO_PENDING);
}

int URLRequest::NotifyConnected(const TransportInfo& info,
                                CompletionOnceCallback callback) {
  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED);
  int result = delegate_->OnConnected(
      this, info,
      base::BindOnce(
          [](URLRequest* request, CompletionOnceCallback callback, int result) {
            request->OnCallToDelegateComplete(result);
            std::move(callback).Run(result);
          },
          this, std::move(callback)));
  if (result != ERR_IO_PENDING)
    OnCallToDelegateComplete(result);
  return result;
}

void URLRequest::ReceivedRedirect(RedirectInfo redirect_info) {
  DCHECK_EQ(OK, status_);
  is_redirecting_ = true;
  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_RECEIVED_REDIRECT);

  // When notifying the URLRequest::Delegate, it can destroy the request,
  // which will destroy |this|.  After calling to the URLRequest::Delegate,
  // pointer must be checked to see if |this| still exists, and if not, the
  // code must return immediately.
  base::WeakPtr<URLRequest> weak_this(weak_factory_.GetWeakPtr());
  bool defer_redirect = false;
  per_hop_load_flags_ = LOAD_NORMAL;
  delegate_->OnReceivedRedirect(this, redirect_info, &defer_redirect);

  // Ensure that the request wasn't detached, destroyed, or canceled in
  // NotifyReceivedRedirect.
  if (!weak_this || failed()) {
    return;
  }

  if (defer_redirect) {
    deferred_redirect_info_ = std::move(redirect_info);
  } else {
    Redirect(redirect_info, /*removed_headers=*/std::nullopt,
             /*modified_headers=*/std::nullopt);
  }
  // |this| may be have been destroyed here.
}

void URLRequest::NotifyResponseStarted(int net_error) {
  DCHECK_LE(net_error, 0);

  // Change status if there was an error.
  if (net_error != OK)
    set_status(net_error);

  // |status_| should not be ERR_IO_PENDING when calling into the
  // URLRequest::Delegate().
  DCHECK_NE(ERR_IO_PENDING, status_);

  net_log_.EndEventWithNetErrorCode(NetLogEventType::URL_REQUEST_START_JOB,
                                    net_error);

  // In some cases (e.g. an event was canceled), we might have sent the
  // completion event and receive a NotifyResponseStarted() later.
  if (!has_notified_completion_ && net_error == OK) {
    if (network_delegate())
      network_delegate()->NotifyResponseStarted(this, net_error);
  }

  // Notify in case the entire URL Request has been finished.
  if (!has_notified_completion_ && net_error != OK)
    NotifyRequestCompleted();

  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_RESPONSE_STARTED);
  delegate_->OnResponseStarted(this, net_error);
  // Nothing may appear below this line as OnResponseStarted may delete
  // |this|.
}

void URLRequest::FollowDeferredRedirect(
    const std::optional<std::vector<std::string>>& removed_headers,
    const std::optional<net::HttpRequestHeaders>& modified_headers) {
  DCHECK(job_.get());
  DCHECK_EQ(OK, status_);
  DCHECK(is_redirecting_);
  DCHECK(deferred_redirect_info_);

  maybe_sent_cookies_.clear();
  maybe_stored_cookies_.clear();

  status_ = ERR_IO_PENDING;

  // While this move is not strictly needed, Redirect() will start a new Job,
  // which will delete `deferred_redirect_info_`. While `redirect_info` should
  // not be needed after it's been deleted, it's best to not have a reference to
  // a deleted object on the stack.
  RedirectInfo redirect_info = std::move(deferred_redirect_info_).value();

  Redirect(redirect_info, removed_headers, modified_headers);
}

void URLRequest::SetAuth(const AuthCredentials& credentials) {
  DCHECK(job_.get());
  DCHECK(job_->NeedsAuth());

  maybe_sent_cookies_.clear();
  maybe_stored_cookies_.clear();

  status_ = ERR_IO_PENDING;
  job_->SetAuth(credentials);
}

void URLRequest::CancelAuth() {
  DCHECK(job_.get());
  DCHECK(job_->NeedsAuth());

  status_ = ERR_IO_PENDING;
  job_->CancelAuth();
}

void URLRequest::ContinueWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key) {
  DCHECK(job_.get());

  // Matches the call in NotifyCertificateRequested.
  OnCallToDelegateComplete();

  status_ = ERR_IO_PENDING;
  job_->ContinueWithCertificate(std::move(client_cert),
                                std::move(client_private_key));
}

void URLRequest::ContinueDespiteLastError() {
  DCHECK(job_.get());

  // Matches the call in NotifySSLCertificateError.
  OnCallToDelegateComplete();

  status_ = ERR_IO_PENDING;
  job_->ContinueDespiteLastError();
}

void URLRequest::AbortAndCloseConnection() {
  DCHECK_EQ(OK, status_);
  DCHECK(!has_notified_completion_);
  DCHECK(job_);
  job_->CloseConnectionOnDestruction();
  job_.reset();
}

void URLRequ
```