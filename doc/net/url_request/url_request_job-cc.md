Response:
Let's break down the thought process for analyzing this `URLRequestJob.cc` file.

1. **Understand the Goal:** The core request is to understand the functionality of `URLRequestJob`, its relationship to JavaScript, its error handling, and how a user's actions might lead to this code being executed.

2. **Initial Scan for Key Concepts:**  Read through the file quickly, looking for recurring terms and important-sounding method names. Keywords like `URLRequest`, `Read`, `Redirect`, `Auth`, `Headers`, `Cookies`, `SourceStream`, `NetLog`, `Error`, `Notify`. These give a high-level idea of the file's concerns.

3. **Deconstruct by Class and Methods:** The primary entity is the `URLRequestJob` class. Analyze its key methods. For each method, consider:
    * **Purpose:** What is the main task this method performs?
    * **Inputs/Outputs:** What data does it take, and what does it return or modify?
    * **Side Effects:** Does it trigger other actions (like notifications)?
    * **Connections to other parts of the system:** Does it interact with `URLRequest`, `SourceStream`, `NetLog`, etc.?

4. **Focus on Core Functionality:**  Identify the most important responsibilities of `URLRequestJob`. From the method names and comments, it's clear that it handles:
    * Reading data (`Read`, `ReadRawData`, `ReadRawDataHelper`, `SourceStreamReadComplete`)
    * Handling redirects (`IsRedirectResponse`, `CanFollowRedirect`, `ReceivedRedirect`)
    * Authentication (`NeedsAuth`, `GetAuthChallengeInfo`, `SetAuth`, `CancelAuth`)
    * Header processing (`GetResponseInfo`, `NotifyHeadersComplete`, `NotifyFinalHeadersReceived`)
    * Error handling (`OnDone`, `NotifyStartError`, `NotifyCanceled`)
    * Referrer policy (`ComputeReferrerForPolicy`)
    * Cookie handling (`CanSetCookie`)
    * Logging (`NetLog`)

5. **Look for JavaScript Interaction:**  This requires understanding how the browser's rendering engine (which executes JavaScript) interacts with the network stack. Key connection points are:
    * **Initiating requests:** JavaScript uses APIs like `fetch` or `XMLHttpRequest` to make network requests. This eventually leads to the creation of a `URLRequest`.
    * **Receiving data:** The data fetched via JavaScript needs to be read and processed. `URLRequestJob` is involved in this data retrieval.
    * **Handling redirects:** JavaScript might be aware of or influenced by redirects.
    * **Cookie management:** JavaScript can access and modify cookies, and the browser enforces cookie policies.
    * **Security considerations:**  Referrer policy and authentication are relevant to JavaScript's security context.

6. **Consider Logic and Assumptions:** For methods with branching logic (like `ComputeReferrerForPolicy`), try to trace the execution flow with hypothetical inputs. This helps understand the conditions under which different outcomes occur. For example, what happens if `secure_referrer_but_insecure_destination` is true?

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using network APIs in JavaScript. This often relates to incorrect configuration or misunderstanding of browser behavior. Examples:
    * Incorrect redirect handling (infinite loops).
    * Security issues with insecure redirects.
    * Cookie setting problems.
    * Not handling network errors properly.

8. **Trace User Actions:**  Work backward from the code to understand how a user's interaction with the browser could lead to `URLRequestJob` being involved. This involves considering the different types of network requests a browser might make (loading web pages, fetching resources, API calls initiated by JavaScript).

9. **Structure the Explanation:** Organize the findings into logical sections: functionality, JavaScript relationship, logical reasoning, usage errors, and debugging. Use clear and concise language.

10. **Refine and Elaborate:** Review the initial analysis and add more detail where necessary. For instance, instead of just saying "handles redirects," explain *how* it handles redirects (checking limits, safety, notifying the `URLRequest`). Provide concrete examples for JavaScript interactions and usage errors.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just reads data."  **Correction:** Realized it does much more than just read, including handling redirects, authentication, and various notifications.
* **Initial thought:** "The JavaScript connection is direct." **Correction:**  Recognized that the interaction is more indirect. JavaScript uses browser APIs, which then interact with the network stack components like `URLRequestJob`.
* **Struggling with the "how to reach here" part:**  **Refinement:** Thought about the different ways a network request can be initiated in a browser and how the `URLRequest` and `URLRequestJob` are created in that process.

By following these steps, combining code analysis with knowledge of web browser architecture and network protocols, a comprehensive understanding of the `URLRequestJob.cc` file can be achieved.
好的，让我们详细分析 `net/url_request/url_request_job.cc` 这个 Chromium 网络栈的核心文件。

**功能列表:**

`URLRequestJob` 是 Chromium 网络栈中处理特定 URL 请求的核心抽象类。它的主要功能包括：

1. **作为所有具体 URL 请求处理器的基类:** 它定义了处理网络请求的通用接口和流程，例如读取数据、处理响应头、处理重定向、处理认证等。不同的协议（HTTP、FTP、Data URLs 等）的请求由继承自 `URLRequestJob` 的子类来实现。

2. **管理数据流:**  它维护了一个 `SourceStream` 链，用于处理接收到的数据。这个链可以包含各种过滤器，例如解压缩、解码等。`URLRequestJobSourceStream` 是这个链的起始点，直接从 `URLRequestJob` 读取原始数据。

3. **处理读取操作:**  `Read()` 方法是客户端（通常是 `URLRequest`）请求读取数据的主要入口。它将读取操作传递给 `SourceStream` 链。

4. **处理响应头:**  `NotifyHeadersComplete()` 方法在接收到完整的响应头后被调用。它负责解析响应头，检查是否需要认证或重定向，并触发相应的处理。

5. **处理重定向:** `IsRedirectResponse()` 检查响应是否是重定向。`CanFollowRedirect()` 决定是否应该跟随重定向。`ReceivedRedirect()` 通知 `URLRequest` 发生了重定向。

6. **处理认证:**  `NeedsAuth()` 判断是否需要认证。 `GetAuthChallengeInfo()` 获取认证挑战信息。 `SetAuth()` 和 `CancelAuth()` 用于设置或取消认证凭据。

7. **处理错误:**  `OnDone()` 方法在请求完成（无论成功或失败）时被调用，负责设置请求状态并通知 `URLRequest`。 `NotifyStartError()` 用于通知启动请求时发生的错误。

8. **计算 Referrer:** `ComputeReferrerForPolicy()` 方法根据 Referrer Policy 计算请求的 Referrer。

9. **记录网络日志:**  使用 `net::NetLog` 记录请求的各种事件，用于调试和性能分析。

10. **管理连接状态:**  `NotifyConnected()` 通知已建立连接。

11. **处理 SSL 证书:**  `NotifyCertificateRequested()` 和 `NotifySSLCertificateError()` 用于处理 SSL 证书相关的事件。

12. **管理 Cookie:**  `CanSetCookie()` 方法判断是否可以设置 Cookie。

13. **提供性能指标:**  `GetTotalReceivedBytes()`, `GetTotalSentBytes()`, `GetReceivedBodyBytes()` 等方法提供请求的字节统计信息。

**与 JavaScript 的关系:**

`URLRequestJob` 本身不是直接用 JavaScript 编写的，它是 C++ 代码。但是，它在幕后支持着 JavaScript 发起的网络请求。当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 对象发起网络请求时，Chromium 浏览器会将这些请求转换为底层的 `URLRequest` 对象，并创建一个相应的 `URLRequestJob` 子类的实例来处理这个请求。

**举例说明:**

假设以下 JavaScript 代码发起了一个简单的 GET 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这段 JavaScript 代码执行时，会发生以下（简化的）过程，其中涉及到 `URLRequestJob`：

1. **JavaScript 发起请求:**  JavaScript 引擎调用浏览器提供的 `fetch` API。
2. **创建 URLRequest:** 浏览器网络栈会创建一个 `URLRequest` 对象来表示这个请求。
3. **创建 URLRequestJob:**  根据请求的 URL 协议 (HTTPS)，会创建一个 `URLRequestHttpJob` (继承自 `URLRequestJob`) 的实例来处理这个请求。
4. **URLRequestJob 开始工作:** `URLRequestHttpJob` 会执行一系列操作，例如 DNS 解析、建立 TCP 连接、TLS 握手（如果是 HTTPS）、发送 HTTP 请求头等。
5. **接收响应头:** 服务器返回响应头后，`URLRequestHttpJob` 的 `NotifyHeadersComplete()` 方法会被调用，解析响应头。
6. **接收响应体:**  `URLRequestHttpJob` 会通过 `Read()` 方法读取响应体数据。数据可能经过 `SourceStream` 链中的过滤器处理。
7. **数据传递给 JavaScript:** 读取到的数据最终会传递回 JavaScript，并被 `response.json()` 方法解析。
8. **完成:** 请求完成后，`URLRequestJob` 的 `OnDone()` 方法会被调用。

**逻辑推理 (假设输入与输出):**

**场景:**  一个 HTTP 重定向请求。

**假设输入:**

* **请求 URL:** `http://example.com/old_page`
* **服务器响应 (对 `/old_page` 的请求):** HTTP 状态码 302 (Found)，`Location` 头为 `https://example.com/new_page`。
* **`URLRequestJob` 的状态:**  已接收到响应头。

**逻辑推理过程:**

1. `NotifyHeadersComplete()` 被调用。
2. `IsRedirectResponse()` 检查响应头，发现 `Location` 头存在，且状态码为 3xx，返回 `true`。
3. `CanFollowRedirect()` 被调用，检查重定向次数限制、目标 URL 的安全性等。假设检查通过。
4. `ReceivedRedirect()` 被调用，通知 `URLRequest` 发生了重定向，并将重定向信息（新的 URL）传递给 `URLRequest`。
5. `URLRequest` 会根据重定向信息创建一个新的 `URLRequestJob` 来请求 `https://example.com/new_page`。

**输出:**

* 原始的 `URLRequestJob` 完成 (但可能不会读取响应体)。
* 一个新的 `URLRequestJob` 被创建，用于请求重定向的目标 URL。
* JavaScript 的 `fetch` API 会收到最终的响应，即来自 `https://example.com/new_page` 的响应。

**用户或编程常见的使用错误:**

1. **无限重定向:**  服务器配置错误，导致请求在两个或多个 URL 之间无限循环重定向。`URLRequestJob` 会通过 `CanFollowRedirect()` 中的重定向次数限制来防止这种情况，最终返回 `ERR_TOO_MANY_REDIRECTS` 错误。

   * **用户操作:** 用户点击了一个链接，或者 JavaScript 代码发起了一个请求，但服务器配置不当导致重定向循环。
   * **调试线索:** 在 Chrome 的开发者工具的网络面板中可以看到请求不断地被重定向，状态码为 3xx。NetLog 中会记录大量的重定向事件，最终会记录一个 `FAILED` 事件，错误码为 `ERR_TOO_MANY_REDIRECTS`。

2. **不安全的重定向:**  从 HTTPS 站点重定向到 HTTP 站点，可能导致安全风险。`URLRequestJob` 会根据安全策略来处理这类重定向。

   * **用户操作:** 用户访问了一个 HTTPS 网站，该网站尝试将其重定向到一个 HTTP 网站。
   * **调试线索:**  NetLog 中可能会记录关于不安全重定向的警告或错误信息。浏览器可能会阻止这种重定向，或者在地址栏中显示警告。

3. **Cookie 设置问题:**  服务器尝试设置 Cookie，但由于各种原因（例如域名不匹配、`Secure` 或 `HttpOnly` 属性不当），Cookie 设置失败。`URLRequestJob` 的 `CanSetCookie()` 方法会根据 Cookie 策略进行检查。

   * **用户操作:** 用户访问一个网站，该网站尝试设置 Cookie 来跟踪用户状态或进行其他操作。
   * **调试线索:** 在 Chrome 开发者工具的 "Application" 面板的 "Cookies" 部分，可以查看已设置的 Cookie 和被阻止的 Cookie。NetLog 中可能会记录 Cookie 设置相关的事件，包括被阻止的原因。

4. **认证失败:** 请求需要认证，但提供的用户名和密码不正确。`URLRequestJob` 会处理认证挑战，并根据提供的凭据尝试认证。

   * **用户操作:** 用户访问需要登录的网站。
   * **调试线索:** 在 Chrome 开发者工具的网络面板中，可以看到请求的状态码为 401 (Unauthorized)。NetLog 中会记录认证相关的事件，包括认证挑战和认证尝试。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览器中输入一个 HTTPS URL 并按下回车：

1. **用户输入 URL:** 用户在地址栏输入 `https://example.com` 并按下回车。
2. **URLRequest 创建:**  浏览器进程创建一个 `URLRequest` 对象，用于请求这个 URL。
3. **URLRequestJob 子类创建:**  由于是 HTTPS 请求，网络栈会创建一个 `URLRequestHttpJob` 对象来处理这个请求。`URLRequestJob` 的构造函数会被调用。
4. **连接建立:** `URLRequestHttpJob` 会执行 DNS 查询、建立 TCP 连接、进行 TLS 握手。`NotifyConnected()` 方法可能会被调用。
5. **发送请求头:** `URLRequestHttpJob` 发送 HTTP 请求头。
6. **接收响应头:** 服务器返回 HTTP 响应头。`NotifyHeadersComplete()` 方法在 `URLRequestHttpJob` 中被调用。在这个方法中，会进行重定向、认证等检查。
7. **接收响应体:** 如果请求成功，`URLRequestHttpJob` 会开始接收响应体数据，并通过 `Read()` 方法读取数据。数据会通过 `SourceStream` 链进行处理。
8. **完成:**  当响应接收完毕或发生错误时，`OnDone()` 方法会被调用，通知 `URLRequest` 请求已完成。

**总结:**

`URLRequestJob.cc` 定义了一个核心的抽象类，负责管理和协调网络请求的生命周期。它与 JavaScript 的交互是间接的，但至关重要，因为它处理了 JavaScript 发起的网络请求的底层细节。理解 `URLRequestJob` 的功能对于调试网络问题、理解 Chromium 的网络栈架构至关重要。 通过分析 NetLog 和开发者工具的网络面板，我们可以追踪用户操作如何一步步地触发 `URLRequestJob` 的各种方法，从而定位和解决问题。

Prompt: 
```
这是目录为net/url_request/url_request_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_job.h"

#include <utility>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/values.h"
#include "net/base/auth.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/load_states.h"
#include "net/base/net_errors.h"
#include "net/base/network_delegate.h"
#include "net/base/proxy_chain.h"
#include "net/base/schemeful_site.h"
#include "net/cert/x509_certificate.h"
#include "net/cookies/cookie_setting_override.h"
#include "net/cookies/cookie_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/ssl/ssl_private_key.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/redirect_util.h"
#include "net/url_request/url_request_context.h"

namespace net {

namespace {

// Callback for TYPE_URL_REQUEST_FILTERS_SET net-internals event.
base::Value::Dict SourceStreamSetParams(SourceStream* source_stream) {
  base::Value::Dict event_params;
  event_params.Set("filters", source_stream->Description());
  return event_params;
}

}  // namespace

// Each SourceStreams own the previous SourceStream in the chain, but the
// ultimate source is URLRequestJob, which has other ownership semantics, so
// this class is a proxy for URLRequestJob that is owned by the first stream
// (in dataflow order).
class URLRequestJob::URLRequestJobSourceStream : public SourceStream {
 public:
  explicit URLRequestJobSourceStream(URLRequestJob* job)
      : SourceStream(SourceStream::TYPE_NONE), job_(job) {
    DCHECK(job_);
  }

  URLRequestJobSourceStream(const URLRequestJobSourceStream&) = delete;
  URLRequestJobSourceStream& operator=(const URLRequestJobSourceStream&) =
      delete;

  ~URLRequestJobSourceStream() override = default;

  // SourceStream implementation:
  int Read(IOBuffer* dest_buffer,
           int buffer_size,
           CompletionOnceCallback callback) override {
    DCHECK(job_);
    return job_->ReadRawDataHelper(dest_buffer, buffer_size,
                                   std::move(callback));
  }

  std::string Description() const override { return std::string(); }

  bool MayHaveMoreBytes() const override { return true; }

 private:
  // It is safe to keep a raw pointer because |job_| owns the last stream which
  // indirectly owns |this|. Therefore, |job_| will not be destroyed when |this|
  // is alive.
  const raw_ptr<URLRequestJob> job_;
};

URLRequestJob::URLRequestJob(URLRequest* request) : request_(request) {}

URLRequestJob::~URLRequestJob() = default;

void URLRequestJob::SetUpload(UploadDataStream* upload) {
}

void URLRequestJob::SetExtraRequestHeaders(const HttpRequestHeaders& headers) {
}

void URLRequestJob::SetPriority(RequestPriority priority) {
}

void URLRequestJob::Kill() {
  weak_factory_.InvalidateWeakPtrs();
  // Make sure the URLRequest is notified that the job is done.  This assumes
  // that the URLRequest took care of setting its error status before calling
  // Kill().
  // TODO(mmenke):  The URLRequest is currently deleted before this method
  // invokes its async callback whenever this is called by the URLRequest.
  // Try to simplify how cancellation works.
  NotifyCanceled();
}

// This method passes reads down the filter chain, where they eventually end up
// at URLRequestJobSourceStream::Read, which calls back into
// URLRequestJob::ReadRawData.
int URLRequestJob::Read(IOBuffer* buf, int buf_size) {
  DCHECK(buf);

  pending_read_buffer_ = buf;
  int result = source_stream_->Read(
      buf, buf_size,
      base::BindOnce(&URLRequestJob::SourceStreamReadComplete,
                     weak_factory_.GetWeakPtr(), false));
  if (result == ERR_IO_PENDING)
    return ERR_IO_PENDING;

  SourceStreamReadComplete(true, result);
  return result;
}

int64_t URLRequestJob::GetTotalReceivedBytes() const {
  return 0;
}

int64_t URLRequestJob::GetTotalSentBytes() const {
  return 0;
}

int64_t URLRequestJob::GetReceivedBodyBytes() const {
  return 0;
}

LoadState URLRequestJob::GetLoadState() const {
  return LOAD_STATE_IDLE;
}

bool URLRequestJob::GetCharset(std::string* charset) {
  return false;
}

void URLRequestJob::GetResponseInfo(HttpResponseInfo* info) {
}

void URLRequestJob::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  // Only certain request types return more than just request start times.
}

bool URLRequestJob::GetTransactionRemoteEndpoint(IPEndPoint* endpoint) const {
  return false;
}

void URLRequestJob::PopulateNetErrorDetails(NetErrorDetails* details) const {
  return;
}

bool URLRequestJob::IsRedirectResponse(GURL* location,
                                       int* http_status_code,
                                       bool* insecure_scheme_was_upgraded) {
  // For non-HTTP jobs, headers will be null.
  HttpResponseHeaders* headers = request_->response_headers();
  if (!headers)
    return false;

  std::string value;
  if (!headers->IsRedirect(&value))
    return false;
  *insecure_scheme_was_upgraded = false;
  *location = request_->url().Resolve(value);
  // If this a redirect to HTTP of a request that had the
  // 'upgrade-insecure-requests' policy set, upgrade it to HTTPS.
  if (request_->upgrade_if_insecure()) {
    if (location->SchemeIs("http")) {
      *insecure_scheme_was_upgraded = true;
      GURL::Replacements replacements;
      replacements.SetSchemeStr("https");
      *location = location->ReplaceComponents(replacements);
    }
  }
  *http_status_code = headers->response_code();
  return true;
}

bool URLRequestJob::CopyFragmentOnRedirect(const GURL& location) const {
  return true;
}

bool URLRequestJob::IsSafeRedirect(const GURL& location) {
  return true;
}

bool URLRequestJob::NeedsAuth() {
  return false;
}

std::unique_ptr<AuthChallengeInfo> URLRequestJob::GetAuthChallengeInfo() {
  // This will only be called if NeedsAuth() returns true, in which
  // case the derived class should implement this!
  NOTREACHED();
}

void URLRequestJob::SetAuth(const AuthCredentials& credentials) {
  // This will only be called if NeedsAuth() returns true, in which
  // case the derived class should implement this!
  NOTREACHED();
}

void URLRequestJob::CancelAuth() {
  // This will only be called if NeedsAuth() returns true, in which
  // case the derived class should implement this!
  NOTREACHED();
}

void URLRequestJob::ContinueWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key) {
  // The derived class should implement this!
  NOTREACHED();
}

void URLRequestJob::ContinueDespiteLastError() {
  // Implementations should know how to recover from errors they generate.
  // If this code was reached, we are trying to recover from an error that
  // we don't know how to recover from.
  NOTREACHED();
}

int64_t URLRequestJob::prefilter_bytes_read() const {
  return prefilter_bytes_read_;
}

bool URLRequestJob::GetMimeType(std::string* mime_type) const {
  return false;
}

int URLRequestJob::GetResponseCode() const {
  HttpResponseHeaders* headers = request_->response_headers();
  if (!headers)
    return -1;
  return headers->response_code();
}

IPEndPoint URLRequestJob::GetResponseRemoteEndpoint() const {
  return IPEndPoint();
}

void URLRequestJob::NotifyURLRequestDestroyed() {
}

ConnectionAttempts URLRequestJob::GetConnectionAttempts() const {
  return {};
}

void URLRequestJob::CloseConnectionOnDestruction() {}

bool URLRequestJob::NeedsRetryWithStorageAccess() {
  return false;
}

namespace {

// Assuming |url| has already been stripped for use as a referrer, if
// |should_strip_to_origin| is true, this method returns the output of the
// "Strip `url` for use as a referrer" algorithm from the Referrer Policy spec
// with its "origin-only" flag set to true:
// https://w3c.github.io/webappsec-referrer-policy/#strip-url
GURL MaybeStripToOrigin(GURL url, bool should_strip_to_origin) {
  if (!should_strip_to_origin)
    return url;

  return url.DeprecatedGetOriginAsURL();
}

}  // namespace

// static
GURL URLRequestJob::ComputeReferrerForPolicy(
    ReferrerPolicy policy,
    const GURL& original_referrer,
    const GURL& destination,
    bool* same_origin_out_for_metrics) {
  // Here and below, numbered lines are from the Referrer Policy spec's
  // "Determine request's referrer" algorithm:
  // https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer
  //
  // 4. Let referrerURL be the result of stripping referrerSource for use as a
  // referrer.
  GURL stripped_referrer = original_referrer.GetAsReferrer();

  // 5. Let referrerOrigin be the result of stripping referrerSource for use as
  // a referrer, with the origin-only flag set to true.
  //
  // (We use a boolean instead of computing the URL right away in order to avoid
  // constructing a new GURL when it's not necessary.)
  bool should_strip_to_origin = false;

  // 6. If the result of serializing referrerURL is a string whose length is
  // greater than 4096, set referrerURL to referrerOrigin.
  if (stripped_referrer.spec().size() > 4096)
    should_strip_to_origin = true;

  bool same_origin = url::IsSameOriginWith(original_referrer, destination);

  if (same_origin_out_for_metrics)
    *same_origin_out_for_metrics = same_origin;

  // 7. The user agent MAY alter referrerURL or referrerOrigin at this point to
  // enforce arbitrary policy considerations in the interests of minimizing data
  // leakage. For example, the user agent could strip the URL down to an origin,
  // modify its host, replace it with an empty string, etc.
  if (base::FeatureList::IsEnabled(
          features::kCapReferrerToOriginOnCrossOrigin) &&
      !same_origin) {
    should_strip_to_origin = true;
  }

  bool secure_referrer_but_insecure_destination =
      original_referrer.SchemeIsCryptographic() &&
      !destination.SchemeIsCryptographic();

  switch (policy) {
    case ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE:
      if (secure_referrer_but_insecure_destination)
        return GURL();
      return MaybeStripToOrigin(std::move(stripped_referrer),
                                should_strip_to_origin);

    case ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN:
      if (secure_referrer_but_insecure_destination)
        return GURL();
      if (!same_origin)
        should_strip_to_origin = true;
      return MaybeStripToOrigin(std::move(stripped_referrer),
                                should_strip_to_origin);

    case ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN:
      if (!same_origin)
        should_strip_to_origin = true;
      return MaybeStripToOrigin(std::move(stripped_referrer),
                                should_strip_to_origin);

    case ReferrerPolicy::NEVER_CLEAR:
      return MaybeStripToOrigin(std::move(stripped_referrer),
                                should_strip_to_origin);

    case ReferrerPolicy::ORIGIN:
      should_strip_to_origin = true;
      return MaybeStripToOrigin(std::move(stripped_referrer),
                                should_strip_to_origin);

    case ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN:
      if (!same_origin)
        return GURL();
      return MaybeStripToOrigin(std::move(stripped_referrer),
                                should_strip_to_origin);

    case ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE:
      if (secure_referrer_but_insecure_destination)
        return GURL();
      should_strip_to_origin = true;
      return MaybeStripToOrigin(std::move(stripped_referrer),
                                should_strip_to_origin);

    case ReferrerPolicy::NO_REFERRER:
      return GURL();
  }

  NOTREACHED();
}

int URLRequestJob::NotifyConnected(const TransportInfo& info,
                                   CompletionOnceCallback callback) {
  return request_->NotifyConnected(info, std::move(callback));
}

void URLRequestJob::NotifyCertificateRequested(
    SSLCertRequestInfo* cert_request_info) {
  request_->NotifyCertificateRequested(cert_request_info);
}

void URLRequestJob::NotifySSLCertificateError(int net_error,
                                              const SSLInfo& ssl_info,
                                              bool fatal) {
  request_->NotifySSLCertificateError(net_error, ssl_info, fatal);
}

bool URLRequestJob::CanSetCookie(
    const net::CanonicalCookie& cookie,
    CookieOptions* options,
    const net::FirstPartySetMetadata& first_party_set_metadata,
    CookieInclusionStatus* inclusion_status) const {
  return request_->CanSetCookie(cookie, options, first_party_set_metadata,
                                inclusion_status);
}

void URLRequestJob::NotifyHeadersComplete() {
  if (has_handled_response_)
    return;

  // Initialize to the current time, and let the subclass optionally override
  // the time stamps if it has that information.  The default request_time is
  // set by URLRequest before it calls our Start method.
  request_->response_info_.response_time =
      request_->response_info_.original_response_time = base::Time::Now();
  GetResponseInfo(&request_->response_info_);

  request_->OnHeadersComplete();

  GURL new_location;
  int http_status_code;
  bool insecure_scheme_was_upgraded;

  if (NeedsAuth()) {
    CHECK(!IsRedirectResponse(&new_location, &http_status_code,
                              &insecure_scheme_was_upgraded));
    std::unique_ptr<AuthChallengeInfo> auth_info = GetAuthChallengeInfo();
    // Need to check for a NULL auth_info because the server may have failed
    // to send a challenge with the 401 response.
    if (auth_info) {
      request_->NotifyAuthRequired(std::move(auth_info));
      // Wait for SetAuth or CancelAuth to be called.
      return;
    }
  }

  if (NeedsRetryWithStorageAccess()) {
    DoneReadingRetryResponse();
    request_->RetryWithStorageAccess();
    return;
  }

  if (IsRedirectResponse(&new_location, &http_status_code,
                         &insecure_scheme_was_upgraded)) {
    CHECK(!NeedsAuth());
    // Redirect response bodies are not read. Notify the transaction
    // so it does not treat being stopped as an error.
    DoneReadingRedirectResponse();

    // Invalid redirect targets are failed early. This means the delegate can
    // assume that, if it accepts the redirect, future calls to
    // OnResponseStarted correspond to |redirect_info.new_url|.
    int redirect_check_result = CanFollowRedirect(new_location);
    if (redirect_check_result != OK) {
      OnDone(redirect_check_result, true /* notify_done */);
      return;
    }

    RedirectInfo redirect_info = RedirectInfo::ComputeRedirectInfo(
        request_->method(), request_->url(), request_->site_for_cookies(),
        request_->first_party_url_policy(), request_->referrer_policy(),
        request_->referrer(), http_status_code, new_location,
        net::RedirectUtil::GetReferrerPolicyHeader(
            request_->response_headers()),
        insecure_scheme_was_upgraded, CopyFragmentOnRedirect(new_location));
    request_->ReceivedRedirect(redirect_info);
    // |this| may be destroyed at this point.
    return;
  }

  NotifyFinalHeadersReceived();
  // |this| may be destroyed at this point.
}

void URLRequestJob::NotifyFinalHeadersReceived() {
  DCHECK(!NeedsAuth() || !GetAuthChallengeInfo());

  if (has_handled_response_)
    return;

  // While the request's status is normally updated in NotifyHeadersComplete(),
  // URLRequestHttpJob::CancelAuth() posts a task to invoke this method
  // directly, which bypasses that logic.
  if (request_->status() == ERR_IO_PENDING)
    request_->set_status(OK);

  has_handled_response_ = true;
  if (request_->status() == OK) {
    DCHECK(!source_stream_);
    source_stream_ = SetUpSourceStream();

    if (!source_stream_) {
      OnDone(ERR_CONTENT_DECODING_INIT_FAILED, true /* notify_done */);
      return;
    }
    if (source_stream_->type() == SourceStream::TYPE_NONE) {
      // If the subclass didn't set |expected_content_size|, and there are
      // headers, and the response body is not compressed, try to get the
      // expected content size from the headers.
      if (expected_content_size_ == -1 && request_->response_headers()) {
        // This sets |expected_content_size_| to its previous value of -1 if
        // there's no Content-Length header.
        expected_content_size_ =
            request_->response_headers()->GetContentLength();
      }
    } else {
      request_->net_log().AddEvent(
          NetLogEventType::URL_REQUEST_FILTERS_SET,
          [&] { return SourceStreamSetParams(source_stream_.get()); });
    }
  }

  request_->NotifyResponseStarted(OK);
  // |this| may be destroyed at this point.
}

void URLRequestJob::ConvertResultToError(int result, Error* error, int* count) {
  if (result >= 0) {
    *error = OK;
    *count = result;
  } else {
    *error = static_cast<Error>(result);
    *count = 0;
  }
}

void URLRequestJob::ReadRawDataComplete(int result) {
  DCHECK_EQ(ERR_IO_PENDING, request_->status());
  DCHECK_NE(ERR_IO_PENDING, result);

  // The headers should be complete before reads complete
  DCHECK(has_handled_response_);

  GatherRawReadStats(result);

  // Notify SourceStream.
  DCHECK(!read_raw_callback_.is_null());

  std::move(read_raw_callback_).Run(result);
  // |this| may be destroyed at this point.
}

void URLRequestJob::NotifyStartError(int net_error) {
  DCHECK(!has_handled_response_);
  DCHECK_EQ(ERR_IO_PENDING, request_->status());

  has_handled_response_ = true;
  // There may be relevant information in the response info even in the
  // error case.
  GetResponseInfo(&request_->response_info_);

  request_->NotifyResponseStarted(net_error);
  // |this| may have been deleted here.
}

void URLRequestJob::OnDone(int net_error, bool notify_done) {
  DCHECK_NE(ERR_IO_PENDING, net_error);
  DCHECK(!done_) << "Job sending done notification twice";
  if (done_)
    return;
  done_ = true;

  // Unless there was an error, we should have at least tried to handle
  // the response before getting here.
  DCHECK(has_handled_response_ || net_error != OK);

  request_->set_is_pending(false);
  // With async IO, it's quite possible to have a few outstanding
  // requests.  We could receive a request to Cancel, followed shortly
  // by a successful IO.  For tracking the status(), once there is
  // an error, we do not change the status back to success.  To
  // enforce this, only set the status if the job is so far
  // successful.
  if (!request_->failed()) {
    if (net_error != net::OK && net_error != ERR_ABORTED) {
      request_->net_log().AddEventWithNetErrorCode(NetLogEventType::FAILED,
                                                   net_error);
    }
    request_->set_status(net_error);
  }

  if (notify_done) {
    // Complete this notification later.  This prevents us from re-entering the
    // delegate if we're done because of a synchronous call.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&URLRequestJob::NotifyDone, weak_factory_.GetWeakPtr()));
  }
}

void URLRequestJob::NotifyDone() {
  // Check if we should notify the URLRequest that we're done because of an
  // error.
  if (request_->failed()) {
    // We report the error differently depending on whether we've called
    // OnResponseStarted yet.
    if (has_handled_response_) {
      // We signal the error by calling OnReadComplete with a bytes_read of -1.
      request_->NotifyReadCompleted(-1);
    } else {
      has_handled_response_ = true;
      // Error code doesn't actually matter here, since the status has already
      // been updated.
      request_->NotifyResponseStarted(request_->status());
    }
  }
}

void URLRequestJob::NotifyCanceled() {
  if (!done_)
    OnDone(ERR_ABORTED, true /* notify_done */);
}

void URLRequestJob::OnCallToDelegate(NetLogEventType type) {
  request_->OnCallToDelegate(type);
}

void URLRequestJob::OnCallToDelegateComplete() {
  request_->OnCallToDelegateComplete();
}

int URLRequestJob::ReadRawData(IOBuffer* buf, int buf_size) {
  return 0;
}

void URLRequestJob::DoneReading() {
  // Do nothing.
}

void URLRequestJob::DoneReadingRedirectResponse() {
}

void URLRequestJob::DoneReadingRetryResponse() {}

std::unique_ptr<SourceStream> URLRequestJob::SetUpSourceStream() {
  return std::make_unique<URLRequestJobSourceStream>(this);
}

void URLRequestJob::SetProxyChain(const ProxyChain& proxy_chain) {
  request_->proxy_chain_ = proxy_chain;
}

void URLRequestJob::SourceStreamReadComplete(bool synchronous, int result) {
  DCHECK_NE(ERR_IO_PENDING, result);

  if (result > 0 && request()->net_log().IsCapturing()) {
    request()->net_log().AddByteTransferEvent(
        NetLogEventType::URL_REQUEST_JOB_FILTERED_BYTES_READ, result,
        pending_read_buffer_->data());
  }
  pending_read_buffer_ = nullptr;

  if (result < 0) {
    OnDone(result, !synchronous /* notify_done */);
    return;
  }

  if (result > 0) {
    postfilter_bytes_read_ += result;
  } else {
    DCHECK_EQ(0, result);
    DoneReading();
    // In the synchronous case, the caller will notify the URLRequest of
    // completion. In the async case, the NotifyReadCompleted call will.
    // TODO(mmenke): Can this be combined with the error case?
    OnDone(OK, false /* notify_done */);
  }

  if (!synchronous)
    request_->NotifyReadCompleted(result);
}

int URLRequestJob::ReadRawDataHelper(IOBuffer* buf,
                                     int buf_size,
                                     CompletionOnceCallback callback) {
  DCHECK(!raw_read_buffer_);

  // Keep a pointer to the read buffer, so URLRequestJob::GatherRawReadStats()
  // has access to it to log stats.
  raw_read_buffer_ = buf;

  // TODO(xunjieli): Make ReadRawData take in a callback rather than requiring
  // subclass to call ReadRawDataComplete upon asynchronous completion.
  int result = ReadRawData(buf, buf_size);

  if (result != ERR_IO_PENDING) {
    // If the read completes synchronously, either success or failure, invoke
    // GatherRawReadStats so we can account for the completed read.
    GatherRawReadStats(result);
  } else {
    read_raw_callback_ = std::move(callback);
  }
  return result;
}

int URLRequestJob::CanFollowRedirect(const GURL& new_url) {
  if (request_->redirect_limit_ <= 0) {
    DVLOG(1) << "disallowing redirect: exceeds limit";
    return ERR_TOO_MANY_REDIRECTS;
  }

  if (!new_url.is_valid())
    return ERR_INVALID_REDIRECT;

  if (!IsSafeRedirect(new_url)) {
    DVLOG(1) << "disallowing redirect: unsafe protocol";
    return ERR_UNSAFE_REDIRECT;
  }

  return OK;
}

void URLRequestJob::GatherRawReadStats(int bytes_read) {
  DCHECK(raw_read_buffer_ || bytes_read == 0);
  DCHECK_NE(ERR_IO_PENDING, bytes_read);

  if (bytes_read > 0) {
    // If there is a filter, bytes will be logged after the filter is applied.
    if (source_stream_->type() != SourceStream::TYPE_NONE &&
        request()->net_log().IsCapturing()) {
      request()->net_log().AddByteTransferEvent(
          NetLogEventType::URL_REQUEST_JOB_BYTES_READ, bytes_read,
          raw_read_buffer_->data());
    }
    RecordBytesRead(bytes_read);
  }
  raw_read_buffer_ = nullptr;
}

void URLRequestJob::RecordBytesRead(int bytes_read) {
  DCHECK_GT(bytes_read, 0);
  prefilter_bytes_read_ += base::checked_cast<size_t>(bytes_read);

  // On first read, notify NetworkQualityEstimator that response headers have
  // been received.
  // TODO(tbansal): Move this to url_request_http_job.cc. This may catch
  // Service Worker jobs twice.
  // If prefilter_bytes_read_ is equal to bytes_read, it indicates this is the
  // first raw read of the response body. This is used as the signal that
  // response headers have been received.
  if (request_->context()->network_quality_estimator()) {
    if (prefilter_bytes_read() == bytes_read) {
      request_->context()->network_quality_estimator()->NotifyHeadersReceived(
          *request_, prefilter_bytes_read());
    } else {
      request_->context()->network_quality_estimator()->NotifyBytesRead(
          *request_, prefilter_bytes_read());
    }
  }

  DVLOG(2) << __FUNCTION__ << "() "
           << "\"" << request_->url().spec() << "\""
           << " pre bytes read = " << bytes_read
           << " pre total = " << prefilter_bytes_read()
           << " post total = " << postfilter_bytes_read();
}

}  // namespace net

"""

```