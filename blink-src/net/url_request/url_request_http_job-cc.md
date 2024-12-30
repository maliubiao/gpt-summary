Response:
The user wants a summary of the functionality of the `url_request_http_job.cc` file in Chromium's network stack. The summary should also cover relationships with JavaScript, logical reasoning with examples, common usage errors, and debugging hints related to user actions.

**Plan:**

1. **Identify Core Functionality:** Analyze the code's structure and the classes/methods it uses to understand its primary purpose. This will involve looking at how it handles HTTP requests.
2. **JavaScript Relationship:**  Consider how network requests initiated by JavaScript in a browser environment interact with this component. Focus on areas like cookie handling, headers, and request initiation.
3. **Logical Reasoning:**  Look for conditional logic and decision points within the code. Create hypothetical inputs and their expected outputs based on this logic.
4. **User/Programming Errors:** Identify common mistakes users or developers might make that could lead to the execution of code within this file, potentially resulting in errors.
5. **User Action Trace:**  Map common user actions in a browser to the execution path leading to this file. This will be helpful for debugging.
6. **First Part Summarization:** Condense the findings from steps 1-5 into a concise summary for the first part of the request.
```
功能：

`URLRequestHttpJob` 是 Chromium 网络栈中处理 HTTP 和 HTTPS 请求的核心类之一。它的主要功能可以归纳为以下几点：

1. **创建 HTTP 事务:**  负责创建和管理底层的 `HttpTransaction` 对象，该对象实际执行网络请求。
2. **处理请求信息:** 从 `URLRequest` 对象中提取请求的 URL、方法、头部、负载等信息，并存储在 `request_info_` 成员中。
3. **管理 Cookie:**
    - 从 CookieStore 中读取与请求 URL 相关的 Cookie，并添加到请求头部的 "Cookie" 字段中。
    - 处理服务器响应中的 "Set-Cookie" 头部，将新的或更新的 Cookie 存储到 CookieStore 中。
    - 考虑同站 (SameSite) 策略、第一方集合 (First-Party Sets) 和隐私模式对 Cookie 的影响。
4. **处理安全相关的头部:**
    - 处理 Strict-Transport-Security (HSTS) 头部，根据 HSTS 策略将后续对该域名的 HTTP 请求升级为 HTTPS。
    - 处理设备绑定会话 (Device Bound Sessions) 相关的头部。
5. **处理重定向:**  虽然这个文件本身不直接处理所有类型的重定向，但它为 HTTP 级别的重定向提供基础，并可能根据 HSTS 策略发起重定向。
6. **集成网络代理:**  尽管代码中没有直接的代理逻辑，但它通过 `HttpTransaction` 与代理解析服务进行交互。
7. **网络日志记录:**  使用 `NetLog` 记录请求的各个阶段和关键事件，用于调试和性能分析。
8. **用户代理 (User-Agent) 管理:**  设置默认的 User-Agent 头部，也可以根据配置进行修改。
9. **内容编码处理:**  处理服务器返回的内容编码，如 gzip、deflate、brötli 和 zstd，并进行解码。
10. **与 NetworkDelegate 交互:**  在请求的关键阶段调用 `NetworkDelegate` 的方法，允许外部代码（如扩展程序）干预请求过程。
11. **处理认证:**  支持 HTTP 认证机制，例如在收到 401 或 407 响应时重新启动事务并添加认证信息。
12. **隐私模式处理:**  根据请求的隐私模式（例如隐身模式）决定是否发送和存储 Cookie。

与 JavaScript 的功能关系：

`URLRequestHttpJob` 与 JavaScript 的功能有密切关系，因为它处理了所有由 JavaScript 发起的 HTTP 和 HTTPS 请求。以下是一些例子：

- **`fetch()` API:** 当 JavaScript 代码使用 `fetch()` API 发起网络请求时，浏览器底层会创建 `URLRequest` 对象，并最终由 `URLRequestHttpJob` 处理。例如：
  ```javascript
  fetch('https://example.com/data.json')
    .then(response => response.json())
    .then(data => console.log(data));
  ```
  在这个例子中，`URLRequestHttpJob` 会负责建立到 `example.com` 的连接，发送请求头（包括可能的 Cookie），接收响应头和响应体，并最终将响应数据传递回 JavaScript 的 `fetch()` API 的 Promise。

- **`XMLHttpRequest` (XHR):**  类似地，当使用 `XMLHttpRequest` 对象发起请求时，也会经过 `URLRequestHttpJob` 处理。例如：
  ```javascript
  const xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://example.com/image.png');
  xhr.onload = function() {
    // 处理响应
  };
  xhr.send();
  ```
  `URLRequestHttpJob` 会处理 XHR 对象发出的 GET 请求，包括设置请求头、处理 Cookie、接收响应等。

- **Cookie 的读写:**  当 JavaScript 使用 `document.cookie` API 读取或设置 Cookie 时，浏览器会将这些操作与 `URLRequestHttpJob` 处理的网络请求关联起来。例如，当一个由 JavaScript 发起的请求发送到服务器时，`URLRequestHttpJob` 会根据 `document.cookie` 的值设置请求头部的 "Cookie" 字段。同样，当服务器通过 "Set-Cookie" 头部设置 Cookie 时，浏览器会更新 JavaScript 可以通过 `document.cookie` 访问的 Cookie。

逻辑推理的假设输入与输出：

**假设输入:**

1. **请求 URL:** `http://example.com`
2. **HSTS 策略:**  `example.com` 已通过 HSTS 设置，要求使用 HTTPS。
3. **用户操作:** 用户在浏览器地址栏输入 `http://example.com` 并回车。

**逻辑推理:**

- `URLRequestHttpJob::Create()` 被调用，传入 `http://example.com` 的 `URLRequest` 对象。
- 代码检查 URL 方案是 HTTP。
- 代码查询 `TransportSecurityState` (HSTS 状态)。
- 发现 `example.com` 存在 HSTS 策略。
- `upgrade_decision` 不为 `SSLUpgradeDecision::kNoUpgrade`。
- 代码创建一个 `URLRequestRedirectJob`，将请求重定向到 `https://example.com`，状态码为 307。

**输出:**

- 浏览器不会直接访问 `http://example.com`。
- 浏览器会发起一个新的请求到 `https://example.com`。
- 用户在地址栏中最终看到的是 `https://example.com`。

用户或编程常见的使用错误：

1. **混合内容错误 (Mixed Content Error):** 在 HTTPS 页面中加载 HTTP 资源。例如，一个 HTTPS 网站尝试加载 `http://example.com/script.js`。这会导致浏览器阻止该请求，`URLRequestHttpJob` 会处理该请求但可能由于安全策略而失败。用户会在浏览器的开发者工具中看到混合内容错误。

2. **Cookie 设置不当:**  开发者在服务器端设置 Cookie 时，`domain` 或 `path` 属性设置错误，导致客户端无法正确发送 Cookie。例如，Cookie 的 `domain` 设置为 `.sub.example.com`，但当前页面是 `example.com`，浏览器可能不会发送该 Cookie。在调试时，可以通过查看请求头部的 "Cookie" 字段来确认 Cookie 是否被正确发送。

3. **CORS (跨域资源共享) 问题:**  JavaScript 代码从一个域名请求另一个域名的资源，但目标服务器没有设置正确的 CORS 头部。例如，`https://app.example.com` 的 JavaScript 代码尝试使用 `fetch()` 请求 `https://api.another-example.com/data`，但 `api.another-example.com` 的响应头缺少 `Access-Control-Allow-Origin` 等头部。`URLRequestHttpJob` 会处理该请求，但浏览器会阻止 JavaScript 代码访问响应内容。

4. **HSTS 设置错误:**  服务器错误地设置了 HSTS 头部，例如设置了非常长的 `max-age`，但之后又想回退到 HTTP。这会导致浏览器在一段时间内强制使用 HTTPS，即使服务器不再支持。用户可能会遇到连接错误。

用户操作是如何一步步的到达这里，作为调试线索：

1. **用户在浏览器地址栏输入 URL 并回车：**
   - 浏览器解析 URL。
   - 创建一个 `URLRequest` 对象。
   - `URLRequestJobFactory` 根据 URL 的 scheme (http/https) 创建相应的 `URLRequestJob`，对于 HTTP 和 HTTPS 会创建 `URLRequestHttpJob`。
   - `URLRequestHttpJob::Start()` 被调用，开始处理请求。

2. **用户点击网页上的链接：**
   - 浏览器解析链接的 URL。
   - 创建一个 `URLRequest` 对象。
   - 同样，`URLRequestJobFactory` 会创建 `URLRequestHttpJob`。

3. **网页上的 JavaScript 代码发起网络请求 (fetch, XHR)：**
   - JavaScript 引擎调用浏览器提供的网络 API。
   - 浏览器创建 `URLRequest` 对象。
   - `URLRequestJobFactory` 创建 `URLRequestHttpJob`。

4. **浏览器扩展程序发起网络请求：**
   - 扩展程序使用 Chrome 提供的 API 发起请求。
   - 同样会创建 `URLRequest` 和 `URLRequestHttpJob`。

**调试线索:**

- **网络面板 (Network tab) in DevTools:** 这是最直接的调试网络请求的工具。可以看到请求的 URL、状态码、头部、Cookie 等信息。可以观察请求是否被重定向，Cookie 是否被正确发送和接收，是否存在 CORS 问题等。
- **`chrome://net-internals/#events`:**  可以查看更底层的网络事件，包括 `URLRequestHttpJob` 的创建、`HttpTransaction` 的启动、Cookie 的读取和设置等详细信息。
- **`chrome://net-internals/#http2`:**  查看 HTTP/2 连接的状态。
- **`chrome://net-internals/#hsts`:** 查看 HSTS 策略。

**总结一下它的功能 (第 1 部分):**

`URLRequestHttpJob` 是 Chromium 网络栈中负责处理 HTTP 和 HTTPS 请求的核心组件。它从 `URLRequest` 获取请求信息，管理底层的 `HttpTransaction`，处理 Cookie、HSTS 等安全相关的头部，并与 `NetworkDelegate` 交互。它直接处理由用户在地址栏输入、点击链接或由 JavaScript 代码发起的网络请求，是连接浏览器上层应用和底层网络通信的关键桥梁。其主要职责包括创建和执行 HTTP 事务，管理请求和响应头，处理 Cookie，执行 HSTS 策略，并记录网络事件以供调试。
```
Prompt: 
```
这是目录为net/url_request/url_request_http_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_http_job.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "base/base_switches.h"
#include "base/check_op.h"
#include "base/command_line.h"
#include "base/compiler_specific.h"
#include "base/containers/adapters.h"
#include "base/feature_list.h"
#include "base/file_version_info.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_functions_internal_overloads.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/types/optional_util.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/http_user_agent_settings.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_delegate.h"
#include "net/base/network_isolation_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/schemeful_site.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/base/url_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/known_roots.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_access_delegate.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_partition_key.h"
#include "net/cookies/cookie_setting_override.h"
#include "net/cookies/cookie_store.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/parsed_cookie.h"
#include "net/filter/brotli_source_stream.h"
#include "net/filter/filter_source_stream.h"
#include "net/filter/gzip_source_stream.h"
#include "net/filter/source_stream.h"
#include "net/filter/zstd_source_stream.h"
#include "net/first_party_sets/first_party_set_entry.h"
#include "net/first_party_sets/first_party_set_metadata.h"
#include "net/first_party_sets/first_party_sets_cache_filter.h"
#include "net/http/http_content_disposition.h"
#include "net/http/http_log_util.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/http/http_transaction.h"
#include "net/http/http_transaction_factory.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_values.h"
#include "net/log/net_log_with_source.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_retry_info.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/storage_access_api/status.h"
#include "net/url_request/clear_site_data.h"
#include "net/url_request/redirect_util.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_error_job.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_redirect_job.h"
#include "net/url_request/websocket_handshake_userdata_key.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/url_constants.h"

#if BUILDFLAG(IS_ANDROID)
#include "net/android/network_library.h"
#endif

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
#include "net/device_bound_sessions/registration_fetcher_param.h"
#include "net/device_bound_sessions/session_challenge_param.h"
#include "net/device_bound_sessions/session_service.h"
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

namespace {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class TpcdHeaderStatus {
  kSet = 0,
  kNoLabel = 1,
  kNoCookie = 2,
  kMaxValue = kNoCookie,
};

void RecordTpcdHeaderStatus(TpcdHeaderStatus status) {
  base::UmaHistogramEnumeration("Privacy.3PCD.SecCookieDeprecationHeaderStatus",
                                status);
}

base::Value::Dict FirstPartySetMetadataNetLogParams(
    const net::FirstPartySetMetadata& first_party_set_metadata,
    const int64_t* const fps_cache_filter) {
  base::Value::Dict dict;
  auto entry_or_empty =
      [](const std::optional<net::FirstPartySetEntry>& entry) -> std::string {
    return entry.has_value() ? entry->GetDebugString() : "none";
  };

  dict.Set("cache_filter",
           fps_cache_filter ? base::NumberToString(*fps_cache_filter) : "none");
  dict.Set("frame_entry",
           entry_or_empty(first_party_set_metadata.frame_entry()));
  dict.Set("top_frame_primary",
           entry_or_empty(first_party_set_metadata.top_frame_entry()));
  return dict;
}

base::Value::Dict CookieInclusionStatusNetLogParams(
    const std::string& operation,
    const std::string& cookie_name,
    const std::string& cookie_domain,
    const std::string& cookie_path,
    const std::optional<net::CookiePartitionKey>& partition_key,
    const net::CookieInclusionStatus& status,
    net::NetLogCaptureMode capture_mode) {
  base::Value::Dict dict;
  dict.Set("operation", operation);
  dict.Set("status", status.GetDebugString());
  if (net::NetLogCaptureIncludesSensitive(capture_mode)) {
    if (!cookie_name.empty())
      dict.Set("name", cookie_name);
    if (!cookie_domain.empty())
      dict.Set("domain", cookie_domain);
    if (!cookie_path.empty())
      dict.Set("path", cookie_path);
  }
  // The partition key is not sensitive, since it is fully determined by the
  // structure of the page. The cookie may either be partitioned or not, but
  // does not have the ability to influence the key's value.
  std::string partition_key_str;
  if (partition_key.has_value()) {
    base::expected<net::CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        serialized = net::CookiePartitionKey::Serialize(partition_key);
    partition_key_str = serialized.has_value()
                            ? serialized.value().GetDebugString()
                            : serialized.error();
  } else {
    partition_key_str = "(none)";
  }
  dict.Set("partition_key", std::move(partition_key_str));
  return dict;
}

// Records details about the most-specific trust anchor in |spki_hashes|,
// which is expected to be ordered with the leaf cert first and the root cert
// last. This complements the per-verification histogram
// Net.Certificate.TrustAnchor.Verify
void LogTrustAnchor(const net::HashValueVector& spki_hashes) {
  // Don't record metrics if there are no hashes; this is true if the HTTP
  // load did not come from an active network connection, such as the disk
  // cache or a synthesized response.
  if (spki_hashes.empty())
    return;

  int32_t id = 0;
  for (const auto& hash : spki_hashes) {
    id = net::GetNetTrustAnchorHistogramIdForSPKI(hash);
    if (id != 0)
      break;
  }
  base::UmaHistogramSparse("Net.Certificate.TrustAnchor.Request", id);
}

net::CookieOptions CreateCookieOptions(
    net::CookieOptions::SameSiteCookieContext same_site_context) {
  net::CookieOptions options;
  options.set_return_excluded_cookies();
  options.set_include_httponly();
  options.set_same_site_cookie_context(same_site_context);
  return options;
}

bool IsTLS13OverTCP(const net::HttpResponseInfo& response_info) {
  // Although IETF QUIC also uses TLS 1.3, our QUIC connections report
  // SSL_CONNECTION_VERSION_QUIC.
  return net::SSLConnectionStatusToVersion(
             response_info.ssl_info.connection_status) ==
         net::SSL_CONNECTION_VERSION_TLS1_3;
}

GURL UpgradeSchemeToCryptographic(const GURL& insecure_url) {
  DCHECK(!insecure_url.SchemeIsCryptographic());
  DCHECK(insecure_url.SchemeIs(url::kHttpScheme) ||
         insecure_url.SchemeIs(url::kWsScheme));

  GURL::Replacements replacements;
  replacements.SetSchemeStr(insecure_url.SchemeIs(url::kHttpScheme)
                                ? url::kHttpsScheme
                                : url::kWssScheme);

  GURL secure_url = insecure_url.ReplaceComponents(replacements);
  DCHECK(secure_url.SchemeIsCryptographic());

  return secure_url;
}

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class ContentEncodingType {
  kUnknown = 0,
  kBrotli = 1,
  kGZip = 2,
  kDeflate = 3,
  kZstd = 4,
  kMaxValue = kZstd,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class HttpRequestStsState {
  kUnknown = 0,
  kUnprotectedHttps = 1,
  kProtectedHttps = 2,
  kUnprotectedHttp = 3,
  kProtectedHttp = 4,
  kMaxValue = kProtectedHttp,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
// LINT.IfChange(HttpRequestSSLUpgradeDecision)
enum class HttpRequestSSLUpgradeDecision {
  // The request was insecure and was not upgraded to use SSL.
  kInsecureNoUpgrade = 0,
  // The request used SSL. It would not have been upgraded if it was insecure.
  kSSLNoUpgrade = 1,
  // The request was insecure but upgraded to use SSL using static data.
  kInsecureStaticUpgrade = 2,
  // The request used SSL. If was insecure, it would have been upgraded using
  // static data.
  kSSLStaticUpgrade = 3,
  // The request was insecure but upgraded to use SSL using dynamic data. It
  // would not have been upgraded using only static data.
  kInsecureDynamicUpgrade = 4,
  // The request used SSL. If it was insecure, it would have been upgraded using
  // dynamic data but not with only static data.
  kSSLDynamicUpgrade = 5,
  kMaxValue = kSSLDynamicUpgrade,
};
// LINT.ThenChange(//tools/metrics/histograms/metadata/enums.xml:HttpRequestSSLUpgradeDecision)

HttpRequestSSLUpgradeDecision GetMetricForSSLUpgradeDecision(
    net::SSLUpgradeDecision upgrade_decision,
    bool is_secure) {
  switch (upgrade_decision) {
    case net::SSLUpgradeDecision::kNoUpgrade:
      return is_secure ? HttpRequestSSLUpgradeDecision::kSSLNoUpgrade
                       : HttpRequestSSLUpgradeDecision::kInsecureNoUpgrade;
    case net::SSLUpgradeDecision::kStaticUpgrade:
      return is_secure ? HttpRequestSSLUpgradeDecision::kSSLStaticUpgrade
                       : HttpRequestSSLUpgradeDecision::kInsecureStaticUpgrade;
    case net::SSLUpgradeDecision::kDynamicUpgrade:
      return is_secure ? HttpRequestSSLUpgradeDecision::kSSLDynamicUpgrade
                       : HttpRequestSSLUpgradeDecision::kInsecureDynamicUpgrade;
  }
  NOTREACHED();
}

void RecordSTSHistograms(net::SSLUpgradeDecision upgrade_decision,
                         bool is_secure,
                         int load_flags) {
  // Embrace the layering violation and only record the histogram for main frame
  // navigations. It's possible to record this outside of net/, but the code is
  // a lot more complicated, and while this flag is deprecated, there are no
  // current plans to remove it. See crbug.com/516499 .
  if (!(load_flags & net::LOAD_MAIN_FRAME_DEPRECATED)) {
    return;
  }
  const bool sts_enabled =
      upgrade_decision != net::SSLUpgradeDecision::kNoUpgrade;
  HttpRequestStsState sts_state = HttpRequestStsState::kUnknown;
  if (is_secure) {
    sts_state = (sts_enabled ? HttpRequestStsState::kProtectedHttps
                             : HttpRequestStsState::kUnprotectedHttps);
  } else {
    sts_state = (sts_enabled ? HttpRequestStsState::kProtectedHttp
                             : HttpRequestStsState::kUnprotectedHttp);
  }
  UMA_HISTOGRAM_ENUMERATION("Net.HttpRequestStsState", sts_state);

  UMA_HISTOGRAM_ENUMERATION(
      "Net.HttpRequestSSLUpgradeDecision",
      GetMetricForSSLUpgradeDecision(upgrade_decision, is_secure));
}

}  // namespace

namespace net {

std::unique_ptr<URLRequestJob> URLRequestHttpJob::Create(URLRequest* request) {
  const GURL& url = request->url();

  // URLRequestContext must have been initialized.
  DCHECK(request->context()->http_transaction_factory());
  DCHECK(url.SchemeIsHTTPOrHTTPS() || url.SchemeIsWSOrWSS());

  SSLUpgradeDecision upgrade_decision = SSLUpgradeDecision::kNoUpgrade;
  if (TransportSecurityState* hsts =
          request->context()->transport_security_state()) {
    upgrade_decision =
        hsts->GetSSLUpgradeDecision(url.host(), request->net_log());
  }

  // Check for reasons not to return a URLRequestHttpJob. These don't apply to
  // https and wss requests.
  if (!url.SchemeIsCryptographic()) {
    // If the request explicitly has been marked to bypass HSTS, ensure that
    // the request is in no-credential mode so that the http site can't read
    // or set cookies which are shared across http/https, then skip the
    // upgrade.
    if (((request->load_flags() & net::LOAD_SHOULD_BYPASS_HSTS) ==
         net::LOAD_SHOULD_BYPASS_HSTS)) {
      CHECK(request->allow_credentials() == false);
    } else {
      // Check for HSTS upgrade.
      if (upgrade_decision != SSLUpgradeDecision::kNoUpgrade) {
        RecordSTSHistograms(upgrade_decision,
                            /*is_secure=*/false, request->load_flags());
        return std::make_unique<URLRequestRedirectJob>(
            request, UpgradeSchemeToCryptographic(url),
            // Use status code 307 to preserve the method, so POST requests
            // work.
            RedirectUtil::ResponseCode::REDIRECT_307_TEMPORARY_REDIRECT,
            "HSTS");
      }
    }

#if BUILDFLAG(IS_ANDROID)
    // Check whether the app allows cleartext traffic to this host, and return
    // ERR_CLEARTEXT_NOT_PERMITTED if not.
    if (request->context()->check_cleartext_permitted() &&
        !android::IsCleartextPermitted(url.host_piece())) {
      RecordSTSHistograms(SSLUpgradeDecision::kNoUpgrade,
                          /*is_secure=*/false, request->load_flags());
      return std::make_unique<URLRequestErrorJob>(request,
                                                  ERR_CLEARTEXT_NOT_PERMITTED);
    }
#endif
  }

  RecordSTSHistograms(upgrade_decision, url.SchemeIsCryptographic(),
                      request->load_flags());
  return base::WrapUnique<URLRequestJob>(new URLRequestHttpJob(
      request, request->context()->http_user_agent_settings()));
}

URLRequestHttpJob::URLRequestHttpJob(
    URLRequest* request,
    const HttpUserAgentSettings* http_user_agent_settings)
    : URLRequestJob(request),
      http_user_agent_settings_(http_user_agent_settings) {
  ResetTimer();
}

URLRequestHttpJob::~URLRequestHttpJob() {
  CHECK(!awaiting_callback_);

  DoneWithRequest(ABORTED);
}

void URLRequestHttpJob::SetPriority(RequestPriority priority) {
  priority_ = priority;
  if (transaction_)
    transaction_->SetPriority(priority_);
}

void URLRequestHttpJob::Start() {
  DCHECK(!transaction_.get());

  request_info_.url = request_->url();
  request_info_.method = request_->method();

  request_info_.network_isolation_key =
      request_->isolation_info().network_isolation_key();
  request_info_.network_anonymization_key =
      request_->isolation_info().network_anonymization_key();
  request_info_.possibly_top_frame_origin =
      request_->isolation_info().top_frame_origin();
  request_info_.frame_origin = request_->isolation_info().frame_origin();
  request_info_.is_subframe_document_resource =
      request_->isolation_info().request_type() ==
      net::IsolationInfo::RequestType::kSubFrame;
  request_info_.is_main_frame_navigation =
      request_->isolation_info().IsMainFrameRequest();
  request_info_.initiator = request_->initiator();
  request_info_.load_flags = request_->load_flags();
  request_info_.priority_incremental = request_->priority_incremental();
  request_info_.secure_dns_policy = request_->secure_dns_policy();
  request_info_.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(request_->traffic_annotation());
  request_info_.socket_tag = request_->socket_tag();
  request_info_.idempotency = request_->GetIdempotency();
#if BUILDFLAG(ENABLE_REPORTING)
  request_info_.reporting_upload_depth = request_->reporting_upload_depth();
#endif

  CookieStore* cookie_store = request()->context()->cookie_store();
  const CookieAccessDelegate* delegate =
      cookie_store ? cookie_store->cookie_access_delegate() : nullptr;

  request_->net_log().BeginEvent(NetLogEventType::FIRST_PARTY_SETS_METADATA);

  std::optional<
      std::pair<FirstPartySetMetadata, FirstPartySetsCacheFilter::MatchInfo>>
      maybe_metadata = cookie_util::ComputeFirstPartySetMetadataMaybeAsync(
          SchemefulSite(request()->url()), request()->isolation_info(),
          delegate,
          base::BindOnce(&URLRequestHttpJob::OnGotFirstPartySetMetadata,
                         weak_factory_.GetWeakPtr()));

  if (maybe_metadata.has_value()) {
    auto [metadata, match_info] = std::move(maybe_metadata).value();
    OnGotFirstPartySetMetadata(std::move(metadata), std::move(match_info));
  }
}

namespace {

bool ShouldBlockAllCookies(PrivacyMode privacy_mode) {
  return privacy_mode == PRIVACY_MODE_ENABLED ||
         privacy_mode == PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS;
}

}  // namespace

void URLRequestHttpJob::OnGotFirstPartySetMetadata(
    FirstPartySetMetadata first_party_set_metadata,
    FirstPartySetsCacheFilter::MatchInfo match_info) {
  first_party_set_metadata_ = std::move(first_party_set_metadata);
  request_info_.fps_cache_filter = match_info.clear_at_run_id;
  request_info_.browser_run_id = match_info.browser_run_id;

  request_->net_log().EndEvent(
      NetLogEventType::FIRST_PARTY_SETS_METADATA, [&]() {
        return FirstPartySetMetadataNetLogParams(
            first_party_set_metadata_,
            base::OptionalToPtr(request_info_.fps_cache_filter));
      });

  // Privacy mode could still be disabled in SetCookieHeaderAndStart if we are
  // going to send previously saved cookies.
  request_info_.privacy_mode = DeterminePrivacyMode();
  request()->net_log().AddEventWithStringParams(
      NetLogEventType::COMPUTED_PRIVACY_MODE, "privacy_mode",
      PrivacyModeToDebugString(request_info_.privacy_mode));

  // Strip Referer from request_info_.extra_headers to prevent, e.g., plugins
  // from overriding headers that are controlled using other means. Otherwise a
  // plugin could set a referrer although sending the referrer is inhibited.
  request_info_.extra_headers.RemoveHeader(HttpRequestHeaders::kReferer);

  // URLRequest::SetReferrer ensures that we do not send username and password
  // fields in the referrer.
  GURL referrer(request_->referrer());

  // Our consumer should have made sure that this is a safe referrer (e.g. via
  // URLRequestJob::ComputeReferrerForPolicy).
  if (referrer.is_valid()) {
    std::string referer_value = referrer.spec();
    request_info_.extra_headers.SetHeader(HttpRequestHeaders::kReferer,
                                          referer_value);
  }

  request_info_.extra_headers.SetHeaderIfMissing(
      HttpRequestHeaders::kUserAgent,
      http_user_agent_settings_ ?
          http_user_agent_settings_->GetUserAgent() : std::string());

  AddExtraHeaders();

  if (ShouldAddCookieHeader()) {
    AddCookieHeaderAndStart();
  } else {
    StartTransaction();
  }
}

void URLRequestHttpJob::Kill() {
  weak_factory_.InvalidateWeakPtrs();
  if (transaction_)
    DestroyTransaction();
  URLRequestJob::Kill();
}

ConnectionAttempts URLRequestHttpJob::GetConnectionAttempts() const {
  if (transaction_)
    return transaction_->GetConnectionAttempts();
  return {};
}

void URLRequestHttpJob::CloseConnectionOnDestruction() {
  DCHECK(transaction_);
  transaction_->CloseConnectionOnDestruction();
}

int URLRequestHttpJob::NotifyConnectedCallback(
    const TransportInfo& info,
    CompletionOnceCallback callback) {
  return URLRequestJob::NotifyConnected(info, std::move(callback));
}

PrivacyMode URLRequestHttpJob::DeterminePrivacyMode() const {
  if (!request()->allow_credentials()) {
    // |allow_credentials_| implies LOAD_DO_NOT_SAVE_COOKIES.
    DCHECK(request_->load_flags() & LOAD_DO_NOT_SAVE_COOKIES);

    // TODO(crbug.com/40089326): Client certs should always be
    // affirmatively omitted for these requests.
    return request()->send_client_certs()
               ? PRIVACY_MODE_ENABLED
               : PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS;
  }

  // Otherwise, check with the delegate if present, or base it off of
  // |URLRequest::DefaultCanUseCookies()| if not.
  // TODO(mmenke): Looks like |URLRequest::DefaultCanUseCookies()| is not too
  // useful, with the network service - remove it.
  NetworkDelegate::PrivacySetting privacy_setting =
      URLRequest::DefaultCanUseCookies()
          ? NetworkDelegate::PrivacySetting::kStateAllowed
          : NetworkDelegate::PrivacySetting::kStateDisallowed;
  if (request_->network_delegate()) {
    privacy_setting =
        request()->network_delegate()->ForcePrivacyMode(*request());
  }
  switch (privacy_setting) {
    case NetworkDelegate::PrivacySetting::kStateAllowed:
      return PRIVACY_MODE_DISABLED;
    case NetworkDelegate::PrivacySetting::kPartitionedStateAllowedOnly:
      return PRIVACY_MODE_ENABLED_PARTITIONED_STATE_ALLOWED;
    case NetworkDelegate::PrivacySetting::kStateDisallowed:
      return PRIVACY_MODE_ENABLED;
  }
  NOTREACHED();
}

void URLRequestHttpJob::NotifyHeadersComplete() {
  DCHECK(!response_info_);
  DCHECK_EQ(0, num_cookie_lines_left_);
  DCHECK(request_->maybe_stored_cookies().empty());

  if (override_response_info_) {
    DCHECK(!transaction_);
    response_info_ = override_response_info_.get();
  } else {
    response_info_ = transaction_->GetResponseInfo();
  }

  ProcessStrictTransportSecurityHeader();
#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
  ProcessDeviceBoundSessionsHeader();
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

  // Clear |set_cookie_access_result_list_| after any processing in case
  // SaveCookiesAndNotifyHeadersComplete is called again.
  request_->set_maybe_stored_cookies(std::move(set_cookie_access_result_list_));

  // The HTTP transaction may be restarted several times for the purposes
  // of sending authorization information. Each time it restarts, we get
  // notified of the headers completion so that we can update the cookie store.
  if (transaction_ && transaction_->IsReadyToRestartForAuth()) {
    // TODO(battre): This breaks the webrequest API for
    // URLRequestTestHTTP.BasicAuthWithCookies
    // where OnBeforeStartTransaction -> OnStartTransaction ->
    // OnBeforeStartTransaction occurs.
    RestartTransactionWithAuth(AuthCredentials());
    return;
  }

  URLRequestJob::NotifyHeadersComplete();
}

void URLRequestHttpJob::DestroyTransaction() {
  DCHECK(transaction_.get());

  DoneWithRequest(ABORTED);

  total_received_bytes_from_previous_transactions_ +=
      transaction_->GetTotalReceivedBytes();
  total_sent_bytes_from_previous_transactions_ +=
      transaction_->GetTotalSentBytes();
  response_info_ = nullptr;
  transaction_.reset();
  override_response_headers_ = nullptr;
  receive_headers_end_ = base::TimeTicks();
}

void URLRequestHttpJob::StartTransaction() {
  DCHECK(!override_response_info_);

  NetworkDelegate* network_delegate = request()->network_delegate();
  if (network_delegate) {
    OnCallToDelegate(
        NetLogEventType::NETWORK_DELEGATE_BEFORE_START_TRANSACTION);
    int rv = network_delegate->NotifyBeforeStartTransaction(
        request_, request_info_.extra_headers,
        base::BindOnce(&URLRequestHttpJob::NotifyBeforeStartTransactionCallback,
                       weak_factory_.GetWeakPtr()));
    // If an extension blocks the request, we rely on the callback to
    // MaybeStartTransactionInternal().
    if (rv == ERR_IO_PENDING)
      return;
    MaybeStartTransactionInternal(rv);
    return;
  }
  StartTransactionInternal();
}

void URLRequestHttpJob::NotifyBeforeStartTransactionCallback(
    int result,
    const std::optional<HttpRequestHeaders>& headers) {
  // The request should not have been cancelled or have already completed.
  DCHECK(!is_done());

  if (headers)
    request_info_.extra_headers = headers.value();
  MaybeStartTransactionInternal(result);
}

void URLRequestHttpJob::MaybeStartTransactionInternal(int result) {
  OnCallToDelegateComplete();
  if (result == OK) {
    StartTransactionInternal();
  } else {
    request_->net_log().AddEventWithStringParams(NetLogEventType::CANCELLED,
                                                 "source", "delegate");
    // Don't call back synchronously to the delegate.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&URLRequestHttpJob::NotifyStartError,
                                  weak_factory_.GetWeakPtr(), result));
  }
}

void URLRequestHttpJob::StartTransactionInternal() {
  DCHECK(!override_response_headers_);

  // NOTE: This method assumes that request_info_ is already setup properly.

  // If we already have a transaction, then we should restart the transaction
  // with auth provided by auth_credentials_.

  int rv;

  // Notify NetworkQualityEstimator.
  NetworkQualityEstimator* network_quality_estimator =
      request()->context()->network_quality_estimator();
  if (network_quality_estimator)
    network_quality_estimator->NotifyStartTransaction(*request_);

  if (transaction_.get()) {
    rv = transaction_->RestartWithAuth(
        auth_credentials_, base::BindOnce(&URLRequestHttpJob::OnStartCompleted,
                                          base::Unretained(this)));
    auth_credentials_ = AuthCredentials();
  } else {
    DCHECK(request_->context()->http_transaction_factory());

    rv = request_->context()->http_transaction_factory()->CreateTransaction(
        priority_, &transaction_);

    if (rv == OK && request_info_.url.SchemeIsWSOrWSS()) {
      base::SupportsUserData::Data* data =
          request_->GetUserData(kWebSocketHandshakeUserDataKey);
      if (data) {
        transaction_->SetWebSocketHandshakeStreamCreateHelper(
            static_cast<WebSocketHandshakeStreamBase::CreateHelper*>(data));
      } else {
        rv = ERR_DISALLOWED_URL_SCHEME;
      }
    }

    if (rv == OK && request_info_.method == "CONNECT") {
      // CONNECT has different kinds of targets than other methods (RFC 9110,
      // section 9.3.6), which are incompatible with URLRequest.
      rv = ERR_METHOD_NOT_SUPPORTED;
    }

    if (rv == OK) {
      transaction_->SetConnectedCallback(base::BindRepeating(
          &URLRequestHttpJob::NotifyConnectedCallback, base::Unretained(this)));
      transaction_->SetRequestHeadersCallback(request_headers_callback_);
      transaction_->SetEarlyResponseHeadersCallback(
          early_response_headers_callback_);
      transaction_->SetResponseHeadersCallback(response_headers_callback_);
      if (is_shared_dictionary_read_allowed_callback_) {
        transaction_->SetIsSharedDictionaryReadAllowedCallback(
            is_shared_dictionary_read_allowed_callback_);
      }

      rv = transaction_->Start(
          &request_info_,
          base::BindOnce(&URLRequestHttpJob::OnStartCompleted,
                         base::Unretained(this)),
          request_->net_log());
      start_time_ = base::TimeTicks::Now();
    }
  }

  if (rv == ERR_IO_PENDING)
    return;

  // The transaction started synchronously, but we need to notify the
  // URLRequest delegate via the message loop.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&URLRequestHttpJob::OnStartCompleted,
                                weak_factory_.GetWeakPtr(), rv));
}

void URLRequestHttpJob::AddExtraHeaders() {
  request_info_.extra_headers.SetAcceptEncodingIfMissing(
      request()->url(), request()->accepted_stream_types(),
      request()->context()->enable_brotli(),
      request()->context()->enable_zstd());

  if (http_user_agent_settings_) {
    // Only add default Accept-Language if the request didn't have it
    // specified.
    std::string accept_language =
        http_user_agent_settings_->GetAcceptLanguage();
    if (!accept_language.empty()) {
      request_info_.extra_headers.SetHeaderIfMissing(
          HttpRequestHeaders::kAcceptLanguage,
          accept_language);
    }
  }
}

void URLRequestHttpJob::AddCookieHeaderAndStart() {
  CookieStore* cookie_store = request_->context()->cookie_store();
  DCHECK(cookie_store);
  DCHECK(ShouldAddCookieHeader());
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
      net::cookie_util::ComputeSameSiteContextForRequest(
          request_->method(), request_->url_chain(),
          request_->site_for_cookies(), request_->initiator(),
          is_main_frame_navigation, force_ignore_site_for_cookies);

  CookieOptions options = CreateCookieOptions(same_site_context);

  cookie_store->GetCookieListWithOptionsAsync(
      request_->url(), options,
      CookiePartitionKeyCollection::FromOptional(
          request_->cookie_partition_key()),
      base::BindOnce(&URLRequestHttpJob::SetCookieHeaderAndStart,
                     weak_factory_.GetWeakPtr(), options));
}

void URLRequestHttpJob::SetCookieHeaderAndStart(
    const CookieOptions& options,
    const CookieAccessResultList& cookies_with_access_result_list,
    const CookieAccessResultList& excluded_list) {
  DCHECK(request_->maybe_sent_cookies().empty());

  CookieAccessResultList maybe_included_cookies =
      cookies_with_access_result_list;
  CookieAccessResultList excluded_cookies = excluded_list;

  if (ShouldBlockAllCookies(request_info_.privacy_mode)) {
    // If cookies are blocked (without our needing to consult the delegate),
    // we move them to `excluded_cookies` and ensure that they have the
    // correct exclusion reason.
    excluded_cookies.insert(
        excluded_cookies.end(),
        std::make_move_iterator(maybe_included_cookies.begin()),
        std::make_move_iterator(maybe_included_cookies.end()));
    maybe_included_cookies.clear();
    for (auto& cookie : excluded_cookies) {
      cookie.access_result.status.AddExclusionReason(
          CookieInclusionStatus::EXCLUDE_USER_PREFERENCES);
    }
  } else {
    // Consult the delegate to ensure that they have the correct exclusion
    // reason.
    AnnotateAndMoveUserBlockedCookies(maybe_included_cookies, excluded_cookies);
  }

  const bool cookie_deprecation_testing_enabled =
      request_->context()->cookie_deprecation_label().has_value();
  const bool cookie_deprecation_testing_has_label =
      cookie_deprecation_testing_enabled &&
      !request_->context()->cookie_deprecation_label().value().empty();
  bool may_set_sec_cookie_deprecation_header =
      cookie_deprecation_testing_has_label;

  if (!maybe_included_cookies.empty()) {
    std::string cookie_line =
        CanonicalCookie::BuildCookieLine(maybe_included_cookies);
    request_info_.extra_headers.SetHeader(HttpRequestHeaders::kCookie,
                                          cookie_line);

    size_t n_partitioned_cookies = 0;

    // TODO(crbug.com/40110557): Reduce the number of times the cookie list
    // is iterated over. Get metrics for every cookie which is included.
    for (const auto& c : maybe_included_cookies) {
      bool request_is_secure = request_->url().SchemeIsCryptographic();
      net::CookieSourceScheme cookie_scheme = c.cookie.SourceScheme();
      CookieRequestSche
"""


```