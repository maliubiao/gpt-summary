Response:
Let's break down the thought process for analyzing the `reporting_uploader.cc` file and answering the prompt.

1. **Understand the Core Purpose:** The file name itself, `reporting_uploader.cc`, strongly suggests its function: uploading reporting data. The initial comments reinforce this, mentioning the "Reporting API" and its purpose of reporting issues to website owners. This becomes the central theme.

2. **Identify Key Components/Classes:**  Scan the code for class definitions and important data structures. The main class is `ReportingUploader` (and its implementation `ReportingUploaderImpl`). The `PendingUpload` struct is also crucial.

3. **Analyze `PendingUpload`:** This structure holds information about a single report upload. Notice its members: `report_origin`, `url`, `isolation_info`, `json` (the report data), `max_depth`, and the `callback`. This tells us what information is necessary for an upload. The `State` enum within `PendingUpload` indicates the lifecycle of an upload (CREATED, SENDING_PREFLIGHT, SENDING_PAYLOAD).

4. **Analyze `ReportingUploaderImpl`:** This class handles the actual upload process. Look at its methods:
    * `StartUpload`: This is the entry point for initiating an upload. It takes the report details as input and decides whether to perform a preflight request.
    * `StartPreflightRequest`: Deals with sending an OPTIONS request for CORS preflight.
    * `StartPayloadRequest`: Sends the actual POST request with the report data.
    * `OnShutdown`:  Handles cleanup and cancels pending uploads.
    * The `URLRequest::Delegate` methods (`OnReceivedRedirect`, `OnAuthRequired`, etc.): These methods handle the lifecycle events of the underlying network request. Notice how they handle errors and redirects.

5. **Trace the Upload Flow:**  Follow the execution path of a typical upload:
    * `StartUpload` is called.
    * If the collector origin is the same as the report origin, `StartPayloadRequest` is called directly.
    * Otherwise, `StartPreflightRequest` is called.
    * `StartPreflightRequest` creates an OPTIONS request.
    * `OnResponseStarted` handles the preflight response.
    * If the preflight is successful, `StartPayloadRequest` is called.
    * `StartPayloadRequest` creates a POST request with the report data.
    * `OnResponseStarted` handles the payload response and calls the final callback.

6. **Look for JavaScript Interaction:** The description mentions the Reporting API, which is triggered by browser events often originating from JavaScript. The comment "Examples of these issues are Content Security Policy violations and Interventions/Deprecations encountered" hints at this. CSP violations, for instance, are often detected and reported via the Reporting API. The presence of `report_origin` also points to the origin of the JavaScript that generated the report.

7. **Consider Logic and Conditions:** Pay attention to `if` statements and conditional logic. The check for same-origin vs. cross-origin and the handling of preflight requests are important. The `max_depth` parameter and its use in preventing infinite loops are also key.

8. **Identify Potential User/Programming Errors:** Think about how developers might misuse the API or how the browser's behavior could lead to issues. Incorrectly configured CORS on the reporting endpoint is a prime example. Sending reports to non-HTTPS URLs is another. The code's handling of redirects and authentication errors provides clues here.

9. **Infer User Actions Leading to the Code:** Connect the code's functionality back to user actions. A user browsing a website, encountering a CSP violation, or triggering a browser intervention are likely scenarios that would generate reports and lead to this code being executed.

10. **Structure the Answer:** Organize the findings into clear categories based on the prompt's questions: Functionality, Relationship with JavaScript, Logic and Assumptions, User/Programming Errors, and Debugging Clues.

11. **Provide Concrete Examples:**  Illustrate the concepts with specific examples for JavaScript interaction, input/output scenarios, and user errors.

12. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or missing information. For instance, initially I might not have explicitly mentioned the role of the `URLRequestContext`, but realizing it's passed to the constructor and used to create requests makes it an important detail to include. Similarly, explaining the significance of `IsolationInfo` is crucial for understanding the security and privacy aspects.

By following this methodical approach, breaking down the code into smaller, manageable parts, and focusing on the core purpose, it's possible to generate a comprehensive and accurate answer to the prompt.
好的，让我们来分析一下 `net/reporting/reporting_uploader.cc` 这个文件。

**功能概述:**

`ReportingUploader` 的主要功能是负责将浏览器生成的报告（reports）上传到指定的收集器（collector）端点。这些报告记录了各种网络问题，例如内容安全策略 (CSP) 违规、浏览器干预和功能弃用等。

核心功能可以归纳为：

1. **接收报告数据:**  `StartUpload` 方法接收需要上传的报告的详细信息，包括报告来源 (report origin)、收集器 URL、报告内容 (JSON 格式) 和最大深度限制。
2. **发起网络请求:**  根据报告的目标端点是否与报告来源同源，决定是否需要先进行 CORS 预检请求 (OPTIONS)。
3. **处理 CORS 预检:** 如果需要预检，则发送 OPTIONS 请求，并根据响应头 (Access-Control-Allow-Origin, Access-Control-Allow-Headers) 验证收集器是否允许跨域上传。
4. **发送报告负载:** 发送 POST 请求到收集器 URL，请求体包含 JSON 格式的报告数据。请求头中会包含 `Content-Type: application/reports+json`。
5. **处理上传结果:** 根据收集器返回的 HTTP 状态码判断上传结果：
    * **成功 (200-299):** 报告上传成功。
    * **移除端点 (410):**  指示该收集器端点已失效，应该被移除。
    * **失败 (其他):** 报告上传失败。
6. **回调通知:**  通过 `UploadCallback` 回调函数通知调用方上传结果。
7. **限制报告深度:**  通过 `max_depth` 参数防止由于报告自身错误或配置问题导致的无限递归报告上传。

**与 JavaScript 的关系:**

`ReportingUploader` 本身是用 C++ 实现的网络栈组件，不直接执行 JavaScript 代码。但是，它的功能与 JavaScript 息息相关，因为 **浏览器中运行的 JavaScript 代码是生成这些报告的来源**。

**举例说明:**

1. **CSP 违规报告:** 当网页的 JavaScript 代码尝试执行违反内容安全策略的操作时（例如，加载了不被允许的来源的脚本），浏览器会检测到这个违规。然后，浏览器会根据配置的 Reporting API 策略，生成一个包含违规详情的报告。这个报告的数据（通常是 JSON 格式）会被传递给 `ReportingUploader` 进行上传。

   * **假设输入 (来自 JavaScript 生成的报告数据):**
     ```json
     {
       "age": 123,
       "body": {
         "blockedURL": "http://evil.com/bad.js",
         "disposition": "enforce",
         "documentURL": "http://example.com/page.html",
         "effectiveDirective": "script-src",
         "originalPolicy": "script-src 'self'",
         "referrer": "",
         "sample": null,
         "sourceFile": "http://example.com/page.html",
         "statusCode": 200,
         "violatedDirective": "script-src"
       },
       "type": "csp-violation"
     }
     ```
   * **`ReportingUploader` 的操作:**  `ReportingUploader` 会将这个 JSON 数据封装在 HTTP POST 请求体中，发送到配置的报告收集器端点。

2. **Intervention 报告:** 当浏览器为了改善用户体验或兼容性而干预网页的行为时（例如，阻止自动播放的视频），也会生成报告。

3. **Deprecation 报告:**  当网页使用了即将被废弃的 Web API 时，浏览器可以生成报告通知开发者。

**逻辑推理 (假设输入与输出):**

假设我们有以下输入调用 `StartUpload`:

* `report_origin`: `https://example.com`
* `url`: `https://collector.example.net/report`
* `isolation_info`: (包含网络隔离信息的对象)
* `json`:  `{"type": "test-report", "message": "Hello from example.com"}`
* `max_depth`: 0
* `eligible_for_credentials`: false (假设是跨域上传)
* `callback`: 一个处理上传结果的回调函数

**推理过程:**

1. 由于 `report_origin` (`https://example.com`) 与 `url` 的 origin (`https://collector.example.net`) 不同，因此需要进行 CORS 预检。
2. `ReportingUploader` 会发送一个 `OPTIONS` 请求到 `https://collector.example.net/report`，包含以下请求头：
   * `Origin`: `https://example.com`
   * `Access-Control-Request-Method`: `POST`
   * `Access-Control-Request-Headers`: `content-type`
3. **假设预检成功:** 收集器返回一个包含以下响应头的 HTTP 200 响应：
   * `Access-Control-Allow-Origin`: `https://example.com` 或 `*`
   * `Access-Control-Allow-Headers`: `content-type` 或 `*`
4. `ReportingUploader` 接收到成功的预检响应后，会发送一个 `POST` 请求到 `https://collector.example.net/report`，包含以下信息：
   * 请求体: `{"type": "test-report", "message": "Hello from example.com"}`
   * 请求头: `Content-Type: application/reports+json`
5. **假设负载上传成功:** 收集器返回 HTTP 200 OK。
6. `ReportingUploader` 会调用提供的 `callback` 函数，并传递 `ReportingUploader::Outcome::SUCCESS`。

**用户或编程常见的使用错误:**

1. **CORS 配置错误:**  收集器端点没有正确配置 CORS 策略，导致预检请求失败。
   * **示例:** 收集器端点返回的 `Access-Control-Allow-Origin` 不是报告来源的域名，或者 `Access-Control-Allow-Headers` 中没有包含 `content-type`。
   * **用户操作:** 用户浏览的网页尝试将报告发送到未正确配置 CORS 的收集器。

2. **收集器端点不可用:**  提供的收集器 URL 无效或服务不可用。
   * **示例:**  URL 拼写错误，或者收集器服务器宕机。
   * **用户操作:** 用户浏览的网页配置了错误的报告收集器 URL。

3. **报告内容格式错误:**  传递给 `StartUpload` 的 `json` 字符串不是有效的 JSON 格式。
   * **示例:**  JSON 字符串缺少引号或包含语法错误。
   * **编程错误:** 生成报告的 JavaScript 代码或后端逻辑生成了错误的 JSON 数据。

4. **HTTPS 问题:** 收集器端点未使用 HTTPS，或者 HTTPS 证书存在问题（例如，过期、不信任）。`ReportingUploader` 会取消非加密的重定向。
   * **用户操作:** 用户浏览的网页尝试将报告发送到 HTTP 收集器，或者 HTTPS 证书无效的收集器。

5. **达到最大报告深度:**  如果由于配置错误或循环报告机制导致报告不断生成并上传，可能会达到 `max_depth` 限制，阻止进一步的上传。
   * **编程错误/配置错误:**  Reporting Policy 配置错误，导致报告自身又触发新的报告生成。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **网页加载并执行 JavaScript:** 用户访问一个网页，浏览器开始加载 HTML、CSS 和 JavaScript。
2. **触发报告生成条件:**  在网页加载或执行过程中，发生了满足 Reporting API 策略的事件，例如：
   * **CSP 违规:** JavaScript 尝试加载被 CSP 阻止的资源。
   * **浏览器干预:** 浏览器为了用户体验阻止了某些操作。
   * **功能弃用:** 网页使用了即将被废弃的 API。
3. **浏览器生成报告:**  浏览器根据配置的 Reporting Policy，生成包含事件详情的报告数据（通常是 JSON 格式）。
4. **调用 ReportingUploader:**  浏览器的 Reporting 机制将生成的报告数据传递给 `ReportingUploader` 的 `StartUpload` 方法。
5. **网络请求:** `ReportingUploader` 根据收集器 URL 和报告来源决定是否需要进行 CORS 预检，然后发起相应的 HTTP 请求。
6. **收集器处理:** 收集器端点接收到报告数据并进行处理（例如，存储到数据库，发送警报）。

**调试线索:**

* **Network 面板:** 使用 Chrome DevTools 的 Network 面板可以查看报告上传的网络请求（OPTIONS 和 POST）。检查请求头、响应头和请求体，可以帮助诊断 CORS 配置问题、服务器错误等。
* **`chrome://net-export/`:**  可以捕获更底层的网络事件，帮助分析连接建立、TLS 握手等问题。
* **`chrome://network-errors/`:**  查看网络错误代码的详细解释。
* **Reporting API 相关 DevTools 面板 (可能在未来版本中出现):**  未来可能会有专门用于查看和调试 Reporting API 的 DevTools 工具。
* **浏览器控制台 (Console):**  一些与 Reporting API 相关的错误或警告可能会输出到控制台。

总而言之，`net/reporting/reporting_uploader.cc` 是 Chromium 网络栈中一个关键的组件，它负责将浏览器生成的报告上传到指定的服务器，帮助网站开发者了解和解决其网站上出现的问题。理解其工作原理有助于调试与 Reporting API 相关的网络问题。

### 提示词
```
这是目录为net/reporting/reporting_uploader.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_uploader.h"

#include <string>
#include <utility>
#include <vector>

#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/not_fatal_until.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/isolation_info.h"
#include "net/base/load_flags.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request_context.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

namespace {

constexpr char kUploadContentType[] = "application/reports+json";

constexpr net::NetworkTrafficAnnotationTag kReportUploadTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("reporting", R"(
        semantics {
          sender: "Reporting API"
          description:
            "The Reporting API reports various issues back to website owners "
            "to help them detect and fix problems."
          trigger:
            "Encountering issues. Examples of these issues are Content "
            "Security Policy violations and Interventions/Deprecations "
            "encountered. See draft of reporting spec here: "
            "https://wicg.github.io/reporting."
          data: "Details of the issue, depending on issue type."
          destination: OTHER
        }
        policy {
          cookies_allowed: NO
          setting: "This feature cannot be disabled by settings."
          policy_exception_justification: "Not implemented."
        })");

// Returns true if |request| contains any of the |allowed_values| in a response
// header field named |header|. |allowed_values| are expected to be lower-case
// and the check is case-insensitive.
bool HasHeaderValues(URLRequest* request,
                     const std::string& header,
                     const std::set<std::string>& allowed_values) {
  std::string response_headers = request->GetResponseHeaderByName(header);
  const std::vector<std::string> response_values =
      base::SplitString(base::ToLowerASCII(response_headers), ",",
                        base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& value : response_values) {
    if (allowed_values.find(value) != allowed_values.end())
      return true;
  }
  return false;
}

ReportingUploader::Outcome ResponseCodeToOutcome(int response_code) {
  if (response_code >= 200 && response_code <= 299)
    return ReportingUploader::Outcome::SUCCESS;
  if (response_code == 410)
    return ReportingUploader::Outcome::REMOVE_ENDPOINT;
  return ReportingUploader::Outcome::FAILURE;
}

struct PendingUpload {
  enum State { CREATED, SENDING_PREFLIGHT, SENDING_PAYLOAD };

  PendingUpload(const url::Origin& report_origin,
                const GURL& url,
                const IsolationInfo& isolation_info,
                const std::string& json,
                int max_depth,
                ReportingUploader::UploadCallback callback)
      : report_origin(report_origin),
        url(url),
        isolation_info(isolation_info),
        payload_reader(UploadOwnedBytesElementReader::CreateWithString(json)),
        max_depth(max_depth),
        callback(std::move(callback)) {}

  void RunCallback(ReportingUploader::Outcome outcome) {
    std::move(callback).Run(outcome);
  }

  State state = CREATED;
  const url::Origin report_origin;
  const GURL url;
  const IsolationInfo isolation_info;
  std::unique_ptr<UploadElementReader> payload_reader;
  int max_depth;
  ReportingUploader::UploadCallback callback;
  std::unique_ptr<URLRequest> request;
};

class ReportingUploaderImpl : public ReportingUploader, URLRequest::Delegate {
 public:
  explicit ReportingUploaderImpl(const URLRequestContext* context)
      : context_(context) {
    DCHECK(context_);
  }

  ~ReportingUploaderImpl() override {
    for (auto& request_and_upload : uploads_) {
      auto& upload = request_and_upload.second;
      upload->RunCallback(Outcome::FAILURE);
    }
  }

  void StartUpload(const url::Origin& report_origin,
                   const GURL& url,
                   const IsolationInfo& isolation_info,
                   const std::string& json,
                   int max_depth,
                   bool eligible_for_credentials,
                   UploadCallback callback) override {
    auto upload =
        std::make_unique<PendingUpload>(report_origin, url, isolation_info,
                                        json, max_depth, std::move(callback));
    auto collector_origin = url::Origin::Create(url);
    if (collector_origin == report_origin) {
      // Skip the preflight check if the reports are being sent to the same
      // origin as the requests they describe.
      StartPayloadRequest(std::move(upload), eligible_for_credentials);
    } else {
      StartPreflightRequest(std::move(upload));
    }
  }

  void OnShutdown() override {
    // Cancels all pending uploads.
    uploads_.clear();
  }

  void StartPreflightRequest(std::unique_ptr<PendingUpload> upload) {
    DCHECK(upload->state == PendingUpload::CREATED);

    upload->state = PendingUpload::SENDING_PREFLIGHT;
    upload->request = context_->CreateRequest(upload->url, IDLE, this,
                                              kReportUploadTrafficAnnotation);

    upload->request->set_method("OPTIONS");

    upload->request->SetLoadFlags(LOAD_DISABLE_CACHE);
    upload->request->set_allow_credentials(false);
    upload->request->set_isolation_info(upload->isolation_info);

    upload->request->set_initiator(upload->report_origin);
    upload->request->SetExtraRequestHeaderByName(
        HttpRequestHeaders::kOrigin, upload->report_origin.Serialize(), true);
    upload->request->SetExtraRequestHeaderByName(
        "Access-Control-Request-Method", "POST", true);
    upload->request->SetExtraRequestHeaderByName(
        "Access-Control-Request-Headers", "content-type", true);

    // Set the max_depth for this request, to cap how deep a stack of "reports
    // about reports" can get.  (Without this, a Reporting policy that uploads
    // reports to the same origin can cause an infinite stack of reports about
    // reports.)
    upload->request->set_reporting_upload_depth(upload->max_depth + 1);

    URLRequest* raw_request = upload->request.get();
    uploads_[raw_request] = std::move(upload);
    raw_request->Start();
  }

  void StartPayloadRequest(std::unique_ptr<PendingUpload> upload,
                           bool eligible_for_credentials) {
    DCHECK(upload->state == PendingUpload::CREATED ||
           upload->state == PendingUpload::SENDING_PREFLIGHT);

    upload->state = PendingUpload::SENDING_PAYLOAD;
    upload->request = context_->CreateRequest(upload->url, IDLE, this,
                                              kReportUploadTrafficAnnotation);
    upload->request->set_method("POST");

    upload->request->SetLoadFlags(LOAD_DISABLE_CACHE);

    // Credentials are sent for V1 reports, if the endpoint is same-origin with
    // the site generating the report (this will be set to false either by the
    // delivery agent determining that this is a V0 report, or by `StartUpload`
    // determining that this is a cross-origin case, and taking the CORS
    // preflight path).
    upload->request->set_allow_credentials(eligible_for_credentials);
    // The site for cookies is taken from the reporting source's IsolationInfo,
    // in the case of V1 reporting endpoints, and will be null for V0 reports.
    upload->request->set_site_for_cookies(
        upload->isolation_info.site_for_cookies());

    // `upload->report_origin` corresponds to the origin of the URL with the
    // response headers that caused the report to sent, so use this for the
    // report request initiator as well. This also aligns with how we use the
    // report origin in the 'Origin:' header for the preflight we send if the
    // collector origin is cross-origin with the report origin.
    upload->request->set_initiator(upload->report_origin);

    // `upload->isolation_info` usually corresponds to the context where a
    // report was generated. For example, if a document loads a resource with a
    // NEL policy, the IsolationInfo will correspond to that document (whereas
    // `upload->report_origin` will correspond to the resource URL). Use this
    // same IsolationInfo for the report upload URLRequest.
    //
    // Note that the values within `upload->isolation_info` can vary widely
    // based on a number of factors:
    //  - For reports corresponding to enterprise endpoints, the IsolationInfo
    //    will be transient (see
    //    `ReportingCacheImpl::GetIsolationInfoForEndpoint()`).
    //
    //  - For V0 reports when Network State Partitioning (NSP) is disabled, the
    //    IsolationInfo will be empty since it is created from an empty NAK (See
    //    `ReportingServiceImpl::FixupNetworkAnonymizationKey()`,
    //    `ReportingCacheImpl::GetIsolationInfoForEndpoint()`, and
    //    `IsolationInfo::DoNotUseCreatePartialFromNak()`). This is CHECK'd
    //    below.
    //
    //  - For V0 reports from cross-site contexts (when NSP is enabled), the
    //    IsolationInfo will be generated from a NetworkAnonymizationKey and the
    //    frame origin will be opaque.
    //
    //  - For V0 reports from same-site contexts (when NSP is enabled), the
    //    frame origin will be created from the top-level site, losing full host
    //    and port information.
    if (upload->isolation_info.IsEmpty()) {
      CHECK(!NetworkAnonymizationKey::IsPartitioningEnabled());
    }
    upload->request->set_isolation_info(upload->isolation_info);

    upload->request->SetExtraRequestHeaderByName(
        HttpRequestHeaders::kContentType, kUploadContentType, true);

    upload->request->set_upload(ElementsUploadDataStream::CreateWithReader(
        std::move(upload->payload_reader)));

    // Set the max_depth for this request, to cap how deep a stack of "reports
    // about reports" can get.  (Without this, a Reporting policy that uploads
    // reports to the same origin can cause an infinite stack of reports about
    // reports.)
    upload->request->set_reporting_upload_depth(upload->max_depth + 1);

    URLRequest* raw_request = upload->request.get();
    uploads_[raw_request] = std::move(upload);
    raw_request->Start();
  }

  // URLRequest::Delegate implementation:

  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override {
    if (!redirect_info.new_url.SchemeIsCryptographic()) {
      request->Cancel();
      return;
    }
  }

  void OnAuthRequired(URLRequest* request,
                      const AuthChallengeInfo& auth_info) override {
    request->Cancel();
  }

  void OnCertificateRequested(URLRequest* request,
                              SSLCertRequestInfo* cert_request_info) override {
    request->Cancel();
  }

  void OnSSLCertificateError(URLRequest* request,
                             int net_error,
                             const SSLInfo& ssl_info,
                             bool fatal) override {
    request->Cancel();
  }

  void OnResponseStarted(URLRequest* request, int net_error) override {
    // Grab Upload from map, and hold on to it in a local unique_ptr so it's
    // removed at the end of the method.
    auto it = uploads_.find(request);
    CHECK(it != uploads_.end(), base::NotFatalUntil::M130);
    std::unique_ptr<PendingUpload> upload = std::move(it->second);
    uploads_.erase(it);

    if (net_error != OK) {
      upload->RunCallback(ReportingUploader::Outcome::FAILURE);
      return;
    }

    // request->GetResponseCode() should work, but doesn't in the cases above
    // where the request was canceled, so get the response code by hand.
    // TODO(juliatuttle): Check if mmenke fixed this yet.
    HttpResponseHeaders* headers = request->response_headers();
    int response_code = headers ? headers->response_code() : 0;

    switch (upload->state) {
      case PendingUpload::SENDING_PREFLIGHT:
        HandlePreflightResponse(std::move(upload), response_code);
        break;
      case PendingUpload::SENDING_PAYLOAD:
        HandlePayloadResponse(std::move(upload), response_code);
        break;
      default:
        NOTREACHED();
    }
  }

  void HandlePreflightResponse(std::unique_ptr<PendingUpload> upload,
                               int response_code) {
    // Check that the preflight succeeded: it must have an HTTP OK status code,
    // with the following headers:
    // - Access-Control-Allow-Origin: * or the report origin
    // - Access-Control-Allow-Headers: * or Content-Type
    // Note that * is allowed here as the credentials mode is never 'include'.
    // Access-Control-Allow-Methods is not checked, as the preflight is always
    // for a POST method, which is safelisted.
    URLRequest* request = upload->request.get();
    bool preflight_succeeded =
        (response_code >= 200 && response_code <= 299) &&
        HasHeaderValues(
            request, "Access-Control-Allow-Origin",
            {"*", base::ToLowerASCII(upload->report_origin.Serialize())}) &&
        HasHeaderValues(request, "Access-Control-Allow-Headers",
                        {"*", "content-type"});
    if (!preflight_succeeded) {
      upload->RunCallback(ReportingUploader::Outcome::FAILURE);
      return;
    }
    // Any upload which required CORS should not receive credentials, as they
    // are sent to same-origin endpoints only.
    StartPayloadRequest(std::move(upload), /*eligible_for_credentials=*/false);
  }

  void HandlePayloadResponse(std::unique_ptr<PendingUpload> upload,
                             int response_code) {
    upload->RunCallback(ResponseCodeToOutcome(response_code));
  }

  void OnReadCompleted(URLRequest* request, int bytes_read) override {
    // Reporting doesn't need anything in the body of the response, so it
    // doesn't read it, so it should never get OnReadCompleted calls.
    NOTREACHED();
  }

  int GetPendingUploadCountForTesting() const override {
    return uploads_.size();
  }

 private:
  raw_ptr<const URLRequestContext> context_;
  std::map<const URLRequest*, std::unique_ptr<PendingUpload>> uploads_;
};

}  // namespace

ReportingUploader::~ReportingUploader() = default;

// static
std::unique_ptr<ReportingUploader> ReportingUploader::Create(
    const URLRequestContext* context) {
  return std::make_unique<ReportingUploaderImpl>(context);
}

}  // namespace net
```