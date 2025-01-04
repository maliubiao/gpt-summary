Response:
The user wants me to analyze the provided C++ source code of `inspector_network_agent.cc` from the Chromium Blink engine. I need to identify its functionalities and explain its relevance to web technologies like JavaScript, HTML, and CSS. If any logical deductions are made, I should provide examples with inputs and outputs. I also need to point out common user or programming errors related to this component. Finally, for this first part of the file, I should summarize its primary functions.

Here's a breakdown of my thought process:

1. **Identify the Core Purpose:** The file name `inspector_network_agent.cc` strongly suggests that this code is part of the browser's developer tools (inspector) and specifically deals with network-related activities. The "agent" part indicates it likely acts as an intermediary, gathering and providing network information.

2. **Scan Included Headers:** Examining the included headers provides valuable clues about the agent's functionalities. I see headers related to:
    * **Networking:** `net/base/ip_address.h`, `net/base/ip_endpoint.h`, `net/http/http_status_code.h`, `net/ssl/*`
    * **Fetch API:** `third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h`
    * **Loader:** `third_party/blink/renderer/core/loader/*`, `third_party/blink/renderer/platform/loader/fetch/*`
    * **Inspector Protocol:** `third_party/blink/renderer/core/inspector/protocol/network.h`
    * **Data Handling:** `base/containers/span.h`, `base/containers/span_or_size.h`, `base/text/base64.h`
    * **DOM and Frames:** `third_party/blink/renderer/core/dom/*`, `third_party/blink/renderer/core/frame/*`
    * **Workers:** `third_party/blink/renderer/core/workers/worker_global_scope.h`
    * **XMLHTTPRequest:** `third_party/blink/renderer/core/xmlhttprequest/xml_http_request.h`

3. **Analyze Key Data Structures and Functions:**  I notice data structures like `protocol::Network::Headers` and functions like `BuildObjectForHeaders`, `BuildObjectForTiming`, which clearly relate to formatting network information for the DevTools protocol. The presence of `GetRequestPostDataCallback` and `GetResponseBodyCallback` points to the agent's ability to retrieve request and response data.

4. **Identify Connections to Web Technologies:**
    * **JavaScript:**  The agent interacts with network requests initiated by JavaScript code (e.g., `fetch`, `XMLHttpRequest`). The ability to inspect request/response headers, bodies, and timing directly relates to debugging JavaScript network interactions.
    * **HTML:** The agent monitors requests for HTML documents, images, scripts, and other resources loaded by the HTML parser. It can capture information about the initial document load and subsequent resource fetches.
    * **CSS:** Similarly, the agent tracks network requests for CSS files. Performance analysis often involves examining CSS loading times and potential blocking issues.

5. **Look for Logic and Potential Errors:** The code includes functions like `Matches` for URL pattern matching and checks for cached resources (`LoadsFromCacheOnly`). Potential errors could arise if the agent fails to read or decode response bodies (as seen in the `ResponseBodyFileReaderLoaderDone` function). Incorrectly configured network overrides could also be a user error.

6. **Formulate Examples:** I need to create simple scenarios to illustrate the agent's interaction with web technologies. For instance, a JavaScript `fetch` call resulting in specific network events captured by the agent.

7. **Synthesize the Summary:** The summary should encompass the core responsibilities of the `InspectorNetworkAgent`, which revolves around capturing, processing, and presenting network activity to the developer tools.

8. **Structure the Response:** I'll organize the answer according to the user's request, covering functionalities, relationships with web technologies, examples, potential errors, and the final summary.
```
功能：

这个 blink 引擎源代码文件 `inspector_network_agent.cc` 的主要功能是作为 Chrome 开发者工具（DevTools）中 "Network" 面板的后端代理。它负责收集和组织与网页网络活动相关的信息，并将这些信息以结构化的方式提供给前端的 DevTools。

具体来说，它的功能包括：

1. **监控网络请求:** 监听和捕获浏览器发出的所有网络请求，包括主文档加载、资源请求（如图片、脚本、样式表）、XMLHttpRequest、Fetch API 请求、WebSocket 连接等。
2. **记录请求和响应的详细信息:**  对于每个网络请求，记录其 URL、HTTP 方法、请求头、请求体（如果适用）、状态码、响应头、响应体（可以选择性捕获）、请求/响应时间、大小、MIME 类型等。
3. **处理各种网络事件:** 捕获与网络请求生命周期相关的各种事件，例如：
    * 请求发起 (`RequestWillBeSent`)
    * 重定向 (`ResponseReceived`)
    * 接收到响应头 (`ResponseReceived`)
    * 接收到响应数据 (`DataReceived`)
    * 请求完成 (`LoadingFinished`)
    * 请求失败 (`LoadingFailed`)
    * 请求被阻止 (例如，由于 CORS 策略或混合内容) (`RequestServedFromCache`, `RequestBlocked`)
4. **支持 WebSocket 监控:** 记录 WebSocket 连接的建立、帧的发送和接收。
5. **提供网络节流功能:** 模拟不同的网络条件（如离线、低延迟、高延迟、不同的连接类型）以帮助开发者测试其网站在不同网络环境下的表现。
6. **支持请求拦截和修改:**  允许开发者在请求发送前拦截并修改请求头或取消请求，以及在收到响应后修改响应内容。
7. **处理缓存:**  跟踪资源是否从缓存加载。
8. **处理安全相关信息:**  记录与 HTTPS 连接相关的安全信息，如 SSL 证书信息、证书透明度 (Certificate Transparency) 信息、混合内容状态等。
9. **支持 Cookie 和 Trust Token 的检查:**  提供查看和管理 Cookie 以及 Trust Token 的功能。
10. **与 Inspector 其他模块交互:**  与其他的 Inspector Agent 协同工作，例如 PageAgent (处理页面相关的事件) 和 SecurityAgent (处理安全相关的事件)。

与 javascript, html, css 的功能关系举例说明：

1. **JavaScript (Fetch API):**
   * **假设输入:** JavaScript 代码执行 `fetch('https://example.com/api/data')` 发起一个网络请求。
   * **功能体现:** `InspectorNetworkAgent` 会捕获到这个请求，记录其 URL (`https://example.com/api/data`)、请求头（可能包含 `Authorization` 等信息）、方法 (`GET`) 等信息。当服务器返回响应时，会记录响应状态码、响应头、响应体（JSON 数据等）。
   * **DevTools 展示:**  在 "Network" 面板中，开发者可以看到这个请求的详细信息，包括请求和响应的 Headers、Preview（如果响应是 JSON 或其他可预览的格式）、Response 等标签页。

2. **HTML (加载图片):**
   * **假设输入:** HTML 文件包含 `<img src="image.png">`。
   * **功能体现:** 当浏览器解析 HTML 并遇到 `<img>` 标签时，会发起对 `image.png` 的网络请求。`InspectorNetworkAgent` 会记录这个请求，包括请求的 URL (`image.png`，相对于 HTML 文件的路径会被解析为完整 URL）、请求头（例如 `Referer`）、以及服务器返回的响应头和图片数据。
   * **DevTools 展示:** 开发者可以在 "Network" 面板中看到 `image.png` 的请求，并查看其加载时间、大小、MIME 类型等信息。

3. **CSS (加载样式表):**
   * **假设输入:** HTML 文件包含 `<link rel="stylesheet" href="style.css">`。
   * **功能体现:**  浏览器加载 HTML 时会请求 `style.css` 文件。 `InspectorNetworkAgent` 会记录这个请求，类似于加载图片的情况。
   * **DevTools 展示:**  开发者可以在 "Network" 面板中分析 `style.css` 的加载情况，例如查看其加载时间是否影响页面渲染速度。

**逻辑推理的假设输入与输出:**

假设开发者在 DevTools 的 "Network" 面板中启用了 "Preserve log" 功能，并且在页面上执行了以下 JavaScript 代码：

```javascript
fetch('https://api.example.com/resource1');
setTimeout(() => {
  fetch('https://api.example.com/resource2');
}, 2000);
```

* **假设输入:**  上述 JavaScript 代码被执行。
* **逻辑推理:** `InspectorNetworkAgent` 会先捕获到对 `https://api.example.com/resource1` 的请求，并记录相关信息。两秒后，会捕获到对 `https://api.example.com/resource2` 的请求。 由于启用了 "Preserve log"，即使页面刷新或导航到其他页面，这两个请求的记录也会保留在 "Network" 面板中。
* **预期输出:**  在 DevTools 的 "Network" 面板中，将会有两条记录，分别对应 `resource1` 和 `resource2` 的请求，并显示它们的请求和响应的详细信息。

**涉及用户或者编程常见的使用错误举例说明:**

1. **CORS 配置错误:**
   * **场景:**  一个 JavaScript 应用尝试使用 `fetch` 从另一个域名的 API 获取数据，但服务端没有正确配置 CORS 头（例如，缺少 `Access-Control-Allow-Origin` 头）。
   * **`InspectorNetworkAgent` 的作用:** `InspectorNetworkAgent` 会捕获到这个请求，并且由于浏览器阻止了跨域请求，会在请求信息中标记出 "CORS error"。
   * **DevTools 展示:**  在 "Network" 面板中，开发者会看到该请求的状态为失败，并且在 "Headers" 标签页中会显示与 CORS 相关的错误信息。

2. **混合内容 (Mixed Content):**
   * **场景:**  一个通过 HTTPS 加载的网页试图加载通过 HTTP 提供的资源（例如，图片或脚本）。
   * **`InspectorNetworkAgent` 的作用:** `InspectorNetworkAgent` 会检测到这种混合内容的情况，并将被阻止的请求标记出来。
   * **DevTools 展示:**  在 "Network" 面板中，混合内容请求的状态通常会显示为被阻止，并且在 "Security" 标签页中会显示混合内容警告。

3. **错误地假设请求已完成:**
   * **编程错误:**  开发者编写 JavaScript 代码，在 `fetch` 请求发送后立即尝试访问响应数据，而没有等待 Promise resolve 或使用 `await`。
   * **`InspectorNetworkAgent` 的作用:** `InspectorNetworkAgent` 会记录请求的不同阶段，开发者可以在 "Timing" 标签页中看到请求的实际耗时。
   * **DevTools 展示:**  开发者可以通过查看 "Network" 面板的时间线和状态来调试这种异步操作相关的错误。

**第1部分功能归纳:**

这部分代码主要负责 `InspectorNetworkAgent` 的初始化和一些基础的网络监控功能设置。它定义了 `InspectorNetworkAgent` 类，并包含了一些辅助函数和数据结构，用于：

* **设置 InspectorNetworkAgent 的基本属性:**  例如，关联 `InspectedFrames` 对象、管理资源数据。
* **定义常量:** 例如，用于限制缓冲区大小。
* **实现一些通用的辅助函数:** 例如，`Matches` 用于 URL 匹配，`LoadsFromCacheOnly` 用于判断是否仅从缓存加载。
* **实现将底层网络数据结构转换为 Inspector 协议定义的格式的函数:** 例如，`BuildObjectForHeaders` 用于将 HTTP 头信息转换为协议对象。
* **处理请求体的读取:**  定义了 `InspectorPostBodyParser` 类来异步读取和解析请求体数据，尤其是处理包含 Blob 数据的请求。
* **定义枚举类型的转换函数:**  例如，将 Blink 内部的枚举类型转换为 DevTools 协议中定义的字符串枚举值（如 `MixedContentTypeForContextType`, `ResourcePriorityJSON`, `BuildBlockedReason`, `BuildCorsError` 等）。
* **支持网络状态模拟:** 定义了 `SetNetworkStateOverride` 函数，允许模拟不同的网络条件。
* **实现 WebSocket 消息的格式化:** 定义了 `WebSocketMessageToProtocol` 函数。
* **处理 Trust Token 相关的参数:** 定义了 `BuildTrustTokenParams` 函数。

总而言之，这部分代码是 `InspectorNetworkAgent` 的基础框架，奠定了其监控和报告网络活动的能力，并提供了与 DevTools 前端通信所需的数据格式转换功能。
```
Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_network_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/inspector/inspector_network_agent.h"

#include <memory>
#include <utility>

#include "base/containers/span.h"
#include "base/containers/span_or_size.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/cert/ct_sct_to_string.h"
#include "net/cert/x509_util.h"
#include "net/http/http_status_code.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "services/network/public/cpp/cors/cors_error_status.h"
#include "services/network/public/mojom/referrer_policy.mojom-blink.h"
#include "services/network/public/mojom/trust_tokens.mojom-blink.h"
#include "services/network/public/mojom/websocket.mojom-blink.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/mixed_content.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_effective_connection_type.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_client.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/network_resources_data.h"
#include "third_party/blink/renderer/core/inspector/protocol/network.h"
#include "third_party/blink/renderer/core/inspector/request_debug_header_scope.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/xmlhttprequest/xml_http_request.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_info.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/render_blocking_behavior.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/service_worker_router_info.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/network/http_header_map.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "third_party/inspector_protocol/crdtp/json.h"

using crdtp::SpanFrom;
using crdtp::json::ConvertCBORToJSON;

namespace blink {

using GetRequestPostDataCallback =
    protocol::Network::Backend::GetRequestPostDataCallback;
using GetResponseBodyCallback =
    protocol::Network::Backend::GetResponseBodyCallback;

namespace {

#if BUILDFLAG(IS_ANDROID)
constexpr int kDefaultTotalBufferSize = 10 * 1000 * 1000;    // 10 MB
constexpr int kDefaultResourceBufferSize = 5 * 1000 * 1000;  // 5 MB
#else
constexpr int kDefaultTotalBufferSize = 200 * 1000 * 1000;    // 200 MB
constexpr int kDefaultResourceBufferSize = 20 * 1000 * 1000;  // 20 MB
#endif

// Pattern may contain stars ('*') which match to any (possibly empty) string.
// Stars implicitly assumed at the begin/end of pattern.
bool Matches(const String& url, const String& pattern) {
  Vector<String> parts;
  pattern.Split("*", parts);
  wtf_size_t pos = 0;
  for (const String& part : parts) {
    pos = url.Find(part, pos);
    if (pos == kNotFound)
      return false;
    pos += part.length();
  }
  return true;
}

bool LoadsFromCacheOnly(const ResourceRequest& request) {
  switch (request.GetCacheMode()) {
    case mojom::FetchCacheMode::kDefault:
    case mojom::FetchCacheMode::kNoStore:
    case mojom::FetchCacheMode::kValidateCache:
    case mojom::FetchCacheMode::kBypassCache:
    case mojom::FetchCacheMode::kForceCache:
      return false;
    case mojom::FetchCacheMode::kOnlyIfCached:
    case mojom::FetchCacheMode::kUnspecifiedOnlyIfCachedStrict:
    case mojom::FetchCacheMode::kUnspecifiedForceCacheMiss:
      return true;
  }
  NOTREACHED();
}

protocol::Network::CertificateTransparencyCompliance
SerializeCTPolicyCompliance(net::ct::CTPolicyCompliance ct_compliance) {
  switch (ct_compliance) {
    case net::ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS:
      return protocol::Network::CertificateTransparencyComplianceEnum::
          Compliant;
    case net::ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS:
    case net::ct::CTPolicyCompliance::CT_POLICY_NOT_DIVERSE_SCTS:
      return protocol::Network::CertificateTransparencyComplianceEnum::
          NotCompliant;
    case net::ct::CTPolicyCompliance::CT_POLICY_BUILD_NOT_TIMELY:
    case net::ct::CTPolicyCompliance::
        CT_POLICY_COMPLIANCE_DETAILS_NOT_AVAILABLE:
      return protocol::Network::CertificateTransparencyComplianceEnum::Unknown;
    case net::ct::CTPolicyCompliance::CT_POLICY_COUNT:
      NOTREACHED();
  }
  NOTREACHED();
}

static std::unique_ptr<protocol::Network::Headers> BuildObjectForHeaders(
    const HTTPHeaderMap& headers) {
  std::unique_ptr<protocol::DictionaryValue> headers_object =
      protocol::DictionaryValue::create();
  for (const auto& header : headers)
    headers_object->setString(header.key.GetString(), header.value);
  protocol::ErrorSupport errors;
  return protocol::Network::Headers::fromValue(headers_object.get(), &errors);
}

class InspectorFileReaderLoaderClient final
    : public GarbageCollected<InspectorFileReaderLoaderClient>,
      public FileReaderClient {
 public:
  InspectorFileReaderLoaderClient(
      scoped_refptr<BlobDataHandle> blob,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      base::OnceCallback<void(std::optional<SegmentedBuffer>)> callback)
      : blob_(std::move(blob)),
        callback_(std::move(callback)),
        loader_(MakeGarbageCollected<FileReaderLoader>(this,
                                                       std::move(task_runner))),
        keep_alive_(this) {}

  InspectorFileReaderLoaderClient(const InspectorFileReaderLoaderClient&) =
      delete;
  InspectorFileReaderLoaderClient& operator=(
      const InspectorFileReaderLoaderClient&) = delete;

  ~InspectorFileReaderLoaderClient() override = default;

  void Start() {
    loader_->Start(blob_);
  }

  FileErrorCode DidStartLoading(uint64_t) override {
    return FileErrorCode::kOK;
  }

  FileErrorCode DidReceiveData(base::span<const uint8_t> data) override {
    if (!data.empty()) {
      raw_data_.Append(data);
    }
    return FileErrorCode::kOK;
  }

  void DidFinishLoading() override { Done(std::move(raw_data_)); }

  void DidFail(FileErrorCode) override { Done(std::nullopt); }

  void Trace(Visitor* visitor) const override {
    FileReaderClient::Trace(visitor);
    visitor->Trace(loader_);
  }

 private:
  void Done(std::optional<SegmentedBuffer> output) {
    std::move(callback_).Run(std::move(output));
    keep_alive_.Clear();
    loader_ = nullptr;
  }

  scoped_refptr<BlobDataHandle> blob_;
  String mime_type_;
  String text_encoding_name_;
  base::OnceCallback<void(std::optional<SegmentedBuffer>)> callback_;
  Member<FileReaderLoader> loader_;
  SegmentedBuffer raw_data_;
  SelfKeepAlive<InspectorFileReaderLoaderClient> keep_alive_;
};

static void ResponseBodyFileReaderLoaderDone(
    const String& mime_type,
    const String& text_encoding_name,
    std::unique_ptr<GetResponseBodyCallback> callback,
    std::optional<SegmentedBuffer> raw_data) {
  if (!raw_data) {
    callback->sendFailure(
        protocol::Response::ServerError("Couldn't read BLOB"));
    return;
  }
  String result;
  bool base64_encoded;
  if (InspectorPageAgent::SegmentedBufferContent(&*raw_data, mime_type,
                                                 text_encoding_name, &result,
                                                 &base64_encoded)) {
    callback->sendSuccess(result, base64_encoded);
  } else {
    callback->sendFailure(
        protocol::Response::ServerError("Couldn't encode data"));
  }
}

class InspectorPostBodyParser
    : public WTF::RefCounted<InspectorPostBodyParser> {
 public:
  InspectorPostBodyParser(
      std::unique_ptr<GetRequestPostDataCallback> callback,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : callback_(std::move(callback)),
        task_runner_(std::move(task_runner)),
        error_(false) {}

  InspectorPostBodyParser(const InspectorPostBodyParser&) = delete;
  InspectorPostBodyParser& operator=(const InspectorPostBodyParser&) = delete;

  void Parse(EncodedFormData* request_body) {
    if (!request_body || request_body->IsEmpty())
      return;

    parts_.Grow(request_body->Elements().size());
    for (wtf_size_t i = 0; i < request_body->Elements().size(); i++) {
      const FormDataElement& data = request_body->Elements()[i];
      switch (data.type_) {
        case FormDataElement::kData:
          parts_[i] = String::FromUTF8WithLatin1Fallback(
              base::as_byte_span(data.data_));
          break;
        case FormDataElement::kEncodedBlob:
          ReadDataBlob(data.blob_data_handle_, &parts_[i]);
          break;
        case FormDataElement::kEncodedFile:
        case FormDataElement::kDataPipe:
          // Do nothing, not supported
          break;
      }
    }
  }

 private:
  friend class WTF::RefCounted<InspectorPostBodyParser>;

  ~InspectorPostBodyParser() {
    if (error_)
      return;
    StringBuilder result;
    for (const auto& part : parts_)
      result.Append(part);
    callback_->sendSuccess(result.ToString());
  }

  void BlobReadCallback(String* destination,
                        std::optional<SegmentedBuffer> raw_data) {
    if (raw_data) {
      Vector<char> flattened_data = std::move(*raw_data).CopyAs<Vector<char>>();
      *destination = String::FromUTF8WithLatin1Fallback(
          base::as_byte_span(flattened_data));
    } else {
      error_ = true;
    }
  }

  void ReadDataBlob(scoped_refptr<blink::BlobDataHandle> blob_handle,
                    String* destination) {
    if (!blob_handle)
      return;
    auto* reader = MakeGarbageCollected<InspectorFileReaderLoaderClient>(
        blob_handle, task_runner_,
        WTF::BindOnce(&InspectorPostBodyParser::BlobReadCallback,
                      WTF::RetainedRef(this), WTF::Unretained(destination)));
    reader->Start();
  }

  std::unique_ptr<GetRequestPostDataCallback> callback_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  bool error_;
  Vector<String> parts_;
};

KURL UrlWithoutFragment(const KURL& url) {
  KURL result = url;
  result.RemoveFragmentIdentifier();
  return result;
}

String MixedContentTypeForContextType(
    mojom::blink::MixedContentContextType context_type) {
  switch (context_type) {
    case mojom::blink::MixedContentContextType::kNotMixedContent:
      return protocol::Security::MixedContentTypeEnum::None;
    case mojom::blink::MixedContentContextType::kBlockable:
      return protocol::Security::MixedContentTypeEnum::Blockable;
    case mojom::blink::MixedContentContextType::kOptionallyBlockable:
    case mojom::blink::MixedContentContextType::kShouldBeBlockable:
      return protocol::Security::MixedContentTypeEnum::OptionallyBlockable;
  }

  return protocol::Security::MixedContentTypeEnum::None;
}

String ResourcePriorityJSON(ResourceLoadPriority priority) {
  switch (priority) {
    case ResourceLoadPriority::kVeryLow:
      return protocol::Network::ResourcePriorityEnum::VeryLow;
    case ResourceLoadPriority::kLow:
      return protocol::Network::ResourcePriorityEnum::Low;
    case ResourceLoadPriority::kMedium:
      return protocol::Network::ResourcePriorityEnum::Medium;
    case ResourceLoadPriority::kHigh:
      return protocol::Network::ResourcePriorityEnum::High;
    case ResourceLoadPriority::kVeryHigh:
      return protocol::Network::ResourcePriorityEnum::VeryHigh;
    case ResourceLoadPriority::kUnresolved:
      break;
  }
  NOTREACHED();
}

String BuildBlockedReason(ResourceRequestBlockedReason reason) {
  switch (reason) {
    case ResourceRequestBlockedReason::kCSP:
      return protocol::Network::BlockedReasonEnum::Csp;
    case ResourceRequestBlockedReason::kMixedContent:
      return protocol::Network::BlockedReasonEnum::MixedContent;
    case ResourceRequestBlockedReason::kOrigin:
      return protocol::Network::BlockedReasonEnum::Origin;
    case ResourceRequestBlockedReason::kInspector:
      return protocol::Network::BlockedReasonEnum::Inspector;
    case ResourceRequestBlockedReason::kSubresourceFilter:
      return protocol::Network::BlockedReasonEnum::SubresourceFilter;
    case ResourceRequestBlockedReason::kContentType:
      return protocol::Network::BlockedReasonEnum::ContentType;
    case ResourceRequestBlockedReason::kOther:
      return protocol::Network::BlockedReasonEnum::Other;
    case blink::ResourceRequestBlockedReason::kCoepFrameResourceNeedsCoepHeader:
      return protocol::Network::BlockedReasonEnum::
          CoepFrameResourceNeedsCoepHeader;
    case blink::ResourceRequestBlockedReason::
        kCoopSandboxedIFrameCannotNavigateToCoopPage:
      return protocol::Network::BlockedReasonEnum::
          CoopSandboxedIframeCannotNavigateToCoopPage;
    case blink::ResourceRequestBlockedReason::kCorpNotSameOrigin:
      return protocol::Network::BlockedReasonEnum::CorpNotSameOrigin;
    case blink::ResourceRequestBlockedReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoep:
      return protocol::Network::BlockedReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByCoep;
    case blink::ResourceRequestBlockedReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByDip:
      return protocol::Network::BlockedReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByDip;
    case blink::ResourceRequestBlockedReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip:
      return protocol::Network::BlockedReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip;
    case blink::ResourceRequestBlockedReason::kCorpNotSameSite:
      return protocol::Network::BlockedReasonEnum::CorpNotSameSite;
    case ResourceRequestBlockedReason::kConversionRequest:
      // This is actually never reached, as the conversion request
      // is marked as successful and no blocking reason is reported.
      NOTREACHED();
  }
  NOTREACHED();
}

Maybe<String> BuildBlockedReason(const ResourceError& error) {
  int error_code = error.ErrorCode();
  if (error_code != net::ERR_BLOCKED_BY_CLIENT &&
      error_code != net::ERR_BLOCKED_BY_RESPONSE) {
    return Maybe<String>();
  }

  std::optional<ResourceRequestBlockedReason> resource_request_blocked_reason =
      error.GetResourceRequestBlockedReason();
  if (resource_request_blocked_reason)
    return BuildBlockedReason(*resource_request_blocked_reason);

  // TODO(karandeepb): Embedder would know how to interpret the
  // `error.extended_error_code_` in this case. For now just return Other.
  return {protocol::Network::BlockedReasonEnum::Other};
}

String BuildCorsError(network::mojom::CorsError cors_error) {
  switch (cors_error) {
    case network::mojom::CorsError::kDisallowedByMode:
      return protocol::Network::CorsErrorEnum::DisallowedByMode;

    case network::mojom::CorsError::kInvalidResponse:
      return protocol::Network::CorsErrorEnum::InvalidResponse;

    case network::mojom::CorsError::kWildcardOriginNotAllowed:
      return protocol::Network::CorsErrorEnum::WildcardOriginNotAllowed;

    case network::mojom::CorsError::kMissingAllowOriginHeader:
      return protocol::Network::CorsErrorEnum::MissingAllowOriginHeader;

    case network::mojom::CorsError::kMultipleAllowOriginValues:
      return protocol::Network::CorsErrorEnum::MultipleAllowOriginValues;

    case network::mojom::CorsError::kInvalidAllowOriginValue:
      return protocol::Network::CorsErrorEnum::InvalidAllowOriginValue;

    case network::mojom::CorsError::kAllowOriginMismatch:
      return protocol::Network::CorsErrorEnum::AllowOriginMismatch;

    case network::mojom::CorsError::kInvalidAllowCredentials:
      return protocol::Network::CorsErrorEnum::InvalidAllowCredentials;

    case network::mojom::CorsError::kCorsDisabledScheme:
      return protocol::Network::CorsErrorEnum::CorsDisabledScheme;

    case network::mojom::CorsError::kPreflightInvalidStatus:
      return protocol::Network::CorsErrorEnum::PreflightInvalidStatus;

    case network::mojom::CorsError::kPreflightDisallowedRedirect:
      return protocol::Network::CorsErrorEnum::PreflightDisallowedRedirect;

    case network::mojom::CorsError::kPreflightWildcardOriginNotAllowed:
      return protocol::Network::CorsErrorEnum::
          PreflightWildcardOriginNotAllowed;

    case network::mojom::CorsError::kPreflightMissingAllowOriginHeader:
      return protocol::Network::CorsErrorEnum::
          PreflightMissingAllowOriginHeader;

    case network::mojom::CorsError::kPreflightMultipleAllowOriginValues:
      return protocol::Network::CorsErrorEnum::
          PreflightMultipleAllowOriginValues;

    case network::mojom::CorsError::kPreflightInvalidAllowOriginValue:
      return protocol::Network::CorsErrorEnum::PreflightInvalidAllowOriginValue;

    case network::mojom::CorsError::kPreflightAllowOriginMismatch:
      return protocol::Network::CorsErrorEnum::PreflightAllowOriginMismatch;

    case network::mojom::CorsError::kPreflightInvalidAllowCredentials:
      return protocol::Network::CorsErrorEnum::PreflightInvalidAllowCredentials;

    case network::mojom::CorsError::kPreflightMissingAllowPrivateNetwork:
      return protocol::Network::CorsErrorEnum::
          PreflightMissingAllowPrivateNetwork;

    case network::mojom::CorsError::kPreflightInvalidAllowPrivateNetwork:
      return protocol::Network::CorsErrorEnum::
          PreflightInvalidAllowPrivateNetwork;

    case network::mojom::CorsError::kInvalidAllowMethodsPreflightResponse:
      return protocol::Network::CorsErrorEnum::
          InvalidAllowMethodsPreflightResponse;

    case network::mojom::CorsError::kInvalidAllowHeadersPreflightResponse:
      return protocol::Network::CorsErrorEnum::
          InvalidAllowHeadersPreflightResponse;

    case network::mojom::CorsError::kMethodDisallowedByPreflightResponse:
      return protocol::Network::CorsErrorEnum::
          MethodDisallowedByPreflightResponse;

    case network::mojom::CorsError::kHeaderDisallowedByPreflightResponse:
      return protocol::Network::CorsErrorEnum::
          HeaderDisallowedByPreflightResponse;

    case network::mojom::CorsError::kRedirectContainsCredentials:
      return protocol::Network::CorsErrorEnum::RedirectContainsCredentials;

    case network::mojom::CorsError::kInsecurePrivateNetwork:
      return protocol::Network::CorsErrorEnum::InsecurePrivateNetwork;

    case network::mojom::CorsError::kInvalidPrivateNetworkAccess:
      return protocol::Network::CorsErrorEnum::InvalidPrivateNetworkAccess;

    case network::mojom::CorsError::kUnexpectedPrivateNetworkAccess:
      return protocol::Network::CorsErrorEnum::UnexpectedPrivateNetworkAccess;

    case network::mojom::CorsError::kPreflightMissingPrivateNetworkAccessId:
      return protocol::Network::CorsErrorEnum::
          PreflightMissingPrivateNetworkAccessId;

    case network::mojom::CorsError::kPreflightMissingPrivateNetworkAccessName:
      return protocol::Network::CorsErrorEnum::
          PreflightMissingPrivateNetworkAccessName;

    case network::mojom::CorsError::kPrivateNetworkAccessPermissionUnavailable:
      return protocol::Network::CorsErrorEnum::
          PrivateNetworkAccessPermissionUnavailable;

    case network::mojom::CorsError::kPrivateNetworkAccessPermissionDenied:
      return protocol::Network::CorsErrorEnum::
          PrivateNetworkAccessPermissionDenied;
  }
}

std::unique_ptr<protocol::Network::CorsErrorStatus> BuildCorsErrorStatus(
    const network::CorsErrorStatus& status) {
  return protocol::Network::CorsErrorStatus::create()
      .setCorsError(BuildCorsError(status.cors_error))
      .setFailedParameter(String::FromUTF8(status.failed_parameter))
      .build();
}

String BuildServiceWorkerResponseSource(const ResourceResponse& response) {
  switch (response.GetServiceWorkerResponseSource()) {
    case network::mojom::FetchResponseSource::kCacheStorage:
      return protocol::Network::ServiceWorkerResponseSourceEnum::CacheStorage;
    case network::mojom::FetchResponseSource::kHttpCache:
      return protocol::Network::ServiceWorkerResponseSourceEnum::HttpCache;
    case network::mojom::FetchResponseSource::kNetwork:
      return protocol::Network::ServiceWorkerResponseSourceEnum::Network;
    case network::mojom::FetchResponseSource::kUnspecified:
      return protocol::Network::ServiceWorkerResponseSourceEnum::FallbackCode;
  }
}

String BuildServiceWorkerRouterSourceType(
    const network::mojom::ServiceWorkerRouterSourceType& type) {
  switch (type) {
    case network::mojom::ServiceWorkerRouterSourceType::kNetwork:
      return protocol::Network::ServiceWorkerRouterSourceEnum::Network;
    case network::mojom::ServiceWorkerRouterSourceType::kRace:
      return protocol::Network::ServiceWorkerRouterSourceEnum::
          RaceNetworkAndFetchHandler;
    case network::mojom::ServiceWorkerRouterSourceType::kFetchEvent:
      return protocol::Network::ServiceWorkerRouterSourceEnum::FetchEvent;
    case network::mojom::ServiceWorkerRouterSourceType::kCache:
      return protocol::Network::ServiceWorkerRouterSourceEnum::Cache;
  }
}

WebConnectionType ToWebConnectionType(const String& connection_type) {
  if (connection_type == protocol::Network::ConnectionTypeEnum::None)
    return kWebConnectionTypeNone;
  if (connection_type == protocol::Network::ConnectionTypeEnum::Cellular2g)
    return kWebConnectionTypeCellular2G;
  if (connection_type == protocol::Network::ConnectionTypeEnum::Cellular3g)
    return kWebConnectionTypeCellular3G;
  if (connection_type == protocol::Network::ConnectionTypeEnum::Cellular4g)
    return kWebConnectionTypeCellular4G;
  if (connection_type == protocol::Network::ConnectionTypeEnum::Bluetooth)
    return kWebConnectionTypeBluetooth;
  if (connection_type == protocol::Network::ConnectionTypeEnum::Ethernet)
    return kWebConnectionTypeEthernet;
  if (connection_type == protocol::Network::ConnectionTypeEnum::Wifi)
    return kWebConnectionTypeWifi;
  if (connection_type == protocol::Network::ConnectionTypeEnum::Wimax)
    return kWebConnectionTypeWimax;
  if (connection_type == protocol::Network::ConnectionTypeEnum::Other)
    return kWebConnectionTypeOther;
  return kWebConnectionTypeUnknown;
}

String GetReferrerPolicy(network::mojom::ReferrerPolicy policy) {
  switch (policy) {
    case network::mojom::ReferrerPolicy::kAlways:
      return protocol::Network::Request::ReferrerPolicyEnum::UnsafeUrl;
    case network::mojom::ReferrerPolicy::kDefault:
      return protocol::Network::Request::ReferrerPolicyEnum::
          StrictOriginWhenCrossOrigin;
    case network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade:
      return protocol::Network::Request::ReferrerPolicyEnum::
          NoReferrerWhenDowngrade;
    case network::mojom::ReferrerPolicy::kNever:
      return protocol::Network::Request::ReferrerPolicyEnum::NoReferrer;
    case network::mojom::ReferrerPolicy::kOrigin:
      return protocol::Network::Request::ReferrerPolicyEnum::Origin;
    case network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin:
      return protocol::Network::Request::ReferrerPolicyEnum::
          OriginWhenCrossOrigin;
    case network::mojom::ReferrerPolicy::kSameOrigin:
      return protocol::Network::Request::ReferrerPolicyEnum::SameOrigin;
    case network::mojom::ReferrerPolicy::kStrictOrigin:
      return protocol::Network::Request::ReferrerPolicyEnum::StrictOrigin;
    case network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin:
      return protocol::Network::Request::ReferrerPolicyEnum::
          StrictOriginWhenCrossOrigin;
  }

  return protocol::Network::Request::ReferrerPolicyEnum::
      NoReferrerWhenDowngrade;
}

std::unique_ptr<protocol::Network::WebSocketFrame> WebSocketMessageToProtocol(
    int op_code,
    bool masked,
    base::span<const char> payload) {
  return protocol::Network::WebSocketFrame::create()
      .setOpcode(op_code)
      .setMask(masked)
      // Only interpret the payload as UTF-8 when it's a text message
      .setPayloadData(op_code == 1 ? String::FromUTF8WithLatin1Fallback(
                                         base::as_bytes(payload))
                                   : Base64Encode(base::as_bytes(payload)))
      .build();
}

String GetTrustTokenOperationType(
    network::mojom::TrustTokenOperationType operation) {
  switch (operation) {
    case network::mojom::TrustTokenOperationType::kIssuance:
      return protocol::Network::TrustTokenOperationTypeEnum::Issuance;
    case network::mojom::TrustTokenOperationType::kRedemption:
      return protocol::Network::TrustTokenOperationTypeEnum::Redemption;
    case network::mojom::TrustTokenOperationType::kSigning:
      return protocol::Network::TrustTokenOperationTypeEnum::Signing;
  }
}

String GetTrustTokenRefreshPolicy(
    network::mojom::TrustTokenRefreshPolicy policy) {
  switch (policy) {
    case network::mojom::TrustTokenRefreshPolicy::kUseCached:
      return protocol::Network::TrustTokenParams::RefreshPolicyEnum::UseCached;
    case network::mojom::TrustTokenRefreshPolicy::kRefresh:
      return protocol::Network::TrustTokenParams::RefreshPolicyEnum::Refresh;
  }
}

std::unique_ptr<protocol::Network::TrustTokenParams> BuildTrustTokenParams(
    const network::mojom::blink::TrustTokenParams& params) {
  auto protocol_params =
      protocol::Network::TrustTokenParams::create()
          .setOperation(GetTrustTokenOperationType(params.operation))
          .setRefreshPolicy(GetTrustTokenRefreshPolicy(params.refresh_policy))
          .build();

  if (!params.issuers.empty()) {
    auto issuers = std::make_unique<protocol::Array<protocol::String>>();
    for (const auto& issuer : params.issuers) {
      issuers->push_back(issuer->ToString());
    }
    protocol_params->setIssuers(std::move(issuers));
  }

  return protocol_params;
}

void SetNetworkStateOverride(bool offline,
                             double latency,
                             double download_throughput,
                             double upload_throughput,
                             WebConnectionType type) {
  // TODO(dgozman): networkStateNotifier is per-process. It would be nice to
  // have per-frame override instead.
  if (offline || latency || download_throughput || upload_throughput) {
    GetNetworkStateNotifier().SetNetworkConnectionInfoOverride(
        !offline, type, std::nullopt, latency,
        download_throughput / (1024 * 1024 / 8));
  } else {
    GetNetworkStateNotifier().ClearOverride();
  }
}

String IPAddressToString(const net::IPAddress& address) {
  String unbracketed = String::FromUTF8(address.ToString());
  if (!address.IsIPv6()) {
    return unbracketed;
  }

  return "[" + unbracketed + "]";
}

namespace ContentEncodingEnum = protocol::Network::ContentEncodingEnum;

String AcceptedEncodingFromProtocol(
    const protocol::Network::ContentEncoding& encoding) {
  String result;
  if (ContentEncodingEnum::Gzip == encoding ||
      ContentEncodingEnum::Br == encoding ||
      ContentEncodingEnum::Deflate == encoding ||
      ContentEncodingEnum::Zstd == encoding) {
    result = encoding;
  }
  return result;
}

using SourceTypeEnum = net::SourceStream::SourceType;
SourceTypeEnum SourceTypeFromString(const String& type) {
  if (type == ContentEncodingEnum::Gzip)
    return SourceTypeEnum::TYPE_GZIP;
  if (type == ContentEncodingEnum::Deflate)
    return SourceTypeEnum::TYPE_DEFLATE;
  if (type == ContentEncodingEnum::Br)
    return SourceTypeEnum::TYPE_BROTLI;
  if (type == ContentEncodingEnum::Zstd) {
    return SourceTypeEnum::TYPE_ZSTD;
  }
  NOTREACHED();
}

}  // namespace

void InspectorNetworkAgent::Restore() {
  if (enabled_.Get())
    Enable();
}

static std::unique_ptr<protocol::Network::ResourceTiming> BuildObjectForTiming(
    const ResourceLoadTiming& timing) {
  return protocol::Network::ResourceTiming::create()
      .setRequestTime(timing.RequestTime().since_origin().InSecondsF())
      .setProxyStart(timing.CalculateMillisecondDelta(timing.ProxyStart()))
      .setProxyEnd(timing.CalculateMillisecondDelta(timing.ProxyEnd()))
      .setDnsStart(timing.Calculate
"""


```