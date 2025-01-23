Response:
The user wants a summary of the functionality of the `mixed_content_checker.cc` file in the Chromium Blink engine. They are also interested in the file's relationship with JavaScript, HTML, and CSS, examples of logical reasoning, common user or programming errors, and debugging information.

**Plan:**

1. **Identify the core responsibility:** Based on the file name and the included headers, determine the main purpose of `mixed_content_checker.cc`.
2. **Analyze key functions:** Examine the prominent functions and their roles in achieving the core responsibility.
3. **Relate to web technologies:** Explain how the functionality interacts with JavaScript, HTML, and CSS, providing concrete examples.
4. **Identify logical reasoning:** Look for conditional statements and decision-making processes within the code and illustrate with hypothetical inputs and outputs.
5. **Pinpoint potential errors:**  Consider common mistakes users or developers might make that this code addresses.
6. **Describe user interaction:**  Outline the steps a user might take to trigger the mixed content checks.
7. **Summarize the functionality:** Provide a concise overview of the file's purpose.
这是 `blink/renderer/core/loader/mixed_content_checker.cc` 文件的第一部分，其主要功能是**检查并处理网页中加载的混合内容（Mixed Content）**。

**功能归纳：**

1. **定义了混合内容的判断标准：**  通过 `IsMixedContent` 函数来判断一个 URL 是否是混合内容。混合内容指的是在 HTTPS 页面中加载的非 HTTPS 资源。
2. **确定混合内容发生的位置：** `InWhichFrameIsContentMixed` 函数用于判断在哪个 Frame 中发生了混合内容加载。
3. **生成关于混合内容的控制台消息：**  `CreateConsoleMessageAboutFetch` 和 `CreateConsoleMessageAboutWebSocket` 函数用于创建在开发者工具的控制台中显示的警告或错误信息，告知用户页面存在混合内容。
4. **记录混合内容的使用情况：** `Count` 函数用于统计不同类型的混合内容被加载的次数，用于数据分析和性能优化。
5. **决定是否阻止混合内容的加载 (对于 Fetch 请求)：** `ShouldBlockFetch` 函数是核心功能之一，它根据安全策略、用户设置等因素，决定是否阻止通过 Fetch API 发起的混合内容请求。
6. **决定是否阻止混合内容的加载 (对于 Worker)：** `ShouldBlockFetchOnWorker` 函数类似于 `ShouldBlockFetch`，但专门用于处理 Web Worker 中的混合内容请求。
7. **决定是否允许混合的 WebSocket 连接：** `IsWebSocketAllowed` 函数用于检查是否允许在 HTTPS 页面中建立到非 HTTPS WebSocket 端点的连接。
8. **处理混合的表单提交：** `IsMixedFormAction` 函数判断表单的提交目标是否为非 HTTPS 地址。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML:**
    * **`<img>` 标签加载 HTTP 图片：**  如果一个 HTTPS 页面中使用了 `<img src="http://example.com/image.jpg">`，`MixedContentChecker` 会检测到这是一个混合内容，可能会在控制台输出警告，并根据策略决定是否阻止图片的加载。
    * **`<script>` 标签加载 HTTP 脚本：** 类似地，`<script src="http://example.com/script.js"></script>` 也会被检测为混合内容，并且 `ShouldBlockFetch` 函数会根据策略判断是否阻止脚本的执行。
    * **`<iframe>` 标签加载 HTTP 页面：**  一个 HTTPS 页面嵌入 `<iframe src="http://example.com/page.html"></iframe>` 时，`InWhichFrameIsContentMixed` 会识别出混合内容发生在 `<iframe>` 中。
    * **`<link>` 标签加载 HTTP CSS：**  `<link rel="stylesheet" href="http://example.com/style.css">` 也会被 `MixedContentChecker` 处理。

* **JavaScript:**
    * **`fetch()` API 请求 HTTP 资源：** 当 JavaScript 代码使用 `fetch('http://example.com/data')` 在 HTTPS 页面发起请求时，`ShouldBlockFetch` 函数会被调用来决定是否阻止请求。
    * **`XMLHttpRequest` 请求 HTTP 资源：**  类似于 `fetch()`，使用 `XMLHttpRequest` 发起 HTTP 请求也会触发混合内容检查。
    * **WebSocket 连接到 `ws://` URL：**  JavaScript 代码尝试创建 `new WebSocket('ws://example.com')` 连接时，`IsWebSocketAllowed` 会被调用来判断是否允许连接。

* **CSS:**
    * **`url()` 函数引用 HTTP 图片或字体：**  在 CSS 文件中使用 `background-image: url('http://example.com/bg.jpg')` 或 `@font-face { src: url('http://example.com/font.woff'); }` 引用 HTTP 资源时，会被 `MixedContentChecker` 检测。

**逻辑推理举例说明：**

**假设输入：**

* 当前页面是通过 HTTPS 加载的 (`origin_protocol` 为 "https")。
* 正在加载的资源 URL 是 HTTP (`url` 的协议为 "http")。

**`IsMixedContent` 函数的逻辑推理：**

1. 函数检查 `origin_protocol` 是否应该被视为限制混合内容的协议 (通过 `SchemeRegistry::ShouldTreatURLSchemeAsRestrictingMixedContent`)。对于 "https"，结果为 true。
2. 函数调用 `IsInsecureUrl(url)` 来判断 `url` 是否不安全。由于 `url` 的协议是 "http"，`IsInsecureUrl` 会返回 true。
3. 因此，`IsMixedContent` 函数返回 true，表示这是一个混合内容。

**假设输入：**

* 一个 HTTPS 页面尝试加载一个 HTTP 的图片资源。
* 用户的浏览器设置允许运行不安全内容 (`settings->GetAllowRunningOfInsecureContent()` 为 true)。
* 当前不是严格的混合内容检查模式 (`settings->GetStrictMixedContentChecking()` 为 false)。

**`ShouldBlockFetch` 函数的部分逻辑推理：**

1. `InWhichFrameIsContentMixed` 会判断混合内容发生在本页面的主 Frame 中。
2. `MixedContent::ContextTypeFromRequestContext` 可能会将图片请求归类为 `kOptionallyBlockable` 或 `kBlockable`，具体取决于浏览器的配置。
3. 如果是 `kOptionallyBlockable`，且不是严格模式，并且 URL 不是 IP 地址，则 `allowed` 会被设置为 true，不会阻止加载。
4. 如果是 `kBlockable`，且用户设置允许运行不安全内容，且不是严格模式，`allowed` 也可能被设置为 true。

**输出：**  根据上述条件，HTTP 图片可能不会被阻止加载，但在开发者工具的控制台中会显示一个警告消息。

**用户或编程常见的使用错误举例说明：**

* **用户错误：**
    * **网站开发者错误地使用了 HTTP 资源链接：**  开发者在 HTTPS 网站的代码中使用了 `http://` 开头的图片、脚本、CSS 或其他资源的 URL，导致混合内容警告或阻止。
    * **配置错误导致资源通过 HTTP 提供：**  服务器配置不当，导致原本应该通过 HTTPS 提供的资源，最终通过 HTTP 提供。

* **编程错误：**
    * **硬编码 HTTP URL：**  在代码中直接写入 `http://` 开头的 URL，而不是使用相对路径或协议相对路径 (`//example.com/image.jpg`)。
    * **动态生成 URL 时未考虑协议：**  在 JavaScript 中动态拼接 URL 时，没有根据当前页面的协议来选择使用 `http://` 或 `https://`。
    * **第三方库或插件使用了 HTTP 资源：**  引入的第三方库或插件内部加载了 HTTP 资源，导致混合内容问题。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 HTTPS 网址并访问，或者点击一个 HTTPS 链接。**
2. **浏览器开始加载该 HTTPS 页面。**
3. **页面 HTML 中包含了对 HTTP 资源的引用（例如 `<img>`, `<script>`, `<link>` 等）。**
4. **浏览器解析 HTML，遇到这些 HTTP 资源引用，并尝试发起对这些资源的请求。**
5. **Blink 引擎的加载器（loader）模块处理这些资源请求。**
6. **`mixed_content_checker.cc` 中的函数会被调用，检查这些 HTTP 请求是否构成混合内容。**
7. **根据配置和策略，决定是否阻止这些请求，并在控制台输出相应的消息。**

**调试线索：**

* **查看浏览器的开发者工具的 "安全" 或 "控制台" 标签：**  通常会显示混合内容警告或错误信息，指出哪个资源被阻止或警告。
* **检查网络请求：**  在开发者工具的 "网络" 标签中，可以查看请求的协议和状态，确认哪些资源是通过 HTTP 加载的。
* **使用浏览器的混合内容阻止功能进行测试：**  可以强制浏览器阻止所有混合内容，以验证网站是否存在混合内容问题。
* **检查网站的 Content Security Policy (CSP) 设置：**  CSP 可以控制浏览器如何处理混合内容。

总而言之，`mixed_content_checker.cc` 是 Chromium Blink 引擎中负责维护 Web 安全的重要组成部分，它通过识别和处理混合内容，保护用户免受潜在的安全风险。

### 提示词
```
这是目录为blink/renderer/core/loader/mixed_content_checker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"

#include <optional>

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/metrics/field_trial_params.h"
#include "build/build_config.h"
#include "build/chromecast_buildflags.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/security_context/insecure_request_policy.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/mixed_content.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_worker_fetch_context.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_fetch_context.h"
#include "third_party/blink/renderer/core/loader/worker_fetch_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_settings.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/mixed_content.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

// When a frame is local, use its full URL to represent the main resource. When
// the frame is remote, the full URL isn't accessible, so use the origin. This
// function is used, for example, to determine the URL to show in console
// messages about mixed content.
KURL MainResourceUrlForFrame(Frame* frame) {
  if (frame->IsRemoteFrame()) {
    return KURL(NullURL(),
                frame->GetSecurityContext()->GetSecurityOrigin()->ToString());
  }
  return To<LocalFrame>(frame)->GetDocument()->Url();
}

const char* RequestContextName(mojom::blink::RequestContextType context) {
  switch (context) {
    case mojom::blink::RequestContextType::ATTRIBUTION_SRC:
      return "attribution src endpoint";
    case mojom::blink::RequestContextType::AUDIO:
      return "audio file";
    case mojom::blink::RequestContextType::BEACON:
      return "Beacon endpoint";
    case mojom::blink::RequestContextType::CSP_REPORT:
      return "Content Security Policy reporting endpoint";
    case mojom::blink::RequestContextType::DOWNLOAD:
      return "download";
    case mojom::blink::RequestContextType::EMBED:
      return "plugin resource";
    case mojom::blink::RequestContextType::EVENT_SOURCE:
      return "EventSource endpoint";
    case mojom::blink::RequestContextType::FAVICON:
      return "favicon";
    case mojom::blink::RequestContextType::FETCH:
      return "resource";
    case mojom::blink::RequestContextType::FONT:
      return "font";
    case mojom::blink::RequestContextType::FORM:
      return "form action";
    case mojom::blink::RequestContextType::FRAME:
      return "frame";
    case mojom::blink::RequestContextType::HYPERLINK:
      return "resource";
    case mojom::blink::RequestContextType::IFRAME:
      return "frame";
    case mojom::blink::RequestContextType::IMAGE:
      return "image";
    case mojom::blink::RequestContextType::IMAGE_SET:
      return "image";
    case mojom::blink::RequestContextType::INTERNAL:
      return "resource";
    case mojom::blink::RequestContextType::LOCATION:
      return "resource";
    case mojom::blink::RequestContextType::JSON:
      return "json";
    case mojom::blink::RequestContextType::MANIFEST:
      return "manifest";
    case mojom::blink::RequestContextType::OBJECT:
      return "plugin resource";
    case mojom::blink::RequestContextType::PING:
      return "hyperlink auditing endpoint";
    case mojom::blink::RequestContextType::PLUGIN:
      return "plugin data";
    case mojom::blink::RequestContextType::PREFETCH:
      return "prefetch resource";
    case mojom::blink::RequestContextType::SCRIPT:
      return "script";
    case mojom::blink::RequestContextType::SERVICE_WORKER:
      return "Service Worker script";
    case mojom::blink::RequestContextType::SHARED_WORKER:
      return "Shared Worker script";
    case mojom::blink::RequestContextType::SPECULATION_RULES:
      return "speculation rules";
    case mojom::blink::RequestContextType::STYLE:
      return "stylesheet";
    case mojom::blink::RequestContextType::SUBRESOURCE:
      return "resource";
    case mojom::blink::RequestContextType::SUBRESOURCE_WEBBUNDLE:
      return "webbundle";
    case mojom::blink::RequestContextType::TRACK:
      return "Text Track";
    case mojom::blink::RequestContextType::UNSPECIFIED:
      return "resource";
    case mojom::blink::RequestContextType::VIDEO:
      return "video";
    case mojom::blink::RequestContextType::WORKER:
      return "Worker script";
    case mojom::blink::RequestContextType::XML_HTTP_REQUEST:
      return "XMLHttpRequest endpoint";
    case mojom::blink::RequestContextType::XSLT:
      return "XSLT";
  }
  NOTREACHED();
}

// Currently we have two slightly different versions, because
// in frames SecurityContext is the source of CSP/InsecureRequestPolicy,
// especially where FetchContext and SecurityContext come from different
// frames (e.g. in nested frames), while in
// workers we should totally rely on FetchContext's FetchClientSettingsObject
// to avoid confusion around off-the-main-thread fetch.
// TODO(hiroshige): Consider merging them once FetchClientSettingsObject
// becomes the source of CSP/InsecureRequestPolicy also in frames.
bool IsWebSocketAllowedInFrame(const BaseFetchContext& fetch_context,
                               const SecurityContext* security_context,
                               Settings* settings,
                               const KURL& url) {
  fetch_context.CountUsage(WebFeature::kMixedContentPresent);
  fetch_context.CountUsage(WebFeature::kMixedContentWebSocket);

  // If we're in strict mode, we'll automagically fail everything, and
  // intentionally skip the client checks in order to prevent degrading the
  // site's security UI.
  bool strict_mode =
      (security_context->GetInsecureRequestPolicy() &
       mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent) !=
          mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone ||
      settings->GetStrictMixedContentChecking();
  if (strict_mode)
    return false;
  return settings && settings->GetAllowRunningOfInsecureContent();
}

bool IsWebSocketAllowedInWorker(const WorkerFetchContext& fetch_context,
                                WorkerSettings* settings,
                                const KURL& url) {
  fetch_context.CountUsage(WebFeature::kMixedContentPresent);
  fetch_context.CountUsage(WebFeature::kMixedContentWebSocket);
  if (ContentSecurityPolicy* policy =
          fetch_context.GetContentSecurityPolicy()) {
    policy->ReportMixedContent(url,
                               ResourceRequest::RedirectStatus::kNoRedirect);
  }

  // If we're in strict mode, we'll automagically fail everything, and
  // intentionally skip the client checks in order to prevent degrading the
  // site's security UI.
  bool strict_mode =
      (fetch_context.GetResourceFetcherProperties()
           .GetFetchClientSettingsObject()
           .GetInsecureRequestsPolicy() &
       mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent) !=
          mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone ||
      settings->GetStrictMixedContentChecking();
  if (strict_mode)
    return false;
  return settings && settings->GetAllowRunningOfInsecureContent();
}

bool IsUrlPotentiallyTrustworthy(const KURL& url) {
  // This saves a copy of the url, which can be expensive for large data URLs.
  // TODO(crbug.com/1322100): Remove this logic once
  // network::IsUrlPotentiallyTrustworthy() doesn't copy the URL.
  if (url.ProtocolIsData()) {
    DCHECK(network::IsUrlPotentiallyTrustworthy(GURL(url)));
    return true;
  }
  return network::IsUrlPotentiallyTrustworthy(GURL(url));
}

}  // namespace

static bool IsInsecureUrl(const KURL& url) {
  // |url| is mixed content if it is not a potentially trustworthy URL.
  // See https://w3c.github.io/webappsec-mixed-content/#should-block-response
  return !IsUrlPotentiallyTrustworthy(url);
}

static void MeasureStricterVersionOfIsMixedContent(Frame& frame,
                                                   const KURL& url,
                                                   const LocalFrame* source) {
  // We're currently only checking for mixed content in `https://*` contexts.
  // What about other "secure" contexts the SchemeRegistry knows about? We'll
  // use this method to measure the occurrence of non-webby mixed content to
  // make sure we're not breaking the world without realizing it.
  const SecurityOrigin* origin =
      frame.GetSecurityContext()->GetSecurityOrigin();
  if (MixedContentChecker::IsMixedContent(origin, url)) {
    if (origin->Protocol() != "https") {
      UseCounter::Count(
          source->GetDocument(),
          WebFeature::kMixedContentInNonHTTPSFrameThatRestrictsMixedContent);
    }
  } else if (!IsUrlPotentiallyTrustworthy(url) &&
             base::Contains(url::GetSecureSchemes(),
                            origin->Protocol().Ascii())) {
    UseCounter::Count(
        source->GetDocument(),
        WebFeature::kMixedContentInSecureFrameThatDoesNotRestrictMixedContent);
  }
}

bool RequestIsSubframeSubresource(Frame* frame) {
  return frame && frame != frame->Tree().Top();
}

// static
bool MixedContentChecker::IsMixedContent(const SecurityOrigin* security_origin,
                                         const KURL& url) {
  return IsMixedContent(
      security_origin->GetOriginOrPrecursorOriginIfOpaque()->Protocol(), url);
}

// static
bool MixedContentChecker::IsMixedContent(const String& origin_protocol,
                                         const KURL& url) {
  if (!SchemeRegistry::ShouldTreatURLSchemeAsRestrictingMixedContent(
          origin_protocol))
    return false;

  return IsInsecureUrl(url);
}

// static
bool MixedContentChecker::IsMixedContent(
    const FetchClientSettingsObject& settings,
    const KURL& url) {
  switch (settings.GetHttpsState()) {
    case HttpsState::kNone:
      return false;

    case HttpsState::kModern:
      return IsInsecureUrl(url);
  }
}

// static
Frame* MixedContentChecker::InWhichFrameIsContentMixed(LocalFrame* frame,
                                                       const KURL& url) {
  // Frameless requests cannot be mixed content.
  if (!frame)
    return nullptr;

  // Check the top frame first.
  Frame& top = frame->Tree().Top();
  MeasureStricterVersionOfIsMixedContent(top, url, frame);
  if (IsMixedContent(top.GetSecurityContext()->GetSecurityOrigin(), url))
    return &top;

  MeasureStricterVersionOfIsMixedContent(*frame, url, frame);
  if (IsMixedContent(frame->GetSecurityContext()->GetSecurityOrigin(), url))
    return frame;

  // No mixed content, no problem.
  return nullptr;
}

// static
ConsoleMessage* MixedContentChecker::CreateConsoleMessageAboutFetch(
    const KURL& main_resource_url,
    const KURL& url,
    mojom::blink::RequestContextType request_context,
    bool allowed,
    std::unique_ptr<SourceLocation> source_location) {
  String message = String::Format(
      "Mixed Content: The page at '%s' was loaded over HTTPS, but requested an "
      "insecure %s '%s'. %s",
      main_resource_url.ElidedString().Utf8().c_str(),
      RequestContextName(request_context), url.ElidedString().Utf8().c_str(),
      allowed ? "This content should also be served over HTTPS."
              : "This request has been blocked; the content must be served "
                "over HTTPS.");
  mojom::ConsoleMessageLevel message_level =
      allowed ? mojom::ConsoleMessageLevel::kWarning
              : mojom::ConsoleMessageLevel::kError;
  if (source_location) {
    return MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kSecurity, message_level, message,
        std::move(source_location));
  }
  return MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kSecurity, message_level, message);
}

// static
void MixedContentChecker::Count(
    Frame* frame,
    mojom::blink::RequestContextType request_context,
    const LocalFrame* source) {
  UseCounter::Count(source->GetDocument(), WebFeature::kMixedContentPresent);

  // Roll blockable content up into a single counter, count unblocked types
  // individually so we can determine when they can be safely moved to the
  // blockable category:
  mojom::blink::MixedContentContextType context_type =
      MixedContent::ContextTypeFromRequestContext(
          request_context, DecideCheckModeForPlugin(frame->GetSettings()));
  if (context_type == mojom::blink::MixedContentContextType::kBlockable) {
    UseCounter::Count(source->GetDocument(),
                      WebFeature::kMixedContentBlockable);
    return;
  }

  WebFeature feature;
  switch (request_context) {
    case mojom::blink::RequestContextType::AUDIO:
      feature = WebFeature::kMixedContentAudio;
      break;
    case mojom::blink::RequestContextType::DOWNLOAD:
      feature = WebFeature::kMixedContentDownload;
      break;
    case mojom::blink::RequestContextType::FAVICON:
      feature = WebFeature::kMixedContentFavicon;
      break;
    case mojom::blink::RequestContextType::IMAGE:
      feature = WebFeature::kMixedContentImage;
      break;
    case mojom::blink::RequestContextType::INTERNAL:
      feature = WebFeature::kMixedContentInternal;
      break;
    case mojom::blink::RequestContextType::PLUGIN:
      feature = WebFeature::kMixedContentPlugin;
      break;
    case mojom::blink::RequestContextType::PREFETCH:
      feature = WebFeature::kMixedContentPrefetch;
      break;
    case mojom::blink::RequestContextType::VIDEO:
      feature = WebFeature::kMixedContentVideo;
      break;

    default:
      NOTREACHED();
  }
  UseCounter::Count(source->GetDocument(), feature);
}

// static
bool MixedContentChecker::ShouldBlockFetch(
    LocalFrame* frame,
    mojom::blink::RequestContextType request_context,
    network::mojom::blink::IPAddressSpace target_address_space,
    const KURL& url_before_redirects,
    ResourceRequest::RedirectStatus redirect_status,
    const KURL& url,
    const String& devtools_id,
    ReportingDisposition reporting_disposition,
    mojom::blink::ContentSecurityNotifier& notifier) {
  Frame* mixed_frame = InWhichFrameIsContentMixed(frame, url);
  if (!mixed_frame)
    return false;

  // Exempt non-webby schemes from mixed content treatment. For subresources,
  // these will be blocked anyway as net::ERR_UNKNOWN_URL_SCHEME, so there's no
  // need to present a security warning. Non-webby main resources (including
  // subframes) are handled in the browser process's mixed content checking,
  // where the URL will be allowed to load, but not treated as mixed content
  // because it can't return data to the browser. See https://crbug.com/621131.
  //
  // TODO(https://crbug.com/1030307): decide whether CORS-enabled is really the
  // right way to draw this distinction.
  if (!SchemeRegistry::ShouldTreatURLSchemeAsCorsEnabled(url.Protocol())) {
    // Record non-webby mixed content to see if it is rare enough that it can be
    // gated behind an enterprise policy. This excludes URLs that are considered
    // potentially-secure such as blob: and filesystem:, which are special-cased
    // in IsInsecureUrl() and cause an early-return because of the
    // InWhichFrameIsContentMixed() check above.
    UseCounter::Count(frame->GetDocument(), WebFeature::kNonWebbyMixedContent);
    return false;
  }

  MixedContentChecker::Count(mixed_frame, request_context, frame);
  if (ContentSecurityPolicy* policy =
          frame->DomWindow()->GetContentSecurityPolicy())
    policy->ReportMixedContent(url_before_redirects, redirect_status);

  Settings* settings = mixed_frame->GetSettings();
  auto& local_frame_host = frame->GetLocalFrameHostRemote();
  WebContentSettingsClient* content_settings_client =
      frame->GetContentSettingsClient();
  const SecurityOrigin* security_origin =
      mixed_frame->GetSecurityContext()->GetSecurityOrigin();
  bool allowed = false;

  // If we're in strict mode, we'll automagically fail everything, and
  // intentionally skip the client checks in order to prevent degrading the
  // site's security UI.
  bool strict_mode =
      (mixed_frame->GetSecurityContext()->GetInsecureRequestPolicy() &
       mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent) !=
          mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone ||
      settings->GetStrictMixedContentChecking();

  mojom::blink::MixedContentContextType context_type =
      MixedContent::ContextTypeFromRequestContext(
          request_context, DecideCheckModeForPlugin(settings));

  switch (context_type) {
    case mojom::blink::MixedContentContextType::kOptionallyBlockable:

#if (BUILDFLAG(IS_FUCHSIA) || BUILDFLAG(IS_LINUX)) && \
    BUILDFLAG(ENABLE_CAST_RECEIVER)
      // Fuchsia WebEngine can be configured to allow loading Mixed Content from
      // an insecure IP address. This is a workaround to revert Fuchsia Cast
      // Receivers to the behavior before crrev.com/c/4032146.
      // TODO(crbug.com/1434440): Remove this workaround when there is a better
      // way to disable blocking Mixed Content with an IP address.
      allowed = !strict_mode;
#else
      allowed = !strict_mode && !GURL(url).HostIsIPAddress();
#endif  // (BUILDFLAG(IS_FUCHSIA) || BUILDFLAG(IS_LINUX)) &&
        // BUILDFLAG(ENABLE_CAST_RECEIVER)

      if (allowed) {
        if (content_settings_client)
          content_settings_client->PassiveInsecureContentFound(url);
        // Only notify embedder about loads that would create CSP reports (i.e.
        // filter out preloads).
        if (reporting_disposition == ReportingDisposition::kReport)
          local_frame_host.DidDisplayInsecureContent();
      }
      break;

    case mojom::blink::MixedContentContextType::kBlockable: {
      // Strictly block subresources that are mixed with respect to their
      // subframes, unless all insecure content is allowed. This is to avoid the
      // following situation: https://a.com embeds https://b.com, which loads a
      // script over insecure HTTP. The user opts to allow the insecure content,
      // thinking that they are allowing an insecure script to run on
      // https://a.com and not realizing that they are in fact allowing an
      // insecure script on https://b.com.
      if (!settings->GetAllowRunningOfInsecureContent() &&
          RequestIsSubframeSubresource(frame) &&
          IsMixedContent(frame->GetSecurityContext()->GetSecurityOrigin(),
                         url)) {
        UseCounter::Count(frame->GetDocument(),
                          WebFeature::kBlockableMixedContentInSubframeBlocked);
        allowed = false;
        break;
      }

      bool should_ask_embedder =
          !strict_mode && settings &&
          (!settings->GetStrictlyBlockBlockableMixedContent() ||
           settings->GetAllowRunningOfInsecureContent());
      if (should_ask_embedder) {
        allowed = settings && settings->GetAllowRunningOfInsecureContent();
        if (content_settings_client) {
          allowed = content_settings_client->AllowRunningInsecureContent(
              allowed, url);
        }
      }
      if (allowed) {
        // Only notify embedder about loads that would create CSP reports (i.e.
        // filter out preloads).
        if (reporting_disposition == ReportingDisposition::kReport) {
          notifier.NotifyInsecureContentRan(KURL(security_origin->ToString()),
                                            url);
        }
        UseCounter::Count(frame->GetDocument(),
                          WebFeature::kMixedContentBlockableAllowed);
      }
      break;
    }

    case mojom::blink::MixedContentContextType::kShouldBeBlockable:
      allowed = !strict_mode;
      if (allowed && reporting_disposition == ReportingDisposition::kReport)
        local_frame_host.DidDisplayInsecureContent();
      break;
    case mojom::blink::MixedContentContextType::kNotMixedContent:
      NOTREACHED();
  };

  // Skip mixed content check for private and local targets.
  // `target_address_space` here is private/local only when resource request
  // has explicitly set `targetAddressSpace` fetch option.
  // TODO(lyf): check the IP address space for initiator, only skip when the
  // initiator is more public.
  if (base::FeatureList::IsEnabled(
          network::features::kPrivateNetworkAccessPermissionPrompt) &&
      RuntimeEnabledFeatures::PrivateNetworkAccessPermissionPromptEnabled(
          frame->DomWindow())) {
    // TODO(crbug.com/323583084): Re-enable PNA permission prompt for documents
    // fetched via service worker.
    if (!frame->Loader()
             .GetDocumentLoader()
             ->GetResponse()
             .WasFetchedViaServiceWorker() &&
        (target_address_space ==
             network::mojom::blink::IPAddressSpace::kPrivate ||
         target_address_space ==
             network::mojom::blink::IPAddressSpace::kLocal)) {
      UseCounter::Count(frame->GetDocument(),
                        WebFeature::kPrivateNetworkAccessPermissionPrompt);
      allowed = true;
    }
  }

  if (reporting_disposition == ReportingDisposition::kReport) {
    frame->GetDocument()->AddConsoleMessage(
        CreateConsoleMessageAboutFetch(MainResourceUrlForFrame(mixed_frame),
                                       url, request_context, allowed, nullptr));
  }
  // Issue is created even when reporting disposition is false i.e. for
  // speculative prefetches. Otherwise the DevTools frontend would not
  // receive an issue with a devtools_id which it can match to a request.
  AuditsIssue::ReportMixedContentIssue(
      MainResourceUrlForFrame(mixed_frame), url, request_context, frame,
      allowed ? MixedContentResolutionStatus::kMixedContentWarning
              : MixedContentResolutionStatus::kMixedContentBlocked,
      devtools_id);
  return !allowed;
}

// static
bool MixedContentChecker::ShouldBlockFetchOnWorker(
    WorkerFetchContext& worker_fetch_context,
    mojom::blink::RequestContextType request_context,
    const KURL& url_before_redirects,
    ResourceRequest::RedirectStatus redirect_status,
    const KURL& url,
    ReportingDisposition reporting_disposition,
    bool is_worklet_global_scope) {
  const FetchClientSettingsObject& fetch_client_settings_object =
      worker_fetch_context.GetResourceFetcherProperties()
          .GetFetchClientSettingsObject();
  if (!MixedContentChecker::IsMixedContent(fetch_client_settings_object, url)) {
    return false;
  }

  worker_fetch_context.CountUsage(WebFeature::kMixedContentPresent);
  worker_fetch_context.CountUsage(WebFeature::kMixedContentBlockable);
  if (auto* policy = worker_fetch_context.GetContentSecurityPolicy())
    policy->ReportMixedContent(url_before_redirects, redirect_status);

  // Blocks all mixed content request from worklets.
  // TODO(horo): Revise this when the spec is updated.
  // Worklets spec: https://www.w3.org/TR/worklets-1/#security-considerations
  // Spec issue: https://github.com/w3c/css-houdini-drafts/issues/92
  if (is_worklet_global_scope)
    return true;

  WorkerSettings* settings = worker_fetch_context.GetWorkerSettings();
  DCHECK(settings);
  bool allowed = false;
  if (!settings->GetAllowRunningOfInsecureContent() &&
      worker_fetch_context.GetWebWorkerFetchContext()->IsOnSubframe()) {
    worker_fetch_context.CountUsage(
        WebFeature::kBlockableMixedContentInSubframeBlocked);
    allowed = false;
  } else {
    bool strict_mode =
        (fetch_client_settings_object.GetInsecureRequestsPolicy() &
         mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent) !=
            mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone ||
        settings->GetStrictMixedContentChecking();
    bool should_ask_embedder =
        !strict_mode && (!settings->GetStrictlyBlockBlockableMixedContent() ||
                         settings->GetAllowRunningOfInsecureContent());
    allowed = should_ask_embedder &&
              worker_fetch_context.AllowRunningInsecureContent(
                  settings->GetAllowRunningOfInsecureContent(), url);
    if (allowed) {
      worker_fetch_context.GetContentSecurityNotifier()
          .NotifyInsecureContentRan(
              KURL(
                  fetch_client_settings_object.GetSecurityOrigin()->ToString()),
              url);
      worker_fetch_context.CountUsage(
          WebFeature::kMixedContentBlockableAllowed);
    }
  }

  if (reporting_disposition == ReportingDisposition::kReport) {
    worker_fetch_context.GetDetachableConsoleLogger().AddConsoleMessage(
        CreateConsoleMessageAboutFetch(worker_fetch_context.Url(), url,
                                       request_context, allowed, nullptr));
  }
  return !allowed;
}

// static
ConsoleMessage* MixedContentChecker::CreateConsoleMessageAboutWebSocket(
    const KURL& main_resource_url,
    const KURL& url,
    bool allowed) {
  String message = String::Format(
      "Mixed Content: The page at '%s' was loaded over HTTPS, but attempted to "
      "connect to the insecure WebSocket endpoint '%s'. %s",
      main_resource_url.ElidedString().Utf8().c_str(),
      url.ElidedString().Utf8().c_str(),
      allowed ? "This endpoint should be available via WSS. Insecure access is "
                "deprecated."
              : "This request has been blocked; this endpoint must be "
                "available over WSS.");
  mojom::ConsoleMessageLevel message_level =
      allowed ? mojom::ConsoleMessageLevel::kWarning
              : mojom::ConsoleMessageLevel::kError;
  return MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kSecurity, message_level, message);
}

// static
bool MixedContentChecker::IsWebSocketAllowed(
    const FrameFetchContext& frame_fetch_context,
    LocalFrame* frame,
    const KURL& url) {
  Frame* mixed_frame = InWhichFrameIsContentMixed(frame, url);
  if (!mixed_frame)
    return true;

  Settings* settings = mixed_frame->GetSettings();
  // Use the current local frame's client; the embedder doesn't distinguish
  // mixed content signals from different frames on the same page.
  WebContentSettingsClient* content_settings_client =
      frame->GetContentSettingsClient();
  const SecurityContext* security_context = mixed_frame->GetSecurityContext();
  const SecurityOrigin* security_origin = security_context->GetSecurityOrigin();

  if (ContentSecurityPolicy* policy =
          frame->DomWindow()->GetContentSecurityPolicy()) {
    policy->ReportMixedContent(url,
                               ResourceRequest::RedirectStatus::kNoRedirect);
  }
  bool allowed = IsWebSocketAllowedInFrame(frame_fetch_context,
                                           security_context, settings, url);
  if (content_settings_client) {
    allowed =
        content_settings_client->AllowRunningInsecureContent(allowed, url);
  }

  if (allowed) {
    frame_fetch_context.GetContentSecurityNotifier().NotifyInsecureContentRan(
        KURL(security_origin->ToString()), url);
  }

  frame->GetDocument()->AddConsoleMessage(CreateConsoleMessageAboutWebSocket(
      MainResourceUrlForFrame(mixed_frame), url, allowed));
  AuditsIssue::ReportMixedContentIssue(
      MainResourceUrlForFrame(mixed_frame), url,

      mojom::blink::RequestContextType::FETCH, frame,
      allowed ? MixedContentResolutionStatus::kMixedContentWarning
              : MixedContentResolutionStatus::kMixedContentBlocked,
      String());
  return allowed;
}

// static
bool MixedContentChecker::IsWebSocketAllowed(
    WorkerFetchContext& worker_fetch_context,
    const KURL& url) {
  const FetchClientSettingsObject& fetch_client_settings_object =
      worker_fetch_context.GetResourceFetcherProperties()
          .GetFetchClientSettingsObject();
  if (!MixedContentChecker::IsMixedContent(fetch_client_settings_object, url)) {
    return true;
  }

  WorkerSettings* settings = worker_fetch_context.GetWorkerSettings();
  const SecurityOrigin* security_origin =
      fetch_client_settings_object.GetSecurityOrigin();

  bool allowed =
      IsWebSocketAllowedInWorker(worker_fetch_context, settings, url);
  allowed = worker_fetch_context.AllowRunningInsecureContent(allowed, url);

  if (allowed) {
    worker_fetch_context.GetContentSecurityNotifier().NotifyInsecureContentRan(
        KURL(security_origin->ToString()), url);
  }

  worker_fetch_context.GetDetachableConsoleLogger().AddConsoleMessage(
      CreateConsoleMessageAboutWebSocket(worker_fetch_context.Url(), url,
                                         allowed));

  return allowed;
}

bool MixedContentChecker::IsMixedFormAction(
    LocalFrame* frame,
    const KURL& url,
    ReportingDisposition reporting_disposition) {
  // For whatever reason, some folks handle forms via JavaScript, and submit to
  // `javascript:void(0)` rather than calling `preventDefault()`. We
  // special-case `javascript:` URLs here, as they don't introduce MixedContent
  // for form submissions.
  if (url.ProtocolIs("javascript"))
    return false;

  Frame* mixed_frame = InWhichFrameIsContentMixed(frame, url);
  if (!mixed_frame)
    return false;

  UseCounter::Count(frame->GetDocument(), WebFeature::kMixedContentPresent);

  // Use
```