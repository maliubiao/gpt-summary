Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The request asks for an explanation of the code's functionality, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common user/programming errors it might help detect.

2. **Initial Scan and Keyword Identification:**  A quick read reveals keywords like "inspector," "issue," "conversion," "protocol," "Audits," and specific issue types like "CookieIssue," "MixedContentIssue," "CSPIssue," etc. This strongly suggests the code is involved in transforming internal representations of browser issues (likely related to DevTools) into a standardized format for communication.

3. **High-Level Functionality Identification:**  The file name (`inspector_issue_conversion.cc`) and the `ConvertInspectorIssueToProtocolFormat` function immediately point to the core purpose: converting internal `InspectorIssue` objects into a `protocol::Audits::InspectorIssue` format. This format is likely used by the Chrome DevTools to display information about these issues to developers.

4. **Dissecting `ConvertInspectorIssueToProtocolFormat`:**
    * **Input:** It takes an `InspectorIssue*` as input.
    * **Output:** It returns a `std::unique_ptr<protocol::Audits::InspectorIssue>`.
    * **Logic:** The function creates a `protocol::Audits::InspectorIssueDetails` object. It then uses a series of `if` statements to check the type of issue (`cookie_issue_details`, `mixed_content_issue_details`, etc.) and populates the `issueDetails` object accordingly. Each issue type has a corresponding `Build...` function.

5. **Analyzing the `Build...` Helper Functions:** These functions take specific `mojom::blink::...Ptr` types (which seem to be internal Blink representations of issue details) and convert them into the corresponding `protocol::Audits::...` types. The code within these functions is mostly a series of `switch` statements that map internal enum values to their DevTools protocol counterparts.

6. **Identifying Connections to Web Technologies:**
    * **Cookies:**  The `CookieIssueDetails`, `BuildAffectedCookie`, `BuildCookieExclusionReason`, and `BuildCookieWarningReason` clearly relate to how browsers handle cookies, a fundamental part of web development and state management.
    * **Mixed Content:** `MixedContentIssueDetails`, `BuildMixedContentResolutionStatus`, and `BuildMixedContentResourceType` are directly related to the security concept of mixed content (HTTPS pages loading HTTP resources).
    * **Content Security Policy (CSP):** `ContentSecurityPolicyIssueDetails` and `BuildViolationType` deal with CSP, a crucial security mechanism for preventing cross-site scripting attacks.
    * **Blocked Resources:** `BlockedByResponseIssueDetails` and `BuildBlockedByResponseReason` are about resources blocked by the server due to security headers like CORP and COEP.
    * **Low Text Contrast:** `LowTextContrastIssueDetails` directly relates to accessibility guidelines for web content.
    * **SharedArrayBuffer:** `SharedArrayBufferIssueDetails` relates to a JavaScript API for shared memory and potential security concerns around its use.

7. **Considering Logical Reasoning and Assumptions:** The code doesn't perform complex logical *analysis* of the issues themselves. Instead, it focuses on *transforming* existing information. The "reasoning" is in the mapping between the internal data structures and the DevTools protocol. A key assumption is that the input `InspectorIssue` object is correctly populated with accurate information.

8. **Identifying Potential User/Programming Errors:** This code isn't directly *causing* user errors, but it helps *report* them. The identified issues often stem from developer mistakes in:
    * Cookie configuration (e.g., incorrect SameSite settings).
    * Serving mixed content on HTTPS pages.
    * Incorrectly configuring CSP headers.
    * Violating security policies like CORP/COEP.
    * Creating inaccessible content with low text contrast.
    * Improper use of SharedArrayBuffers.

9. **Structuring the Explanation:**  Organize the findings logically:
    * Start with the core function.
    * Explain the helper functions.
    * Detail the connections to web technologies with specific examples.
    * Explain the nature of the logical transformation.
    * Provide examples of user/programming errors detected.

10. **Refinement and Clarity:** Review the explanation for clarity and accuracy. Ensure that technical terms are explained adequately and that the examples are easy to understand. Use formatting (like bullet points) to improve readability.

Self-Correction/Refinement during the process:

* **Initial thought:** Maybe this code *analyzes* the issues.
* **Correction:** No, the code primarily *converts* the *results* of analysis performed elsewhere. The `InspectorIssue` object is assumed to contain the analyzed information.
* **Initial thought:**  Focus solely on the C++ aspects.
* **Correction:** Emphasize the *connection* to web technologies and how the converted data is used in the DevTools, making it relevant to web developers.
* **Initial thought:** Provide overly technical C++ explanations.
* **Correction:** Keep the C++ details focused on the function and data flow, emphasizing the *purpose* rather than the low-level implementation.

By following these steps, we can arrive at a comprehensive and informative explanation of the provided code snippet.
这个C++源代码文件 `inspector_issue_conversion.cc` 的主要功能是将 Blink 引擎内部表示的各种检查器问题（Inspector Issues）转换成与 Chrome DevTools 协议 (CDP - Chrome DevTools Protocol) 中 `Audits.InspectorIssue` 类型相兼容的格式。

简单来说，它就像一个翻译器，将 Blink 内部的错误和警告信息转换成 DevTools 可以理解并展示给开发者的标准格式。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件本身不直接执行 JavaScript, HTML 或 CSS 代码，但它处理的问题 **源于** 这些技术的使用和潜在错误。  它负责将与这些技术相关的违规行为和问题转化为 DevTools 可以理解的报告。

以下是一些与 JavaScript, HTML, CSS 功能相关的例子：

1. **Cookie 问题 (CookieIssue):**
   - **关系:** Cookie 是 Web 开发中用于存储用户信息的常用机制，涉及到 HTTP 响应头和请求头，以及 JavaScript 的 `document.cookie` API。
   - **例子:** 当一个 Cookie 由于 SameSite 属性设置不当，在跨站请求中被阻止时，Blink 内部会产生一个 `CookieIssue`。 `inspector_issue_conversion.cc` 会将这个内部表示转换成 `protocol::Audits::InspectorIssue`，包含被影响的 Cookie 的名称、域、路径、以及被排除或警告的原因（例如 `ExcludeSameSiteNoneInsecure`， `WarnSameSiteUnspecifiedCrossSiteContext`）。
   - **假设输入:** 一个 `mojom::blink::AffectedCookiePtr` 指向一个名为 "my_cookie"，域名为 "example.com"，路径为 "/"，并且由于 `kExcludeSameSiteNoneInsecure` 原因被排除的 Cookie。
   - **输出:** 一个 `protocol::Audits::AffectedCookie` 对象，其 `name` 为 "my_cookie"， `domain` 为 "example.com"， `path` 为 "/"，以及一个包含 `ExcludeSameSiteNoneInsecure` 的 `cookieExclusionReasons` 数组。

2. **混合内容问题 (MixedContentIssue):**
   - **关系:** 当一个 HTTPS 页面加载 HTTP 资源时，就会出现混合内容问题，这是一种安全风险。
   - **例子:** 如果一个 HTTPS 页面尝试加载一个 HTTP 图片 (`<img>` 标签的 `src` 属性是 HTTP URL)，Blink 会检测到 `MixedContentIssue`。 `inspector_issue_conversion.cc` 会将此问题转换为 DevTools 可识别的格式，包括被阻塞的 URL、请求上下文类型（例如 `IMAGE`）、以及解决状态（例如 `MixedContentBlocked`）。
   - **假设输入:** 一个 `mojom::blink::MixedContentIssueDetailsPtr` 指示一个加载了 HTTP 图片资源，其 `insecure_url` 为 "http://insecure.example.com/image.png"，`request_context` 为 `RequestContextType::IMAGE`， `resolution_status` 为 `MixedContentResolutionStatus::kMixedContentBlocked`。
   - **输出:** 一个 `protocol::Audits::MixedContentIssueDetails` 对象，其 `insecureURL` 为 "http://insecure.example.com/image.png"， `resourceType` 为 "Image"， `resolutionStatus` 为 "MixedContentBlocked"。

3. **内容安全策略问题 (ContentSecurityPolicyIssue):**
   - **关系:** CSP 是一种 HTTP 响应头，允许网站声明哪些来源的内容可以被加载，用于防止 XSS 攻击。
   - **例子:** 如果一个网站设置了 CSP，禁止执行内联 JavaScript (`script-src 'self'`), 并且 HTML 中包含一个 `<script>alert('hello');</script>` 标签，Blink 会产生一个 `ContentSecurityPolicyIssue`。 `inspector_issue_conversion.cc` 会将这个违规行为转换成包含违规指令 (`violated_directive` 为 "script-src")、是否为报告模式 (`is_report_only`) 以及违规类型 (`content_security_policy_violation_type` 为 `kInlineViolation`) 的 DevTools 信息。
   - **假设输入:** 一个 `mojom::blink::ContentSecurityPolicyIssueDetailsPtr` 指示一个内联脚本违规， `violated_directive` 为 "script-src"， `is_report_only` 为 false， `content_security_policy_violation_type` 为 `ContentSecurityPolicyViolationType::kInlineViolation`。
   - **输出:** 一个 `protocol::Audits::ContentSecurityPolicyIssueDetails` 对象，其 `violatedDirective` 为 "script-src"， `isReportOnly` 为 false， `contentSecurityPolicyViolationType` 为 "kInlineViolation"。

4. **跨域资源共享 (CORS) 相关问题 (通过 BlockedByResponseIssue 体现):**
   - **关系:** CORS 是一种机制，允许服务器指定哪些来源的跨域请求是被允许的。
   - **例子:** 如果一个网站尝试通过 JavaScript 的 `fetch` API 向另一个域名发送请求，但目标服务器的 CORS 配置不允许该来源的请求，浏览器会阻止该请求，并产生一个 `BlockedByResponseIssue`。 `inspector_issue_conversion.cc` 会将这个信息转换成 DevTools 可以理解的格式，包含被阻止请求的 ID 和被阻止的原因 (`reason` 例如 `CorpNotSameOrigin`)。
   - **假设输入:** 一个 `mojom::blink::BlockedByResponseIssueDetailsPtr` 指示一个由于 CORS 策略 (`CorpNotSameOrigin`) 被阻止的请求， `request` 包含该请求的 `request_id`。
   - **输出:** 一个 `protocol::Audits::BlockedByResponseIssueDetails` 对象，其 `reason` 为 "CorpNotSameOrigin"，并且包含对应请求信息的 `AffectedRequest` 对象。

5. **低文本对比度问题 (LowTextContrastIssue):**
   - **关系:** 这直接关系到 CSS 的颜色属性和网页可访问性。
   - **例子:** 如果页面上的文本颜色和背景颜色对比度过低，不符合 WCAG 标准，Blink 会检测到 `LowTextContrastIssue`。 `inspector_issue_conversion.cc` 会将此问题转换为包含对比度值、阈值、字体大小、字体粗细以及违规节点选择器的信息。
   - **假设输入:** 一个 `mojom::blink::LowTextContrastIssueDetailsPtr` 指示一个低对比度问题， `contrast_ratio` 为 2.5， `threshold_aa` 为 4.5， `violating_node_selector` 为 ".my-text"。
   - **输出:** 一个 `protocol::Audits::LowTextContrastIssueDetails` 对象，其 `contrastRatio` 为 2.5， `thresholdAA` 为 4.5， `violatingNodeSelector` 为 ".my-text"。

**逻辑推理及假设输入与输出:**

此文件主要进行的是数据转换，而不是复杂的逻辑推理。它的逻辑基于 `switch` 语句，根据不同的 `mojom::blink::InspectorIssueCode` 和其他枚举类型，选择正确的 `protocol::Audits` 类型并填充相应的数据。

上述例子中已经给出了假设输入和输出，它们展示了从 Blink 内部数据结构到 DevTools 协议格式的映射。

**涉及用户或编程常见的使用错误:**

`inspector_issue_conversion.cc` 本身不直接涉及用户或编程错误，但它帮助开发者发现这些错误，这些错误通常与以下方面有关：

1. **Cookie 配置错误:**
   - **错误:** 没有正确设置 `SameSite` 属性，导致 Cookie 在跨站场景下被意外阻止或泄露。
   - **DevTools 提示:** "Cookie “…” was blocked because it had the “SameSite=None” attribute but was not secure."

2. **混合内容加载:**
   - **错误:** 在 HTTPS 网站上引用了 HTTP 资源。
   - **DevTools 提示:** "Mixed Content: The page at 'https://example.com/' was loaded over HTTPS, but requested an insecure image 'http://insecure.example.com/image.png'. This request has been blocked; the content must be served over HTTPS."

3. **CSP 配置错误:**
   - **错误:** CSP 指令配置过于严格或不正确，阻止了合法的资源加载或脚本执行。
   - **DevTools 提示:** "Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'self'". Either the 'unsafe-inline' keyword, a hash ('sha256-…'), or a nonce ('nonce-…') is required to enable inline execution."

4. **CORS 配置错误:**
   - **错误:** 后端
Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_issue_conversion.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspector_issue_conversion.h"

#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink-forward.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue.h"
#include "third_party/blink/renderer/core/inspector/protocol/audits.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

std::unique_ptr<protocol::Audits::AffectedCookie> BuildAffectedCookie(
    const mojom::blink::AffectedCookiePtr& cookie) {
  auto protocol_cookie = std::move(protocol::Audits::AffectedCookie::create()
                                       .setName(cookie->name)
                                       .setPath(cookie->path)
                                       .setDomain(cookie->domain));
  return protocol_cookie.build();
}

std::unique_ptr<protocol::Audits::AffectedRequest> BuildAffectedRequest(
    const mojom::blink::AffectedRequestPtr& request) {
  auto protocol_request = protocol::Audits::AffectedRequest::create()
                              .setRequestId(request->request_id)
                              .build();
  if (!request->url.empty()) {
    protocol_request->setUrl(request->url);
  }
  return protocol_request;
}

std::unique_ptr<protocol::Audits::AffectedFrame> BuildAffectedFrame(
    const mojom::blink::AffectedFramePtr& frame) {
  return protocol::Audits::AffectedFrame::create()
      .setFrameId(frame->frame_id)
      .build();
}

blink::protocol::String InspectorIssueCodeValue(
    mojom::blink::InspectorIssueCode code) {
  switch (code) {
    case mojom::blink::InspectorIssueCode::kCookieIssue:
      return protocol::Audits::InspectorIssueCodeEnum::CookieIssue;
    case mojom::blink::InspectorIssueCode::kMixedContentIssue:
      return protocol::Audits::InspectorIssueCodeEnum::MixedContentIssue;
    case mojom::blink::InspectorIssueCode::kBlockedByResponseIssue:
      return protocol::Audits::InspectorIssueCodeEnum::BlockedByResponseIssue;
    case mojom::blink::InspectorIssueCode::kContentSecurityPolicyIssue:
      return protocol::Audits::InspectorIssueCodeEnum::
          ContentSecurityPolicyIssue;
    case mojom::blink::InspectorIssueCode::kSharedArrayBufferIssue:
      return protocol::Audits::InspectorIssueCodeEnum::SharedArrayBufferIssue;
    case mojom::blink::InspectorIssueCode::kLowTextContrastIssue:
      return protocol::Audits::InspectorIssueCodeEnum::LowTextContrastIssue;
    case mojom::blink::InspectorIssueCode::kHeavyAdIssue:
    case mojom::blink::InspectorIssueCode::kFederatedAuthRequestIssue:
    case mojom::blink::InspectorIssueCode::kFederatedAuthUserInfoRequestIssue:
    case mojom::blink::InspectorIssueCode::kBounceTrackingIssue:
    case mojom::blink::InspectorIssueCode::kCookieDeprecationMetadataIssue:
    case mojom::blink::InspectorIssueCode::kGenericIssue:
    case mojom::blink::InspectorIssueCode::kDeprecationIssue:
    case mojom::blink::InspectorIssueCode::kAttributionReportingIssue:
      NOTREACHED();
  }
}

protocol::String BuildCookieExclusionReason(
    mojom::blink::CookieExclusionReason exclusion_reason) {
  switch (exclusion_reason) {
    case blink::mojom::blink::CookieExclusionReason::
        kExcludeSameSiteUnspecifiedTreatedAsLax:
      return protocol::Audits::CookieExclusionReasonEnum::
          ExcludeSameSiteUnspecifiedTreatedAsLax;
    case blink::mojom::blink::CookieExclusionReason::
        kExcludeSameSiteNoneInsecure:
      return protocol::Audits::CookieExclusionReasonEnum::
          ExcludeSameSiteNoneInsecure;
    case blink::mojom::blink::CookieExclusionReason::kExcludeSameSiteLax:
      return protocol::Audits::CookieExclusionReasonEnum::ExcludeSameSiteLax;
    case blink::mojom::blink::CookieExclusionReason::kExcludeSameSiteStrict:
      return protocol::Audits::CookieExclusionReasonEnum::ExcludeSameSiteStrict;
    case blink::mojom::blink::CookieExclusionReason::kExcludeDomainNonASCII:
      return protocol::Audits::CookieExclusionReasonEnum::ExcludeDomainNonASCII;
    case blink::mojom::blink::CookieExclusionReason::kExcludeThirdPartyPhaseout:
      return protocol::Audits::CookieExclusionReasonEnum::
          ExcludeThirdPartyPhaseout;
    case blink::mojom::blink::CookieExclusionReason::kExcludePortMismatch:
      return protocol::Audits::CookieExclusionReasonEnum::ExcludePortMismatch;
    case blink::mojom::blink::CookieExclusionReason::kExcludeSchemeMismatch:
      return protocol::Audits::CookieExclusionReasonEnum::ExcludeSchemeMismatch;
  }
}

std::unique_ptr<std::vector<blink::protocol::String>>
BuildCookieExclusionReasons(
    const WTF::Vector<mojom::blink::CookieExclusionReason>& exclusion_reasons) {
  auto protocol_exclusion_reasons =
      std::make_unique<std::vector<blink::protocol::String>>();
  for (const auto& reason : exclusion_reasons) {
    protocol_exclusion_reasons->push_back(BuildCookieExclusionReason(reason));
  }
  return protocol_exclusion_reasons;
}

protocol::String BuildCookieWarningReason(
    mojom::blink::CookieWarningReason warning_reason) {
  switch (warning_reason) {
    case blink::mojom::blink::CookieWarningReason::
        kWarnSameSiteUnspecifiedCrossSiteContext:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnSameSiteUnspecifiedCrossSiteContext;
    case blink::mojom::blink::CookieWarningReason::kWarnSameSiteNoneInsecure:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnSameSiteNoneInsecure;
    case blink::mojom::blink::CookieWarningReason::
        kWarnSameSiteUnspecifiedLaxAllowUnsafe:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnSameSiteUnspecifiedLaxAllowUnsafe;
    case blink::mojom::blink::CookieWarningReason::
        kWarnSameSiteStrictLaxDowngradeStrict:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnSameSiteStrictLaxDowngradeStrict;
    case blink::mojom::blink::CookieWarningReason::
        kWarnSameSiteStrictCrossDowngradeStrict:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnSameSiteStrictCrossDowngradeStrict;
    case blink::mojom::blink::CookieWarningReason::
        kWarnSameSiteStrictCrossDowngradeLax:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnSameSiteStrictCrossDowngradeLax;
    case blink::mojom::blink::CookieWarningReason::
        kWarnSameSiteLaxCrossDowngradeStrict:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnSameSiteLaxCrossDowngradeStrict;
    case blink::mojom::blink::CookieWarningReason::
        kWarnSameSiteLaxCrossDowngradeLax:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnSameSiteLaxCrossDowngradeLax;
    case blink::mojom::blink::CookieWarningReason::
        kWarnAttributeValueExceedsMaxSize:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnAttributeValueExceedsMaxSize;
    case blink::mojom::blink::CookieWarningReason::kWarnDomainNonASCII:
      return protocol::Audits::CookieWarningReasonEnum::WarnDomainNonASCII;
    case blink::mojom::blink::CookieWarningReason::kWarnThirdPartyPhaseout:
      return protocol::Audits::CookieWarningReasonEnum::WarnThirdPartyPhaseout;
    case blink::mojom::blink::CookieWarningReason::
        kWarnCrossSiteRedirectDowngradeChangesInclusion:
      return protocol::Audits::CookieWarningReasonEnum::
          WarnCrossSiteRedirectDowngradeChangesInclusion;
  }
}

std::unique_ptr<std::vector<blink::protocol::String>> BuildCookieWarningReasons(
    const WTF::Vector<mojom::blink::CookieWarningReason>& warning_reasons) {
  auto protocol_warning_reasons =
      std::make_unique<std::vector<blink::protocol::String>>();
  for (const auto& reason : warning_reasons) {
    protocol_warning_reasons->push_back(BuildCookieWarningReason(reason));
  }
  return protocol_warning_reasons;
}
protocol::String BuildCookieOperation(mojom::blink::CookieOperation operation) {
  switch (operation) {
    case blink::mojom::blink::CookieOperation::kSetCookie:
      return protocol::Audits::CookieOperationEnum::SetCookie;
    case blink::mojom::blink::CookieOperation::kReadCookie:
      return protocol::Audits::CookieOperationEnum::ReadCookie;
  }
}

protocol::String BuildMixedContentResolutionStatus(
    mojom::blink::MixedContentResolutionStatus resolution_type) {
  switch (resolution_type) {
    case blink::mojom::blink::MixedContentResolutionStatus::
        kMixedContentBlocked:
      return protocol::Audits::MixedContentResolutionStatusEnum::
          MixedContentBlocked;
    case blink::mojom::blink::MixedContentResolutionStatus::
        kMixedContentAutomaticallyUpgraded:
      return protocol::Audits::MixedContentResolutionStatusEnum::
          MixedContentAutomaticallyUpgraded;
    case blink::mojom::blink::MixedContentResolutionStatus::
        kMixedContentWarning:
      return protocol::Audits::MixedContentResolutionStatusEnum::
          MixedContentWarning;
  }
}

protocol::String BuildMixedContentResourceType(
    mojom::blink::RequestContextType request_context) {
  switch (request_context) {
    case mojom::blink::RequestContextType::ATTRIBUTION_SRC:
      return protocol::Audits::MixedContentResourceTypeEnum::AttributionSrc;
    case blink::mojom::blink::RequestContextType::AUDIO:
      return protocol::Audits::MixedContentResourceTypeEnum::Audio;
    case blink::mojom::blink::RequestContextType::BEACON:
      return protocol::Audits::MixedContentResourceTypeEnum::Beacon;
    case blink::mojom::blink::RequestContextType::CSP_REPORT:
      return protocol::Audits::MixedContentResourceTypeEnum::CSPReport;
    case blink::mojom::blink::RequestContextType::DOWNLOAD:
      return protocol::Audits::MixedContentResourceTypeEnum::Download;
    case blink::mojom::blink::RequestContextType::EMBED:
      return protocol::Audits::MixedContentResourceTypeEnum::PluginResource;
    case blink::mojom::blink::RequestContextType::EVENT_SOURCE:
      return protocol::Audits::MixedContentResourceTypeEnum::EventSource;
    case blink::mojom::blink::RequestContextType::FAVICON:
      return protocol::Audits::MixedContentResourceTypeEnum::Favicon;
    case blink::mojom::blink::RequestContextType::FETCH:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case blink::mojom::blink::RequestContextType::FONT:
      return protocol::Audits::MixedContentResourceTypeEnum::Font;
    case blink::mojom::blink::RequestContextType::FORM:
      return protocol::Audits::MixedContentResourceTypeEnum::Form;
    case blink::mojom::blink::RequestContextType::FRAME:
      return protocol::Audits::MixedContentResourceTypeEnum::Frame;
    case blink::mojom::blink::RequestContextType::HYPERLINK:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case blink::mojom::blink::RequestContextType::IFRAME:
      return protocol::Audits::MixedContentResourceTypeEnum::Frame;
    case blink::mojom::blink::RequestContextType::IMAGE:
      return protocol::Audits::MixedContentResourceTypeEnum::Image;
    case blink::mojom::blink::RequestContextType::IMAGE_SET:
      return protocol::Audits::MixedContentResourceTypeEnum::Image;
    case blink::mojom::blink::RequestContextType::INTERNAL:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case blink::mojom::blink::RequestContextType::JSON:
      // TODO(crbug.com/1511738): Consider adding a type
      // specific to JSON modules requests
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case blink::mojom::blink::RequestContextType::LOCATION:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case blink::mojom::blink::RequestContextType::MANIFEST:
      return protocol::Audits::MixedContentResourceTypeEnum::Manifest;
    case blink::mojom::blink::RequestContextType::OBJECT:
      return protocol::Audits::MixedContentResourceTypeEnum::PluginResource;
    case blink::mojom::blink::RequestContextType::PING:
      return protocol::Audits::MixedContentResourceTypeEnum::Ping;
    case blink::mojom::blink::RequestContextType::PLUGIN:
      return protocol::Audits::MixedContentResourceTypeEnum::PluginData;
    case blink::mojom::blink::RequestContextType::PREFETCH:
      return protocol::Audits::MixedContentResourceTypeEnum::Prefetch;
    case blink::mojom::blink::RequestContextType::SCRIPT:
      return protocol::Audits::MixedContentResourceTypeEnum::Script;
    case blink::mojom::blink::RequestContextType::SERVICE_WORKER:
      return protocol::Audits::MixedContentResourceTypeEnum::ServiceWorker;
    case blink::mojom::blink::RequestContextType::SHARED_WORKER:
      return protocol::Audits::MixedContentResourceTypeEnum::SharedWorker;
    case blink::mojom::blink::RequestContextType::SPECULATION_RULES:
      return protocol::Audits::MixedContentResourceTypeEnum::SpeculationRules;
    case blink::mojom::blink::RequestContextType::STYLE:
      return protocol::Audits::MixedContentResourceTypeEnum::Stylesheet;
    case blink::mojom::blink::RequestContextType::SUBRESOURCE:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case blink::mojom::blink::RequestContextType::SUBRESOURCE_WEBBUNDLE:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case blink::mojom::blink::RequestContextType::TRACK:
      return protocol::Audits::MixedContentResourceTypeEnum::Track;
    case blink::mojom::blink::RequestContextType::UNSPECIFIED:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case blink::mojom::blink::RequestContextType::VIDEO:
      return protocol::Audits::MixedContentResourceTypeEnum::Video;
    case blink::mojom::blink::RequestContextType::WORKER:
      return protocol::Audits::MixedContentResourceTypeEnum::Worker;
    case blink::mojom::blink::RequestContextType::XML_HTTP_REQUEST:
      return protocol::Audits::MixedContentResourceTypeEnum::XMLHttpRequest;
    case blink::mojom::blink::RequestContextType::XSLT:
      return protocol::Audits::MixedContentResourceTypeEnum::XSLT;
  }
}

protocol::String BuildBlockedByResponseReason(
    network::mojom::blink::BlockedByResponseReason reason) {
  switch (reason) {
    case network::mojom::blink::BlockedByResponseReason::
        kCoepFrameResourceNeedsCoepHeader:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CoepFrameResourceNeedsCoepHeader;
    case network::mojom::blink::BlockedByResponseReason::
        kCoopSandboxedIFrameCannotNavigateToCoopPage:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CoopSandboxedIFrameCannotNavigateToCoopPage;
    case network::mojom::blink::BlockedByResponseReason::kCorpNotSameOrigin:
      return protocol::Audits::BlockedByResponseReasonEnum::CorpNotSameOrigin;
    case network::mojom::blink::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoep:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByCoep;
    case network::mojom::blink::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByDip:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByDip;
    case network::mojom::blink::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip;
    case network::mojom::blink::BlockedByResponseReason::kCorpNotSameSite:
      return protocol::Audits::BlockedByResponseReasonEnum::CorpNotSameSite;
  }
}

protocol::String BuildViolationType(
    mojom::blink::ContentSecurityPolicyViolationType violation_type) {
  switch (violation_type) {
    case blink::mojom::blink::ContentSecurityPolicyViolationType::
        kInlineViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KInlineViolation;
    case blink::mojom::blink::ContentSecurityPolicyViolationType::
        kEvalViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KEvalViolation;
    case blink::mojom::blink::ContentSecurityPolicyViolationType::
        kWasmEvalViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KWasmEvalViolation;
    case blink::mojom::blink::ContentSecurityPolicyViolationType::kURLViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KURLViolation;
    case blink::mojom::blink::ContentSecurityPolicyViolationType::
        kTrustedTypesSinkViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KTrustedTypesSinkViolation;
    case blink::mojom::blink::ContentSecurityPolicyViolationType::
        kTrustedTypesPolicyViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KTrustedTypesPolicyViolation;
  }
}

protocol::String BuildSABIssueType(
    blink::mojom::blink::SharedArrayBufferIssueType type) {
  switch (type) {
    case blink::mojom::blink::SharedArrayBufferIssueType::kTransferIssue:
      return protocol::Audits::SharedArrayBufferIssueTypeEnum::TransferIssue;
    case blink::mojom::blink::SharedArrayBufferIssueType::kCreationIssue:
      return protocol::Audits::SharedArrayBufferIssueTypeEnum::CreationIssue;
  }
}

std::unique_ptr<protocol::Audits::SourceCodeLocation> BuildAffectedLocation(
    const blink::mojom::blink::AffectedLocationPtr& affected_location) {
  auto protocol_affected_location =
      protocol::Audits::SourceCodeLocation::create()
          .setUrl(affected_location->url)
          .setColumnNumber(affected_location->column)
          .setLineNumber(affected_location->line)
          .build();
  if (!affected_location->script_id.empty())
    protocol_affected_location->setScriptId(affected_location->script_id);
  return protocol_affected_location;
}

}  // namespace

std::unique_ptr<protocol::Audits::InspectorIssue>
ConvertInspectorIssueToProtocolFormat(InspectorIssue* issue) {
  auto issueDetails = protocol::Audits::InspectorIssueDetails::create();

  if (issue->Details()->cookie_issue_details) {
    const auto* d = issue->Details()->cookie_issue_details.get();
    auto cookieDetails =
        std::move(protocol::Audits::CookieIssueDetails::create()
                      .setCookie(BuildAffectedCookie(d->cookie))
                      .setCookieExclusionReasons(
                          BuildCookieExclusionReasons(d->exclusion_reason))
                      .setCookieWarningReasons(
                          BuildCookieWarningReasons(d->warning_reason))
                      .setOperation(BuildCookieOperation(d->operation)));

    if (d->site_for_cookies) {
      cookieDetails.setSiteForCookies(*d->site_for_cookies);
    }
    if (d->cookie_url) {
      cookieDetails.setCookieUrl(*d->cookie_url);
    }
    if (d->request) {
      cookieDetails.setRequest(BuildAffectedRequest(d->request));
    }
    issueDetails.setCookieIssueDetails(cookieDetails.build());
  }

  if (issue->Details()->mixed_content_issue_details) {
    const auto* d = issue->Details()->mixed_content_issue_details.get();
    auto mixedContentDetails =
        protocol::Audits::MixedContentIssueDetails::create()
            .setResourceType(BuildMixedContentResourceType(d->request_context))
            .setResolutionStatus(
                BuildMixedContentResolutionStatus(d->resolution_status))
            .setInsecureURL(d->insecure_url)
            .setMainResourceURL(d->main_resource_url)
            .build();
    if (d->request) {
      mixedContentDetails->setRequest(BuildAffectedRequest(d->request));
    }
    if (d->frame) {
      mixedContentDetails->setFrame(BuildAffectedFrame(d->frame));
    }
    issueDetails.setMixedContentIssueDetails(std::move(mixedContentDetails));
  }

  if (issue->Details()->blocked_by_response_issue_details) {
    const auto* d = issue->Details()->blocked_by_response_issue_details.get();
    auto blockedByResponseDetails =
        protocol::Audits::BlockedByResponseIssueDetails::create()
            .setRequest(BuildAffectedRequest(d->request))
            .setReason(BuildBlockedByResponseReason(d->reason))
            .build();
    if (d->parentFrame) {
      blockedByResponseDetails->setParentFrame(
          BuildAffectedFrame(d->parentFrame));
    }
    if (d->blockedFrame) {
      blockedByResponseDetails->setBlockedFrame(
          BuildAffectedFrame(d->blockedFrame));
    }
    issueDetails.setBlockedByResponseIssueDetails(
        std::move(blockedByResponseDetails));
  }

  if (issue->Details()->csp_issue_details) {
    const auto* d = issue->Details()->csp_issue_details.get();
    auto cspDetails =
        std::move(protocol::Audits::ContentSecurityPolicyIssueDetails::create()
                      .setViolatedDirective(d->violated_directive)
                      .setIsReportOnly(d->is_report_only)
                      .setContentSecurityPolicyViolationType(BuildViolationType(
                          d->content_security_policy_violation_type)));
    if (d->blocked_url) {
      cspDetails.setBlockedURL(*d->blocked_url);
    }
    if (d->frame_ancestor)
      cspDetails.setFrameAncestor(BuildAffectedFrame(d->frame_ancestor));
    if (d->affected_location) {
      cspDetails.setSourceCodeLocation(
          BuildAffectedLocation(d->affected_location));
    }
    if (d->violating_node_id)
      cspDetails.setViolatingNodeId(d->violating_node_id);
    issueDetails.setContentSecurityPolicyIssueDetails(cspDetails.build());
  }

  if (issue->Details()->sab_issue_details) {
    const auto* d = issue->Details()->sab_issue_details.get();
    auto details =
        protocol::Audits::SharedArrayBufferIssueDetails::create()
            .setIsWarning(d->is_warning)
            .setType(BuildSABIssueType(d->type))
            .setSourceCodeLocation(BuildAffectedLocation(d->affected_location))
            .build();
    issueDetails.setSharedArrayBufferIssueDetails(std::move(details));
  }

  if (issue->Details()->low_text_contrast_details) {
    const auto* d = issue->Details()->low_text_contrast_details.get();
    auto lowContrastDetails =
        protocol::Audits::LowTextContrastIssueDetails::create()
            .setThresholdAA(d->threshold_aa)
            .setThresholdAAA(d->threshold_aaa)
            .setFontSize(d->font_size)
            .setFontWeight(d->font_weight)
            .setContrastRatio(d->contrast_ratio)
            .setViolatingNodeSelector(d->violating_node_selector)
            .setViolatingNodeId(d->violating_node_id)
            .build();
    issueDetails.setLowTextContrastIssueDetails(std::move(lowContrastDetails));
  }

  auto final_issue = protocol::Audits::InspectorIssue::create()
                         .setCode(InspectorIssueCodeValue(issue->Code()))
                         .setDetails(issueDetails.build())
                         .build();
  if (issue->Details()->issue_id) {
    String issue_id = String::FromUTF8(issue->Details()->issue_id->ToString());
    final_issue->setIssueId(issue_id);
  }
  return final_issue;
}

}  // namespace blink

"""

```