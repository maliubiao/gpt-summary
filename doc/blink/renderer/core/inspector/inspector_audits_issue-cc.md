Response:
The user wants to understand the functionality of the `inspector_audits_issue.cc` file in the Chromium Blink engine. This file seems to be responsible for creating and reporting issues found during auditing, likely for the DevTools "Issues" panel.

Here's a breakdown of how to approach this:

1. **Core Functionality:** Identify the central purpose of the file. It's about reporting different types of issues.
2. **Issue Types:**  Look for methods that create specific types of issues. The code uses enums like `InspectorIssueCodeEnum` to categorize them.
3. **Data Structures:** Observe how issue details are structured using `protocol::Audits` types.
4. **Relationships to Web Technologies:** Analyze if any of the reported issues are directly related to JavaScript, HTML, or CSS.
5. **Logic and Transformations:**  Check for functions that convert internal representations (like `RendererCorsIssueCode`) to protocol-level representations.
6. **User/Programming Errors:**  Consider what kind of mistakes these audit issues might highlight.
7. **Input/Output Examples:**  For some specific issue types, think about potential triggers and the resulting reported information.
```
功能归纳：
```

`inspector_audits_issue.cc` 文件的主要功能是**创建和报告各种类型的与网页开发相关的审计问题**，这些问题会被发送到 Chrome 开发者工具的 "Issues" 面板进行展示。它提供了一系列静态方法，用于根据不同的场景和错误类型生成相应的 `protocol::Audits::InspectorIssue` 对象。

**更具体地说，该文件负责：**

1. **定义 `AuditsIssue` 类:**  这是一个用于封装 `protocol::Audits::InspectorIssue` 对象的类，方便在 Blink 内部使用。
2. **创建特定类型的审计问题:**  该文件包含多个静态方法，用于创建不同类型的审计问题，例如：
    * **Quirks Mode Issue (怪异模式问题):**  当页面以 Quirks Mode 或 Limited Quirks Mode 渲染时报告。
    * **CORS Issue (跨域资源共享问题):** 当发生 CORS 错误时报告。
    * **Attribution Reporting Issue (归因报告问题):**  当归因报告 API 的使用出现问题时报告。
    * **SharedArrayBuffer Issue (共享数组缓冲区问题):** 当使用 SharedArrayBuffer 出现问题时报告。
    * **Deprecation Issue (废弃问题):**  当使用了已废弃的 API 或功能时报告。
    * **Client Hint Issue (客户端提示问题):**  当客户端提示配置不正确时报告。
    * **Blocked by Response Issue (响应被阻止问题):** 当请求因 COEP/COOP/CORP 等策略被阻止时报告。
    * **Mixed Content Issue (混合内容问题):** 当 HTTPS 页面加载 HTTP 资源时报告。
    * **Generic Issue (通用问题):**  用于报告一些无法归类到其他特定类型的问题，通常与表单可访问性相关。
    * **Property Rule Issue (属性规则问题):**  当 CSS 属性规则存在潜在问题时报告。
    * **Stylesheet Loading Issue (样式表加载问题):** 当样式表加载存在问题时报告，例如使用 `@import` 但位置靠后。
3. **将 Blink 内部数据转换为 DevTools 协议格式:**  这些方法接收 Blink 内部的数据结构（例如 `ExecutionContext`, `Element`, `ResourceError` 等），并将其转换为符合 DevTools 协议 (`protocol::Audits`) 的格式，以便发送到开发者工具。
4. **关联问题与源代码位置:**  许多方法会尝试获取导致问题的源代码位置（URL、行号、列号），并将其包含在报告中。
5. **关联问题与网络请求和帧:**  对于与网络请求相关的问题（如 CORS、混合内容、阻止问题），会包含相关的请求 ID 和帧 ID。
6. **管理 `InspectorIssue` 对象的生命周期:** `AuditsIssue` 类负责持有和转移 `protocol::Audits::InspectorIssue` 对象的所有权。

**与 JavaScript, HTML, CSS 功能的关系举例说明：**

* **JavaScript:**
    * **Deprecation Issue:**  如果 JavaScript 代码中使用了 `document.all` (一个已废弃的 API)，`ReportDeprecationIssue` 方法会被调用，报告该 API 的使用。
        * **假设输入:**  在 JavaScript 代码中使用了 `document.all`。
        * **输出:**  一个 Deprecation Issue 会在开发者工具中显示，指明 `document.all` 已废弃以及其在代码中的位置。
    * **SharedArrayBuffer Issue:** 如果 JavaScript 代码尝试在不允许的情况下传输 SharedArrayBuffer，`ReportSharedArrayBufferIssue` 方法会被调用。
        * **假设输入:**  尝试在一个没有正确配置的跨域上下文中传输 SharedArrayBuffer。
        * **输出:**  一个 SharedArrayBuffer Issue 会在开发者工具中显示，提示传输失败的原因和代码位置。
* **HTML:**
    * **Quirks Mode Issue:** 如果 HTML 文档缺少 `<!DOCTYPE html>` 或存在其他导致浏览器进入怪异模式的因素，`ReportQuirksModeIssue` 方法会被调用。
        * **假设输入:**  一个 HTML 文件内容为 `<html><head><title>Test</title></head><body>Hello</body></html>` (缺少 `<!DOCTYPE html>`)。
        * **输出:**  一个 Quirks Mode Issue 会在开发者工具中显示，指示页面正在以怪异模式渲染。
    * **Generic Issue (Form Accessibility):**  如果 HTML 表单中的 `<label>` 标签的 `for` 属性指向一个不存在的输入元素的 `id`，`ReportGenericIssue` 会被调用。
        * **假设输入:**  HTML 代码片段 `<label for="nonexistent">Label</label><input type="text" id="myInput">`。
        * **输出:**  一个 Generic Issue 会在开发者工具中显示，提示 "Form label with 'for' attribute matching no existing input id"。
* **CSS:**
    * **Property Rule Issue:**  如果 CSS 中使用了不推荐或有潜在风险的属性值，`ReportPropertyRuleIssue` 可能会被调用。 例如，使用了 `zoom: 5;`。
        * **假设输入:**  CSS 样式规则 `body { zoom: 5; }`。
        * **输出:**  一个 Property Rule Issue 会在开发者工具中显示，说明 `zoom` 属性可能存在的问题。
    * **Stylesheet Loading Late Import Issue:** 如果 CSS 中使用了 `@import` 规则，但该规则出现在其他样式声明之后，`ReportStylesheetLoadingLateImportIssue` 会被调用。
        * **假设输入:**  CSS 文件内容：`body { color: black; } @import "other.css";`
        * **输出:**  一个 Stylesheet Loading Issue 会在开发者工具中显示，提示 `@import` 规则应该放在最前面。

**涉及用户或编程常见的使用错误举例说明：**

* **CORS Issue:** 开发者忘记在服务器端设置正确的 CORS 头，导致跨域请求失败。
    * **场景:**  前端 JavaScript 代码尝试使用 `fetch` 或 `XMLHttpRequest` 从另一个域名请求数据，但服务器没有返回 `Access-Control-Allow-Origin` 头。
    * **报告:**  `ReportCorsIssue` 会被调用，开发者工具的 "Issues" 面板会显示 CORS 错误信息，包括请求 URL 和错误原因。
* **Mixed Content Issue:**  开发者在 HTTPS 网站中嵌入了来自 HTTP 地址的图片或脚本。
    * **场景:**  一个网站使用 `https://example.com`，但在页面中使用了 `<img src="http://other.com/image.png">`。
    * **报告:** `ReportMixedContentIssue` 会被调用，开发者工具会显示混合内容警告或错误，指出不安全的资源 URL。
* **Attribution Reporting Issue:**  开发者错误地配置了归因报告相关的 HTTP 头或 JavaScript API 调用。
    * **场景:**  `Attribution-Reporting-Register-Source` 头的格式不正确。
    * **报告:** `ReportAttributionIssue` 会被调用，开发者工具会显示归因报告配置错误的信息。

总而言之，`inspector_audits_issue.cc` 是 Blink 引擎中一个至关重要的组成部分，它负责将各种网页开发问题以结构化的方式报告给开发者，帮助他们调试和优化网页。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_audits_issue.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"

#include "base/unguessable_token.h"
#include "services/network/public/mojom/blocked_by_response_reason.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_security_policy_violation_event_init.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/protocol/audits.h"
#include "third_party/blink/renderer/core/inspector/protocol/network.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"

namespace blink {

AuditsIssue::AuditsIssue(
    std::unique_ptr<protocol::Audits::InspectorIssue> issue)
    : issue_(std::move(issue)) {}

AuditsIssue::AuditsIssue(AuditsIssue&&) = default;
AuditsIssue& AuditsIssue::operator=(AuditsIssue&&) = default;
AuditsIssue::~AuditsIssue() = default;

std::unique_ptr<protocol::Audits::InspectorIssue> AuditsIssue::TakeIssue() {
  return std::move(issue_);
}

void AuditsIssue::ReportQuirksModeIssue(ExecutionContext* execution_context,
                                        bool isLimitedQuirksMode,
                                        DOMNodeId document_node_id,
                                        String url,
                                        String frame_id,
                                        String loader_id) {
  auto quirks_mode_issue_details =
      protocol::Audits::QuirksModeIssueDetails::create()
          .setIsLimitedQuirksMode(isLimitedQuirksMode)
          .setDocumentNodeId(document_node_id)
          .setUrl(url)
          .setFrameId(frame_id)
          .setLoaderId(loader_id)
          .build();

  auto details =
      protocol::Audits::InspectorIssueDetails::create()
          .setQuirksModeIssueDetails(std::move(quirks_mode_issue_details))
          .build();

  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(protocol::Audits::InspectorIssueCodeEnum::QuirksModeIssue)
          .setDetails(std::move(details))
          .build();
  execution_context->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

namespace {

protocol::Network::CorsError RendererCorsIssueCodeToProtocol(
    RendererCorsIssueCode code) {
  switch (code) {
    case RendererCorsIssueCode::kCorsDisabledScheme:
      return protocol::Network::CorsErrorEnum::CorsDisabledScheme;
    case RendererCorsIssueCode::kNoCorsRedirectModeNotFollow:
      return protocol::Network::CorsErrorEnum::NoCorsRedirectModeNotFollow;
    case RendererCorsIssueCode::kDisallowedByMode:
      return protocol::Network::CorsErrorEnum::DisallowedByMode;
  }
}
}  // namespace

std::unique_ptr<protocol::Audits::SourceCodeLocation> CreateProtocolLocation(
    const SourceLocation& location) {
  auto protocol_location = protocol::Audits::SourceCodeLocation::create()
                               .setUrl(location.Url())
                               .setLineNumber(location.LineNumber() - 1)
                               .setColumnNumber(location.ColumnNumber())
                               .build();
  if (location.ScriptId()) {
    protocol_location->setScriptId(WTF::String::Number(location.ScriptId()));
  }
  return protocol_location;
}

protocol::Audits::GenericIssueErrorType
AuditsIssue::GenericIssueErrorTypeToProtocol(
    mojom::blink::GenericIssueErrorType error_type) {
  switch (error_type) {
    case mojom::blink::GenericIssueErrorType::kFormLabelForNameError:
      return protocol::Audits::GenericIssueErrorTypeEnum::FormLabelForNameError;
    case mojom::blink::GenericIssueErrorType::kFormDuplicateIdForInputError:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormDuplicateIdForInputError;
    case mojom::blink::GenericIssueErrorType::kFormInputWithNoLabelError:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormInputWithNoLabelError;
    case mojom::blink::GenericIssueErrorType::
        kFormAutocompleteAttributeEmptyError:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormAutocompleteAttributeEmptyError;
    case mojom::blink::GenericIssueErrorType::
        kFormEmptyIdAndNameAttributesForInputError:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormEmptyIdAndNameAttributesForInputError;
    case mojom::blink::GenericIssueErrorType::
        kFormAriaLabelledByToNonExistingId:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormAriaLabelledByToNonExistingId;
    case mojom::blink::GenericIssueErrorType::
        kFormInputAssignedAutocompleteValueToIdOrNameAttributeError:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormInputAssignedAutocompleteValueToIdOrNameAttributeError;
    case mojom::blink::GenericIssueErrorType::
        kFormLabelHasNeitherForNorNestedInput:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormLabelHasNeitherForNorNestedInput;
    case mojom::blink::GenericIssueErrorType::
        kFormLabelForMatchesNonExistingIdError:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormLabelForMatchesNonExistingIdError;
    case mojom::blink::GenericIssueErrorType::
        kFormInputHasWrongButWellIntendedAutocompleteValueError:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          FormInputHasWrongButWellIntendedAutocompleteValueError;
    case mojom::blink::GenericIssueErrorType::kResponseWasBlockedByORB:
      return protocol::Audits::GenericIssueErrorTypeEnum::
          ResponseWasBlockedByORB;
  }
}

void AuditsIssue::ReportCorsIssue(
    ExecutionContext* execution_context,
    int64_t identifier,
    RendererCorsIssueCode code,
    String url,
    String initiator_origin,
    String failedParameter,
    std::optional<base::UnguessableToken> issue_id) {
  String devtools_request_id =
      IdentifiersFactory::SubresourceRequestId(identifier);
  std::unique_ptr<protocol::Audits::AffectedRequest> affected_request =
      protocol::Audits::AffectedRequest::create()
          .setRequestId(devtools_request_id)
          .setUrl(url)
          .build();
  auto protocol_cors_error_status =
      protocol::Network::CorsErrorStatus::create()
          .setCorsError(RendererCorsIssueCodeToProtocol(code))
          .setFailedParameter(failedParameter)
          .build();
  auto cors_issue_details =
      protocol::Audits::CorsIssueDetails::create()
          .setIsWarning(false)
          .setRequest(std::move(affected_request))
          .setCorsErrorStatus(std::move(protocol_cors_error_status))
          .build();
  cors_issue_details->setInitiatorOrigin(initiator_origin);
  auto location = CaptureSourceLocation(execution_context);
  if (location) {
    cors_issue_details->setLocation(CreateProtocolLocation(*location));
  }
  auto details = protocol::Audits::InspectorIssueDetails::create()
                     .setCorsIssueDetails(std::move(cors_issue_details))
                     .build();
  auto issue = protocol::Audits::InspectorIssue::create()
                   .setCode(protocol::Audits::InspectorIssueCodeEnum::CorsIssue)
                   .setDetails(std::move(details))
                   .build();
  if (issue_id) {
    issue->setIssueId(IdentifiersFactory::IdFromToken(*issue_id));
  }
  execution_context->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

namespace {

using mojom::blink::AttributionReportingIssueType;

protocol::Audits::AttributionReportingIssueType
BuildAttributionReportingIssueType(AttributionReportingIssueType type) {
  switch (type) {
    case AttributionReportingIssueType::kPermissionPolicyDisabled:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          PermissionPolicyDisabled;
    case AttributionReportingIssueType::kUntrustworthyReportingOrigin:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          UntrustworthyReportingOrigin;
    case AttributionReportingIssueType::kInsecureContext:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          InsecureContext;
    case AttributionReportingIssueType::kInvalidRegisterSourceHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::InvalidHeader;
    case AttributionReportingIssueType::kInvalidRegisterTriggerHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          InvalidRegisterTriggerHeader;
    case AttributionReportingIssueType::kSourceAndTriggerHeaders:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          SourceAndTriggerHeaders;
    case AttributionReportingIssueType::kSourceIgnored:
      return protocol::Audits::AttributionReportingIssueTypeEnum::SourceIgnored;
    case AttributionReportingIssueType::kTriggerIgnored:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          TriggerIgnored;
    case AttributionReportingIssueType::kOsSourceIgnored:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          OsSourceIgnored;
    case AttributionReportingIssueType::kOsTriggerIgnored:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          OsTriggerIgnored;
    case AttributionReportingIssueType::kInvalidRegisterOsSourceHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          InvalidRegisterOsSourceHeader;
    case AttributionReportingIssueType::kInvalidRegisterOsTriggerHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          InvalidRegisterOsTriggerHeader;
    case AttributionReportingIssueType::kWebAndOsHeaders:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          WebAndOsHeaders;
    case AttributionReportingIssueType::kNoWebOrOsSupport:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          NoWebOrOsSupport;
    case AttributionReportingIssueType::
        kNavigationRegistrationWithoutTransientUserActivation:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          NavigationRegistrationWithoutTransientUserActivation;
    case AttributionReportingIssueType::kInvalidInfoHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          InvalidInfoHeader;
    case AttributionReportingIssueType::kNoRegisterSourceHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          NoRegisterSourceHeader;
    case AttributionReportingIssueType::kNoRegisterTriggerHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          NoRegisterTriggerHeader;
    case AttributionReportingIssueType::kNoRegisterOsSourceHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          NoRegisterOsSourceHeader;
    case AttributionReportingIssueType::kNoRegisterOsTriggerHeader:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          NoRegisterOsTriggerHeader;
    case AttributionReportingIssueType::
        kNavigationRegistrationUniqueScopeAlreadySet:
      return protocol::Audits::AttributionReportingIssueTypeEnum::
          NavigationRegistrationUniqueScopeAlreadySet;
  }
}

}  // namespace

void AuditsIssue::ReportAttributionIssue(
    ExecutionContext* execution_context,
    AttributionReportingIssueType type,
    Element* element,
    const String& request_id,
    const String& invalid_parameter) {
  auto details = protocol::Audits::AttributionReportingIssueDetails::create()
                     .setViolationType(BuildAttributionReportingIssueType(type))
                     .build();

  if (element) {
    details->setViolatingNodeId(element->GetDomNodeId());
  }
  if (!request_id.IsNull()) {
    details->setRequest(protocol::Audits::AffectedRequest::create()
                            .setRequestId(request_id)
                            .build());
  }
  if (!invalid_parameter.IsNull()) {
    details->setInvalidParameter(invalid_parameter);
  }

  auto issue_details =
      protocol::Audits::InspectorIssueDetails::create()
          .setAttributionReportingIssueDetails(std::move(details))
          .build();
  auto issue = protocol::Audits::InspectorIssue::create()
                   .setCode(protocol::Audits::InspectorIssueCodeEnum::
                                AttributionReportingIssue)
                   .setDetails(std::move(issue_details))
                   .build();
  execution_context->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

namespace {

protocol::Audits::SharedArrayBufferIssueType
SharedArrayBufferIssueTypeToProtocol(SharedArrayBufferIssueType issue_type) {
  switch (issue_type) {
    case SharedArrayBufferIssueType::kTransferIssue:
      return protocol::Audits::SharedArrayBufferIssueTypeEnum::TransferIssue;
    case SharedArrayBufferIssueType::kCreationIssue:
      return protocol::Audits::SharedArrayBufferIssueTypeEnum::CreationIssue;
  }
}

protocol::Audits::BlockedByResponseReason BlockedByResponseReasonToProtocol(
    network::mojom::BlockedByResponseReason reason) {
  switch (reason) {
    case network::mojom::BlockedByResponseReason::
        kCoepFrameResourceNeedsCoepHeader:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CoepFrameResourceNeedsCoepHeader;
    case network::mojom::BlockedByResponseReason::
        kCoopSandboxedIFrameCannotNavigateToCoopPage:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CoopSandboxedIFrameCannotNavigateToCoopPage;
    case network::mojom::BlockedByResponseReason::kCorpNotSameOrigin:
      return protocol::Audits::BlockedByResponseReasonEnum::CorpNotSameOrigin;
    case network::mojom::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoep:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByCoep;
    case network::mojom::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByDip:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByDip;
    case network::mojom::BlockedByResponseReason::
        kCorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip:
      return protocol::Audits::BlockedByResponseReasonEnum::
          CorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip;
    case network::mojom::BlockedByResponseReason::kCorpNotSameSite:
      return protocol::Audits::BlockedByResponseReasonEnum::CorpNotSameSite;
  }
}

protocol::Audits::MixedContentResourceType
RequestContextToMixedContentResourceType(
    mojom::blink::RequestContextType request_context) {
  switch (request_context) {
    case mojom::blink::RequestContextType::ATTRIBUTION_SRC:
      return protocol::Audits::MixedContentResourceTypeEnum::AttributionSrc;
    case mojom::blink::RequestContextType::AUDIO:
      return protocol::Audits::MixedContentResourceTypeEnum::Audio;
    case mojom::blink::RequestContextType::BEACON:
      return protocol::Audits::MixedContentResourceTypeEnum::Beacon;
    case mojom::blink::RequestContextType::CSP_REPORT:
      return protocol::Audits::MixedContentResourceTypeEnum::CSPReport;
    case mojom::blink::RequestContextType::DOWNLOAD:
      return protocol::Audits::MixedContentResourceTypeEnum::Download;
    case mojom::blink::RequestContextType::EMBED:
      return protocol::Audits::MixedContentResourceTypeEnum::PluginResource;
    case mojom::blink::RequestContextType::EVENT_SOURCE:
      return protocol::Audits::MixedContentResourceTypeEnum::EventSource;
    case mojom::blink::RequestContextType::FAVICON:
      return protocol::Audits::MixedContentResourceTypeEnum::Favicon;
    case mojom::blink::RequestContextType::FETCH:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case mojom::blink::RequestContextType::FONT:
      return protocol::Audits::MixedContentResourceTypeEnum::Font;
    case mojom::blink::RequestContextType::FORM:
      return protocol::Audits::MixedContentResourceTypeEnum::Form;
    case mojom::blink::RequestContextType::FRAME:
      return protocol::Audits::MixedContentResourceTypeEnum::Frame;
    case mojom::blink::RequestContextType::HYPERLINK:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case mojom::blink::RequestContextType::IFRAME:
      return protocol::Audits::MixedContentResourceTypeEnum::Frame;
    case mojom::blink::RequestContextType::IMAGE:
      return protocol::Audits::MixedContentResourceTypeEnum::Image;
    case mojom::blink::RequestContextType::IMAGE_SET:
      return protocol::Audits::MixedContentResourceTypeEnum::Image;
    case mojom::blink::RequestContextType::INTERNAL:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case mojom::blink::RequestContextType::JSON:
      // TODO(crbug.com/1511738): Consider adding a type
      // specific to JSON modules requests
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case mojom::blink::RequestContextType::LOCATION:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case mojom::blink::RequestContextType::MANIFEST:
      return protocol::Audits::MixedContentResourceTypeEnum::Manifest;
    case mojom::blink::RequestContextType::OBJECT:
      return protocol::Audits::MixedContentResourceTypeEnum::PluginResource;
    case mojom::blink::RequestContextType::PING:
      return protocol::Audits::MixedContentResourceTypeEnum::Ping;
    case mojom::blink::RequestContextType::PLUGIN:
      return protocol::Audits::MixedContentResourceTypeEnum::PluginData;
    case mojom::blink::RequestContextType::PREFETCH:
      return protocol::Audits::MixedContentResourceTypeEnum::Prefetch;
    case mojom::blink::RequestContextType::SCRIPT:
      return protocol::Audits::MixedContentResourceTypeEnum::Script;
    case mojom::blink::RequestContextType::SERVICE_WORKER:
      return protocol::Audits::MixedContentResourceTypeEnum::ServiceWorker;
    case mojom::blink::RequestContextType::SHARED_WORKER:
      return protocol::Audits::MixedContentResourceTypeEnum::SharedWorker;
    case mojom::blink::RequestContextType::SPECULATION_RULES:
      return protocol::Audits::MixedContentResourceTypeEnum::SpeculationRules;
    case mojom::blink::RequestContextType::STYLE:
      return protocol::Audits::MixedContentResourceTypeEnum::Stylesheet;
    case mojom::blink::RequestContextType::SUBRESOURCE:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case mojom::blink::RequestContextType::SUBRESOURCE_WEBBUNDLE:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case mojom::blink::RequestContextType::TRACK:
      return protocol::Audits::MixedContentResourceTypeEnum::Track;
    case mojom::blink::RequestContextType::UNSPECIFIED:
      return protocol::Audits::MixedContentResourceTypeEnum::Resource;
    case mojom::blink::RequestContextType::VIDEO:
      return protocol::Audits::MixedContentResourceTypeEnum::Video;
    case mojom::blink::RequestContextType::WORKER:
      return protocol::Audits::MixedContentResourceTypeEnum::Worker;
    case mojom::blink::RequestContextType::XML_HTTP_REQUEST:
      return protocol::Audits::MixedContentResourceTypeEnum::XMLHttpRequest;
    case mojom::blink::RequestContextType::XSLT:
      return protocol::Audits::MixedContentResourceTypeEnum::XSLT;
  }
}

protocol::Audits::MixedContentResolutionStatus
MixedContentResolutionStatusToProtocol(
    MixedContentResolutionStatus resolution_type) {
  switch (resolution_type) {
    case MixedContentResolutionStatus::kMixedContentBlocked:
      return protocol::Audits::MixedContentResolutionStatusEnum::
          MixedContentBlocked;
    case MixedContentResolutionStatus::kMixedContentAutomaticallyUpgraded:
      return protocol::Audits::MixedContentResolutionStatusEnum::
          MixedContentAutomaticallyUpgraded;
    case MixedContentResolutionStatus::kMixedContentWarning:
      return protocol::Audits::MixedContentResolutionStatusEnum::
          MixedContentWarning;
  }
}

protocol::Audits::ContentSecurityPolicyViolationType CSPViolationTypeToProtocol(
    ContentSecurityPolicyViolationType violation_type) {
  switch (violation_type) {
    case ContentSecurityPolicyViolationType::kEvalViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KEvalViolation;
    case ContentSecurityPolicyViolationType::kWasmEvalViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KWasmEvalViolation;
    case ContentSecurityPolicyViolationType::kInlineViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KInlineViolation;
    case ContentSecurityPolicyViolationType::kTrustedTypesPolicyViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KTrustedTypesPolicyViolation;
    case ContentSecurityPolicyViolationType::kTrustedTypesSinkViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KTrustedTypesSinkViolation;
    case ContentSecurityPolicyViolationType::kURLViolation:
      return protocol::Audits::ContentSecurityPolicyViolationTypeEnum::
          KURLViolation;
  }
}

}  // namespace

void AuditsIssue::ReportSharedArrayBufferIssue(
    ExecutionContext* execution_context,
    bool shared_buffer_transfer_allowed,
    SharedArrayBufferIssueType issue_type) {
  auto source_location = CaptureSourceLocation(execution_context);
  auto sab_issue_details =
      protocol::Audits::SharedArrayBufferIssueDetails::create()
          .setSourceCodeLocation(CreateProtocolLocation(*source_location))
          .setIsWarning(shared_buffer_transfer_allowed)
          .setType(SharedArrayBufferIssueTypeToProtocol(issue_type))
          .build();
  auto issue_details =
      protocol::Audits::InspectorIssueDetails::create()
          .setSharedArrayBufferIssueDetails(std::move(sab_issue_details))
          .build();
  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(
              protocol::Audits::InspectorIssueCodeEnum::SharedArrayBufferIssue)
          .setDetails(std::move(issue_details))
          .build();
  execution_context->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

// static
void AuditsIssue::ReportDeprecationIssue(ExecutionContext* execution_context,
                                         String type) {
  auto source_location = CaptureSourceLocation(execution_context);
  auto deprecation_issue_details =
      protocol::Audits::DeprecationIssueDetails::create()
          .setSourceCodeLocation(CreateProtocolLocation(*source_location))
          .setType(type)
          .build();
  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    auto affected_frame =
        protocol::Audits::AffectedFrame::create()
            .setFrameId(IdentifiersFactory::FrameId(window->GetFrame()))
            .build();
    deprecation_issue_details->setAffectedFrame(std::move(affected_frame));
  }
  auto issue_details =
      protocol::Audits::InspectorIssueDetails::create()
          .setDeprecationIssueDetails(std::move(deprecation_issue_details))
          .build();
  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(protocol::Audits::InspectorIssueCodeEnum::DeprecationIssue)
          .setDetails(std::move(issue_details))
          .build();
  execution_context->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

namespace {

protocol::Audits::ClientHintIssueReason ClientHintIssueReasonToProtocol(
    ClientHintIssueReason reason) {
  switch (reason) {
    case ClientHintIssueReason::kMetaTagAllowListInvalidOrigin:
      return protocol::Audits::ClientHintIssueReasonEnum::
          MetaTagAllowListInvalidOrigin;
    case ClientHintIssueReason::kMetaTagModifiedHTML:
      return protocol::Audits::ClientHintIssueReasonEnum::MetaTagModifiedHTML;
  }
}

}  // namespace

// static
void AuditsIssue::ReportClientHintIssue(LocalDOMWindow* local_dom_window,
                                        ClientHintIssueReason reason) {
  auto source_location = CaptureSourceLocation(local_dom_window);
  auto client_hint_issue_details =
      protocol::Audits::ClientHintIssueDetails::create()
          .setSourceCodeLocation(CreateProtocolLocation(*source_location))
          .setClientHintIssueReason(ClientHintIssueReasonToProtocol(reason))
          .build();
  auto issue_details =
      protocol::Audits::InspectorIssueDetails::create()
          .setClientHintIssueDetails(std::move(client_hint_issue_details))
          .build();
  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(protocol::Audits::InspectorIssueCodeEnum::ClientHintIssue)
          .setDetails(std::move(issue_details))
          .build();
  local_dom_window->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

AuditsIssue AuditsIssue::CreateBlockedByResponseIssue(
    network::mojom::BlockedByResponseReason reason,
    uint64_t identifier,
    DocumentLoader* loader,
    const ResourceError& error,
    const base::UnguessableToken& token) {
  auto affected_request =
      protocol::Audits::AffectedRequest::create()
          .setRequestId(IdentifiersFactory::RequestId(loader, identifier))
          .setUrl(error.FailingURL())
          .build();

  auto affected_frame = protocol::Audits::AffectedFrame::create()
                            .setFrameId(IdentifiersFactory::IdFromToken(token))
                            .build();

  auto blocked_by_response_details =
      protocol::Audits::BlockedByResponseIssueDetails::create()
          .setReason(BlockedByResponseReasonToProtocol(reason))
          .setRequest(std::move(affected_request))
          .setParentFrame(std::move(affected_frame))
          .build();

  auto details = protocol::Audits::InspectorIssueDetails::create()
                     .setBlockedByResponseIssueDetails(
                         std::move(blocked_by_response_details))
                     .build();

  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(
              protocol::Audits::InspectorIssueCodeEnum::BlockedByResponseIssue)
          .setDetails(std::move(details))
          .build();

  return AuditsIssue(std::move(issue));
}

void AuditsIssue::ReportMixedContentIssue(
    const KURL& main_resource_url,
    const KURL& insecure_url,
    const mojom::blink::RequestContextType request_context,
    LocalFrame* frame,
    const MixedContentResolutionStatus resolution_status,
    const String& devtools_id) {
  auto affected_frame =
      protocol::Audits::AffectedFrame::create()
          .setFrameId(frame->GetDevToolsFrameToken().ToString().c_str())
          .build();

  auto mixedContentDetails =
      protocol::Audits::MixedContentIssueDetails::create()
          .setResourceType(
              RequestContextToMixedContentResourceType(request_context))
          .setResolutionStatus(
              MixedContentResolutionStatusToProtocol(resolution_status))
          .setInsecureURL(insecure_url.GetString())
          .setMainResourceURL(main_resource_url.GetString())
          .setFrame(std::move(affected_frame))
          .build();

  if (!devtools_id.IsNull()) {
    auto request = protocol::Audits::AffectedRequest::create()
                       .setRequestId(devtools_id)
                       .setUrl(insecure_url.GetString())
                       .build();
    mixedContentDetails->setRequest(std::move(request));
  }

  auto details =
      protocol::Audits::InspectorIssueDetails::create()
          .setMixedContentIssueDetails(std::move(mixedContentDetails))
          .build();
  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(protocol::Audits::InspectorIssueCodeEnum::MixedContentIssue)
          .setDetails(std::move(details))
          .build();

  frame->DomWindow()->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

void AuditsIssue::ReportGenericIssue(
    LocalFrame* frame,
    mojom::blink::GenericIssueErrorType error_type,
    int violating_node_id) {
  auto audits_issue_details =
      protocol::Audits::GenericIssueDetails::create()
          .setErrorType(GenericIssueErrorTypeToProtocol(error_type))
          .setViolatingNodeId(violating_node_id)
          .build();

  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(protocol::Audits::InspectorIssueCodeEnum::GenericIssue)
          .setDetails(
              protocol::Audits::InspectorIssueDetails::create()
                  .setGenericIssueDetails(std::move(audits_issue_details))
                  .build())
          .build();

  frame->DomWindow()->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

void AuditsIssue::ReportGenericIssue(
    LocalFrame* frame,
    mojom::blink::GenericIssueErrorType error_type,
    int violating_node_id,
    const String& violating_node_attribute) {
  auto audits_issue_details =
      protocol::Audits::GenericIssueDetails::create()
          .setErrorType(GenericIssueErrorTypeToProtocol(error_type))
          .setViolatingNodeId(violating_node_id)
          .setViolatingNodeAttribute(violating_node_attribute)
          .build();

  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(protocol::Audits::InspectorIssueCodeEnum::GenericIssue)
          .setDetails(
              protocol::Audits::InspectorIssueDetails::create()
                  .setGenericIssueDetails(std::move(audits_issue_details))
                  .build())
          .build();

  frame->DomWindow()->AddInspectorIssue(AuditsIssue(std::move(issue)));
}

void AuditsIssue::ReportPropertyRuleIssue(
    Document* document,
    const KURL& url,
    WTF::OrdinalNumber line,
    WTF::OrdinalNumber column,
    protocol::Audits::PropertyRuleIssueReason reason,
    const String& propertyValue) {
  if (!document || !document->GetExecutionContext()) {
    return;
  }
  auto sourceCodeLocation = protocol::Audits::SourceCodeLocation::create()
                                .setUrl(url)
                                .setLineNumber(line.ZeroBasedInt())
                                .setColumnNumber(column.OneBasedInt())
                                .build();

  auto details = protocol::Audits::PropertyRuleIssueDetails::create()
                     .setSourceCodeLocation(std::move(sourceCodeLocation))
                     .setPropertyRuleIssueReason(reason)
                     .build();

  if (!propertyValue.IsNull()) {
    details->setPropertyValue(propertyValue);
  }

  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(protocol::Audits::InspectorIssueCodeEnum::PropertyRuleIssue)
          .setDetails(protocol::Audits::InspectorIssueDetails::create()
                          .setPropertyRuleIssueDetails(std::move(details))
                          .build())
          .build();

  document->GetExecutionContext()->AddInspectorIssue(
      AuditsIssue(std::move(issue)));
}

void AuditsIssue::ReportStylesheetLoadingLateImportIssue(
    Document* document,
    const KURL& url,
    WTF::OrdinalNumber line,
    WTF::OrdinalNumber column) {
  if (!document || !document->GetExecutionContext()) {
    return;
  }
  auto sourceCodeLocation = protocol::Audits::SourceCodeLocation::create()
                                .setUrl(url)
                                .setLineNumber(line.ZeroBasedInt())
                                .setColumnNumber(column.OneBasedInt())
                                .build();
  auto details = protocol::Audits::StylesheetLoadingIssueDetails::create()
                     .setSourceCodeLocation(std::move(sourceCodeLocation))
                     .setStyleSheetLoadingIssueReason(
                         protocol::Audits::StyleSheetLoadingIssueReasonEnum::
                             LateImportRule)
                     .build();

  auto issue =
      protocol::Audits::InspectorIssue::create()
          .setCode(
              protocol::Audits::InspectorIssueCodeEnum::StylesheetLoadingIssue)
          .s
"""


```