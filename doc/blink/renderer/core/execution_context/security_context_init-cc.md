Response:
Let's break down the thought process for analyzing the `security_context_init.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relation to web technologies (JavaScript, HTML, CSS), examples, logic reasoning (input/output), and common user/programming errors.

2. **Identify Key Areas:**  The filename and the included headers provide crucial clues. `security_context_init.cc` strongly suggests this file deals with setting up the security context of a web page/frame. Headers like `ContentSecurityPolicy.h`, `permissions_policy.h`, `DocumentPolicy.h`, `LocalFrame.h`, and `ExecutionContext.h` confirm this.

3. **High-Level Functionality:** Based on the includes and namespace (`blink`), the core functionality is likely related to initializing and applying security policies. This involves parsing policy headers, filtering based on origin trials, and setting these policies on the `SecurityContext`.

4. **Break Down the Code - Function by Function:**  Analyze each function individually.

    * **`FilterByOriginTrial`:** The name is self-explanatory. It iterates through the `DocumentPolicy` and removes entries that are disabled by origin trials. This function is internal and helps ensure that features controlled by origin trials are correctly enabled/disabled.

    * **`SecurityContextInit` (constructor):**  Simple initialization, storing the `ExecutionContext`.

    * **`ApplyDocumentPolicy`:** This is a crucial function.
        * It takes a `ParsedDocumentPolicy` and a report-only header.
        * It filters the main policy based on origin trials.
        * It uses `UseCounter` to track usage of the Document-Policy header.
        * It sets the main `DocumentPolicy` on the `SecurityContext`.
        * It parses the report-only header, filters it, and sets the report-only policy.
        * It notes that console messages related to report-only policies are discarded at this stage.

    * **`ApplyPermissionsPolicy`:** Another central function dealing with permissions.
        * It takes a `LocalFrame`, `ResourceResponse`, `FramePolicy`, isolated app policy, and fenced frame properties.
        * It handles the case of view-source mode, setting a default policy.
        * It retrieves Permissions-Policy and Feature-Policy headers (both enforced and report-only).
        * It uses `PermissionsPolicyParser` to parse these headers.
        * It logs parser errors to the console.
        * It handles container policies for iframes and fenced frames.
        * It considers sandbox flags.
        * It has special logic for isolated apps and fenced frames (fixed and flexible permissions).
        * It sets both the enforced and report-only `PermissionsPolicy` on the `SecurityContext`. Crucially, it notes that report-only policies only apply if they are *stricter* than the enforced policy.

    * **`InitPermissionsPolicyFrom`:**  Copies permissions policy state from another `SecurityContext`. Used when creating new execution contexts.

    * **`InitDocumentPolicyFrom`:**  Similar to the previous function, but for document policies.

5. **Relate to Web Technologies:** Now, connect the functions and concepts to JavaScript, HTML, and CSS.

    * **HTML:**  The `<meta>` tag for Content Security Policy and the `<iframe>` tag with `allow` attribute for Permissions Policy are direct links. The Document-Policy header is also set by the server.
    * **JavaScript:**  JavaScript interacts with the effects of these policies. For example, a script might be blocked by CSP, or an API might be unavailable due to Permissions Policy. The `console.log` messages are the primary way developers see policy violations.
    * **CSS:** CSS can be affected by CSP (e.g., `style-src` directive). Permissions Policy generally doesn't directly restrict CSS, but features that CSS might trigger (like geolocation via a background image request) could be blocked.

6. **Logic Reasoning (Input/Output):**  Focus on the `ApplyDocumentPolicy` and `ApplyPermissionsPolicy` functions. Think about the inputs (policy headers, frame type, etc.) and how they influence the output (the `PermissionsPolicy` and `DocumentPolicy` objects set on the `SecurityContext`).

7. **Common Errors:** Consider what mistakes developers might make when dealing with these policies. Incorrect header syntax, conflicting policies, forgetting to set report-only policies, and misunderstanding inheritance are good starting points.

8. **Structure the Output:** Organize the information logically using headings and bullet points to make it easy to read and understand. Start with a summary, then detail the functions, and finally address the relationships to web technologies, logic, and errors.

9. **Refine and Review:**  Read through the generated explanation. Is it clear? Accurate?  Are there any gaps?  For instance, initially, I might have just said "parses headers," but refining it to "parses HTTP headers related to security policies" is more precise. Also, adding specific examples for each web technology strengthens the explanation. Making sure to clearly differentiate between enforced and report-only policies is important.

By following this systematic approach, we can thoroughly analyze the code and provide a comprehensive explanation of its functionality and its relevance to web development.
好的， 这份代码文件 `security_context_init.cc` 的主要功能是**初始化和应用与安全相关的策略到执行上下文（`ExecutionContext`）中**。  更具体地说，它负责处理**文档策略（Document Policy）** 和 **权限策略（Permissions Policy）**。

以下是它的详细功能分解，以及与 JavaScript, HTML, CSS 的关系举例说明：

**主要功能:**

1. **应用文档策略 (Document Policy):**
   - 解析 HTTP 响应头中的 `Document-Policy` 和 `Report-Only-Document-Policy`。
   - 过滤掉当前源试用（Origin Trial）上下文中未启用的策略特性。
   - 将解析后的文档策略应用到 `SecurityContext` 中，包括强制执行的策略和仅用于报告的策略。
   - 记录 `Document-Policy` 头的使用情况。
   - **与 JavaScript, HTML 的关系:**
     - **HTML:**  `Document-Policy` 可以通过 HTTP 头部发送，影响浏览器对文档中某些特性的处理。 例如，一个策略可能禁止使用某些新的 JavaScript API，或者限制某些 HTML 特性的行为。
     - **JavaScript:**  JavaScript 代码的行为会受到文档策略的约束。 例如，如果文档策略禁止使用 `document.requestFullScreen()`, 那么调用该方法将会失败。
     - **举例说明:**
       - **假设输入:**  HTTP 响应头包含 `Document-Policy: vibrate 'none'`.
       - **输出:**  该页面的 JavaScript 代码将无法使用 `navigator.vibrate()` API。  如果尝试调用，可能会抛出一个错误或者什么也不发生（取决于具体的实现）。

2. **应用权限策略 (Permissions Policy):**
   - 解析 HTTP 响应头中的 `Permissions-Policy` 和 `Permissions-Policy-Report-Only`，以及旧版的 `Feature-Policy` 和 `Feature-Policy-Report-Only`。
   - 将解析后的权限策略应用到 `SecurityContext` 中，包括强制执行的策略和仅用于报告的策略。
   - 考虑父框架的权限策略、`<iframe>` 标签上的 `allow` 属性（作为容器策略）以及沙箱属性的影响。
   - 对于隔离的应用程序（Isolated Apps），会应用特殊的策略处理。
   - 对于围栏框架（Fenced Frames），会根据其特性和父框架的策略应用不同的策略。
   - 生成并向控制台输出策略解析过程中的错误和警告信息。
   - 记录 `Permissions-Policy` 和 `Feature-Policy` 头的使用情况。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **HTML:** `<iframe allow="...">` 属性用于设置嵌入的 iframe 的权限策略。 HTTP 头部也能设置权限策略。
     - **JavaScript:** 权限策略控制着 JavaScript 代码可以访问的浏览器特性和 API。 例如，摄像头、麦克风、地理位置等敏感 API 的访问都可能受到权限策略的限制。
     - **CSS:**  虽然权限策略主要影响 JavaScript API，但某些 CSS 特性，例如通过 `url()` 访问某些资源，可能会间接受到策略的影响（例如，如果策略禁止访问某个特定的来源）。
     - **举例说明:**
       - **假设输入:**  HTTP 响应头包含 `Permissions-Policy: geolocation=self`.
       - **输出:**  该页面的 JavaScript 代码可以调用 `navigator.geolocation` API，因为策略允许当前源（`self`）。 如果是其他来源的脚本尝试调用，将会被阻止。
       - **假设输入:**  HTML 中有 `<iframe src="..." allow="camera"></iframe>`.
       - **输出:**  该 iframe 中的 JavaScript 代码可以请求访问摄像头，即使父页面的权限策略可能不允许摄像头访问。 `allow` 属性充当了容器策略。

3. **从其他安全上下文初始化策略:**
   - `InitPermissionsPolicyFrom` 和 `InitDocumentPolicyFrom` 函数允许从另一个 `SecurityContext` 复制权限策略和文档策略。 这在创建新的执行上下文时很有用，例如在创建新的 worker 或 iframe 时。

**逻辑推理的假设输入与输出:**

* **假设输入 (Permissions Policy):**
    - 当前页面加载了一个包含以下 HTTP 响应头的资源：`Permissions-Policy: microphone=()`
    - 页面上的 JavaScript 代码尝试调用 `navigator.mediaDevices.getUserMedia({ audio: true })`.
* **输出 (Permissions Policy):**
    - 由于权限策略明确禁止麦克风访问（`microphone=()` 表示没有任何来源允许访问），`getUserMedia` 调用将会失败，并可能抛出一个 `NotAllowedError` 类型的 `DOMException`。  浏览器控制台可能会显示一个与权限策略相关的警告信息。

**用户或编程常见的使用错误举例说明:**

1. **拼写错误或语法错误的策略指令:**
   - **错误示例:**  在 HTTP 头部中写入 `Permisions-Policy: camera=self` (拼写错误)。
   - **结果:**  浏览器可能无法正确解析策略，导致策略失效或者行为不符合预期。开发者可能认为已经设置了权限策略，但实际上并没有生效。
   - **控制台提示:**  浏览器通常会在控制台中输出关于策略解析错误的警告信息。

2. **策略冲突或覆盖:**
   - **错误示例:**  同时通过 HTTP 头部和 `<meta>` 标签设置了不同的 Content Security Policy，或者在父页面和 iframe 中设置了冲突的 Permissions Policy。
   - **结果:**  浏览器会按照特定的优先级规则处理这些策略，开发者可能不清楚最终生效的是哪个策略。
   - **控制台提示:**  浏览器可能会在控制台中输出关于策略覆盖或冲突的警告信息。

3. **忘记设置报告策略:**
   - **错误示例:**  开发者只设置了强制执行的 Permissions Policy，但没有设置 Report-Only 的版本。
   - **结果:**  当用户访问的网站违反了策略时，浏览器会直接阻止相关功能，但开发者可能无法及时了解到这些违规行为，不利于问题的排查和改进。
   - **建议:**  建议同时设置 Report-Only 的策略，以便在不影响用户体验的情况下收集违规报告。

4. **对策略的作用域理解不足:**
   - **错误示例:**  开发者以为在顶级页面设置的 Permissions Policy 会自动应用到所有的子框架，但实际上子框架需要显式地通过 `allow` 属性或自身的 HTTP 头部声明策略。
   - **结果:**  子框架的行为可能不符合开发者的预期，某些功能可能被意外地允许或禁止。

5. **源试用 (Origin Trial) 配置错误:**
   - **错误示例:**  开发者在本地测试时启用了某个源试用特性，并在 `Document-Policy` 中使用了该特性，但忘记在生产环境中配置相应的源试用令牌。
   - **结果:**  在生产环境中，由于源试用令牌缺失，该策略特性将被禁用，导致网站行为与本地测试不一致。  `FilterByOriginTrial` 函数会移除这些未启用的特性。

总而言之，`security_context_init.cc` 是 Blink 渲染引擎中一个核心的组成部分，它确保了 Web 内容能够按照既定的安全策略运行，防止潜在的安全漏洞和恶意行为。理解这个文件的功能对于理解浏览器如何处理安全策略至关重要。

### 提示词
```
这是目录为blink/renderer/core/execution_context/security_context_init.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/execution_context/security_context_init.h"

#include <optional>

#include "base/metrics/histogram_macros.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "third_party/blink/public/common/frame/fenced_frame_permissions_policies.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/permissions_policy/document_policy_parser.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {
namespace {

// Helper function to filter out features that are not in origin trial in
// ParsedDocumentPolicy.
DocumentPolicy::ParsedDocumentPolicy FilterByOriginTrial(
    const DocumentPolicy::ParsedDocumentPolicy& parsed_policy,
    ExecutionContext* context) {
  DocumentPolicy::ParsedDocumentPolicy filtered_policy;
  for (auto i = parsed_policy.feature_state.begin(),
            last = parsed_policy.feature_state.end();
       i != last;) {
    if (!DisabledByOriginTrial(i->first, context))
      filtered_policy.feature_state.insert(*i);
    ++i;
  }
  for (auto i = parsed_policy.endpoint_map.begin(),
            last = parsed_policy.endpoint_map.end();
       i != last;) {
    if (!DisabledByOriginTrial(i->first, context))
      filtered_policy.endpoint_map.insert(*i);
    ++i;
  }
  return filtered_policy;
}

}  // namespace

// A helper class that allows the security context be initialized in the
// process of constructing the document.
SecurityContextInit::SecurityContextInit(ExecutionContext* context)
    : execution_context_(context) {}

void SecurityContextInit::ApplyDocumentPolicy(
    DocumentPolicy::ParsedDocumentPolicy& document_policy,
    const String& report_only_document_policy_header) {
  // Because Document-Policy http header is parsed in DocumentLoader,
  // when origin trial context is not initialized yet.
  // Needs to filter out features that are not in origin trial after
  // we have origin trial information available.
  document_policy = FilterByOriginTrial(document_policy, execution_context_);
  if (!document_policy.feature_state.empty()) {
    UseCounter::Count(execution_context_, WebFeature::kDocumentPolicyHeader);
    for (const auto& policy_entry : document_policy.feature_state) {
      UMA_HISTOGRAM_ENUMERATION("Blink.UseCounter.DocumentPolicy.Header",
                                policy_entry.first);
    }
  }
  execution_context_->GetSecurityContext().SetDocumentPolicy(
      DocumentPolicy::CreateWithHeaderPolicy(document_policy));

  // Handle Report-Only-Document-Policy HTTP header.
  // Console messages generated from logger are discarded, because currently
  // there is no way to output them to console.
  // Calling |Document::AddConsoleMessage| in
  // |SecurityContextInit::ApplyPendingDataToDocument| will have no effect,
  // because when the function is called, the document is not fully initialized
  // yet (|document_| field in current frame is not yet initialized yet).
  DocumentPolicy::ParsedDocumentPolicy report_only_document_policy;
  PolicyParserMessageBuffer logger("%s", /* discard_message */ true);
  std::optional<DocumentPolicy::ParsedDocumentPolicy>
      report_only_parsed_policy = DocumentPolicyParser::Parse(
          report_only_document_policy_header, logger);
  if (report_only_parsed_policy) {
    report_only_document_policy =
        FilterByOriginTrial(*report_only_parsed_policy, execution_context_);
    if (!report_only_document_policy.feature_state.empty()) {
      UseCounter::Count(execution_context_,
                        WebFeature::kDocumentPolicyReportOnlyHeader);
      execution_context_->GetSecurityContext().SetReportOnlyDocumentPolicy(
          DocumentPolicy::CreateWithHeaderPolicy(report_only_document_policy));
    }
  }
}

void SecurityContextInit::ApplyPermissionsPolicy(
    LocalFrame& frame,
    const ResourceResponse& response,
    const FramePolicy& frame_policy,
    const std::optional<ParsedPermissionsPolicy>& isolated_app_policy,
    const base::optional_ref<const FencedFrame::RedactedFencedFrameProperties>
        fenced_frame_properties) {
  const url::Origin origin =
      execution_context_->GetSecurityOrigin()->ToUrlOrigin();
  // If we are a HTMLViewSourceDocument we use container, header or
  // inherited policies. https://crbug.com/898688.
  if (frame.InViewSourceMode()) {
    execution_context_->GetSecurityContext().SetPermissionsPolicy(
        PermissionsPolicy::CreateFromParentPolicy(nullptr, /*header_policy=*/{},
                                                  {}, origin));
    return;
  }

  const String& permissions_policy_header =
      response.HttpHeaderField(http_names::kPermissionsPolicy);
  const String& report_only_permissions_policy_header =
      response.HttpHeaderField(http_names::kPermissionsPolicyReportOnly);
  if (!permissions_policy_header.empty())
    UseCounter::Count(execution_context_, WebFeature::kPermissionsPolicyHeader);

  PolicyParserMessageBuffer feature_policy_logger(
      "Error with Feature-Policy header: ");
  PolicyParserMessageBuffer report_only_feature_policy_logger(
      "Error with Feature-Policy-Report-Only header: ");

  PolicyParserMessageBuffer permissions_policy_logger(
      "Error with Permissions-Policy header: ");
  PolicyParserMessageBuffer report_only_permissions_policy_logger(
      "Error with Permissions-Policy-Report-Only header: ");

  WTF::StringBuilder policy_builder;
  policy_builder.Append(response.HttpHeaderField(http_names::kFeaturePolicy));
  String feature_policy_header = policy_builder.ToString();
  if (!feature_policy_header.empty())
    UseCounter::Count(execution_context_, WebFeature::kFeaturePolicyHeader);

  permissions_policy_header_ = PermissionsPolicyParser::ParseHeader(
      feature_policy_header, permissions_policy_header,
      execution_context_->GetSecurityOrigin(), feature_policy_logger,
      permissions_policy_logger, execution_context_);

  ParsedPermissionsPolicy parsed_report_only_permissions_policy_header =
      PermissionsPolicyParser::ParseHeader(
          response.HttpHeaderField(http_names::kFeaturePolicyReportOnly),
          report_only_permissions_policy_header,
          execution_context_->GetSecurityOrigin(),
          report_only_feature_policy_logger,
          report_only_permissions_policy_logger, execution_context_);

  if (!response.HttpHeaderField(http_names::kFeaturePolicyReportOnly).empty()) {
    UseCounter::Count(execution_context_,
                      WebFeature::kFeaturePolicyReportOnlyHeader);
  }

  auto messages = Vector<PolicyParserMessageBuffer::Message>();
  messages.AppendVector(feature_policy_logger.GetMessages());
  messages.AppendVector(report_only_feature_policy_logger.GetMessages());
  messages.AppendVector(permissions_policy_logger.GetMessages());
  messages.AppendVector(report_only_permissions_policy_logger.GetMessages());

  for (const auto& message : messages) {
    execution_context_->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kSecurity, message.level,
        message.content));
  }

  ParsedPermissionsPolicy container_policy;
  if (frame.Owner() || frame.IsFencedFrameRoot()) {
    container_policy = frame_policy.container_policy;
  }

  // DocumentLoader applied the sandbox flags before calling this function, so
  // they are accessible here.
  auto sandbox_flags = execution_context_->GetSandboxFlags();

  if (RuntimeEnabledFeatures::BlockingFocusWithoutUserActivationEnabled() &&
      frame.Tree().Parent() &&
      (sandbox_flags & network::mojom::blink::WebSandboxFlags::kNavigation) !=
          network::mojom::blink::WebSandboxFlags::kNone) {
    // Enforcing the policy for sandbox frames (for context see
    // https://crbug.com/954349).
    DisallowFeatureIfNotPresent(
        mojom::blink::PermissionsPolicyFeature::kFocusWithoutUserActivation,
        container_policy);
  }

  if (isolated_app_policy) {
    DCHECK(frame.IsOutermostMainFrame());
    std::unique_ptr<PermissionsPolicy> permissions_policy =
        PermissionsPolicy::CreateFromParsedPolicy(permissions_policy_header_,
                                                  isolated_app_policy, origin);
    execution_context_->GetSecurityContext().SetPermissionsPolicy(
        std::move(permissions_policy));
  } else {
    std::unique_ptr<PermissionsPolicy> permissions_policy;
    if (frame.IsFencedFrameRoot()) {
      if (!fenced_frame_properties.has_value()) {
        // Without fenced frame properties, there won't be a list of effective
        // enabled permissions or information about the embedder's permissions
        // policies, so we create a permissions policy with every permission
        // disabled.
        permissions_policy = PermissionsPolicy::CreateFixedForFencedFrame(
            origin, /*header_policy=*/permissions_policy_header_, {});
      } else if (fenced_frame_properties->parent_permissions_info()
                     .has_value()) {
        // Fenced frames with flexible permissions are allowed to inherit
        // certain permissions from their parent.
        auto parent_permissions_policy =
            PermissionsPolicy::CreateFromParsedPolicy(
                fenced_frame_properties->parent_permissions_info()
                    ->parsed_permissions_policy,
                /*base_policy=*/std::nullopt,
                fenced_frame_properties->parent_permissions_info()->origin);

        permissions_policy = PermissionsPolicy::CreateFlexibleForFencedFrame(
            parent_permissions_policy.get(),
            /*header_policy=*/permissions_policy_header_, container_policy,
            origin);

        // Warn if a disallowed permissions policy is attempted to be enabled.
        for (const auto& policy : container_policy) {
          if (!base::Contains(blink::kFencedFrameAllowedFeatures,
                              policy.feature)) {
            bool is_isolated_context =
                execution_context_ && execution_context_->IsIsolatedContext();
            execution_context_->AddConsoleMessage(
                MakeGarbageCollected<ConsoleMessage>(
                    mojom::blink::ConsoleMessageSource::kSecurity,
                    mojom::blink::ConsoleMessageLevel::kWarning,
                    "The permissions policy '" +
                        GetNameForFeature(policy.feature, is_isolated_context) +
                        "' is disallowed in fenced frames and will not be "
                        "enabled."));
          }
        }
      } else {
        // Fenced frames with fixed permissions have a list of required
        // permission policies to load and can't be granted extra policies, so
        // use the required policies instead of inheriting from its parent. Note
        // that the parent policies must allow the required policies, which is
        // checked separately in
        // NavigationRequest::CheckPermissionsPoliciesForFencedFrames.
        permissions_policy = PermissionsPolicy::CreateFixedForFencedFrame(
            origin, /*header_policy=*/permissions_policy_header_,
            fenced_frame_properties->effective_enabled_permissions());
      }
    } else {
      auto* parent_permissions_policy = frame.Tree().Parent()
                                            ? frame.Tree()
                                                  .Parent()
                                                  ->GetSecurityContext()
                                                  ->GetPermissionsPolicy()
                                            : nullptr;
      permissions_policy = PermissionsPolicy::CreateFromParentPolicy(
          parent_permissions_policy,
          /*header_policy=*/permissions_policy_header_, container_policy,
          origin);
    }
    execution_context_->GetSecurityContext().SetPermissionsPolicy(
        std::move(permissions_policy));
  }

  // Report-only permissions policy only takes effect when it is stricter than
  // enforced permissions policy, i.e. when enforced permissions policy allows a
  // feature while report-only permissions policy do not. In such scenario, a
  // report-only policy violation report will be generated, but the feature is
  // still allowed to be used. Since child frames cannot loosen enforced
  // permissions policy, there is no need to inherit parent policy and container
  // policy for report-only permissions policy. For inherited policies, the
  // behavior is dominated by enforced permissions policy.
  if (!parsed_report_only_permissions_policy_header.empty()) {
    std::unique_ptr<PermissionsPolicy> report_only_policy =
        PermissionsPolicy::CreateFromParentPolicy(
            nullptr /* parent_policy */,
            /*header_policy=*/parsed_report_only_permissions_policy_header,
            {} /* container_policy */,
            execution_context_->GetSecurityOrigin()->ToUrlOrigin());
    execution_context_->GetSecurityContext().SetReportOnlyPermissionsPolicy(
        std::move(report_only_policy));
  }
}

void SecurityContextInit::InitPermissionsPolicyFrom(
    const SecurityContext& other) {
  auto& security_context = execution_context_->GetSecurityContext();
  security_context.SetPermissionsPolicy(
      PermissionsPolicy::CopyStateFrom(other.GetPermissionsPolicy()));
  security_context.SetReportOnlyPermissionsPolicy(
      PermissionsPolicy::CopyStateFrom(other.GetReportOnlyPermissionsPolicy()));
}

void SecurityContextInit::InitDocumentPolicyFrom(const SecurityContext& other) {
  auto& security_context = execution_context_->GetSecurityContext();
  security_context.SetDocumentPolicy(
      DocumentPolicy::CopyStateFrom(other.GetDocumentPolicy()));
  security_context.SetReportOnlyDocumentPolicy(
      DocumentPolicy::CopyStateFrom(other.GetReportOnlyDocumentPolicy()));
}
}  // namespace blink
```