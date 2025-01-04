Response:
The user wants a summary of the functionalities of the provided C++ code snippet, which is part of the `ContentSecurityPolicy` class in the Chromium Blink engine. I need to identify the key roles of this code in enforcing and reporting Content Security Policy restrictions. Specifically, I should look for:

1. **Core CSP enforcement logic:** How it checks if a resource or action is allowed based on the policy.
2. **Relationship to web technologies:** How these checks relate to JavaScript, HTML, and CSS.
3. **Examples of usage and potential errors:**  Scenarios where these functions are used and common mistakes developers might make.

Let's break down the code section by section:

* **`AllowFromSource`:** This function appears to be the central point for checking if a resource from a given URL is permitted by the CSP. It handles bypassing logic for certain schemes and iterates through the loaded policies.
* **Specific `Allow...` functions:**  These functions (`AllowBaseURI`, `AllowConnectToSource`, etc.) seem to be wrappers around `AllowFromSource` for different CSP directives, indicating how CSP controls various resource types.
* **Trusted Types functions:** `AllowTrustedTypePolicy` and `AllowTrustedTypeAssignmentFailure` deal with the Trusted Types CSP feature, which is related to preventing DOM XSS.
* **`IsActive` and `IsActiveForConnections`:** These indicate the state of the CSP.
* **`EnforceSandboxFlags`, `RequireTrustedTypes`, `EnforceStrictMixedContentChecking`, `UpgradeInsecureRequests`:** These functions set flags based on CSP directives.
* **`StripURLForUseInReport`:** This function sanitizes URLs before including them in violation reports.
* **`GatherSecurityPolicyViolationEventData`:** This function prepares data for violation reports.
* **`ReportViolation` and `PostViolationReport`:** These functions handle the process of reporting CSP violations.
* **`ReportMixedContent`, `ReportReportOnlyInMeta`, `ReportMetaOutsideHead`:** These handle specific reporting scenarios.
* **`LogToConsole`:**  Logs messages to the browser's console.
* **`BuildCSPViolationType`:** Converts internal violation types to public enum values.
* **`ReportBlockedScriptExecutionToInspector`:**  Sends information to the browser's developer tools.
* **`ShouldBypassMainWorldDeprecated`:**  Checks if CSP should be bypassed in certain isolated JavaScript environments.
* **`ShouldSendViolationReport` and `DidSendViolationReport`:**  Manages the sending of violation reports to prevent duplicates.
* **`GetDirectiveName` and `GetDirectiveType`:**  Functions for mapping between directive names and enum values.
* **`ShouldBypassContentSecurityPolicy`:** Determines if CSP should be bypassed for a given URL.
* **`GetParsedPolicies` and `HasPolicyFromSource`:** Accessors for the loaded policies.
* **`AllowFencedFrameOpaqueURL`:** Checks if opaque URLs are allowed in fenced frames based on CSP.
* **`HasEnforceFrameAncestorsDirectives`:** Checks if any enforced `frame-ancestors` directive is present.
* **`Count`:**  Used for internal metrics.

**In summary, the core functionalities are:**

1. **Authorization:** Determining if a specific action (loading a resource, form submission, etc.) is permitted based on the active CSP directives.
2. **Reporting:** Generating and dispatching reports when a CSP directive is violated.
3. **Configuration:** Managing the internal state and flags based on the parsed CSP headers.
4. **Integration with browser features:** Interacting with the browser's console, developer tools, and other internal systems.
这是 blink 引擎中 `ContentSecurityPolicy` 类的部分实现，主要负责**执行内容安全策略 (CSP) 的检查和报告违规行为**。

**功能归纳:**

这部分代码主要负责以下功能：

1. **资源加载许可检查 (Allow From Source):**  核心功能是根据已加载的 CSP 策略，判断是否允许从特定来源加载资源。它针对不同类型的资源（脚本、图片、样式、连接等）提供统一的入口 `AllowFromSource`，并根据传入的参数（URL、nonce、hash 等）和策略进行匹配检查。

2. **特定资源类型许可检查:**  提供了一系列针对特定资源类型的检查函数，如 `AllowBaseURI`, `AllowConnectToSource`, `AllowFormAction`, `AllowImageFromSource`, `AllowMediaFromSource`, `AllowObjectFromSource`, `AllowScriptFromSource`, `AllowWorkerContextFromSource`。这些函数内部调用 `AllowFromSource`，并传入相应的 CSP 指令名称。

3. **Trusted Types 支持:**  实现了对 Trusted Types CSP 功能的支持，包括检查是否允许创建特定的 Trusted Type Policy (`AllowTrustedTypePolicy`) 以及报告 Trusted Types 赋值失败的情况 (`AllowTrustedTypeAssignmentFailure`)。

4. **策略激活状态查询:**  提供了 `IsActive` 和 `IsActiveForConnections` 方法，用于查询 CSP 策略是否已激活。

5. **沙箱标志管理:**  `EnforceSandboxFlags` 方法用于设置沙箱标志，这些标志会限制文档的能力。

6. **安全请求升级和混合内容处理:**  `RequireTrustedTypes`, `EnforceStrictMixedContentChecking`, `UpgradeInsecureRequests` 方法根据 CSP 指令设置相应的内部标志，影响混合内容的处理和是否需要 Trusted Types。

7. **违规报告生成与发送:**  `ReportViolation` 和 `PostViolationReport` 负责生成详细的违规报告，并将其发送到策略中指定的报告端点。报告中包含违规的指令、被阻止的 URL、文档 URL 等信息。

8. **URL 净化:**  `StripURLForUseInReport` 函数用于在生成违规报告时对 URL 进行清理，移除敏感信息（如用户名、密码、片段标识符），并根据跨域情况进行简化。

9. **控制台日志记录:**  `LogToConsole` 函数用于将 CSP 相关的消息记录到浏览器的控制台中。

10. **与开发者工具集成:**  `ReportBlockedScriptExecutionToInspector` 函数用于向浏览器的开发者工具报告脚本执行被阻止的情况。

11. **实验性功能支持:**  `ExperimentalFeaturesEnabled` 方法用于判断是否启用了实验性的 CSP 功能。

12. **绕过策略机制:**  `ShouldBypassContentSecurityPolicy` 方法用于判断在特定情况下是否应该绕过 CSP 检查，例如对于某些特定的 URL 协议。

13. **策略信息访问:**  `GetParsedPolicies` 和 `HasPolicyFromSource` 允许访问已解析的 CSP 策略信息。

14. **Fenced Frame 支持:**  `AllowFencedFrameOpaqueURL` 判断是否允许在 fenced frame 中使用 opaque URL。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

CSP 的主要目标是增强 Web 应用的安全性，防止跨站脚本攻击 (XSS) 等安全威胁。它通过限制浏览器加载和执行的资源来源来实现这一目标。

* **JavaScript:**
    * **功能关系:**  `AllowScriptFromSource` 用于检查是否允许加载和执行来自特定来源的 JavaScript 代码。`script-src` 指令用于控制 JavaScript 的来源。
    * **举例说明:**
        * **假设输入:** CSP 指令为 `script-src 'self' https://example.com;`，尝试加载一个位于 `https://evil.com/malicious.js` 的脚本。
        * **输出:** `AllowScriptFromSource` 将返回 `false`，浏览器会阻止该脚本的加载和执行，并在控制台生成 CSP 违规报告。
        * **常见错误:**  开发者可能错误地配置 `script-src`，例如忘记添加 CDN 的域名，导致 CDN 上的 JavaScript 文件被阻止。

* **HTML:**
    * **功能关系:**  CSP 可以控制 HTML 中 `<base>` 标签的 `href` 属性 (`AllowBaseURI`)，`<form>` 标签的 `action` 属性 (`AllowFormAction`)，以及 `<iframe>` 等嵌入内容的来源 (`AllowFrameSrc`, `AllowFencedFrameSrc`)。
    * **举例说明:**
        * **假设输入:** CSP 指令为 `base-uri 'self';`，HTML 中包含 `<base href="https://example.net/">`。
        * **输出:** `AllowBaseURI` 将返回 `false`，浏览器会阻止修改文档的基础 URI。
        * **常见错误:**  在 CSP 中限制了 `frame-ancestors`，但开发者尝试在不允许的页面中嵌入该页面，导致嵌入失败。

* **CSS:**
    * **功能关系:**  CSP 可以控制 CSS 文件的来源 (`AllowFromSource` 结合 `style-src`) 以及内联样式和 `style` 标签的使用 (`style-src 'unsafe-inline'`)。
    * **举例说明:**
        * **假设输入:** CSP 指令为 `style-src 'self';`，HTML 中包含 `<link rel="stylesheet" href="https://cdn.evil.com/styles.css">`。
        * **输出:**  `AllowFromSource` (针对 `style-src`) 将返回 `false`，浏览器会阻止该样式表的加载。
        * **常见错误:**  忘记在 `style-src` 中添加允许的字体来源，导致页面上使用的字体无法加载。

**逻辑推理的假设输入与输出:**

* **假设输入:**
    * CSP 策略: `img-src https://images.example.com;`
    * 尝试加载的图片 URL: `https://images.example.com/logo.png`
    * 调用函数: `AllowImageFromSource(url)`
* **输出:** `true` (因为图片来源与策略匹配)

* **假设输入:**
    * CSP 策略: `connect-src 'self';`
    * 尝试建立连接的 URL: `wss://api.external.com`
    * 调用函数: `AllowConnectToSource(url)`
* **输出:** `false` (因为连接的目标域名不在允许的列表中)

**用户或编程常见的使用错误举例:**

1. **配置过于严格:**  例如，`script-src 'none'` 会阻止所有 JavaScript 代码的执行，可能导致网站功能完全失效。
2. **忘记添加必要的来源:**  使用了 CDN 或第三方服务，但忘记在 CSP 指令中添加相应的域名，导致资源加载失败。
3. **错误地使用 'unsafe-inline' 或 'unsafe-eval':**  虽然允许内联脚本和动态代码执行，但也降低了 CSP 的安全性，应尽量避免使用。
4. **Report-Only 模式下未观察报告:**  开发者可能设置了 Report-Only 模式来测试 CSP，但没有配置报告端点或查看报告，导致无法发现潜在的违规行为。
5. **混合使用 Report-URI 和 Report-To:**  虽然两者都可以用于报告违规，但推荐使用 `report-to` 指令，因为它提供了更灵活的配置和功能。
6. **在 `<meta>` 标签中设置 Report-Only 策略:**  CSP 规范禁止通过 `<meta>` 标签设置 Report-Only 策略，浏览器会忽略这种配置。
7. **在 `<body>` 中设置 `<meta>` 标签的 CSP 策略:**  CSP 策略只能通过 `<meta>` 标签在 `<head>` 中设置，否则会被忽略。

总而言之，这段代码是 Chromium Blink 引擎中实现 CSP 核心功能的重要组成部分，它负责根据配置的策略对各种类型的资源加载和执行进行细致的检查，并在发现违规行为时生成报告，从而有效地提升 Web 应用的安全性。

Prompt: 
```
这是目录为blink/renderer/core/frame/csp/content_security_policy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
::kPolicyAreaStyle;

  if (ShouldBypassContentSecurityPolicy(url, area)) {
    if (type != CSPDirectiveName::ScriptSrcElem)
      return true;

    Count(parser_disposition == kParserInserted
              ? WebFeature::kScriptWithCSPBypassingSchemeParserInserted
              : WebFeature::kScriptWithCSPBypassingSchemeNotParserInserted);

    // If we're running experimental features, bypass CSP only for
    // non-parser-inserted resources whose scheme otherwise bypasses CSP. If
    // we're not running experimental features, bypass CSP for all resources
    // regardless of parser state. Once we have more data via the
    // 'ScriptWithCSPBypassingScheme*' metrics, make a decision about what
    // behavior to ship. https://crbug.com/653521
    if ((parser_disposition == kNotParserInserted ||
         !ExperimentalFeaturesEnabled()) &&
        // The schemes where javascript:-URLs are blocked are usually
        // privileged pages, so do not allow the CSP to be bypassed either.
        !SchemeRegistry::ShouldTreatURLSchemeAsNotAllowingJavascriptURLs(
            delegate_->GetSecurityOrigin()->Protocol())) {
      return true;
    }
  }

  CSPCheckResult result = CSPCheckResult::Allowed();
  for (const auto& policy : policies_) {
    if (!CheckHeaderTypeMatches(check_header_type, reporting_disposition,
                                policy->header->type)) {
      continue;
    }
    result &= CSPDirectiveListAllowFromSource(
        *policy, this, type, url, url_before_redirects, redirect_status,
        reporting_disposition, nonce, hashes, parser_disposition);
  }

  if (result.WouldBlockIfWildcardDoesNotMatchWs()) {
    Count(WebFeature::kCspWouldBlockIfWildcardDoesNotMatchWs);
  }
  if (result.WouldBlockIfWildcardDoesNotMatchFtp()) {
    Count(WebFeature::kCspWouldBlockIfWildcardDoesNotMatchFtp);
  }

  return result.IsAllowed();
}

bool ContentSecurityPolicy::AllowBaseURI(const KURL& url) {
  // `base-uri` isn't affected by 'upgrade-insecure-requests', so we use
  // CheckHeaderType::kCheckAll to check both report-only and enforce headers
  // here.
  return AllowFromSource(CSPDirectiveName::BaseURI, url, url,
                         RedirectStatus::kNoRedirect);
}

bool ContentSecurityPolicy::AllowConnectToSource(
    const KURL& url,
    const KURL& url_before_redirects,
    RedirectStatus redirect_status,
    ReportingDisposition reporting_disposition,
    CheckHeaderType check_header_type) {
  return AllowFromSource(CSPDirectiveName::ConnectSrc, url,
                         url_before_redirects, redirect_status,
                         reporting_disposition, check_header_type);
}

bool ContentSecurityPolicy::AllowFormAction(const KURL& url) {
  return AllowFromSource(CSPDirectiveName::FormAction, url, url,
                         RedirectStatus::kNoRedirect);
}

bool ContentSecurityPolicy::AllowImageFromSource(
    const KURL& url,
    const KURL& url_before_redirects,
    RedirectStatus redirect_status,
    ReportingDisposition reporting_disposition,
    CheckHeaderType check_header_type) {
  return AllowFromSource(CSPDirectiveName::ImgSrc, url, url_before_redirects,
                         redirect_status, reporting_disposition,
                         check_header_type);
}

bool ContentSecurityPolicy::AllowMediaFromSource(const KURL& url) {
  return AllowFromSource(CSPDirectiveName::MediaSrc, url, url,
                         RedirectStatus::kNoRedirect);
}

bool ContentSecurityPolicy::AllowObjectFromSource(const KURL& url) {
  return AllowFromSource(CSPDirectiveName::ObjectSrc, url, url,
                         RedirectStatus::kNoRedirect);
}

bool ContentSecurityPolicy::AllowScriptFromSource(
    const KURL& url,
    const String& nonce,
    const IntegrityMetadataSet& hashes,
    ParserDisposition parser_disposition,
    const KURL& url_before_redirects,
    RedirectStatus redirect_status,
    ReportingDisposition reporting_disposition,
    CheckHeaderType check_header_type) {
  return AllowFromSource(CSPDirectiveName::ScriptSrcElem, url,
                         url_before_redirects, redirect_status,
                         reporting_disposition, check_header_type, nonce,
                         hashes, parser_disposition);
}

bool ContentSecurityPolicy::AllowWorkerContextFromSource(const KURL& url) {
  return AllowFromSource(CSPDirectiveName::WorkerSrc, url, url,
                         RedirectStatus::kNoRedirect);
}

// The return value indicates whether the policy is allowed or not.
// If the return value is false, the out-parameter violation_details indicates
// the type of the violation, and if the return value is true,
// it indicates if a report-only violation occurred.
bool ContentSecurityPolicy::AllowTrustedTypePolicy(
    const String& policy_name,
    bool is_duplicate,
    AllowTrustedTypePolicyDetails& violation_details,
    std::optional<base::UnguessableToken> issue_id) {
  bool is_allowed = true;
  violation_details = AllowTrustedTypePolicyDetails::kAllowed;
  for (const auto& policy : policies_) {
    if (!CheckHeaderTypeMatches(CheckHeaderType::kCheckAll,
                                ReportingDisposition::kReport,
                                policy->header->type)) {
      continue;
    }
    auto new_violation_details = AllowTrustedTypePolicyDetails::kAllowed;
    bool new_allowed = CSPDirectiveListAllowTrustedTypePolicy(
        *policy, this, policy_name, is_duplicate, new_violation_details,
        issue_id);
    // Report the first violation that is enforced.
    // If there is none, report the first violation that is report-only.
    if ((is_allowed && !new_allowed) ||
        violation_details == AllowTrustedTypePolicyDetails::kAllowed) {
      violation_details = new_violation_details;
    }
    is_allowed &= new_allowed;
  }

  return is_allowed;
}

bool ContentSecurityPolicy::AllowTrustedTypeAssignmentFailure(
    const String& message,
    const String& sample,
    const String& sample_prefix,
    std::optional<base::UnguessableToken> issue_id) {
  bool allow = true;
  for (const auto& policy : policies_) {
    allow &= CSPDirectiveListAllowTrustedTypeAssignmentFailure(
        *policy, this, message, sample, sample_prefix, issue_id);
  }
  return allow;
}

bool ContentSecurityPolicy::IsActive() const {
  return !policies_.empty();
}

bool ContentSecurityPolicy::IsActiveForConnections() const {
  for (const auto& policy : policies_) {
    if (CSPDirectiveListIsActiveForConnections(*policy))
      return true;
  }
  return false;
}

const KURL ContentSecurityPolicy::FallbackUrlForPlugin() const {
  return delegate_ ? delegate_->Url() : KURL();
}

void ContentSecurityPolicy::EnforceSandboxFlags(
    network::mojom::blink::WebSandboxFlags mask) {
  sandbox_mask_ |= mask;
}

void ContentSecurityPolicy::RequireTrustedTypes() {
  // We store whether CSP demands a policy. The caller still needs to check
  // whether the feature is enabled in the first place.
  require_trusted_types_ = true;
}

void ContentSecurityPolicy::EnforceStrictMixedContentChecking() {
  insecure_request_policy_ |=
      mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent;
}

void ContentSecurityPolicy::UpgradeInsecureRequests() {
  insecure_request_policy_ |=
      mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests;
}

// https://www.w3.org/TR/CSP3/#strip-url-for-use-in-reports
static String StripURLForUseInReport(const SecurityOrigin* security_origin,
                                     const KURL& url,
                                     CSPDirectiveName effective_type) {
  if (!url.IsValid())
    return String();

  // https://www.w3.org/TR/CSP3/#strip-url-for-use-in-reports
  // > 1. If url's scheme is not "`https`", "'http'", "`wss`" or "`ws`" then
  // >    return url's scheme.
  static const char* const allow_list[] = {"http", "https", "ws", "wss"};
  if (!base::Contains(allow_list, url.Protocol()))
    return url.Protocol();

  // Until we're more careful about the way we deal with navigations in frames
  // (and, by extension, in plugin documents), strip cross-origin 'frame-src'
  // and 'object-src' violations down to an origin. https://crbug.com/633306
  bool can_safely_expose_url =
      security_origin->CanRequest(url) ||
      (effective_type != CSPDirectiveName::FrameSrc &&
       effective_type != CSPDirectiveName::ObjectSrc &&
       effective_type != CSPDirectiveName::FencedFrameSrc);

  if (!can_safely_expose_url)
    return SecurityOrigin::Create(url)->ToString();

  // https://www.w3.org/TR/CSP3/#strip-url-for-use-in-reports
  // > 2. Set url’s fragment to the empty string.
  // > 3. Set url’s username to the empty string.
  // > 4. Set url’s password to the empty string.
  KURL stripped_url = url;
  stripped_url.RemoveFragmentIdentifier();
  stripped_url.SetUser(String());
  stripped_url.SetPass(String());

  // https://www.w3.org/TR/CSP3/#strip-url-for-use-in-reports
  // > 5. Return the result of executing the URL serializer on url.
  return stripped_url.GetString();
}

namespace {
std::unique_ptr<SourceLocation> GatherSecurityPolicyViolationEventData(
    SecurityPolicyViolationEventInit* init,
    ContentSecurityPolicyDelegate* delegate,
    const String& directive_text,
    CSPDirectiveName effective_type,
    const KURL& blocked_url,
    const String& header,
    ContentSecurityPolicyType header_type,
    ContentSecurityPolicyViolationType violation_type,
    std::unique_ptr<SourceLocation> source_location,
    const String& script_source,
    const String& sample_prefix) {
  if (effective_type == CSPDirectiveName::FrameAncestors) {
    // If this load was blocked via 'frame-ancestors', then the URL of
    // |document| has not yet been initialized. In this case, we'll set both
    // 'documentURI' and 'blockedURI' to the blocked document's URL.
    String stripped_url =
        StripURLForUseInReport(delegate->GetSecurityOrigin(), blocked_url,
                               CSPDirectiveName::DefaultSrc);
    init->setDocumentURI(stripped_url);
    init->setBlockedURI(stripped_url);
  } else {
    String stripped_url =
        StripURLForUseInReport(delegate->GetSecurityOrigin(), delegate->Url(),
                               CSPDirectiveName::DefaultSrc);
    init->setDocumentURI(stripped_url);
    switch (violation_type) {
      case ContentSecurityPolicyViolationType::kInlineViolation:
        init->setBlockedURI("inline");
        break;
      case ContentSecurityPolicyViolationType::kEvalViolation:
        init->setBlockedURI("eval");
        break;
      case ContentSecurityPolicyViolationType::kWasmEvalViolation:
        init->setBlockedURI("wasm-eval");
        break;
      case ContentSecurityPolicyViolationType::kURLViolation:
        // We pass RedirectStatus::kNoRedirect so that StripURLForUseInReport
        // does not strip path and query from the URL. This is safe since
        // blocked_url at this point is always the original url (before
        // redirects).
        init->setBlockedURI(StripURLForUseInReport(
            delegate->GetSecurityOrigin(), blocked_url, effective_type));
        break;
      case ContentSecurityPolicyViolationType::kTrustedTypesSinkViolation:
        init->setBlockedURI("trusted-types-sink");
        break;
      case ContentSecurityPolicyViolationType::kTrustedTypesPolicyViolation:
        init->setBlockedURI("trusted-types-policy");
        break;
    }
  }

  String effective_directive =
      ContentSecurityPolicy::GetDirectiveName(effective_type);
  init->setViolatedDirective(effective_directive);
  init->setEffectiveDirective(effective_directive);
  init->setOriginalPolicy(header);
  init->setDisposition(
      header_type == ContentSecurityPolicyType::kEnforce
          ? securitypolicyviolation_disposition_names::kEnforce
          : securitypolicyviolation_disposition_names::kReport);
  init->setStatusCode(0);

  // See https://w3c.github.io/webappsec-csp/#create-violation-for-global.
  // Step 3. If global is a Window object, set violation’s referrer to global’s
  // document's referrer. [spec text]
  String referrer = delegate->GetDocumentReferrer();
  if (referrer)
    init->setReferrer(referrer);

  // Step 4. Set violation’s status to the HTTP status code for the resource
  // associated with violation’s global object. [spec text]
  std::optional<uint16_t> status_code = delegate->GetStatusCode();
  if (status_code)
    init->setStatusCode(*status_code);

  // If no source location is provided, use the source location from the
  // |delegate|.
  // Step 2. If the user agent is currently executing script, and can extract a
  // source file’s URL, line number, and column number from the global, set
  // violation’s source file, line number, and column number accordingly.
  // [spec text]
  if (!source_location)
    source_location = delegate->GetSourceLocation();
  if (source_location && source_location->LineNumber()) {
    KURL source_url = KURL(source_location->Url());
    // The source file might be a script loaded from a redirect. Web browser
    // usually tries to hide post-redirect information. The script might be
    // cross-origin with the document, but also with other scripts. As a result,
    // everything is cleared no matter the |source_url| origin.
    // See https://crbug.com/1074317
    //
    // Note: The username, password and ref are stripped later below by
    // StripURLForUseInReport(..)
    source_url.SetQuery(String());

    // The |source_url| is the URL of the script that triggered the CSP
    // violation. It is the URL pre-redirect. So it is safe to expose it in
    // reports without leaking any new informations to the document. See
    // https://crrev.com/c/2187792.
    String source_file = StripURLForUseInReport(delegate->GetSecurityOrigin(),
                                                source_url, effective_type);

    init->setSourceFile(source_file);
    init->setLineNumber(source_location->LineNumber());
    init->setColumnNumber(source_location->ColumnNumber());
  } else {
    init->setSourceFile(String());
    init->setLineNumber(0);
    init->setColumnNumber(0);
  }

  // Build the sample string. CSP demands that the sample is restricted to
  // 40 characters (kMaxSampleLength), to prevent inadvertent exfiltration of
  // user data. For some use cases, we also have a sample prefix, which
  // must not depend on user data and where we will apply the sample limit
  // separately.
  StringBuilder sample;
  if (!sample_prefix.empty()) {
    sample.Append(sample_prefix.StripWhiteSpace().Left(
        ContentSecurityPolicy::kMaxSampleLength));
    sample.Append("|");
  }
  if (!script_source.empty()) {
    sample.Append(script_source.StripWhiteSpace().Left(
        ContentSecurityPolicy::kMaxSampleLength));
  }
  if (!sample.empty())
    init->setSample(sample.ToString());

  return source_location;
}
}  // namespace

void ContentSecurityPolicy::ReportViolation(
    const String& directive_text,
    CSPDirectiveName effective_type,
    const String& console_message,
    const KURL& blocked_url,
    const Vector<String>& report_endpoints,
    bool use_reporting_api,
    const String& header,
    ContentSecurityPolicyType header_type,
    ContentSecurityPolicyViolationType violation_type,
    std::unique_ptr<SourceLocation> source_location,
    LocalFrame* context_frame,
    Element* element,
    const String& source,
    const String& source_prefix,
    std::optional<base::UnguessableToken> issue_id) {
  DCHECK(violation_type == kURLViolation || blocked_url.IsEmpty());

  // TODO(crbug.com/1279745): Remove/clarify what this block is about.
  if (!delegate_ && !context_frame) {
    DCHECK(effective_type == CSPDirectiveName::ChildSrc ||
           effective_type == CSPDirectiveName::FrameSrc ||
           effective_type == CSPDirectiveName::TrustedTypes ||
           effective_type == CSPDirectiveName::RequireTrustedTypesFor ||
           effective_type == CSPDirectiveName::FencedFrameSrc);
    return;
  }
  DCHECK(
      (delegate_ && !context_frame) ||
      ((effective_type == CSPDirectiveName::FrameAncestors) && context_frame));

  SecurityPolicyViolationEventInit* violation_data =
      SecurityPolicyViolationEventInit::Create();

  // If we're processing 'frame-ancestors', use the delegate for the
  // |context_frame|'s document to gather data. Otherwise, use the policy's
  // |delegate_|.
  ContentSecurityPolicyDelegate* relevant_delegate =
      context_frame
          ? &context_frame->DomWindow()->GetContentSecurityPolicyDelegate()
          : delegate_.Get();
  DCHECK(relevant_delegate);
  // Let GatherSecurityPolicyViolationEventData decide which source location to
  // report.
  source_location = GatherSecurityPolicyViolationEventData(
      violation_data, relevant_delegate, directive_text, effective_type,
      blocked_url, header, header_type, violation_type,
      std::move(source_location), source, source_prefix);

  // TODO(mkwst): Obviously, we shouldn't hit this check, as extension-loaded
  // resources should be allowed regardless. We apparently do, however, so
  // we should at least stop spamming reporting endpoints. See
  // https://crbug.com/524356 for detail.
  if (!violation_data->sourceFile().empty() &&
      ShouldBypassContentSecurityPolicy(KURL(violation_data->sourceFile()))) {
    return;
  }

  PostViolationReport(violation_data, context_frame, report_endpoints,
                      use_reporting_api);

  // Fire a violation event if we're working with a delegate and we don't have a
  // `context_frame` (i.e. we're not processing 'frame-ancestors').
  if (delegate_ && !context_frame)
    delegate_->DispatchViolationEvent(*violation_data, element);

  AuditsIssue audits_issue = AuditsIssue::CreateContentSecurityPolicyIssue(
      *violation_data, header_type == ContentSecurityPolicyType::kReport,
      violation_type, context_frame, element, source_location.get(), issue_id);

  if (context_frame) {
    context_frame->DomWindow()->AddInspectorIssue(std::move(audits_issue));
  } else if (delegate_) {
    delegate_->AddInspectorIssue(std::move(audits_issue));
  }
}

void ContentSecurityPolicy::PostViolationReport(
    const SecurityPolicyViolationEventInit* violation_data,
    LocalFrame* context_frame,
    const Vector<String>& report_endpoints,
    bool use_reporting_api) {
  // We need to be careful here when deciding what information to send to the
  // report-uri. Currently, we send only the current document's URL and the
  // directive that was violated. The document's URL is safe to send because
  // it's the document itself that's requesting that it be sent. You could
  // make an argument that we shouldn't send HTTPS document URLs to HTTP
  // report-uris (for the same reasons that we supress the Referer in that
  // case), but the Referer is sent implicitly whereas this request is only
  // sent explicitly. As for which directive was violated, that's pretty
  // harmless information.
  //
  // TODO(mkwst): This justification is BS. Insecure reports are mixed content,
  // let's kill them. https://crbug.com/695363

  auto csp_report = std::make_unique<JSONObject>();
  csp_report->SetString("document-uri", violation_data->documentURI());
  csp_report->SetString("referrer", violation_data->referrer());
  csp_report->SetString("violated-directive",
                        violation_data->violatedDirective());
  csp_report->SetString("effective-directive",
                        violation_data->effectiveDirective());
  csp_report->SetString("original-policy", violation_data->originalPolicy());
  csp_report->SetString("disposition",
                        violation_data->disposition().AsString());
  csp_report->SetString("blocked-uri", violation_data->blockedURI());
  if (violation_data->lineNumber())
    csp_report->SetInteger("line-number", violation_data->lineNumber());
  if (violation_data->columnNumber())
    csp_report->SetInteger("column-number", violation_data->columnNumber());
  if (!violation_data->sourceFile().empty())
    csp_report->SetString("source-file", violation_data->sourceFile());
  csp_report->SetInteger("status-code", violation_data->statusCode());

  csp_report->SetString("script-sample", violation_data->sample());

  auto report_object = std::make_unique<JSONObject>();
  report_object->SetObject("csp-report", std::move(csp_report));
  String stringified_report = report_object->ToJSONString();

  // Only POST unique reports to the external endpoint; repeated reports add no
  // value on the server side, as they're indistinguishable. Note that we'll
  // fire the DOM event for every violation, as the page has enough context to
  // react in some reasonable way to each violation as it occurs.
  if (ShouldSendViolationReport(stringified_report)) {
    DidSendViolationReport(stringified_report);

    // If we're processing 'frame-ancestors', use the delegate for the
    // |context_frame|'s document to post violation report. Otherwise, use the
    // policy's |delegate_|.
    bool is_frame_ancestors_violation = !!context_frame;
    ContentSecurityPolicyDelegate* relevant_delegate =
        is_frame_ancestors_violation
            ? &context_frame->DomWindow()->GetContentSecurityPolicyDelegate()
            : delegate_.Get();
    DCHECK(relevant_delegate);

    relevant_delegate->PostViolationReport(*violation_data, stringified_report,
                                           is_frame_ancestors_violation,
                                           report_endpoints, use_reporting_api);
  }
}

void ContentSecurityPolicy::ReportMixedContent(const KURL& blocked_url,
                                               RedirectStatus redirect_status) {
  for (const auto& policy : policies_) {
    if (policy->block_all_mixed_content) {
      ReportViolation(GetDirectiveName(CSPDirectiveName::BlockAllMixedContent),
                      CSPDirectiveName::BlockAllMixedContent, String(),
                      blocked_url, policy->report_endpoints,
                      policy->use_reporting_api, policy->header->header_value,
                      policy->header->type,
                      ContentSecurityPolicyViolationType::kURLViolation,
                      std::unique_ptr<SourceLocation>(),
                      /*contextFrame=*/nullptr);
    }
  }
}

void ContentSecurityPolicy::ReportReportOnlyInMeta(const String& header) {
  LogToConsole("The report-only Content Security Policy '" + header +
               "' was delivered via a <meta> element, which is disallowed. The "
               "policy has been ignored.");
}

void ContentSecurityPolicy::ReportMetaOutsideHead(const String& header) {
  LogToConsole("The Content Security Policy '" + header +
               "' was delivered via a <meta> element outside the document's "
               "<head>, which is disallowed. The policy has been ignored.");
}

void ContentSecurityPolicy::LogToConsole(const String& message,
                                         mojom::ConsoleMessageLevel level) {
  LogToConsole(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kSecurity, level, message));
}

mojom::blink::ContentSecurityPolicyViolationType
ContentSecurityPolicy::BuildCSPViolationType(
    ContentSecurityPolicyViolationType violation_type) {
  switch (violation_type) {
    case blink::ContentSecurityPolicyViolationType::kEvalViolation:
      return mojom::blink::ContentSecurityPolicyViolationType::kEvalViolation;
    case blink::ContentSecurityPolicyViolationType::kWasmEvalViolation:
      return mojom::blink::ContentSecurityPolicyViolationType::
          kWasmEvalViolation;
    case blink::ContentSecurityPolicyViolationType::kInlineViolation:
      return mojom::blink::ContentSecurityPolicyViolationType::kInlineViolation;
    case blink::ContentSecurityPolicyViolationType::
        kTrustedTypesPolicyViolation:
      return mojom::blink::ContentSecurityPolicyViolationType::
          kTrustedTypesPolicyViolation;
    case blink::ContentSecurityPolicyViolationType::kTrustedTypesSinkViolation:
      return mojom::blink::ContentSecurityPolicyViolationType::
          kTrustedTypesSinkViolation;
    case blink::ContentSecurityPolicyViolationType::kURLViolation:
      return mojom::blink::ContentSecurityPolicyViolationType::kURLViolation;
  }
}

void ContentSecurityPolicy::LogToConsole(ConsoleMessage* console_message,
                                         LocalFrame* frame) {
  if (frame)
    frame->DomWindow()->AddConsoleMessage(console_message);
  else if (delegate_)
    delegate_->AddConsoleMessage(console_message);
  else
    console_messages_.push_back(console_message);
}

void ContentSecurityPolicy::ReportBlockedScriptExecutionToInspector(
    const String& directive_text) const {
  if (delegate_)
    delegate_->ReportBlockedScriptExecutionToInspector(directive_text);
}

bool ContentSecurityPolicy::ExperimentalFeaturesEnabled() const {
  return RuntimeEnabledFeatures::
      ExperimentalContentSecurityPolicyFeaturesEnabled();
}

bool ContentSecurityPolicy::RequiresTrustedTypes() const {
  return base::ranges::any_of(policies_, [](const auto& policy) {
    return !CSPDirectiveListIsReportOnly(*policy) &&
           CSPDirectiveListRequiresTrustedTypes(*policy);
  });
}

// static
bool ContentSecurityPolicy::ShouldBypassMainWorldDeprecated(
    const ExecutionContext* context) {
  if (!context)
    return false;

  return ShouldBypassMainWorldDeprecated(context->GetCurrentWorld());
}

// static
bool ContentSecurityPolicy::ShouldBypassMainWorldDeprecated(
    const DOMWrapperWorld* world) {
  if (!world || !world->IsIsolatedWorld())
    return false;

  return IsolatedWorldCSP::Get().HasContentSecurityPolicy(world->GetWorldId());
}

bool ContentSecurityPolicy::ShouldSendViolationReport(
    const String& report) const {
  // Collisions have no security impact, so we can save space by storing only
  // the string's hash rather than the whole report.
  return !violation_reports_sent_.Contains(report.Impl()->GetHash());
}

void ContentSecurityPolicy::DidSendViolationReport(const String& report) {
  violation_reports_sent_.insert(report.Impl()->GetHash());
}

const char* ContentSecurityPolicy::GetDirectiveName(CSPDirectiveName type) {
  switch (type) {
    case CSPDirectiveName::BaseURI:
      return "base-uri";
    case CSPDirectiveName::BlockAllMixedContent:
      return "block-all-mixed-content";
    case CSPDirectiveName::ChildSrc:
      return "child-src";
    case CSPDirectiveName::ConnectSrc:
      return "connect-src";
    case CSPDirectiveName::DefaultSrc:
      return "default-src";
    case CSPDirectiveName::FencedFrameSrc:
      return "fenced-frame-src";
    case CSPDirectiveName::FontSrc:
      return "font-src";
    case CSPDirectiveName::FormAction:
      return "form-action";
    case CSPDirectiveName::FrameAncestors:
      return "frame-ancestors";
    case CSPDirectiveName::FrameSrc:
      return "frame-src";
    case CSPDirectiveName::ImgSrc:
      return "img-src";
    case CSPDirectiveName::ManifestSrc:
      return "manifest-src";
    case CSPDirectiveName::MediaSrc:
      return "media-src";
    case CSPDirectiveName::ObjectSrc:
      return "object-src";
    case CSPDirectiveName::ReportTo:
      return "report-to";
    case CSPDirectiveName::ReportURI:
      return "report-uri";
    case CSPDirectiveName::RequireTrustedTypesFor:
      return "require-trusted-types-for";
    case CSPDirectiveName::Sandbox:
      return "sandbox";
    case CSPDirectiveName::ScriptSrc:
      return "script-src";
    case CSPDirectiveName::ScriptSrcAttr:
      return "script-src-attr";
    case CSPDirectiveName::ScriptSrcElem:
      return "script-src-elem";
    case CSPDirectiveName::StyleSrc:
      return "style-src";
    case CSPDirectiveName::StyleSrcAttr:
      return "style-src-attr";
    case CSPDirectiveName::StyleSrcElem:
      return "style-src-elem";
    case CSPDirectiveName::TreatAsPublicAddress:
      return "treat-as-public-address";
    case CSPDirectiveName::TrustedTypes:
      return "trusted-types";
    case CSPDirectiveName::UpgradeInsecureRequests:
      return "upgrade-insecure-requests";
    case CSPDirectiveName::WorkerSrc:
      return "worker-src";

    case CSPDirectiveName::Unknown:
      NOTREACHED();
  }

  NOTREACHED();
}

CSPDirectiveName ContentSecurityPolicy::GetDirectiveType(const String& name) {
  if (name == "base-uri")
    return CSPDirectiveName::BaseURI;
  if (name == "block-all-mixed-content")
    return CSPDirectiveName::BlockAllMixedContent;
  if (name == "child-src")
    return CSPDirectiveName::ChildSrc;
  if (name == "connect-src")
    return CSPDirectiveName::ConnectSrc;
  if (name == "default-src")
    return CSPDirectiveName::DefaultSrc;
  if (name == "fenced-frame-src")
    return CSPDirectiveName::FencedFrameSrc;
  if (name == "font-src")
    return CSPDirectiveName::FontSrc;
  if (name == "form-action")
    return CSPDirectiveName::FormAction;
  if (name == "frame-ancestors")
    return CSPDirectiveName::FrameAncestors;
  if (name == "frame-src")
    return CSPDirectiveName::FrameSrc;
  if (name == "img-src")
    return CSPDirectiveName::ImgSrc;
  if (name == "manifest-src")
    return CSPDirectiveName::ManifestSrc;
  if (name == "media-src")
    return CSPDirectiveName::MediaSrc;
  if (name == "object-src")
    return CSPDirectiveName::ObjectSrc;
  if (name == "report-to")
    return CSPDirectiveName::ReportTo;
  if (name == "report-uri")
    return CSPDirectiveName::ReportURI;
  if (name == "require-trusted-types-for")
    return CSPDirectiveName::RequireTrustedTypesFor;
  if (name == "sandbox")
    return CSPDirectiveName::Sandbox;
  if (name == "script-src")
    return CSPDirectiveName::ScriptSrc;
  if (name == "script-src-attr")
    return CSPDirectiveName::ScriptSrcAttr;
  if (name == "script-src-elem")
    return CSPDirectiveName::ScriptSrcElem;
  if (name == "style-src")
    return CSPDirectiveName::StyleSrc;
  if (name == "style-src-attr")
    return CSPDirectiveName::StyleSrcAttr;
  if (name == "style-src-elem")
    return CSPDirectiveName::StyleSrcElem;
  if (name == "treat-as-public-address")
    return CSPDirectiveName::TreatAsPublicAddress;
  if (name == "trusted-types")
    return CSPDirectiveName::TrustedTypes;
  if (name == "upgrade-insecure-requests")
    return CSPDirectiveName::UpgradeInsecureRequests;
  if (name == "worker-src")
    return CSPDirectiveName::WorkerSrc;

  return CSPDirectiveName::Unknown;
}

bool ContentSecurityPolicy::ShouldBypassContentSecurityPolicy(
    const KURL& url,
    SchemeRegistry::PolicyAreas area) const {
  bool should_bypass_csp;
  if (SecurityOrigin::ShouldUseInnerURL(url)) {
    should_bypass_csp = SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
        SecurityOrigin::ExtractInnerURL(url).Protocol(), area);
    if (should_bypass_csp) {
      Count(WebFeature::kInnerSchemeBypassesCSP);
    }
  } else {
    should_bypass_csp = SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
        url.Protocol(), area);
  }
  if (should_bypass_csp) {
    Count(WebFeature::kSchemeBypassesCSP);
  }

  return should_bypass_csp;
}

const WTF::Vector<network::mojom::blink::ContentSecurityPolicyPtr>&
ContentSecurityPolicy::GetParsedPolicies() const {
  return policies_;
}

bool ContentSecurityPolicy::HasPolicyFromSource(
    ContentSecurityPolicySource source) const {
  for (const auto& policy : policies_) {
    if (policy->header->source == source)
      return true;
  }
  return false;
}

bool ContentSecurityPolicy::AllowFencedFrameOpaqueURL() const {
  for (const auto& policy : GetParsedPolicies()) {
    if (!AllowOpaqueFencedFrames(policy)) {
      return false;
    }
  }
  return true;
}

bool ContentSecurityPolicy::HasEnforceFrameAncestorsDirectives() {
  return base::ranges::any_of(policies_, [](const auto& csp) {
    return csp->header->type ==
               network::mojom::ContentSecurityPolicyType::kEnforce &&
           csp->directives.Contains(
               network::mojom::CSPDirectiveName::FrameAncestors);
  });
}

void ContentSecurityPolicy::Count(WebFeature feature) const {
  if (delegate_)
    delegate_->Count(feature);
}

}  // namespace blink

"""


```