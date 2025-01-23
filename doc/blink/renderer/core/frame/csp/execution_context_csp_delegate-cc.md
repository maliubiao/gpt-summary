Response:
Let's break down the thought process to analyze the `ExecutionContextCSPDelegate.cc` file and generate the comprehensive response.

1. **Understand the Core Purpose:** The file name itself is a strong clue: `ExecutionContextCSPDelegate`. "Delegate" often signifies an object that handles responsibilities on behalf of another. "ExecutionContext" likely refers to a context where code runs (like a browser tab or a worker). "CSP" stands for Content Security Policy. Therefore, the fundamental purpose is to manage CSP-related actions within different execution contexts.

2. **Identify Key Dependencies (Includes):**  The `#include` directives provide immediate insights into what this class interacts with. I'd scan these for relevant terms:
    * `network/public/cpp/web_sandbox_flags.h`, `network/public/mojom/web_sandbox_flags.mojom-blink.h`:  Sandboxing.
    * `public/common/security_context/insecure_request_policy.h`, `public/mojom/security_context/insecure_request_policy.mojom-blink.h`: Handling insecure requests (like HTTP on a HTTPS page).
    * `public/mojom/devtools/inspector_issue.mojom-blink.h`: Reporting issues to developer tools.
    * `public/mojom/frame/frame.mojom-blink.h`: Interacting with frames.
    * `bindings/core/v8/capture_source_location.h`:  Capturing the location of code.
    * `core/dom/document.h`: Working with the DOM.
    * `core/events/security_policy_violation_event.h`:  Handling CSP violations.
    * `core/execution_context/execution_context.h`, `core/execution_context/security_context.h`: The core context and its security aspects.
    * `core/frame/csp/csp_violation_report_body.h`: Creating reports for CSP violations.
    * `core/frame/local_dom_window.h`, `core/frame/local_frame.h`, `core/frame/local_frame_client.h`, `core/frame/report.h`, `core/frame/reporting_context.h`:  Frame-related structures and reporting mechanisms.
    * `core/inspector/inspector_audits_issue.h`: Reporting audit issues.
    * `core/loader/document_loader.h`, `core/loader/ping_loader.h`: Loading resources and sending reports.
    * `core/probe/core_probes.h`:  Instrumentation and debugging.
    * `core/workers/worker_global_scope.h`, `core/workers/worklet_global_scope.h`: Handling CSP in workers and worklets.
    * `platform/bindings/source_location.h`: Source code location.
    * `platform/instrumentation/use_counter.h`: Tracking feature usage.
    * `platform/network/encoded_form_data.h`: Encoding data for reports.
    * `platform/weborigin/security_origin.h`:  Security origins.

3. **Analyze Key Methods:**  Go through the public methods of the class and understand their roles:
    * `ExecutionContextCSPDelegate(ExecutionContext& execution_context)`: Constructor, associating the delegate with an execution context.
    * `Trace(Visitor* visitor) const`: For Blink's tracing system.
    * `GetSecurityOrigin()`: Returns the security origin of the context.
    * `Url() const`: Returns the URL of the context.
    * `SetSandboxFlags(network::mojom::blink::WebSandboxFlags mask)`: Applies sandbox restrictions. Note the comments about timing and worker/worklet differences.
    * `SetRequireTrustedTypes()`: Enforces Trusted Types.
    * `AddInsecureRequestPolicy(mojom::blink::InsecureRequestPolicy policy)`: Handles "Upgrade Insecure Requests."
    * `GetSourceLocation()`: Gets the location of the code.
    * `GetStatusCode()`: Retrieves the HTTP status code (if available).
    * `GetDocumentReferrer()`: Gets the document referrer (if available).
    * `DispatchViolationEvent(const SecurityPolicyViolationEventInit& violation_data, Element* element)`:  Dispatches a CSP violation event.
    * `PostViolationReport(...)`: Sends a report about a CSP violation.
    * `Count(WebFeature feature)`: Tracks usage of specific web features.
    * `AddConsoleMessage(ConsoleMessage* console_message)`: Logs a message to the console.
    * `AddInspectorIssue(AuditsIssue issue)`: Reports an issue to the inspector.
    * `DisableEval(const String& error_message)`: Disables `eval()`.
    * `SetWasmEvalErrorMessage(const String& error_message)`: Sets the error message for blocked WebAssembly `eval()`.
    * `ReportBlockedScriptExecutionToInspector(const String& directive_text)`:  Informs the inspector about blocked scripts.
    * `DidAddContentSecurityPolicies(...)`:  Called when CSP policies are added.
    * `GetSecurityContext()`: Returns the security context.
    * `GetDocument()`: Returns the document (if available).
    * `DispatchViolationEventInternal(...)`:  The internal implementation for dispatching violation events.

4. **Connect Methods to Functionality:** Now, link the methods to their overall function within the CSP framework. For example:
    * Methods like `DispatchViolationEvent` and `PostViolationReport` are clearly central to handling CSP violations.
    * `SetSandboxFlags` and `AddInsecureRequestPolicy` are about enforcing security directives.
    * `DisableEval` and `SetWasmEvalErrorMessage` relate to controlling JavaScript and WebAssembly execution.

5. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**  Think about how CSP interacts with these technologies:
    * **JavaScript:** CSP can block inline scripts, `eval()`, and dynamically created scripts. `DisableEval`, `SetWasmEvalErrorMessage`, and `ReportBlockedScriptExecutionToInspector` directly relate to this.
    * **HTML:** CSP is often delivered via HTTP headers or `<meta>` tags in HTML. The `DidAddContentSecurityPolicies` method touches on this. The sandbox flags can also restrict HTML features.
    * **CSS:** CSP can restrict the loading of stylesheets and the use of inline styles. While not explicitly mentioned in the method names, the general blocking of resources applies to CSS.

6. **Formulate Examples:** Create concrete examples to illustrate the connections:
    * **JavaScript Blocking:** Show how a CSP directive like `script-src 'self'` would cause `DispatchViolationEvent` and potentially `PostViolationReport` if an inline script is encountered.
    * **HTML `meta` tag:** Demonstrate how a `<meta>` tag setting CSP would be processed (related to `DidAddContentSecurityPolicies`).
    * **CSS Blocking:** While not explicitly a method's direct action, explain how CSP could prevent a stylesheet from loading, leading to a violation report.

7. **Consider Logical Reasoning (Input/Output):**  For methods that involve decision-making or state changes, consider the inputs and expected outputs. For instance, `AddInsecureRequestPolicy`:
    * **Input:**  A policy like `mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests`.
    * **Output:** The security context's insecure request policy is updated, and potentially the frame is notified. The `Count` function is called.

8. **Think About User/Programming Errors:**  Identify common mistakes developers might make related to CSP:
    * **Incorrectly configured CSP:** Leading to blocking of legitimate resources.
    * **Forgetting to include 'unsafe-inline' or 'unsafe-eval' when needed (and understanding the security implications).**
    * **Misunderstanding how CSP directives cascade or are inherited.**

9. **Structure the Response:** Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Detail the core functionalities with explanations.
    * Provide clear examples relating to JavaScript, HTML, and CSS.
    * Include input/output examples for logical methods.
    * Outline common user/programming errors.

10. **Review and Refine:**  Read through the generated response, checking for clarity, accuracy, and completeness. Ensure the examples are easy to understand and directly relate to the methods and concepts discussed. For example, initially, I might just say "handles CSP violations," but refining it means listing the *specific* actions like dispatching events and posting reports. Also, ensure that the connection between the included headers and the described functionality is clear.
这个文件 `execution_context_csp_delegate.cc` 是 Chromium Blink 引擎中负责处理内容安全策略 (CSP) 相关的逻辑的代理类。它充当了 `ExecutionContext`（例如，一个文档、一个 Worker）和实际的 CSP 执行逻辑之间的桥梁。

以下是它的主要功能，以及与 JavaScript、HTML 和 CSS 的关系，逻辑推理示例，以及常见的使用错误：

**核心功能:**

1. **CSP 策略实施:**
   - 它负责获取与当前 `ExecutionContext` 关联的 CSP 策略。
   - 它会根据 CSP 策略检查各种操作，例如：
     - 加载外部资源 (脚本、样式表、图像、字体等)。
     - 执行内联脚本或样式。
     - 使用 `eval()` 等动态代码执行机制。
     - 提交表单到特定的 URL。
     - 嵌入 `<frame>` 或 `<iframe>` 等子框架。
   - 如果某个操作违反了 CSP 策略，它会采取相应的措施，例如阻止该操作。

2. **CSP 违规报告:**
   - 当检测到 CSP 违规时，它会生成并发送违规报告。
   - 报告可以发送到一个或多个指定的 URI（通过 `report-uri` 或 `report-to` 指令）。
   - 报告包含了违规的详细信息，例如被阻止的资源 URL、违反的指令等。

3. **沙箱标志管理:**
   - 它负责设置和管理与 `ExecutionContext` 相关的沙箱标志。
   - 这些标志可以限制某些 Web 功能，例如脚本执行、表单提交等。
   - CSP 可以通过 `sandbox` 指令来设置这些标志。

4. **不安全请求策略处理 (Upgrade Insecure Requests):**
   - 它处理 `upgrade-insecure-requests` 指令，该指令指示浏览器将页面上的所有 HTTP URL 视为 HTTPS URL。

5. **Trusted Types 支持:**
   - 它处理与 Trusted Types 相关的策略，用于防止基于 DOM 的跨站点脚本攻击 (XSS)。

6. **开发者工具集成:**
   - 它会将 CSP 违规信息报告给 Chrome 的开发者工具，方便开发者调试。

7. **性能计数和监控:**
   - 它使用 `UseCounter` 来跟踪 CSP 相关特性的使用情况。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - **阻止内联脚本:** 如果 CSP 策略中没有 `'unsafe-inline'`，该代理会阻止 HTML 中的 `<script>` 标签内的 JavaScript 代码执行。
      ```html
      <!-- 如果 CSP 中没有 'unsafe-inline'，以下代码会被阻止 -->
      <script>
        console.log("This script might be blocked by CSP.");
      </script>
      ```
      **假设输入:**  HTML 页面包含内联 `<script>`，CSP 策略为 `script-src 'self'`.
      **输出:**  浏览器阻止脚本执行，并在控制台输出 CSP 违规报告。
    - **阻止 `eval()` 等动态代码执行:** 如果 CSP 策略中没有 `'unsafe-eval'`，该代理会阻止 `eval()`、`Function()` 构造函数等的使用。
      ```javascript
      // 如果 CSP 中没有 'unsafe-eval'，以下代码会被阻止
      eval("console.log('This will be blocked.');");
      ```
      **假设输入:** JavaScript 代码中调用了 `eval()`，CSP 策略为 `script-src 'self'`.
      **输出:** 浏览器阻止 `eval()` 执行，并在控制台输出 CSP 违规报告。
    - **报告脚本阻塞事件到 Inspector:** 当脚本执行被 CSP 阻止时，该代理会将信息发送到开发者工具。

* **HTML:**
    - **处理 `<meta>` 标签中的 CSP:**  虽然这个文件本身不直接解析 `<meta>` 标签，但它处理的 CSP 策略可能来源于 HTML 中的 `<meta>` 标签。`DidAddContentSecurityPolicies` 方法会记录 CSP 的来源 (HTTP Header 或 Meta 标签)。
      ```html
      <meta http-equiv="Content-Security-Policy" content="script-src 'self'">
      ```
    - **阻止加载外部脚本:** 如果 CSP 策略限制了脚本来源，该代理会阻止加载来自未授权域的外部脚本。
      ```html
      <!-- 如果 CSP 中不允许 example.com，以下脚本加载会被阻止 -->
      <script src="https://example.com/script.js"></script>
      ```
      **假设输入:** HTML 页面引用了来自 `example.com` 的脚本，CSP 策略为 `script-src 'self'`.
      **输出:** 浏览器阻止脚本加载，并在控制台输出 CSP 违规报告。
    - **处理 `<iframe>` 的 `sandbox` 属性:**  CSP 的 `sandbox` 指令与 `<iframe>` 标签的 `sandbox` 属性相关，该代理负责应用这些沙箱限制。

* **CSS:**
    - **阻止内联样式:** 如果 CSP 策略中没有 `'unsafe-inline'`，该代理会阻止 HTML 标签的 `style` 属性中的 CSS 代码。
      ```html
      <!-- 如果 CSP 中没有 'unsafe-inline'，以下样式可能不会生效 -->
      <div style="color: red;">This text might not be red.</div>
      ```
      **假设输入:** HTML 元素包含内联 `style` 属性，CSP 策略为 `style-src 'self'`.
      **输出:** 浏览器阻止内联样式的应用，并在控制台输出 CSP 违规报告。
    - **阻止加载外部样式表:** 如果 CSP 策略限制了样式表来源，该代理会阻止加载来自未授权域的外部样式表。
      ```html
      <!-- 如果 CSP 中不允许 example.com，以下样式表加载会被阻止 -->
      <link rel="stylesheet" href="https://example.com/style.css">
      ```
      **假设输入:** HTML 页面引用了来自 `example.com` 的样式表，CSP 策略为 `style-src 'self'`.
      **输出:** 浏览器阻止样式表加载，并在控制台输出 CSP 违规报告。

**逻辑推理的假设输入与输出:**

* **假设输入:** 用户尝试加载一个来自 `https://evil.com/malicious.js` 的脚本，而当前页面的 CSP 策略为 `script-src 'self'`.
* **输出:** `ExecutionContextCSPDelegate` 会检测到违反了 `script-src` 指令，阻止脚本的加载，并可能发送一个 CSP 违规报告到配置的报告 URI。控制台也会显示一个错误信息。

* **假设输入:** 用户在一个网页上执行了 `eval("2 + 2")`，而当前页面的 CSP 策略为 `script-src 'self'`.
* **输出:** `ExecutionContextCSPDelegate` 会检测到违反了缺少 `'unsafe-eval'` 的 `script-src` 指令，阻止 `eval()` 的执行，并可能发送一个 CSP 违规报告。控制台会显示一个错误信息。

**涉及用户或编程常见的使用错误:**

1. **配置过于严格的 CSP:** 开发者可能会设置一个过于严格的 CSP 策略，导致浏览器阻止了合法的资源或代码，从而破坏网站功能。例如，忘记添加 `'self'` 到 `script-src` 可能会阻止网站自己的脚本运行。

   ```
   // 错误示例：阻止了同源的脚本
   Content-Security-Policy: script-src 'none'
   ```
   **结果:** 网站上的所有脚本都无法运行。

2. **忘记添加 `'unsafe-inline'` 或 `'unsafe-eval'`:** 在某些情况下，可能需要使用内联脚本或 `eval()`，如果忘记在 CSP 中添加相应的关键字，会导致功能失效。然而，需要理解这些关键字会降低 CSP 的安全性，应该谨慎使用。

3. **混合内容错误 (Mixed Content):**  在 HTTPS 页面上加载 HTTP 资源会被 CSP 阻止（除非有特定的策略允许）。开发者可能不小心在 HTTPS 网站上使用了 HTTP 链接。

   ```html
   <!-- 在 HTTPS 页面上，以下图片加载可能被阻止 -->
   <img src="http://example.com/image.jpg">
   ```
   **结果:** 图片可能无法加载，并在控制台显示混合内容错误。

4. **报告 URI 配置错误:** 如果开发者配置了 `report-uri` 或 `report-to` 但配置错误（例如，URI 不存在或服务器无法接收报告），则 CSP 违规报告将无法发送。

5. **对 CSP 的理解不足:** 开发者可能不完全理解 CSP 指令及其作用，导致配置不当或安全漏洞。例如，错误地使用了通配符 `*`。

总而言之，`execution_context_csp_delegate.cc` 是 Blink 引擎中一个至关重要的组件，它负责在各种执行环境中强制执行内容安全策略，保护用户免受跨站点脚本攻击等安全威胁，并与 JavaScript、HTML 和 CSS 的加载和执行密切相关。理解其功能有助于开发者更好地配置和调试 CSP 策略。

### 提示词
```
这是目录为blink/renderer/core/frame/csp/execution_context_csp_delegate.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/csp/execution_context_csp_delegate.h"

#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/security_context/insecure_request_policy.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/events/security_policy_violation_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/csp/csp_violation_report_body.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/report.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/ping_loader.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

ExecutionContextCSPDelegate::ExecutionContextCSPDelegate(
    ExecutionContext& execution_context)
    : execution_context_(&execution_context) {}

void ExecutionContextCSPDelegate::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  ContentSecurityPolicyDelegate::Trace(visitor);
}

const SecurityOrigin* ExecutionContextCSPDelegate::GetSecurityOrigin() {
  return execution_context_->GetSecurityOrigin();
}

const KURL& ExecutionContextCSPDelegate::Url() const {
  return execution_context_->Url();
}

void ExecutionContextCSPDelegate::SetSandboxFlags(
    network::mojom::blink::WebSandboxFlags mask) {
  // Ideally sandbox flags are determined at construction time since
  // sandbox flags influence the security origin and that influences
  // the Agent that is assigned for the ExecutionContext. Changing
  // an ExecutionContext's agent in the middle of an object lifecycle
  // is not permitted.

  // Since Workers and Worklets don't share agents (each one is unique)
  // we allow them to apply new sandbox flags on top of the current ones.
  WorkerOrWorkletGlobalScope* worklet_or_worker =
      DynamicTo<WorkerOrWorkletGlobalScope>(execution_context_.Get());
  if (worklet_or_worker) {
    worklet_or_worker->SetSandboxFlags(mask);
  }
  // Just check that all the sandbox flags that are set by CSP have
  // already been set on the security context. Meta tags can't set them
  // and we should have already constructed the document with the correct
  // sandbox flags from CSP already.
  network::mojom::blink::WebSandboxFlags flags =
      execution_context_->GetSandboxFlags();
  CHECK_EQ(flags | mask, flags);
}

void ExecutionContextCSPDelegate::SetRequireTrustedTypes() {
  execution_context_->SetRequireTrustedTypes();
}

void ExecutionContextCSPDelegate::AddInsecureRequestPolicy(
    mojom::blink::InsecureRequestPolicy policy) {
  SecurityContext& security_context = GetSecurityContext();

  auto* window = DynamicTo<LocalDOMWindow>(execution_context_.Get());

  // Step 2. Set settings’s insecure requests policy to Upgrade. [spec text]
  // Upgrade Insecure Requests: Update the policy.
  security_context.SetInsecureRequestPolicy(
      security_context.GetInsecureRequestPolicy() | policy);
  if (window && window->GetFrame()) {
    window->GetFrame()->GetLocalFrameHostRemote().EnforceInsecureRequestPolicy(
        security_context.GetInsecureRequestPolicy());
  }

  // Upgrade Insecure Requests: Update the set of insecure URLs to upgrade.
  if ((policy &
       mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests) !=
      mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone) {
    // Spec: Enforcing part of:
    // https://w3c.github.io/webappsec-upgrade-insecure-requests/#delivery
    // Step 3. Let tuple be a tuple of the protected resource’s URL's host and
    // port. [spec text]
    // Step 4. Insert tuple into settings’s upgrade insecure navigations set.
    // [spec text]
    Count(WebFeature::kUpgradeInsecureRequestsEnabled);
    // We don't add the hash if |window| is null, to prevent
    // WorkerGlobalScope::Url() before it's ready. https://crbug.com/861564
    // This should be safe, because the insecure navigations set is not used
    // in non-Document contexts.
    if (window && !Url().Host().empty()) {
      uint32_t hash = Url().Host().ToString().Impl()->GetHash();
      security_context.AddInsecureNavigationUpgrade(hash);
      if (auto* frame = window->GetFrame()) {
        frame->GetLocalFrameHostRemote().EnforceInsecureNavigationsSet(
            SecurityContext::SerializeInsecureNavigationSet(
                GetSecurityContext().InsecureNavigationsToUpgrade()));
      }
    }
  }
}

std::unique_ptr<SourceLocation>
ExecutionContextCSPDelegate::GetSourceLocation() {
  return CaptureSourceLocation(execution_context_);
}

std::optional<uint16_t> ExecutionContextCSPDelegate::GetStatusCode() {
  std::optional<uint16_t> status_code;

  // TODO(mkwst): We only have status code information for Documents. It would
  // be nice to get them for Workers as well.
  Document* document = GetDocument();
  if (document && document->Loader())
    status_code = document->Loader()->GetResponse().HttpStatusCode();

  return status_code;
}

String ExecutionContextCSPDelegate::GetDocumentReferrer() {
  String referrer;

  // TODO(mkwst): We only have referrer information for Documents. It would be
  // nice to get them for Workers as well.
  if (Document* document = GetDocument())
    referrer = document->referrer();
  return referrer;
}

void ExecutionContextCSPDelegate::DispatchViolationEvent(
    const SecurityPolicyViolationEventInit& violation_data,
    Element* element) {
  execution_context_->GetTaskRunner(TaskType::kNetworking)
      ->PostTask(
          FROM_HERE,
          WTF::BindOnce(
              &ExecutionContextCSPDelegate::DispatchViolationEventInternal,
              WrapPersistent(this), WrapPersistent(&violation_data),
              WrapPersistent(element)));
}

void ExecutionContextCSPDelegate::PostViolationReport(
    const SecurityPolicyViolationEventInit& violation_data,
    const String& stringified_report,
    bool is_frame_ancestors_violation,
    const Vector<String>& report_endpoints,
    bool use_reporting_api) {
  DCHECK_EQ(is_frame_ancestors_violation,
            network::mojom::blink::CSPDirectiveName::FrameAncestors ==
                ContentSecurityPolicy::GetDirectiveType(
                    violation_data.effectiveDirective()));

  // We do not support reporting for worklets, since they don't have a
  // ResourceFetcher.
  //
  // TODO(https://crbug.com/1222576): Send CSP reports for worklets using the
  // owner document's ResourceFetcher.
  if (DynamicTo<WorkletGlobalScope>(execution_context_.Get()))
    return;

  scoped_refptr<EncodedFormData> report =
      EncodedFormData::Create(stringified_report.Utf8());

  // Construct and route the report to the ReportingContext, to be observed
  // by any ReportingObservers.
  auto* body = MakeGarbageCollected<CSPViolationReportBody>(violation_data);
  String url_sending_report = is_frame_ancestors_violation
                                  ? violation_data.documentURI()
                                  : Url().GetString();
  Report* observed_report = MakeGarbageCollected<Report>(
      ReportType::kCSPViolation, url_sending_report, body);
  ReportingContext::From(execution_context_.Get())
      ->QueueReport(observed_report,
                    use_reporting_api ? report_endpoints : Vector<String>());

  if (use_reporting_api)
    return;

  for (const auto& report_endpoint : report_endpoints) {
    PingLoader::SendViolationReport(execution_context_.Get(),
                                    KURL(report_endpoint), report,
                                    is_frame_ancestors_violation);
  }
}

void ExecutionContextCSPDelegate::Count(WebFeature feature) {
  UseCounter::Count(execution_context_, feature);
}

void ExecutionContextCSPDelegate::AddConsoleMessage(
    ConsoleMessage* console_message) {
  execution_context_->AddConsoleMessage(console_message);
}

void ExecutionContextCSPDelegate::AddInspectorIssue(AuditsIssue issue) {
  execution_context_->AddInspectorIssue(std::move(issue));
}

void ExecutionContextCSPDelegate::DisableEval(const String& error_message) {
  execution_context_->DisableEval(error_message);
}

void ExecutionContextCSPDelegate::SetWasmEvalErrorMessage(
    const String& error_message) {
  execution_context_->SetWasmEvalErrorMessage(error_message);
}

void ExecutionContextCSPDelegate::ReportBlockedScriptExecutionToInspector(
    const String& directive_text) {
  probe::ScriptExecutionBlockedByCSP(execution_context_, directive_text);
}

void ExecutionContextCSPDelegate::DidAddContentSecurityPolicies(
    WTF::Vector<network::mojom::blink::ContentSecurityPolicyPtr> policies) {
  auto* window = DynamicTo<LocalDOMWindow>(execution_context_.Get());
  if (!window)
    return;

  LocalFrame* frame = window->GetFrame();
  if (!frame)
    return;

  // Record what source was used to find main frame CSP. Do not record
  // this for fence frame roots since they will never become an
  // outermost main frame.
  if (frame->IsMainFrame() && !frame->IsInFencedFrameTree()) {
    for (const auto& policy : policies) {
      switch (policy->header->source) {
        case network::mojom::ContentSecurityPolicySource::kHTTP:
          Count(WebFeature::kMainFrameCSPViaHTTP);
          break;
        case network::mojom::ContentSecurityPolicySource::kMeta:
          Count(WebFeature::kMainFrameCSPViaMeta);
          break;
      }
    }
  }
}

SecurityContext& ExecutionContextCSPDelegate::GetSecurityContext() {
  return execution_context_->GetSecurityContext();
}

Document* ExecutionContextCSPDelegate::GetDocument() {
  auto* window = DynamicTo<LocalDOMWindow>(execution_context_.Get());
  return window ? window->document() : nullptr;
}

void ExecutionContextCSPDelegate::DispatchViolationEventInternal(
    const SecurityPolicyViolationEventInit* violation_data,
    Element* element) {
  // Worklets don't support Events in general.
  if (execution_context_->IsWorkletGlobalScope())
    return;

  // https://w3c.github.io/webappsec-csp/#report-violation.
  // Step 3.1. If target is not null, and global is a Window, and target’s
  // shadow-including root is not global’s associated Document, set target to
  // null. [spec text]
  // Step 3.2. If target is null:
  //    Step 3.2.1. Set target be violation’s global object.
  //    Step 3.2.2. If target is a Window, set target to target’s associated
  //    Document. [spec text]
  // Step 3.3. Fire an event named securitypolicyviolation that uses the
  // SecurityPolicyViolationEvent interface at target.. [spec text]
  SecurityPolicyViolationEvent& event = *SecurityPolicyViolationEvent::Create(
      event_type_names::kSecuritypolicyviolation, violation_data);
  DCHECK(event.bubbles());

  if (auto* document = GetDocument()) {
    if (element && element->isConnected() && element->GetDocument() == document)
      element->DispatchEvent(event);
    else
      document->DispatchEvent(event);
  } else if (auto* scope = DynamicTo<WorkerGlobalScope>(*execution_context_)) {
    scope->DispatchEvent(event);
  }
}

}  // namespace blink
```