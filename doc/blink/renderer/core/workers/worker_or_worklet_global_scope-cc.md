Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Request:** The request asks for the functionality of `WorkerOrWorkletGlobalScope.cc`, its relationship to web technologies (JS, HTML, CSS), examples of logic, and common usage errors.

2. **Identify the Core Concept:** The name `WorkerOrWorkletGlobalScope` immediately suggests it's about the global scope within web workers and worklets. This is a foundational piece of information.

3. **Initial Scan for Key Components:** Quickly scan the `#include` directives and the class definition. Notice inclusions like:
    * `WorkerOrWorkletScriptController`:  Handles JavaScript execution.
    * `ResourceFetcher`: Manages network requests.
    * `ContentSecurityPolicyDelegate`:  Deals with security policies.
    * `EventQueue`: Manages events.
    * `WorkerReportingProxy`: Handles communication with the main thread for reporting.

4. **Analyze the Constructor and Destructor:** The constructor reveals important setup steps:
    * Takes arguments related to security origin, agent, name, devtools, fetch context, and more.
    * Initializes `WorkerOrWorkletScriptController`.
    * Sets the security origin and policy container.
    * Potentially reattaches the thread for workers.
    * The destructor handles cleanup, including disposing the script controller and stopping resource fetching.

5. **Categorize Functionality:**  Group the methods based on their apparent purpose. This helps to organize the information:

    * **JavaScript Execution:**  Look for methods related to script control (`script_controller_`, `DisableEval`, `SetWasmEvalErrorMessage`, `CanExecuteScripts`).
    * **Network Requests:** Focus on `ResourceFetcher`, `CreateFetcherInternal`, `CreateOutsideSettingsFetcher`, `FetchModuleScript`, `GetAcceptLanguages`.
    * **Security:** Identify methods related to security policies (`ContentSecurityPolicyDelegate`, `SetSandboxFlags`, `SetOutsideContentSecurityPolicies`, `InitContentSecurityPolicyFromVector`, `BindContentSecurityPolicyToExecutionContext`), and secure context (`HasInsecureContextInAncestors`).
    * **Events:**  Note the `EventTarget` inheritance and the `EventQueue` inclusion.
    * **Metrics and Reporting:** Find methods like `CountUse`, `CountDeprecation`, `CountWebDXFeature`, `ReportingProxy`, and `OnConsoleApiMessage`.
    * **Lifecycle Management:**  Consider the constructor, destructor, `Dispose`.
    * **Configuration and Settings:**  Look for `content_settings_client_`, `v8_cache_options_`.
    * **Module Loading:** The presence of `FetchModuleScript` indicates support for ES modules.
    * **Throttling:**  `GetThrottleOptionOverride`, `UpdateFetcherThrottleOptionOverride`, `GetOutstandingThrottledLimit`.

6. **Connect to Web Technologies:** For each category of functionality, think about how it relates to JavaScript, HTML, and CSS:

    * **JavaScript:**  Directly related through script execution, module loading, and APIs accessible in workers/worklets.
    * **HTML:** Workers are often created from HTML (via `<script>` with `type="module"` or `new Worker()`). The fetching of the worker script itself is related to HTML parsing and loading.
    * **CSS:** While workers don't directly manipulate the DOM, they can fetch CSS files, and CSP can restrict CSS loading. The `FetchModuleScript` could potentially fetch CSS modules in the future (though not explicitly stated here).

7. **Develop Examples:**  For each relationship identified, create concrete examples. Think about typical worker/worklet use cases:

    * **JavaScript:**  `postMessage`, `importScripts`, module imports, `fetch()`.
    * **HTML:**  Creating a worker, linking a module worker script.
    * **CSS:** Fetching stylesheets using `fetch()`, CSP blocking stylesheets.

8. **Identify Logic and Assumptions:**  Look for conditional statements, loops, and key decisions within the code. Focus on interesting parts like:

    * The `OutsideSettingsCSPDelegate`:  How it handles CSP for the initial worker script fetch.
    * The different paths for `ResourceFetcher` initialization (with and without `web_worker_fetch_context_`).
    * The logic for counting features and deprecations.
    * The handling of sandbox flags.

9. **Consider User/Programming Errors:**  Think about common mistakes developers make when working with workers/worklets:

    * Incorrect paths in `importScripts` or module imports.
    * Violating CSP.
    * Forgetting to handle errors in `fetch()`.
    * Trying to access DOM APIs directly in a worker.
    * Security issues like mixing secure and insecure content.

10. **Refine and Structure:** Organize the findings into a clear and logical structure. Use headings and bullet points to improve readability. Ensure the language is precise and avoids jargon where possible. Review the code comments for additional insights. For instance, the comments about "outsideSettings" and "insideSettings" fetches are crucial.

11. **Iterate and Verify:** Briefly reread the code to ensure no major functionalities were missed. Check that the examples are accurate and the explanations are clear. For example, double-checking the purpose of `WorkerReportingProxy` ensures it's accurately described.

By following these steps, you can systematically analyze the C++ code and generate a comprehensive explanation of its functionality and its relationship to web technologies. The key is to move from a high-level understanding to detailed analysis and then back to a structured summary.
This C++ source code file, `worker_or_worklet_global_scope.cc`, within the Chromium Blink rendering engine, defines the `WorkerOrWorkletGlobalScope` class. This class serves as the **base class for the global scope of both web workers and worklets**. It encapsulates the common functionalities and states shared by these two types of JavaScript execution environments that run in separate threads.

Here's a breakdown of its functionalities:

**Core Responsibilities and Features:**

1. **Shared Base for Workers and Worklets:**  It provides a common foundation, reducing code duplication for features that are identical or similar across workers (Dedicated Workers, Shared Workers, Service Workers) and worklets (Animation Worklets, Audio Worklets, Layout Worklets, Paint Worklets, Shared Storage Worklets).

2. **JavaScript Execution Environment Management:**
   - It holds a `WorkerOrWorkletScriptController` which is responsible for managing the execution of JavaScript code within the worker or worklet. This includes compiling, running, and controlling the lifecycle of scripts.
   - It provides methods to disable `eval()` (`DisableEval`) and set error messages for `eval()` and WebAssembly evaluation (`SetWasmEvalErrorMessage`), contributing to security.
   - It determines if scripts can be executed (`CanExecuteScripts`).

3. **Networking and Resource Fetching:**
   - It manages `ResourceFetcher` objects for fetching resources (like scripts, data, etc.) from the network.
   - It handles both "inside settings" fetches (using the global scope's own security context) and "outside settings" fetches (for initial script loading, using settings from the parent context). The `OutsideSettingsCSPDelegate` specifically manages CSP during this initial fetch.
   - It supports fetching JavaScript modules (`FetchModuleScript`).
   - It interacts with `WebWorkerFetchContext` to provide the necessary context for network requests.
   - It handles throttle options for resource loading (`GetThrottleOptionOverride`, `UpdateFetcherThrottleOptionOverride`, `GetOutstandingThrottledLimit`).

4. **Security Context and Policies:**
   - It holds a `SecurityOrigin` representing the origin of the worker/worklet.
   - It manages Content Security Policy (CSP) through `ContentSecurityPolicy` and its delegate. It distinguishes between CSP applied during the initial script fetch and CSP active during normal execution.
   - It allows setting sandbox flags (`SetSandboxFlags`) to restrict the capabilities of the worker/worklet.
   - It tracks if the creator context was secure (`is_creator_secure_context_`) to determine if the worker/worklet has an insecure context in its ancestry.

5. **Event Handling:**
   - It inherits from `EventTarget`, making it capable of dispatching and receiving events. However, the `InterfaceName()` and wrapping methods are intentionally marked as `NOTREACHED()` because the global object itself acts as the wrapper.

6. **Metrics and Feature Usage Tracking:**
   - It includes functionality to count the usage of Web Features (`CountUse`) and deprecated features (`CountDeprecation`), contributing to Chromium's usage statistics.
   - It also tracks WebDX features (`CountWebDXFeature`).

7. **Communication with the Main Thread:**
   - It uses `WorkerReportingProxy` to send console messages, feature usage counts, and other reports back to the main browser process.

8. **Lifecycle Management:**
   - The `Dispose()` method handles the cleanup of resources when the worker or worklet is being destroyed.

9. **Module Loading:**
    - It includes logic for fetching and processing JavaScript modules, crucial for modern web development.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:** This class is fundamental to the execution of JavaScript within workers and worklets. It manages the JavaScript engine's state, handles script loading and execution, and provides access to APIs.
    * **Example:** When a JavaScript worker script calls `fetch()`, the `ResourceFetcher` managed by this class is responsible for making the network request.
    * **Example:** The `DisableEval()` method directly impacts the ability of JavaScript code within the worker/worklet to dynamically execute strings as code.
    * **Example:**  The `FetchModuleScript` method is used when a worker or worklet uses `import` statements to load other JavaScript modules.

* **HTML:**  Workers and worklets are often created from HTML pages.
    * **Example:** When an HTML page creates a new `Worker("my_worker.js")`, the browser will instantiate a `WorkerOrWorkletGlobalScope` (specifically a `DedicatedWorkerGlobalScope`) to run the `my_worker.js` script.
    * **Example:** The initial loading of the worker script is influenced by the HTML's Content Security Policy, which is handled in part by the `OutsideSettingsCSPDelegate`.

* **CSS:** While workers and worklets don't directly manipulate the DOM and styles, they can interact with CSS in certain ways, primarily through fetching CSS files.
    * **Example:** A worker might fetch a CSS file using `fetch()` to analyze its content or use it for some other purpose. The `ResourceFetcher` would handle this.
    * **Example:** The Content Security Policy enforced by this class can restrict the loading of CSS resources, potentially preventing a worker from fetching external stylesheets.

**Logic and Assumptions:**

* **Assumption:** The code assumes that worker and worklet execution happens in separate threads. This is a core principle of web workers and worklets, allowing for parallel execution and avoiding blocking the main browser thread.
* **Assumption:** It assumes a clear distinction between the initial loading of the worker/worklet script (handled with "outside settings") and subsequent resource fetching during its normal execution ("inside settings").
* **Logic (Hypothetical Input/Output for `CanExecuteScripts`):**
    * **Input:** A worker has been created, and no explicit action has been taken to forbid script execution.
    * **Output:** `CanExecuteScripts()` would likely return `true`.
    * **Input:** The worker's Content Security Policy includes a `script-src 'none'` directive.
    * **Output:** `CanExecuteScripts()` would likely return `false`.
    * **Input:** `DisableEval()` has been called on the worker.
    * **Output:** `CanExecuteScripts()` would still return `true` (as the ability to execute scripts generally is not disabled, just `eval()`). However, calls to `eval()` would now throw errors.

**User or Programming Common Usage Errors:**

1. **Incorrectly assuming DOM access:**  A common mistake is trying to access DOM APIs (like `document`, `window`) directly within a worker or worklet. These are not available in these contexts. The `WorkerOrWorkletGlobalScope` doesn't provide direct access to these.

    * **Example Error:**  A JavaScript worker script contains `document.getElementById('myElement').textContent = 'Hello';`. This will result in an error because `document` is undefined in the worker scope.

2. **Violating Content Security Policy:**  If the worker's script or resources it tries to fetch violate the active CSP, the requests will be blocked.

    * **Example Error:** The HTML page has a CSP header `Content-Security-Policy: script-src 'self';` and the worker tries to `importScripts('https://example.com/external.js')`. This will be blocked because `example.com` is not in the `'self'` allowed list. The `OutsideSettingsCSPDelegate` and the regular CSP enforcement within `WorkerOrWorkletGlobalScope` would handle this.

3. **Incorrectly handling asynchronous operations:** Workers heavily rely on asynchronous operations (like `fetch`, `setTimeout`). Forgetting to handle promises or use callbacks correctly can lead to unexpected behavior.

    * **Example Error:** A worker initiates a `fetch()` request but doesn't use `.then()` or `await` to process the response. The worker might proceed without the data, leading to errors.

4. **Security Issues with `eval()`:**  Using `eval()` in workers can introduce security vulnerabilities if the evaluated code comes from an untrusted source. The `DisableEval()` mechanism is a safeguard against this.

    * **Example Error:** A worker receives a string from the main thread via `postMessage` and uses `eval()` on it without proper sanitization. If the main thread is compromised, this could lead to malicious code execution within the worker.

5. **Forgetting to `postMessage` back to the main thread:** Workers operate in isolation. To communicate results back to the main thread, developers need to use the `postMessage()` API.

    * **Example Error:** A worker performs a calculation but doesn't send the result back to the main thread using `postMessage()`, making the worker's computation useless to the main page.

In summary, `WorkerOrWorkletGlobalScope.cc` is a foundational piece of the Blink rendering engine, responsible for managing the core functionalities and security aspects of JavaScript execution within web workers and worklets. It bridges the gap between the browser's infrastructure and the JavaScript runtime environment for these isolated execution contexts.

### 提示词
```
这是目录为blink/renderer/core/workers/worker_or_worklet_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"

#include <utility>

#include "base/metrics/histogram_functions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_sample_collector.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/content_security_notifier.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_security_policy_struct.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_worker_fetch_context.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/dom/events/event_queue.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/policy_container.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/loader/loader_factory_for_worker.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_fetch_request.h"
#include "third_party/blink/renderer/core/loader/resource_load_observer_for_worker.h"
#include "third_party/blink/renderer/core/loader/subresource_filter.h"
#include "third_party/blink/renderer/core/loader/worker_fetch_context.h"
#include "third_party/blink/renderer/core/loader/worker_resource_fetcher_properties.h"
#include "third_party/blink/renderer/core/loader/worker_resource_timing_notifier_impl.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/fetch_client_settings_object_impl.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_reporting_proxy.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/detachable_use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"
#include "third_party/blink/renderer/platform/loader/fetch/null_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_observer.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

// This is the implementation of ContentSecurityPolicyDelegate for the
// outsideSettings fetch.
// This lives on the worker thread.
//
// Unlike the ContentSecurityPolicy bound to ExecutionContext (which is
// used for insideSettings fetch), OutsideSettingsCSPDelegate shouldn't
// access WorkerOrWorkletGlobalScope (except for logging).
//
// For details of outsideSettings/insideSettings fetch, see README.md.
class OutsideSettingsCSPDelegate final
    : public GarbageCollected<OutsideSettingsCSPDelegate>,
      public ContentSecurityPolicyDelegate {
 public:
  OutsideSettingsCSPDelegate(
      const FetchClientSettingsObject& outside_settings_object,
      UseCounter& use_counter,
      WorkerOrWorkletGlobalScope& global_scope_for_logging)
      : outside_settings_object_(&outside_settings_object),
        use_counter_(use_counter),
        global_scope_for_logging_(&global_scope_for_logging) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(global_scope_for_logging_);
    visitor->Trace(use_counter_);
    visitor->Trace(outside_settings_object_);
  }

  const KURL& Url() const override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    return outside_settings_object_->GlobalObjectUrl();
  }

  const SecurityOrigin* GetSecurityOrigin() override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    return outside_settings_object_->GetSecurityOrigin();
  }

  // We don't have to do anything here, as we don't want to update
  // SecurityContext of either parent context or WorkerOrWorkletGlobalScope.
  void SetSandboxFlags(network::mojom::blink::WebSandboxFlags) override {}
  void SetRequireTrustedTypes() override {}
  void AddInsecureRequestPolicy(mojom::blink::InsecureRequestPolicy) override {}
  void DisableEval(const String& error_message) override {}
  void SetWasmEvalErrorMessage(const String& error_message) override {}

  std::unique_ptr<SourceLocation> GetSourceLocation() override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    // https://w3c.github.io/webappsec-csp/#create-violation-for-global
    // Step 2. If the user agent is currently executing script, and can extract
    // a source file's URL, line number, and column number from the global, set
    // violation's source file, line number, and column number accordingly.
    // [spec text]
    //
    // We can assume the user agent is not executing script during fetching the
    // top-level worker script, so return nullptr.
    return nullptr;
  }

  std::optional<uint16_t> GetStatusCode() override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    // TODO(crbug/928965): Plumb the status code of the parent Document if any.
    return std::nullopt;
  }

  String GetDocumentReferrer() override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    // TODO(crbug/928965): Plumb the referrer from the parent context.
    return String();
  }

  void DispatchViolationEvent(const SecurityPolicyViolationEventInit&,
                              Element*) override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    // TODO(crbug/928964): Fire an event on the parent context.
    // Before OutsideSettingsCSPDelegate was introduced, the event had been
    // fired on WorkerGlobalScope, which had been virtually no-op because
    // there can't be no event handlers yet.
    // Currently, no events are fired.
  }

  void PostViolationReport(const SecurityPolicyViolationEventInit&,
                           const String& stringified_report,
                           bool is_frame_ancestors_violation,
                           const Vector<String>& report_endpoints,
                           bool use_reporting_api) override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    // TODO(crbug/929370): Support POSTing violation reports from a Worker.
  }

  void Count(WebFeature feature) override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    use_counter_->CountUse(feature);
  }

  void AddConsoleMessage(ConsoleMessage* message) override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    global_scope_for_logging_->AddConsoleMessage(message);
  }

  void ReportBlockedScriptExecutionToInspector(
      const String& directive_text) override {
    // This shouldn't be called during top-level worker script fetch.
    NOTREACHED();
  }

  void DidAddContentSecurityPolicies(
      WTF::Vector<network::mojom::blink::ContentSecurityPolicyPtr>) override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    // We do nothing here, because if the added policies should be reported to
    // LocalFrameClient, then they are already reported on the parent
    // Document.
    // ExecutionContextCSPDelegate::DidAddContentSecurityPolicies() does
    // nothing for workers/worklets.
  }

  void AddInspectorIssue(AuditsIssue issue) override {
    DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
    global_scope_for_logging_->AddInspectorIssue(std::move(issue));
  }

 private:
  const Member<const FetchClientSettingsObject> outside_settings_object_;
  const Member<UseCounter> use_counter_;

  // |global_scope_for_logging_| should be used only for AddConsoleMessage() and
  // AddInspectorIssue().
  const Member<WorkerOrWorkletGlobalScope> global_scope_for_logging_;

  THREAD_CHECKER(worker_thread_checker_);
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class WorkerOrWorkletInterfaceNameType {
  kOther = 0,
  kDedicatedWorkerGlobalScope = 1,
  kSharedWorkerGlobalScope = 2,
  kServiceWorkerGlobalScope = 3,
  kAnimationWorkletGlobalScope = 4,
  kAudioWorkletGlobalScope = 5,
  kLayoutWorkletGlobalScope = 6,
  kPaintWorkletGlobalScope = 7,
  kShadowRealmGlobalScope = 8,
  kSharedStorageWorkletGlobalScope = 9,

  kMaxValue = kSharedStorageWorkletGlobalScope,
};

}  // namespace

WorkerOrWorkletGlobalScope::WorkerOrWorkletGlobalScope(
    v8::Isolate* isolate,
    scoped_refptr<SecurityOrigin> origin,
    bool is_creator_secure_context,
    Agent* agent,
    const String& name,
    const base::UnguessableToken& parent_devtools_token,
    mojom::blink::V8CacheOptions v8_cache_options,
    WorkerClients* worker_clients,
    std::unique_ptr<WebContentSettingsClient> content_settings_client,
    scoped_refptr<WebWorkerFetchContext> web_worker_fetch_context,
    WorkerReportingProxy& reporting_proxy,
    bool is_worker_loaded_from_data_url,
    bool is_default_world_of_isolate)
    : ExecutionContext(isolate, agent),
      is_creator_secure_context_(is_creator_secure_context),
      name_(name),
      parent_devtools_token_(parent_devtools_token),
      worker_clients_(worker_clients),
      content_settings_client_(std::move(content_settings_client)),
      web_worker_fetch_context_(std::move(web_worker_fetch_context)),
      script_controller_(MakeGarbageCollected<WorkerOrWorkletScriptController>(
          this,
          isolate,
          /*is_default_world_of_isolate=*/is_default_world_of_isolate)),
      v8_cache_options_(v8_cache_options),
      reporting_proxy_(reporting_proxy) {
  GetSecurityContext().SetIsWorkerLoadedFromDataURL(
      is_worker_loaded_from_data_url);
  GetSecurityContext().SetSecurityOrigin(std::move(origin));

  SetPolicyContainer(PolicyContainer::CreateEmpty());
  if (worker_clients_)
    worker_clients_->ReattachThread();
}

WorkerOrWorkletGlobalScope::~WorkerOrWorkletGlobalScope() = default;

// EventTarget
const AtomicString& WorkerOrWorkletGlobalScope::InterfaceName() const {
  NOTREACHED() << "Each global scope that uses events should define its own "
                  "interface name.";
}

v8::Local<v8::Value> WorkerOrWorkletGlobalScope::Wrap(ScriptState*) {
  LOG(FATAL) << "WorkerOrWorkletGlobalScope must never be wrapped with wrap "
                "method. The global object of ECMAScript environment is used "
                "as the wrapper.";
}

v8::Local<v8::Object> WorkerOrWorkletGlobalScope::AssociateWithWrapper(
    v8::Isolate*,
    const WrapperTypeInfo*,
    v8::Local<v8::Object> wrapper) {
  LOG(FATAL) << "WorkerOrWorkletGlobalScope must never be wrapped with wrap "
                "method. The global object of ECMAScript environment is used "
                "as the wrapper.";
}

void WorkerOrWorkletGlobalScope::CountUse(WebFeature feature) {
  DCHECK(IsContextThread());

  // `reporting_proxy_` should outlive `this` but there seems a situation where
  // the assumption is broken. Don't count features while the context is
  // destroyed.
  // TODO(https://crbug.com/1298450): Fix the lifetime of WorkerReportingProxy.
  if (IsContextDestroyed())
    return;

  DCHECK_NE(feature, WebFeature::kPageVisits);
  DCHECK_LE(feature, WebFeature::kMaxValue);
  if (used_features_[static_cast<size_t>(feature)])
    return;
  used_features_.set(static_cast<size_t>(feature));

  // Record CountUse users for investigating crbug.com/40918057.
  base::UmaHistogramSparse("ServiceWorker.CountUse.WebFeature",
                           static_cast<int>(feature));
  {
    WorkerOrWorkletInterfaceNameType type =
        WorkerOrWorkletInterfaceNameType::kOther;
    if (IsDedicatedWorkerGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kDedicatedWorkerGlobalScope;
      base::UmaHistogramSparse(
          "ServiceWorker.CountUse.DedicatedWorker.WebFeature",
          static_cast<int>(feature));
    } else if (IsSharedWorkerGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kSharedWorkerGlobalScope;
    } else if (IsServiceWorkerGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kServiceWorkerGlobalScope;
    } else if (IsAnimationWorkletGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kAnimationWorkletGlobalScope;
    } else if (IsAudioWorkletGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kAudioWorkletGlobalScope;
    } else if (IsLayoutWorkletGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kLayoutWorkletGlobalScope;
    } else if (IsPaintWorkletGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kPaintWorkletGlobalScope;
    } else if (IsShadowRealmGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kShadowRealmGlobalScope;
    } else if (IsSharedStorageWorkletGlobalScope()) {
      type = WorkerOrWorkletInterfaceNameType::kSharedStorageWorkletGlobalScope;
    }

    base::UmaHistogramEnumeration("ServiceWorker.CountUse.CallerInterface",
                                  type);
  }

  ReportingProxy().CountFeature(feature);
}

void WorkerOrWorkletGlobalScope::CountDeprecation(WebFeature feature) {
  Deprecation::CountDeprecation(this, feature);
}

void WorkerOrWorkletGlobalScope::CountWebDXFeature(WebDXFeature feature) {
  DCHECK(IsContextThread());

  // `reporting_proxy_` should outlive `this` but there seems a situation where
  // the assumption is broken. Don't count features while the context is
  // destroyed.
  // TODO(https://crbug.com/40058806): Fix the lifetime of WorkerReportingProxy.
  if (IsContextDestroyed()) {
    return;
  }

  DCHECK_NE(feature, WebDXFeature::kPageVisits);
  DCHECK_LE(feature, WebDXFeature::kMaxValue);
  if (used_webdx_features_[static_cast<size_t>(feature)]) {
    return;
  }
  used_webdx_features_.set(static_cast<size_t>(feature));

  ReportingProxy().CountWebDXFeature(feature);
}

ResourceLoadScheduler::ThrottleOptionOverride
WorkerOrWorkletGlobalScope::GetThrottleOptionOverride() const {
  return ResourceLoadScheduler::ThrottleOptionOverride::kNone;
}

void WorkerOrWorkletGlobalScope::UpdateFetcherThrottleOptionOverride() {
  if (inside_settings_resource_fetcher_) {
    inside_settings_resource_fetcher_->SetThrottleOptionOverride(
        GetThrottleOptionOverride());
  }
}

void WorkerOrWorkletGlobalScope::InitializeWebFetchContextIfNeeded() {
  if (web_fetch_context_initialized_)
    return;
  web_fetch_context_initialized_ = true;

  if (!web_worker_fetch_context_)
    return;

  DCHECK(!subresource_filter_);
  web_worker_fetch_context_->InitializeOnWorkerThread(navigator());
  std::unique_ptr<blink::WebDocumentSubresourceFilter> web_filter =
      web_worker_fetch_context_->TakeSubresourceFilter();
  if (web_filter) {
    subresource_filter_ =
        MakeGarbageCollected<SubresourceFilter>(this, std::move(web_filter));
  }
}

ResourceFetcher* WorkerOrWorkletGlobalScope::Fetcher() {
  DCHECK(IsContextThread());
  // Worklets don't support subresource fetch.
  DCHECK(IsWorkerGlobalScope());

  // Check if the fetcher has already been initialized, otherwise initialize it.
  if (inside_settings_resource_fetcher_)
    return inside_settings_resource_fetcher_.Get();

  // Because CSP is initialized inside the WorkerGlobalScope or
  // WorkletGlobalScope constructor, GetContentSecurityPolicy() should be
  // non-null here.
  DCHECK(GetContentSecurityPolicy());

  auto* resource_timing_notifier =
      WorkerResourceTimingNotifierImpl::CreateForInsideResourceFetcher(*this);
  inside_settings_resource_fetcher_ = CreateFetcherInternal(
      *MakeGarbageCollected<FetchClientSettingsObjectImpl>(*this),
      *GetContentSecurityPolicy(), *resource_timing_notifier);
  return inside_settings_resource_fetcher_.Get();
}

ResourceFetcher* WorkerOrWorkletGlobalScope::CreateFetcherInternal(
    const FetchClientSettingsObject& fetch_client_settings_object,
    ContentSecurityPolicy& content_security_policy,
    WorkerResourceTimingNotifier& resource_timing_notifier) {
  DCHECK(IsContextThread());
  InitializeWebFetchContextIfNeeded();
  ResourceFetcher* fetcher = nullptr;
  if (web_worker_fetch_context_) {
    auto& properties =
        *MakeGarbageCollected<DetachableResourceFetcherProperties>(
            *MakeGarbageCollected<WorkerResourceFetcherProperties>(
                *this, fetch_client_settings_object,
                web_worker_fetch_context_));
    auto* worker_fetch_context = MakeGarbageCollected<WorkerFetchContext>(
        properties, *this, web_worker_fetch_context_, subresource_filter_,
        content_security_policy, resource_timing_notifier);
    ResourceFetcherInit init(
        properties, worker_fetch_context, GetTaskRunner(TaskType::kNetworking),
        GetTaskRunner(TaskType::kNetworkingUnfreezable),
        MakeGarbageCollected<LoaderFactoryForWorker>(*this,
                                                     web_worker_fetch_context_),
        this, MakeGarbageCollected<BackForwardCacheLoaderHelperImpl>(*this));
    init.use_counter = MakeGarbageCollected<DetachableUseCounter>(this);
    init.console_logger = MakeGarbageCollected<DetachableConsoleLogger>(this);

    // Potentially support throttling network requests from a worker.  Note,
    // this does not work currently for worklets, but worklets should not be
    // able to make network requests anyway.
    if (IsWorkerGlobalScope()) {
      init.frame_or_worker_scheduler = GetScheduler();

      // The only network requests possible from a worker are
      // RequestContext::FETCH which are not normally throttlable.
      // Possibly override this restriction so network from a throttled
      // worker will also be throttled.
      init.throttle_option_override = GetThrottleOptionOverride();
    }

    fetcher = MakeGarbageCollected<ResourceFetcher>(init);
    fetcher->SetResourceLoadObserver(
        MakeGarbageCollected<ResourceLoadObserverForWorker>(
            *probe::ToCoreProbeSink(static_cast<ExecutionContext*>(this)),
            fetcher->GetProperties(), *worker_fetch_context,
            GetDevToolsToken()));
  } else {
    auto& properties =
        *MakeGarbageCollected<DetachableResourceFetcherProperties>(
            *MakeGarbageCollected<NullResourceFetcherProperties>());
    // This code path is for unittests.
    fetcher = MakeGarbageCollected<ResourceFetcher>(
        ResourceFetcherInit(properties, &FetchContext::NullInstance(),
                            GetTaskRunner(TaskType::kNetworking),
                            GetTaskRunner(TaskType::kNetworkingUnfreezable),
                            nullptr /* loader_factory */, this,
                            nullptr /* back_forward_cache_loader_helper */));
  }
  if (IsContextPaused())
    fetcher->SetDefersLoading(LoaderFreezeMode::kStrict);
  resource_fetchers_.insert(fetcher);
  return fetcher;
}

ResourceFetcher* WorkerOrWorkletGlobalScope::CreateOutsideSettingsFetcher(
    const FetchClientSettingsObject& outside_settings_object,
    WorkerResourceTimingNotifier& outside_resource_timing_notifier) {
  DCHECK(IsContextThread());

  auto* content_security_policy = MakeGarbageCollected<ContentSecurityPolicy>();
  content_security_policy->SetSupportsWasmEval(
      SchemeRegistry::SchemeSupportsWasmEvalCSP(
          outside_settings_object.GetSecurityOrigin()->Protocol()));
  content_security_policy->AddPolicies(
      mojo::Clone(outside_content_security_policies_));

  OutsideSettingsCSPDelegate* csp_delegate =
      MakeGarbageCollected<OutsideSettingsCSPDelegate>(outside_settings_object,
                                                       *this, *this);
  content_security_policy->BindToDelegate(*csp_delegate);

  return CreateFetcherInternal(outside_settings_object,
                               *content_security_policy,
                               outside_resource_timing_notifier);
}

bool WorkerOrWorkletGlobalScope::IsJSExecutionForbidden() const {
  return script_controller_->IsExecutionForbidden();
}

void WorkerOrWorkletGlobalScope::DisableEval(const String& error_message) {
  script_controller_->DisableEval(error_message);
}

void WorkerOrWorkletGlobalScope::SetWasmEvalErrorMessage(
    const String& error_message) {
  script_controller_->SetWasmEvalErrorMessage(error_message);
}

bool WorkerOrWorkletGlobalScope::CanExecuteScripts(
    ReasonForCallingCanExecuteScripts) {
  return !IsJSExecutionForbidden();
}

bool WorkerOrWorkletGlobalScope::HasInsecureContextInAncestors() const {
  return !is_creator_secure_context_;
}

void WorkerOrWorkletGlobalScope::Dispose() {
  DCHECK(script_controller_);

  RemoveAllEventListeners();

  script_controller_->Dispose();
  script_controller_.Clear();

  for (ResourceFetcher* resource_fetcher : resource_fetchers_) {
    resource_fetcher->StopFetching();
    resource_fetcher->ClearContext();
  }
  IdentifiabilitySampleCollector::Get()->FlushSource(UkmRecorder(),
                                                     UkmSourceID());
}

scoped_refptr<base::SingleThreadTaskRunner>
WorkerOrWorkletGlobalScope::GetTaskRunner(TaskType type) {
  DCHECK(IsContextThread());
  return GetThread()->GetTaskRunner(type);
}

void WorkerOrWorkletGlobalScope::SetSandboxFlags(
    network::mojom::blink::WebSandboxFlags mask) {
  GetSecurityContext().SetSandboxFlags(mask);
  if (IsSandboxed(network::mojom::blink::WebSandboxFlags::kOrigin) &&
      !GetSecurityOrigin()->IsOpaque()) {
    GetSecurityContext().SetSecurityOrigin(
        GetSecurityOrigin()->DeriveNewOpaqueOrigin());
  }
}

void WorkerOrWorkletGlobalScope::SetOutsideContentSecurityPolicies(
    Vector<network::mojom::blink::ContentSecurityPolicyPtr> policies) {
  outside_content_security_policies_ = std::move(policies);
}

void WorkerOrWorkletGlobalScope::InitContentSecurityPolicyFromVector(
    Vector<network::mojom::blink::ContentSecurityPolicyPtr> policies) {
  if (!GetContentSecurityPolicy()) {
    auto* csp = MakeGarbageCollected<ContentSecurityPolicy>();
    csp->SetSupportsWasmEval(SchemeRegistry::SchemeSupportsWasmEvalCSP(
        GetSecurityOrigin()->Protocol()));

    // Check if the embedder wants to add any default policies, and add them.
    WebVector<WebContentSecurityPolicyHeader> embedder_default_csp;
    Platform::Current()->AppendContentSecurityPolicy(WebURL(Url()),
                                                     &embedder_default_csp);
    for (const auto& header : embedder_default_csp) {
      csp->AddPolicies(ParseContentSecurityPolicies(
          header.header_value, header.type, header.source, Url()));
    }

    SetContentSecurityPolicy(csp);
  }
  GetContentSecurityPolicy()->AddPolicies(std::move(policies));
}

void WorkerOrWorkletGlobalScope::BindContentSecurityPolicyToExecutionContext() {
  DCHECK(IsContextThread());
  GetContentSecurityPolicy()->BindToDelegate(
      GetContentSecurityPolicyDelegate());
}

// Implementation of the "fetch a module worker script graph" algorithm in the
// HTML spec:
// https://html.spec.whatwg.org/C/#fetch-a-module-worker-script-tree
void WorkerOrWorkletGlobalScope::FetchModuleScript(
    const KURL& module_url_record,
    const FetchClientSettingsObjectSnapshot& fetch_client_settings_object,
    WorkerResourceTimingNotifier& resource_timing_notifier,
    mojom::blink::RequestContextType context_type,
    network::mojom::RequestDestination destination,
    network::mojom::CredentialsMode credentials_mode,
    ModuleScriptCustomFetchType custom_fetch_type,
    ModuleTreeClient* client) {
  // Step 2: "Let options be a script fetch options whose cryptographic nonce is
  // the empty string,
  String nonce;
  // integrity metadata is the empty string,
  String integrity_attribute;
  // parser metadata is "not-parser-inserted,
  ParserDisposition parser_state = kNotParserInserted;

  RejectCoepUnsafeNone reject_coep_unsafe_none(false);
  if (ShouldRejectCoepUnsafeNoneTopModuleScript() &&
      destination == network::mojom::RequestDestination::kWorker) {
    DCHECK(!base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
    reject_coep_unsafe_none = RejectCoepUnsafeNone(true);
  }

  // credentials mode is credentials mode, and referrer policy is the empty
  // string.
  // Module worker scripts are fetched with fetchpriority kAuto.
  ScriptFetchOptions options(
      nonce, IntegrityMetadataSet(), integrity_attribute, parser_state,
      credentials_mode, network::mojom::ReferrerPolicy::kDefault,
      mojom::blink::FetchPriorityHint::kAuto,
      RenderBlockingBehavior::kNonBlocking, reject_coep_unsafe_none);

  Modulator* modulator = Modulator::From(ScriptController()->GetScriptState());
  // Step 3. "Perform the internal module script graph fetching procedure ..."
  modulator->FetchTree(
      module_url_record, ModuleType::kJavaScript,
      CreateOutsideSettingsFetcher(fetch_client_settings_object,
                                   resource_timing_notifier),
      context_type, destination, options, custom_fetch_type, client);
}

void WorkerOrWorkletGlobalScope::SetDefersLoadingForResourceFetchers(
    LoaderFreezeMode mode) {
  for (ResourceFetcher* resource_fetcher : resource_fetchers_)
    resource_fetcher->SetDefersLoading(mode);
}

int WorkerOrWorkletGlobalScope::GetOutstandingThrottledLimit() const {
  // Default to what has been a typical throttle limit for iframes.  Note,
  // however, this value is largely meaningless unless the global has set
  // a ThrottleOptionOverride.  Workers can only make fetch/xhr requests
  // which are not throttlable by default.  If GetThrottleOptionOverride()
  // is overridden, then this method should also be overridden with a
  // more meaningful value.
  return 2;
}

String WorkerOrWorkletGlobalScope::GetAcceptLanguages() const {
  return web_worker_fetch_context_->GetAcceptLanguages();
}

void WorkerOrWorkletGlobalScope::OnConsoleApiMessage(
    mojom::ConsoleMessageLevel level,
    const String& message,
    SourceLocation* location) {
  reporting_proxy_.ReportConsoleMessage(
      mojom::ConsoleMessageSource::kConsoleApi, level, message, location);
}

void WorkerOrWorkletGlobalScope::Trace(Visitor* visitor) const {
  visitor->Trace(inside_settings_resource_fetcher_);
  visitor->Trace(resource_fetchers_);
  visitor->Trace(subresource_filter_);
  visitor->Trace(script_controller_);
  EventTarget::Trace(visitor);
  ExecutionContext::Trace(visitor);
}

}  // namespace blink
```