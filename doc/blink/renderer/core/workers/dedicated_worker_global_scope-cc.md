Response:
Let's break down the thought process for analyzing this C++ code for `DedicatedWorkerGlobalScope`.

1. **Understand the Goal:** The core request is to understand the functionality of this C++ file within the Chromium/Blink engine, specifically its relationship to web standards (JavaScript, HTML, CSS), its internal logic, and potential user/developer errors.

2. **Initial Skim and Keyword Spotting:**  Read through the file quickly, looking for recognizable terms and concepts. Keywords like "worker," "JavaScript," "postMessage," "fetch," "URL," "CSP," "Origin Trial," "requestAnimationFrame,"  and "back/forward cache" jump out. These immediately give clues about the file's purpose. The file path `blink/renderer/core/workers/` confirms it's about web workers within the rendering engine.

3. **Identify the Core Class:** The class `DedicatedWorkerGlobalScope` is central. The methods within this class likely represent the key functionalities.

4. **Analyze Key Methods (Function by Function):** Go through the more prominent methods and understand their roles:

    * **`Create()`:**  This is a static factory method, indicating how instances of `DedicatedWorkerGlobalScope` are created. Notice the parameters: `GlobalScopeCreationParams`, `DedicatedWorkerThread`, `DedicatedWorkerHost`, `BackForwardCacheControllerHost`. These suggest dependencies and the overall architecture. The conditional logic based on `IsOffMainThreadScriptFetchDisabled()` is important.

    * **`ParseCreationParams()`:** This static method suggests pre-processing or extracting specific data from the creation parameters.

    * **Constructor(s):** Analyze the parameters and the initialization of member variables. The handling of `parent_cross_origin_isolated_capability` and `parent_is_isolated_context` is significant for security.

    * **`Initialize()`:** This method is called after the worker is created. It deals with setting the worker's URL, referrer policy, and Content Security Policy.

    * **`FetchAndRunClassicScript()` and `FetchAndRunModuleScript()`:** These are crucial for understanding how worker scripts are loaded and executed. The distinction between classic and module scripts is important. Note the involvement of `WorkerClassicScriptLoader` and `WorkerModuleTreeClient`.

    * **`postMessage()`:** This is a fundamental worker API for communication. Pay attention to the serialization and transfer of data.

    * **`DidReceiveResponseForClassicScript()` and `DidFetchClassicScript()`:** These callbacks handle the results of fetching classic scripts. The error handling in `DidFetchClassicScript()` is worth noting.

    * **`requestAnimationFrame()` and `cancelAnimationFrame()`:** These methods integrate the worker with animation timing.

    * **`UpdateBackForwardCacheDisablingFeatures()`, `EvictFromBackForwardCache()`, `DidBufferLoadWhileInBackForwardCache()`, `SetIsInBackForwardCache()`:** These methods deal with the back/forward cache, a significant performance optimization in browsers.

    * **`WorkerScriptFetchFinished()`:** This method signals the completion of the initial script fetch.

5. **Relate to Web Standards (JavaScript, HTML, CSS):**  Connect the C++ methods to their corresponding JavaScript APIs and HTML concepts:

    * `DedicatedWorkerGlobalScope` directly corresponds to the global scope within a dedicated worker.
    * `postMessage()` is the JavaScript API for sending messages to and from workers.
    * `importScripts()` (implicitly handled by the script loading mechanisms) and `import` statements relate to `FetchAndRunClassicScript()` and `FetchAndRunModuleScript()`.
    * The handling of URLs, referrer policy, and CSP directly reflects web standards for security and resource loading.
    * `requestAnimationFrame()` is the JavaScript API for scheduling animations.
    * The back/forward cache interaction relates to browser history and page navigation.

6. **Identify Logical Reasoning and Assumptions:** Look for conditional statements (`if`, `else`), loops (though less common in this file), and any explicit logic within the methods. For example, the logic in `Create()` based on `IsOffMainThreadScriptFetchDisabled()` is a clear example of conditional execution. The assumption is that the `GlobalScopeCreationParams` object contains all the necessary information to set up the worker.

7. **Pinpoint Potential User/Programming Errors:** Think about how developers might misuse the worker APIs or encounter issues:

    * Incorrectly using `postMessage()` with non-transferable objects.
    * Issues with module loading (e.g., incorrect paths, CORS problems).
    * Misunderstanding the scope and limitations of workers (e.g., direct DOM access).
    * Errors related to Content Security Policy blocking script execution.
    * Not handling errors during script fetching.
    * Incorrect usage of `requestAnimationFrame` or `cancelAnimationFrame`.

8. **Structure the Output:** Organize the findings into logical categories (Functionality, Relationship to Web Standards, Logical Reasoning, Usage Errors) for clarity and readability. Use examples to illustrate the connections to JavaScript, HTML, and CSS.

9. **Refine and Elaborate:** Review the initial analysis and add more detail and context where necessary. For example, explain *why* the back/forward cache methods are important or provide more specific examples of `postMessage()` usage. Explain the significance of "cross-origin isolated capability."

10. **Self-Correction/Review:**  Re-read the code and the analysis to ensure accuracy and completeness. Are there any methods that were missed or misunderstood? Is the explanation clear and easy to follow?  For instance, initially, one might overlook the subtle difference in how origin trials are handled. Reviewing would highlight this. Also, ensure the assumed inputs and outputs for the logical reasoning examples are valid.
This C++ file, `dedicated_worker_global_scope.cc`, is a core component of the Blink rendering engine responsible for managing the global execution context of **dedicated web workers**. Dedicated workers are a way to run JavaScript code in a background thread, separate from the main thread of a web page. This separation allows for potentially long-running scripts to execute without blocking the user interface.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Creation and Initialization of Dedicated Worker Global Scope:**
   - The `DedicatedWorkerGlobalScope::Create()` method is responsible for creating instances of this class. It takes parameters like creation parameters, the worker thread, and handles for inter-process communication (IPC) with the browser process.
   - The constructor initializes various aspects of the worker's environment, including security settings (cross-origin isolation), origin trials, and sets up communication channels.
   - The `Initialize()` method completes the setup after the worker script has been fetched, configuring the worker's URL, referrer policy, and Content Security Policy (CSP).

2. **Script Loading and Execution:**
   - **`FetchAndRunClassicScript()`:**  Handles fetching and executing classic JavaScript worker scripts. It initiates the download of the script and then uses the JavaScript engine to execute it.
   - **`FetchAndRunModuleScript()`:**  Handles fetching and executing JavaScript module worker scripts. This involves resolving module dependencies and executing them in the correct order.
   - The code manages different strategies for fetching scripts, potentially utilizing off-main-thread fetching for performance.

3. **Message Passing (Communication):**
   - **`postMessage()`:** Implements the `postMessage()` JavaScript API, allowing the dedicated worker to send messages back to the main thread or to other workers. This involves serializing JavaScript objects for transmission and handling transferables (objects that are moved rather than copied).

4. **Animation Integration:**
   - **`requestAnimationFrame()`:**  Provides the `requestAnimationFrame()` API within the worker context, allowing for smooth animations synchronized with the browser's refresh rate.
   - **`cancelAnimationFrame()`:**  Allows canceling pending animation frame requests.

5. **Back/Forward Cache Support:**
   - The class interacts with the browser's back/forward cache to manage the state of dedicated workers when a user navigates back or forward.
   - It tracks features that might prevent the worker from being cached (`UpdateBackForwardCacheDisablingFeatures()`).
   - It handles evicting the worker from the cache (`EvictFromBackForwardCache()`).
   - It tracks the amount of data buffered while the worker is in the back/forward cache (`DidBufferLoadWhileInBackForwardCache()`).
   - It updates the worker's state when it enters or leaves the back/forward cache (`SetIsInBackForwardCache()`).

6. **Security and Isolation:**
   - The code manages cross-origin isolation settings, ensuring workers from different origins are properly isolated for security.
   - It interacts with Content Security Policy to enforce security restrictions on the worker's environment.

7. **Origin Trials:**
   - It supports origin trials, allowing developers to experiment with new web platform features.

8. **Instrumentation and Debugging:**
   - The code includes tracing and histogram recording for performance analysis and debugging.
   - It interacts with the browser's inspector for debugging worker threads.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:** This file is fundamentally about executing JavaScript code within a dedicated worker. The `FetchAndRun*Script()` methods load and run JavaScript. The `postMessage()` method is a core JavaScript API for worker communication. `requestAnimationFrame` is a JavaScript API for animation timing.
    * **Example:** When a JavaScript in the main thread calls `new Worker('my_worker.js')`, the browser (via Blink) will eventually create a `DedicatedWorkerGlobalScope` to execute the code in `my_worker.js`. The JavaScript code in `my_worker.js` can then use `postMessage()` to send data back to the main thread.

* **HTML:** Dedicated workers are created from HTML pages using the `<script>` tag with `type="module"` or by using the `Worker()` constructor in JavaScript.
    * **Example:** The HTML might contain `<script>const myWorker = new Worker('worker.js'); myWorker.postMessage('hello worker');</script>`. This code triggers the creation of a dedicated worker, and `DedicatedWorkerGlobalScope` manages the execution environment for `worker.js`.

* **CSS:** While dedicated workers themselves don't directly render HTML or CSS, they can be used for tasks related to CSS, such as pre-processing stylesheets or performing complex layout calculations off the main thread.
    * **Example:** A dedicated worker could fetch a large CSS file, parse it, and send the parsed structure back to the main thread to avoid blocking the UI.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `FetchAndRunClassicScript` function:

* **Hypothetical Input:**
    * `script_url`:  A `KURL` object representing the URL of the worker script (e.g., `https://example.com/my_worker.js`).
    * `worker_main_script_load_params`: Contains parameters related to script loading, such as credentials mode.
    * `policy_container`: Contains security policies.
    * `outside_settings_object`: Settings inherited from the creating context.
    * `outside_resource_timing_notifier`:  For reporting resource timing.
    * `stack_id`:  A stack trace ID for debugging.

* **Logical Steps:**
    1. The function checks if off-main-thread script fetching is enabled.
    2. It creates a `WorkerClassicScriptLoader` to handle the network request.
    3. It initiates an asynchronous fetch of the script at the given `script_url`.
    4. Callbacks (`DidReceiveResponseForClassicScript`, `DidFetchClassicScript`) are set up to handle the response.

* **Hypothetical Output (on success):**
    * The worker script is successfully downloaded.
    * The `DidFetchClassicScript` callback is invoked.
    * The `Initialize()` method is called to configure the worker's environment based on the downloaded script's response headers.
    * The JavaScript engine starts executing the downloaded script.

* **Hypothetical Output (on failure):**
    * The script download fails (e.g., network error, 404).
    * The `DidFetchClassicScript` callback detects the failure.
    * An error event is fired in the worker.
    * The worker might be terminated.

**Common User/Programming Errors:**

1. **Incorrect `postMessage()` Usage:**
   - **Error:** Trying to `postMessage()` objects that cannot be serialized or transferred.
   - **Example:** Trying to send a DOM node directly via `postMessage()`. This will likely result in an error or unexpected behavior as DOM nodes are not transferable. The developer should instead send the necessary data *about* the DOM node.

2. **CORS Issues with Worker Scripts:**
   - **Error:**  The worker script is hosted on a different origin and the server doesn't send the correct CORS headers (`Access-Control-Allow-Origin`).
   - **Example:** An HTML page on `example.com` tries to create a worker from `cdn.another-domain.com/worker.js`, but `cdn.another-domain.com` doesn't have `Access-Control-Allow-Origin: https://example.com` in its response headers. The browser will block the script loading.

3. **CSP Blocking Worker Script:**
   - **Error:** The Content Security Policy of the document creating the worker or the worker itself blocks the loading or execution of the worker script.
   - **Example:** The parent page has a CSP that doesn't allow loading scripts from the worker's origin or requires a specific nonce or hash.

4. **Misunderstanding Worker Scope:**
   - **Error:**  Trying to directly access the DOM or UI elements from within the dedicated worker.
   - **Example:**  JavaScript code in the worker might try `document.getElementById('myElement')`. This will fail because the worker runs in a separate thread and doesn't have access to the main thread's DOM. Communication via `postMessage()` is required.

5. **Errors in Module Script Paths:**
   - **Error:** When using module workers, providing incorrect or unresolved paths in `import` statements within the worker script.
   - **Example:**  A module worker tries to `import` a module using a relative path that is incorrect based on the worker's location.

6. **Forgetting to Handle Errors During Script Fetching:**
   - **Error:** Not implementing error handling in the worker's JavaScript to deal with potential issues during the initial script load.
   - **Example:** The worker script might not have an `onerror` handler to catch errors that occur if the script fails to load or parse.

This file plays a crucial role in enabling the functionality of dedicated web workers in Blink, providing the underlying infrastructure for script execution, communication, and integration with the browser environment.

Prompt: 
```
这是目录为blink/renderer/core/workers/dedicated_worker_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/workers/dedicated_worker_global_scope.h"

#include <memory>

#include "base/check_is_test.h"
#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/trace_event/trace_id_helper.h"
#include "base/trace_event/typed_macros.h"
#include "base/types/pass_key.h"
#include "net/storage_access_api/status.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/worker_main_script_load_parameters.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/back_forward_cache_controller.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/post_message_helper.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_post_message_options.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/inspector/worker_thread_debugger.h"
#include "third_party/blink/renderer/core/messaging/blink_transferable_message.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker_object_proxy.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker_thread.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/worker_classic_script_loader.h"
#include "third_party/blink/renderer/core/workers/worker_clients.h"
#include "third_party/blink/renderer/core/workers/worker_module_tree_client.h"
#include "third_party/blink/renderer/platform/back_forward_cache_buffer_limit_tracker.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"

namespace blink {

// static
DedicatedWorkerGlobalScope* DedicatedWorkerGlobalScope::Create(
    std::unique_ptr<GlobalScopeCreationParams> creation_params,
    DedicatedWorkerThread* thread,
    base::TimeTicks time_origin,
    mojo::PendingRemote<mojom::blink::DedicatedWorkerHost>
        dedicated_worker_host,
    mojo::PendingRemote<mojom::blink::BackForwardCacheControllerHost>
        back_forward_cache_controller_host) {
  TRACE_EVENT("blink.worker", "DedicatedWorkerGlobalScope::Create");
  std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
      inherited_trial_features =
          std::move(creation_params->inherited_trial_features);
  BeginFrameProviderParams begin_frame_provider_params =
      creation_params->begin_frame_provider_params;

  KURL response_script_url = creation_params->script_url;
  network::mojom::ReferrerPolicy response_referrer_policy =
      creation_params->referrer_policy;
  const bool parent_cross_origin_isolated_capability =
      creation_params->parent_cross_origin_isolated_capability;
  const bool parent_is_isolated_context =
      creation_params->parent_is_isolated_context;
  base::TimeTicks start_time;
  if (creation_params->dedicated_worker_start_time.has_value()) {
    start_time = *creation_params->dedicated_worker_start_time;
  } else {
    CHECK_IS_TEST();
    // Set a fake value for tests so that the value can be read in
    // `DedicatedWorkerGlobalScope::WorkerScriptFetchFinished()`.
    start_time = base::TimeTicks::Now();
  }

  Vector<network::mojom::blink::ContentSecurityPolicyPtr> response_csp =
      std::move(creation_params->response_content_security_policies);
  auto* global_scope = MakeGarbageCollected<DedicatedWorkerGlobalScope>(
      base::PassKey<DedicatedWorkerGlobalScope>(), std::move(creation_params),
      thread, time_origin, std::move(inherited_trial_features),
      begin_frame_provider_params, parent_cross_origin_isolated_capability,
      parent_is_isolated_context, std::move(dedicated_worker_host),
      std::move(back_forward_cache_controller_host), start_time);

  if (global_scope->IsOffMainThreadScriptFetchDisabled()) {
    // Legacy on-the-main-thread worker script fetch (to be removed):
    // Pass dummy origin trial tokens here as it is already set to outside's
    // origin trial tokens in DedicatedWorkerGlobalScope's constructor.
    global_scope->Initialize(response_script_url, response_referrer_policy,
                             std::move(response_csp),
                             nullptr /* response_origin_trial_tokens */);
    return global_scope;
  } else {
    // Off-the-main-thread worker script fetch:
    // Initialize() is called after script fetch.
    return global_scope;
  }
}

// static
DedicatedWorkerGlobalScope::ParsedCreationParams
DedicatedWorkerGlobalScope::ParseCreationParams(
    std::unique_ptr<GlobalScopeCreationParams> creation_params) {
  ParsedCreationParams parsed_creation_params;

  // Copy some stuff we need after passing the creation params to
  // WorkerGlobalScope.
  parsed_creation_params.parent_context_token =
      creation_params->parent_context_token.value();
  parsed_creation_params.parent_storage_access_api_status =
      creation_params->parent_storage_access_api_status;

  parsed_creation_params.creation_params = std::move(creation_params);
  return parsed_creation_params;
}

DedicatedWorkerGlobalScope::DedicatedWorkerGlobalScope(
    base::PassKey<DedicatedWorkerGlobalScope>,
    std::unique_ptr<GlobalScopeCreationParams> creation_params,
    DedicatedWorkerThread* thread,
    base::TimeTicks time_origin,
    std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
        inherited_trial_features,
    const BeginFrameProviderParams& begin_frame_provider_params,
    bool parent_cross_origin_isolated_capability,
    bool parent_is_isolated_context,
    mojo::PendingRemote<mojom::blink::DedicatedWorkerHost>
        dedicated_worker_host,
    mojo::PendingRemote<mojom::blink::BackForwardCacheControllerHost>
        back_forward_cache_controller_host,
    base::TimeTicks dedicated_worker_start_time)
    : DedicatedWorkerGlobalScope(
          ParseCreationParams(std::move(creation_params)),
          thread,
          time_origin,
          std::move(inherited_trial_features),
          begin_frame_provider_params,
          parent_cross_origin_isolated_capability,
          parent_is_isolated_context,
          std::move(dedicated_worker_host),
          std::move(back_forward_cache_controller_host),
          dedicated_worker_start_time) {}

DedicatedWorkerGlobalScope::DedicatedWorkerGlobalScope(
    ParsedCreationParams parsed_creation_params,
    DedicatedWorkerThread* thread,
    base::TimeTicks time_origin,
    std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
        inherited_trial_features,
    const BeginFrameProviderParams& begin_frame_provider_params,
    bool parent_cross_origin_isolated_capability,
    bool parent_is_isolated_context,
    mojo::PendingRemote<mojom::blink::DedicatedWorkerHost>
        dedicated_worker_host,
    mojo::PendingRemote<mojom::blink::BackForwardCacheControllerHost>
        back_forward_cache_controller_host,
    base::TimeTicks dedicated_worker_start_time)
    : WorkerGlobalScope(std::move(parsed_creation_params.creation_params),
                        thread,
                        time_origin,
                        false),
      token_(thread->WorkerObjectProxy().token()),
      parent_token_(parsed_creation_params.parent_context_token),
      cross_origin_isolated_capability_(Agent::IsCrossOriginIsolated()),
      is_isolated_context_(Agent::IsIsolatedContext()),
      animation_frame_provider_(
          MakeGarbageCollected<WorkerAnimationFrameProvider>(
              this,
              begin_frame_provider_params)),
      storage_access_api_status_(
          parsed_creation_params.parent_storage_access_api_status),
      dedicated_worker_start_time_(dedicated_worker_start_time) {
  // https://html.spec.whatwg.org/C/#run-a-worker
  // Step 14.10 "If shared is false and owner's cross-origin isolated
  // capability is false, then set worker global scope's cross-origin isolated
  // capability to false."
  if (!parent_cross_origin_isolated_capability) {
    cross_origin_isolated_capability_ = false;
  }

  // TODO(mkwst): This needs a specification.
  if (!parent_is_isolated_context) {
    is_isolated_context_ = false;
  }

  // Dedicated workers don't need to pause after script fetch.
  ReadyToRunWorkerScript();
  // Inherit the outside's enabled origin trial features.
  OriginTrialContext::ActivateWorkerInheritedFeatures(
      this, inherited_trial_features.get());

  dedicated_worker_host_.Bind(std::move(dedicated_worker_host),
                              GetTaskRunner(TaskType::kInternalDefault));
  back_forward_cache_controller_host_.Bind(
      std::move(back_forward_cache_controller_host),
      GetTaskRunner(TaskType::kInternalDefault));
}

DedicatedWorkerGlobalScope::~DedicatedWorkerGlobalScope() = default;

void DedicatedWorkerGlobalScope::Dispose() {
  BackForwardCacheBufferLimitTracker::Get()
      .DidRemoveFrameOrWorkerFromBackForwardCache(
          total_bytes_buffered_while_in_back_forward_cache_);
  total_bytes_buffered_while_in_back_forward_cache_ = 0;
  WorkerGlobalScope::Dispose();
}

const AtomicString& DedicatedWorkerGlobalScope::InterfaceName() const {
  return event_target_names::kDedicatedWorkerGlobalScope;
}

// https://html.spec.whatwg.org/C/#worker-processing-model
void DedicatedWorkerGlobalScope::Initialize(
    const KURL& response_url,
    network::mojom::ReferrerPolicy response_referrer_policy,
    Vector<network::mojom::blink::ContentSecurityPolicyPtr> response_csp,
    const Vector<String>* /* response_origin_trial_tokens */) {
  TRACE_EVENT("blink.worker", "DedicatedWorkerGlobalScope::Initialize",
              "response_url", response_url);
  // Step 14.3. "Set worker global scope's url to response's url."
  InitializeURL(response_url);

  // Step 14.4. "Set worker global scope's HTTPS state to response's HTTPS
  // state."
  // This is done in the constructor of WorkerGlobalScope.

  // Step 14.5. "Set worker global scope's referrer policy to the result of
  // parsing the `Referrer-Policy` header of response."
  SetReferrerPolicy(response_referrer_policy);

  // The following is the Content-Security-Policy part of "Initialize worker
  // global scope's policy container"
  // https://html.spec.whatwg.org/#initialize-worker-policy-container
  //
  // For workers delivered from network schemes we use the parsed CSP from the
  // response headers, while for local schemes CSP is inherited from the owner.
  Vector<network::mojom::blink::ContentSecurityPolicyPtr> csp_list =
      response_url.ProtocolIsAbout() || response_url.ProtocolIsData() ||
              response_url.ProtocolIs("blob") ||
              response_url.ProtocolIs("filesystem")
          ? mojo::Clone(OutsideContentSecurityPolicies())
          : std::move(response_csp);
  InitContentSecurityPolicyFromVector(std::move(csp_list));
  BindContentSecurityPolicyToExecutionContext();

  // This should be called after OriginTrialContext::AddTokens() to install
  // origin trial features in JavaScript's global object.
  // DedicatedWorkerGlobalScope inherits the outside's OriginTrialTokens in the
  // constructor instead of the response origin trial tokens.
  ScriptController()->PrepareForEvaluation();

  // Step 14.11. "If is shared is false and response's url's scheme is "data",
  // then set worker global scope's cross-origin isolated capability to false."
  if (response_url.ProtocolIsData()) {
    cross_origin_isolated_capability_ = false;

    // TODO(mkwst): This needs a spec.
    is_isolated_context_ = false;
  }
}

// https://html.spec.whatwg.org/C/#worker-processing-model
void DedicatedWorkerGlobalScope::FetchAndRunClassicScript(
    const KURL& script_url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<PolicyContainer> policy_container,
    const FetchClientSettingsObjectSnapshot& outside_settings_object,
    WorkerResourceTimingNotifier& outside_resource_timing_notifier,
    const v8_inspector::V8StackTraceId& stack_id) {
  DCHECK(base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
  DCHECK(!IsContextPaused());
  TRACE_EVENT("blink.worker",
              "DedicatedWorkerGlobalScope::FetchAndRunClassicScript",
              "script_url", script_url);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(
      "blink.worker", "DedicatedWorkerGlobalScope Fetch", TRACE_ID_LOCAL(this));
  fetch_classic_script_start_time_ = base::TimeTicks::Now();

  // TODO(crbug.com/1177199): SetPolicyContainer once we passed down policy
  // container from DedicatedWorkerHost

  // Step 12. "Fetch a classic worker script given url, outside settings,
  // destination, and inside settings."
  mojom::blink::RequestContextType context_type =
      mojom::blink::RequestContextType::WORKER;
  network::mojom::RequestDestination destination =
      network::mojom::RequestDestination::kWorker;

  // Step 12.1. "Set request's reserved client to inside settings."
  // The browesr process takes care of this.

  // Step 12.2. "Fetch request, and asynchronously wait to run the remaining
  // steps as part of fetch's process response for the response response."
  WorkerClassicScriptLoader* classic_script_loader =
      MakeGarbageCollected<WorkerClassicScriptLoader>();
  classic_script_loader->LoadTopLevelScriptAsynchronously(
      *this,
      CreateOutsideSettingsFetcher(outside_settings_object,
                                   outside_resource_timing_notifier),
      script_url, std::move(worker_main_script_load_params), context_type,
      destination, network::mojom::RequestMode::kSameOrigin,
      network::mojom::CredentialsMode::kSameOrigin,
      WTF::BindOnce(
          &DedicatedWorkerGlobalScope::DidReceiveResponseForClassicScript,
          WrapWeakPersistent(this), WrapPersistent(classic_script_loader)),
      WTF::BindOnce(&DedicatedWorkerGlobalScope::DidFetchClassicScript,
                    WrapWeakPersistent(this),
                    WrapPersistent(classic_script_loader), stack_id));
}

// https://html.spec.whatwg.org/C/#worker-processing-model
void DedicatedWorkerGlobalScope::FetchAndRunModuleScript(
    const KURL& module_url_record,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<PolicyContainer> policy_container,
    const FetchClientSettingsObjectSnapshot& outside_settings_object,
    WorkerResourceTimingNotifier& outside_resource_timing_notifier,
    network::mojom::CredentialsMode credentials_mode,
    RejectCoepUnsafeNone reject_coep_unsafe_none) {
  TRACE_EVENT("blink.worker",
              "DedicatedWorkerGlobalScope::FetchAndRunModuleScript",
              "module_url_record", module_url_record);
  // TODO(crbug.com/1177199): SetPolicyContainer once we passed down policy
  // container from DedicatedWorkerHost

  reject_coep_unsafe_none_ = reject_coep_unsafe_none;

  if (worker_main_script_load_params) {
    SetWorkerMainScriptLoadingParametersForModules(
        std::move(worker_main_script_load_params));
  }

  // Step 12: "Let destination be "sharedworker" if is shared is true, and
  // "worker" otherwise."
  mojom::blink::RequestContextType context_type =
      mojom::blink::RequestContextType::WORKER;
  network::mojom::RequestDestination destination =
      network::mojom::RequestDestination::kWorker;

  // Step 13: "... Fetch a module worker script graph given url, outside
  // settings, destination, the value of the credentials member of options, and
  // inside settings."
  FetchModuleScript(module_url_record, outside_settings_object,
                    outside_resource_timing_notifier, context_type, destination,
                    credentials_mode,
                    ModuleScriptCustomFetchType::kWorkerConstructor,
                    MakeGarbageCollected<WorkerModuleTreeClient>(
                        ScriptController()->GetScriptState()));
}

bool DedicatedWorkerGlobalScope::IsOffMainThreadScriptFetchDisabled() {
  // The top-level dedicated worker script is loaded on the main thread when the
  // script type is classic and PlzDedicatedWorker (off-the-main-thread script
  // fetch) is disabled.
  // TODO(https://crbug.com/835717): Remove this function after dedicated
  // workers support off-the-main-thread script fetch by default.
  return GetScriptType() == mojom::blink::ScriptType::kClassic &&
         !base::FeatureList::IsEnabled(features::kPlzDedicatedWorker);
}

const String DedicatedWorkerGlobalScope::name() const {
  return Name();
}

void DedicatedWorkerGlobalScope::postMessage(ScriptState* script_state,
                                             const ScriptValue& message,
                                             HeapVector<ScriptValue> transfer,
                                             ExceptionState& exception_state) {
  PostMessageOptions* options = PostMessageOptions::Create();
  if (!transfer.empty())
    options->setTransfer(std::move(transfer));
  postMessage(script_state, message, options, exception_state);
}

void DedicatedWorkerGlobalScope::postMessage(ScriptState* script_state,
                                             const ScriptValue& message,
                                             const PostMessageOptions* options,
                                             ExceptionState& exception_state) {
  TRACE_EVENT("blink.worker", "DedicatedWorkerGlobalScope::postMessage");
  Transferables transferables;
  scoped_refptr<SerializedScriptValue> serialized_message =
      PostMessageHelper::SerializeMessageByMove(script_state->GetIsolate(),
                                                message, options, transferables,
                                                exception_state);
  if (exception_state.HadException())
    return;
  DCHECK(serialized_message);
  BlinkTransferableMessage transferable_message;
  transferable_message.message = serialized_message;
  transferable_message.sender_origin =
      GetExecutionContext()->GetSecurityOrigin()->IsolatedCopy();
  // Disentangle the port in preparation for sending it to the remote context.
  transferable_message.ports = MessagePort::DisentanglePorts(
      ExecutionContext::From(script_state), transferables.message_ports,
      exception_state);
  if (exception_state.HadException())
    return;
  uint64_t trace_id = base::trace_event::GetNextGlobalTraceId();
  transferable_message.trace_id = trace_id;
  WorkerThreadDebugger* debugger =
      WorkerThreadDebugger::From(script_state->GetIsolate());
  transferable_message.sender_stack_trace_id =
      debugger->StoreCurrentStackTrace("postMessage");
  WorkerObjectProxy().PostMessageToWorkerObject(
      std::move(transferable_message));

  TRACE_EVENT_INSTANT(
      "devtools.timeline", "SchedulePostMessage", "data",
      [&](perfetto::TracedValue context) {
        inspector_schedule_post_message_event::Data(
            std::move(context), GetExecutionContext(), trace_id);
      },
      perfetto::Flow::Global(trace_id));  // SchedulePostMessage
}

void DedicatedWorkerGlobalScope::DidReceiveResponseForClassicScript(
    WorkerClassicScriptLoader* classic_script_loader) {
  DCHECK(IsContextThread());
  DCHECK(base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
  probe::DidReceiveScriptResponse(this, classic_script_loader->Identifier());
}

// https://html.spec.whatwg.org/C/#worker-processing-model
void DedicatedWorkerGlobalScope::DidFetchClassicScript(
    WorkerClassicScriptLoader* classic_script_loader,
    const v8_inspector::V8StackTraceId& stack_id) {
  DCHECK(IsContextThread());
  DCHECK(base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
  TRACE_EVENT("blink.worker",
              "DedicatedWorkerGlobalScope::DidFetchClassicScript");
  TRACE_EVENT_NESTABLE_ASYNC_END0(
      "blink.worker", "DedicatedWorkerGlobalScope Fetch", TRACE_ID_LOCAL(this));
  base::UmaHistogramTimes(
      "Worker.TopLevelScript.FetchClassicScriptTime",
      base::TimeTicks::Now() - fetch_classic_script_start_time_);

  // Step 12. "If the algorithm asynchronously completes with null, then:"
  if (classic_script_loader->Failed()) {
    // Step 12.1. "Queue a task to fire an event named error at worker."
    // DidFailToFetchClassicScript() will asynchronously fire the event.
    ReportingProxy().DidFailToFetchClassicScript();

    // Step 12.2. "Run the environment discarding steps for inside settings."
    // Do nothing because the HTML spec doesn't define these steps for web
    // workers.

    // Schedule worker termination.
    close();

    // Step 12.3. "Return."
    return;
  }
  ReportingProxy().DidFetchScript();
  probe::ScriptImported(this, classic_script_loader->Identifier(),
                        classic_script_loader->SourceText());

  auto response_referrer_policy = network::mojom::ReferrerPolicy::kDefault;
  if (!classic_script_loader->GetReferrerPolicy().IsNull()) {
    SecurityPolicy::ReferrerPolicyFromHeaderValue(
        classic_script_loader->GetReferrerPolicy(),
        kDoNotSupportReferrerPolicyLegacyKeywords, &response_referrer_policy);
  }

  // Step 12.3-12.6 are implemented in Initialize().
  // Pass dummy origin trial tokens here as it is already set to outside's
  // origin trial tokens in DedicatedWorkerGlobalScope's constructor.
  Initialize(classic_script_loader->ResponseURL(), response_referrer_policy,
             classic_script_loader->GetContentSecurityPolicy()
                 ? mojo::Clone(classic_script_loader->GetContentSecurityPolicy()
                                   ->GetParsedPolicies())
                 : Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
             nullptr /* response_origin_trial_tokens */);

  // Step 12.7. "Asynchronously complete the perform the fetch steps with
  // response."
  EvaluateClassicScript(
      classic_script_loader->ResponseURL(), classic_script_loader->SourceText(),
      classic_script_loader->ReleaseCachedMetadata(), stack_id);
}

int DedicatedWorkerGlobalScope::requestAnimationFrame(
    V8FrameRequestCallback* callback,
    ExceptionState& exception_state) {
  auto* frame_callback = MakeGarbageCollected<V8FrameCallback>(callback);
  frame_callback->SetUseLegacyTimeBase(false);

  int ret = animation_frame_provider_->RegisterCallback(frame_callback);

  if (ret == WorkerAnimationFrameProvider::kInvalidCallbackId) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "requestAnimationFrame not supported in this Worker.");
  }

  return ret;
}

void DedicatedWorkerGlobalScope::cancelAnimationFrame(int id) {
  animation_frame_provider_->CancelCallback(id);
}

DedicatedWorkerObjectProxy& DedicatedWorkerGlobalScope::WorkerObjectProxy()
    const {
  return static_cast<DedicatedWorkerThread*>(GetThread())->WorkerObjectProxy();
}

void DedicatedWorkerGlobalScope::UpdateBackForwardCacheDisablingFeatures(
    BlockingDetails details) {
  // `back_forward_cache_controller_host_` might not be bound when non-
  // PlzDedicatedWorker is used. Non-PlzDedicatedWorker will be removed in near
  // future.
  // TODO(hajimehoshi): Remove this 'if' branch after non-PlzDedicatedWorker is
  // removed.
  if (!back_forward_cache_controller_host_.is_bound()) {
    return;
  }
  auto mojom_details = LocalFrame::ConvertFeatureAndLocationToMojomStruct(
      *details.non_sticky_features_and_js_locations,
      *details.sticky_features_and_js_locations);
  back_forward_cache_controller_host_
      ->DidChangeBackForwardCacheDisablingFeatures(std::move(mojom_details));
}

void DedicatedWorkerGlobalScope::Trace(Visitor* visitor) const {
  visitor->Trace(dedicated_worker_host_);
  visitor->Trace(back_forward_cache_controller_host_);
  visitor->Trace(animation_frame_provider_);
  WorkerGlobalScope::Trace(visitor);
}

void DedicatedWorkerGlobalScope::EvictFromBackForwardCache(
    mojom::blink::RendererEvictionReason reason,
    std::unique_ptr<SourceLocation> source_location) {
  if (!back_forward_cache_controller_host_.is_bound()) {
    return;
  }
  if (!GetExecutionContext()->is_in_back_forward_cache()) {
    // Don't send an eviction message unless the document associated with this
    // DedicatedWorker is in back/forward cache.
    // TODO(crbug.com/1163843): Maybe also check if eviction is already disabled
    // for the document?
    return;
  }
  UMA_HISTOGRAM_ENUMERATION("BackForwardCache.Eviction.Renderer", reason);
  // This implementation shouldn't be called for JavaScript execution. Since we
  // capture source location only when the eviction reason is JavaScript
  // execution, `source_location` should always be null here.
  CHECK(!source_location);
  back_forward_cache_controller_host_->EvictFromBackForwardCache(
      /*reason=*/std::move(reason), /*source=*/nullptr);
}

void DedicatedWorkerGlobalScope::DidBufferLoadWhileInBackForwardCache(
    bool update_process_wide_count,
    size_t num_bytes) {
  total_bytes_buffered_while_in_back_forward_cache_ += num_bytes;
  if (update_process_wide_count) {
    BackForwardCacheBufferLimitTracker::Get().DidBufferBytes(num_bytes);
  }
}

void DedicatedWorkerGlobalScope::SetIsInBackForwardCache(
    bool is_in_back_forward_cache) {
  WorkerGlobalScope::SetIsInBackForwardCache(is_in_back_forward_cache);
  if (!is_in_back_forward_cache) {
    BackForwardCacheBufferLimitTracker::Get()
        .DidRemoveFrameOrWorkerFromBackForwardCache(
            total_bytes_buffered_while_in_back_forward_cache_);
    total_bytes_buffered_while_in_back_forward_cache_ = 0;
  }
}

net::StorageAccessApiStatus
DedicatedWorkerGlobalScope::GetStorageAccessApiStatus() const {
  return storage_access_api_status_;
}

void DedicatedWorkerGlobalScope::WorkerScriptFetchFinished(
    Script& worker_script,
    std::optional<v8_inspector::V8StackTraceId> stack_id) {
  CHECK(!dedicated_worker_start_time_.is_null());
  base::UmaHistogramTimes(
      "Worker.TopLevelScript.StartToWorkerScriptFetchFinishedTime",
      base::TimeTicks::Now() - dedicated_worker_start_time_);
  WorkerGlobalScope::WorkerScriptFetchFinished(worker_script, stack_id);
}

}  // namespace blink

"""

```