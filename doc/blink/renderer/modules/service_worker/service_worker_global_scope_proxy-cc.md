Response:
Let's break down the thought process for analyzing the `ServiceWorkerGlobalScopeProxy.cc` file.

1. **Understand the Goal:** The primary goal is to understand the purpose of this specific C++ file within the Chromium Blink engine, especially its relation to JavaScript, HTML, and CSS, identify potential errors, and trace how user actions lead to its execution.

2. **Initial Scan and Keywords:**  The first step is to quickly scan the file for prominent keywords and structures. I see:
    * `ServiceWorkerGlobalScopeProxy` (the central class)
    * `#include` directives (indicating dependencies)
    * `DCHECK` statements (assertions for debugging)
    * Method names like `BindServiceWorker`, `OnNavigationPreloadResponse`, `ReportException`, `DidEvaluateTopLevelScript`, etc.
    * Mentions of `WorkerGlobalScope`, `WebEmbeddedWorkerImpl`, `WebServiceWorkerContextClient`.
    * `mojom` references (indicating interaction with the Mojo IPC system).
    * Namespaces like `blink`.

3. **Inferring the Core Functionality:** Based on the class name and the included headers/method names, I can infer that this class acts as an *intermediary* or *proxy* for the Service Worker's global scope. It doesn't *implement* the core logic of the Service Worker itself, but rather manages communication and lifecycle events related to it. The "proxy" in the name is a significant clue.

4. **Identifying Key Interactions:**  The presence of `WebServiceWorkerContextClient` and `WebEmbeddedWorkerImpl` suggests interactions with other components. The `Client()` method implies delegation of tasks. The `Bind...` methods point to setting up communication channels. The "navigation preload" methods suggest involvement in how service workers intercept and handle navigation requests.

5. **Connecting to JavaScript:** The methods `ReportException`, `ReportConsoleMessage`, `WillEvaluateScript`, and `DidEvaluateTopLevelScript` clearly link this C++ code to the execution of JavaScript within the Service Worker. These methods deal with capturing errors, console logs, and the lifecycle of script execution.

6. **Connecting to HTML and CSS (Indirectly):**  Service Workers, while written in JavaScript, directly influence how web pages (HTML and their associated CSS and other resources) are loaded and handled. The "navigation preload" feature is a prime example. A service worker can intercept a navigation request for an HTML page and serve it from its cache or modify the request. This is a crucial link, though indirect.

7. **Logical Reasoning and Scenarios:** Now, let's think about specific scenarios:
    * **Script Evaluation:** When a Service Worker script is loaded, the `WillEvaluateScript` and `DidEvaluateTopLevelScript` methods are called. *Input:* The raw script content. *Output:* Success or failure of execution.
    * **Navigation Preload:** When a navigation occurs and navigation preload is enabled, the service worker is notified, and it can set up a preload request. *Input:* Navigation request URL. *Output:*  Either a successful response or an error.
    * **Console Logging:** When `console.log()` is called in the Service Worker script, `ReportConsoleMessage` is invoked. *Input:* Log message, source, level. *Output:* The message is displayed in the browser's developer console.

8. **Identifying Potential Errors:** The `DCHECK` statements are good indicators of potential internal errors or assumptions that must hold true. Common user errors relate to:
    * **Incorrect Service Worker Script:** Syntax errors, runtime errors in the JavaScript.
    * **Network Issues:**  Problems fetching the Service Worker script itself or resources it tries to access.
    * **API Usage Errors:**  Using Service Worker APIs incorrectly (e.g., incorrect caching strategies).

9. **Tracing User Actions (Debugging):**  How does a user end up triggering this code?
    * **Registering a Service Worker:** The user's browser navigates to a page that includes JavaScript code to register a Service Worker.
    * **Navigation:**  Navigating to a page controlled by a Service Worker.
    * **Resource Loading:**  The Service Worker intercepts requests for resources (HTML, CSS, images, etc.).
    * **JavaScript Errors:** Errors in the Service Worker script itself.
    * **Console Logging:**  The Service Worker using `console.log()`.

10. **Structuring the Answer:**  Finally, organize the findings logically:
    * Start with a summary of the file's purpose.
    * Explain the relationship to JavaScript, HTML, and CSS with concrete examples.
    * Provide logical reasoning with input/output scenarios.
    * Discuss common user errors.
    * Outline the steps to reach this code during debugging.

11. **Refinement and Detail:** Review the generated answer and add more specific details. For instance,  mentioning the different types of errors (network, script) and being precise about the user actions (registration, navigation). Ensuring the language is clear and accessible. For example, explaining what "navigation preload" is.

This step-by-step approach allows for a comprehensive analysis of the source code, going beyond a simple listing of its methods and connecting it to the broader web development context.
The file `blink/renderer/modules/service_worker/service_worker_global_scope_proxy.cc` in the Chromium Blink engine serves as a **proxy** or **intermediary** for interacting with the **Service Worker's global scope**. It lives on the **main thread** (also known as the browser process's render thread in this context) and manages communication with the actual `ServiceWorkerGlobalScope` object, which resides on a dedicated **worker thread**.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Cross-Thread Communication:** The primary role of this proxy is to facilitate communication between the main thread and the worker thread where the Service Worker is running. Since these threads have separate memory spaces, direct access is not possible. The proxy marshals calls and data between the two.

2. **Lifecycle Management:** It handles lifecycle events of the Service Worker's global scope, such as:
    * **Initialization:**  Notifying the main thread when the worker context is being initialized (`WillInitializeWorkerContext`, `DidCreateWorkerGlobalScope`).
    * **Script Loading and Evaluation:**  Signaling when the Service Worker script is loaded, fetched, and evaluated (`DidLoadClassicScript`, `DidFetchScript`, `DidFailToFetchClassicScript`, `DidFailToFetchModuleScript`, `WillEvaluateScript`, `DidEvaluateTopLevelScript`).
    * **Closure and Termination:**  Managing the shutdown of the worker (`DidCloseWorkerGlobalScope`, `WillDestroyWorkerGlobalScope`, `DidTerminateWorkerThread`).

3. **Dispatching Events:** It receives events from the worker thread and forwards them to the appropriate handlers on the main thread. Examples include:
    * **Navigation Preload:** Handling responses and errors related to navigation preload (`OnNavigationPreloadResponse`, `OnNavigationPreloadError`, `OnNavigationPreloadComplete`, `SetupNavigationPreload`).
    * **Reporting Errors and Console Messages:** Relaying exceptions and console messages from the Service Worker script to the browser's developer tools (`ReportException`, `ReportConsoleMessage`).
    * **Feature Counting:**  Tracking the usage of specific web features within the Service Worker (`CountFeature`).

4. **Binding Interfaces:** It handles the binding of Mojo interfaces that allow the Service Worker to interact with other browser components (`BindServiceWorker`, `BindControllerServiceWorker`).

5. **Termination Requests:**  It allows the main thread to request the termination of the Service Worker (`RequestTermination`).

**Relationship to JavaScript, HTML, and CSS:**

This C++ code is deeply intertwined with JavaScript functionality within the browser. Here's how:

* **JavaScript Execution:** The proxy manages the lifecycle of the JavaScript execution environment within the Service Worker. Methods like `WillEvaluateScript` and `DidEvaluateTopLevelScript` directly relate to the execution of the Service Worker's JavaScript code. When the browser fetches and runs the Service Worker's JavaScript file, these methods are called to track the progress.
    * **Example:**  When your Service Worker script contains `console.log("Hello from Service Worker");`, the `ReportConsoleMessage` method in this proxy will be called (indirectly) to forward that message to the browser's console. The input would be the message string "Hello from Service Worker", the source (service-worker), and the log level (log). The output would be the message appearing in the developer tools.
    * **Example:** If your Service Worker script throws an error, like `throw new Error("Something went wrong");`, the `ReportException` method will be called. The input would be the error message "Something went wrong", the line and column number where the error occurred, and the URL of the script. The output would be an error message displayed in the browser's console.

* **Navigation Interception (Indirectly related to HTML):** Service Workers can intercept network requests, including those for HTML pages. The `OnNavigationPreloadResponse`, `OnNavigationPreloadError`, and `SetupNavigationPreload` methods are part of the mechanism that allows Service Workers to optimize navigation by potentially providing cached content or even generating the response themselves.
    * **Example:** If a user navigates to a page that is controlled by a Service Worker, and that Service Worker has implemented a "navigation preload" strategy, this proxy will be involved in setting up a parallel request for the HTML page. The input to `SetupNavigationPreload` would be the URL of the HTML page being navigated to. The output would be the initiation of a network request from the browser to potentially speed up the navigation.

* **Fetching Resources (Related to HTML, CSS, Images, etc.):**  Service Workers can intercept fetch requests for any resource, including HTML, CSS, images, and JavaScript files. While this proxy doesn't directly handle the fetch logic, it plays a role in managing the communication and events surrounding these fetch interceptions.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider the `DidEvaluateTopLevelScript` method:

* **Hypothetical Input:**
    * The Service Worker script has finished executing.
    * `success = true` (if the script executed without errors) or `success = false` (if there were errors).
* **Logical Process:**
    1. The `WorkerGlobalScope` on the worker thread calls this method on the proxy.
    2. It records the time taken for script evaluation.
    3. It calls `WorkerGlobalScope()->DidEvaluateScript()` (on the worker thread) for internal bookkeeping.
    4. It calls `Client().DidEvaluateScript(success)` to notify the main thread about the evaluation result.
    5. It emits a trace event for performance monitoring.
* **Hypothetical Output:**
    * A performance metric is recorded.
    * The main thread is informed whether the Service Worker script executed successfully. This information can be used to determine if the Service Worker is ready to handle events.

**User and Programming Errors:**

* **JavaScript Errors in Service Worker Script:**  If the Service Worker's JavaScript code contains syntax or runtime errors, the `DidEvaluateTopLevelScript` method will be called with `success = false`. The `ReportException` method will also be called to provide details about the error in the developer console. A common user error is writing incorrect JavaScript code within the Service Worker.

* **Network Errors Fetching Service Worker Script:** If the browser fails to download the Service Worker script (e.g., due to a 404 error), methods like `DidFailToFetchClassicScript` or `DidFailToFetchModuleScript` will be called. This indicates a problem with the URL provided when registering the Service Worker.

* **Incorrectly Implementing Navigation Preload:** If a developer misconfigures the navigation preload feature in their Service Worker, leading to errors in the preload request, the `OnNavigationPreloadError` method will be invoked.

* **Uncaught Exceptions in Event Handlers:** If a Service Worker has an event listener (e.g., for the `fetch` event) that throws an uncaught exception, the `ReportException` method will be used to report this error. This can lead to the Service Worker not functioning as expected.

**User Operations and Debugging Lineage:**

To reach this code during debugging, a typical sequence of user operations would be:

1. **User navigates to a website that uses Service Workers.**  The browser detects the presence of a Service Worker registration.
2. **The browser attempts to download and register the Service Worker script.** This involves network requests and script parsing. If successful, the `DidLoadClassicScript` or `DidFetchScript` methods would be called.
3. **The Service Worker script is executed in a worker thread.** This is where `WillEvaluateScript` and `DidEvaluateTopLevelScript` come into play.
4. **The Service Worker might intercept network requests.** If the user navigates to another page on the same site or resources are requested, the Service Worker's `fetch` event listener might be triggered.
5. **If there are errors during script execution or event handling,** methods like `ReportException` or `ReportConsoleMessage` will be called.
6. **If navigation preload is enabled and a navigation occurs,** the methods related to navigation preload will be invoked.

**Debugging:**

* **Setting breakpoints:** A developer would typically set breakpoints in this `ServiceWorkerGlobalScopeProxy.cc` file to understand the flow of control and examine the state of variables when certain events occur in the Service Worker lifecycle.
* **Examining console messages:** Observing console messages (both regular logs and errors) originating from the Service Worker can provide clues about what's happening.
* **Using browser developer tools:** The "Application" or "Service Workers" tab in the browser's developer tools allows inspection of registered Service Workers, their status, and any errors encountered. This often provides a higher-level view that correlates with the low-level actions happening in this C++ code.

In summary, `ServiceWorkerGlobalScopeProxy.cc` is a crucial piece of infrastructure that bridges the gap between the main browser thread and the Service Worker's execution environment, ensuring smooth communication and proper management of the Service Worker's lifecycle and JavaScript execution.

### 提示词
```
这是目录为blink/renderer/modules/service_worker/service_worker_global_scope_proxy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope_proxy.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_functions.h"
#include "base/strings/strcat.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "services/network/public/mojom/url_loader.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_client.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_event_status.mojom-blink.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_error.h"
#include "third_party/blink/public/web/modules/service_worker/web_service_worker_context_client.h"
#include "third_party/blink/public/web/web_serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/headers.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/modules/exported/web_embedded_worker_impl.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope.h"
#include "third_party/blink/renderer/modules/service_worker/wait_until_observer.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

ServiceWorkerGlobalScopeProxy::~ServiceWorkerGlobalScopeProxy() {
  DCHECK(parent_thread_default_task_runner_->BelongsToCurrentThread());
  // Verify that the proxy has been detached.
  DCHECK(!embedded_worker_);
}

void ServiceWorkerGlobalScopeProxy::BindServiceWorker(
    CrossVariantMojoReceiver<mojom::blink::ServiceWorkerInterfaceBase>
        receiver) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  WorkerGlobalScope()->BindServiceWorker(std::move(receiver));
}

void ServiceWorkerGlobalScopeProxy::BindControllerServiceWorker(
    CrossVariantMojoReceiver<mojom::blink::ControllerServiceWorkerInterfaceBase>
        receiver) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  WorkerGlobalScope()->BindControllerServiceWorker(std::move(receiver));
}

void ServiceWorkerGlobalScopeProxy::OnNavigationPreloadResponse(
    int fetch_event_id,
    std::unique_ptr<WebURLResponse> response,
    mojo::ScopedDataPipeConsumerHandle data_pipe) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  WorkerGlobalScope()->OnNavigationPreloadResponse(
      fetch_event_id, std::move(response), std::move(data_pipe));
}

void ServiceWorkerGlobalScopeProxy::OnNavigationPreloadError(
    int fetch_event_id,
    std::unique_ptr<WebServiceWorkerError> error) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  WorkerGlobalScope()->OnNavigationPreloadError(fetch_event_id,
                                                std::move(error));
}

void ServiceWorkerGlobalScopeProxy::OnNavigationPreloadComplete(
    int fetch_event_id,
    base::TimeTicks completion_time,
    int64_t encoded_data_length,
    int64_t encoded_body_length,
    int64_t decoded_body_length) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  WorkerGlobalScope()->OnNavigationPreloadComplete(
      fetch_event_id, completion_time, encoded_data_length, encoded_body_length,
      decoded_body_length);
}

void ServiceWorkerGlobalScopeProxy::CountFeature(WebFeature feature) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().CountFeature(feature);
}

void ServiceWorkerGlobalScopeProxy::ReportException(
    const String& error_message,
    std::unique_ptr<SourceLocation> location,
    int exception_id) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().ReportException(error_message, location->LineNumber(),
                           location->ColumnNumber(), location->Url());
}

void ServiceWorkerGlobalScopeProxy::ReportConsoleMessage(
    mojom::ConsoleMessageSource source,
    mojom::ConsoleMessageLevel level,
    const String& message,
    SourceLocation* location) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().ReportConsoleMessage(source, level, message, location->LineNumber(),
                                location->Url());
}

void ServiceWorkerGlobalScopeProxy::WillInitializeWorkerContext() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().WillInitializeWorkerContext();
}

void ServiceWorkerGlobalScopeProxy::DidCreateWorkerGlobalScope(
    WorkerOrWorkletGlobalScope* worker_global_scope) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  DCHECK(!worker_global_scope_);
  worker_global_scope_ =
      static_cast<ServiceWorkerGlobalScope*>(worker_global_scope);
  scoped_refptr<base::SequencedTaskRunner> worker_task_runner =
      worker_global_scope->GetThread()->GetTaskRunner(
          TaskType::kInternalDefault);
  Client().WorkerContextStarted(this, std::move(worker_task_runner));
}

void ServiceWorkerGlobalScopeProxy::DidLoadClassicScript() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().WorkerScriptLoadedOnWorkerThread();
}

void ServiceWorkerGlobalScopeProxy::DidFetchScript() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().WorkerScriptLoadedOnWorkerThread();
}

void ServiceWorkerGlobalScopeProxy::DidFailToFetchClassicScript() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().FailedToFetchClassicScript();
}

void ServiceWorkerGlobalScopeProxy::DidFailToFetchModuleScript() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().FailedToFetchModuleScript();
}

void ServiceWorkerGlobalScopeProxy::WillEvaluateScript() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(
      "ServiceWorker", "ServiceWorkerGlobalScopeProxy::EvaluateTopLevelScript",
      TRACE_ID_LOCAL(this));
  ScriptState::Scope scope(
      WorkerGlobalScope()->ScriptController()->GetScriptState());
  Client().WillEvaluateScript(
      WorkerGlobalScope()->ScriptController()->GetContext());
  top_level_script_evaluation_start_time_ = base::TimeTicks::Now();
}

void ServiceWorkerGlobalScopeProxy::DidEvaluateTopLevelScript(bool success) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  base::UmaHistogramTimes(
      base::StrCat({"ServiceWorker.EvaluateTopLevelScript.",
                    success ? "Succeeded" : "Failed", ".Time"}),
      base::TimeTicks::Now() - top_level_script_evaluation_start_time_);
  WorkerGlobalScope()->DidEvaluateScript();
  Client().DidEvaluateScript(success);
  TRACE_EVENT_NESTABLE_ASYNC_END1(
      "ServiceWorker", "ServiceWorkerGlobalScopeProxy::EvaluateTopLevelScript",
      TRACE_ID_LOCAL(this), "success", success);
}

void ServiceWorkerGlobalScopeProxy::DidCloseWorkerGlobalScope() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  // close() is not web-exposed for ServiceWorker. This is called when
  // ServiceWorkerGlobalScope internally requests close(), for example, due to
  // failure on startup when installed scripts couldn't be read.
  //
  // This may look like a roundabout way to terminate the thread, but close()
  // seems like the standard way to initiate termination from inside the thread.

  // ServiceWorkerGlobalScope expects us to terminate the thread, so request
  // that here.
  PostCrossThreadTask(
      *parent_thread_default_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&WebEmbeddedWorkerImpl::TerminateWorkerContext,
                          CrossThreadUnretained(embedded_worker_.get())));

  // NOTE: WorkerThread calls WillDestroyWorkerGlobalScope() synchronously after
  // this function returns, since it calls DidCloseWorkerGlobalScope() then
  // PrepareForShutdownOnWorkerThread().
}

void ServiceWorkerGlobalScopeProxy::WillDestroyWorkerGlobalScope() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  v8::HandleScope handle_scope(WorkerGlobalScope()->GetThread()->GetIsolate());
  Client().WillDestroyWorkerContext(
      WorkerGlobalScope()->ScriptController()->GetContext());
  worker_global_scope_ = nullptr;
}

void ServiceWorkerGlobalScopeProxy::DidTerminateWorkerThread() {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  // This must be called after WillDestroyWorkerGlobalScope().
  DCHECK(!worker_global_scope_);
  Client().WorkerContextDestroyed();
}

bool ServiceWorkerGlobalScopeProxy::IsServiceWorkerGlobalScopeProxy() const {
  return true;
}

void ServiceWorkerGlobalScopeProxy::SetupNavigationPreload(
    int fetch_event_id,
    const KURL& url,
    mojo::PendingReceiver<network::mojom::blink::URLLoaderClient>
        preload_url_loader_client_receiver) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().SetupNavigationPreload(
      fetch_event_id, url, std::move(preload_url_loader_client_receiver));
}

void ServiceWorkerGlobalScopeProxy::RequestTermination(
    CrossThreadOnceFunction<void(bool)> callback) {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  Client().RequestTermination(ConvertToBaseOnceCallback(std::move(callback)));
}

bool ServiceWorkerGlobalScopeProxy::
    ShouldNotifyServiceWorkerOnWebSocketActivity(
        v8::Local<v8::Context> context) {
  return Client().ShouldNotifyServiceWorkerOnWebSocketActivity(context);
}

ServiceWorkerGlobalScopeProxy::ServiceWorkerGlobalScopeProxy(
    WebEmbeddedWorkerImpl& embedded_worker,
    WebServiceWorkerContextClient& client,
    scoped_refptr<base::SingleThreadTaskRunner>
        parent_thread_default_task_runner)
    : embedded_worker_(&embedded_worker),
      parent_thread_default_task_runner_(
          std::move(parent_thread_default_task_runner)),
      client_(&client),
      worker_global_scope_(nullptr) {
  DETACH_FROM_THREAD(worker_thread_checker_);
  DCHECK(parent_thread_default_task_runner_);
}

void ServiceWorkerGlobalScopeProxy::Detach() {
  DCHECK(parent_thread_default_task_runner_->BelongsToCurrentThread());
  embedded_worker_ = nullptr;
  client_ = nullptr;
}

void ServiceWorkerGlobalScopeProxy::TerminateWorkerContext() {
  DCHECK(parent_thread_default_task_runner_->BelongsToCurrentThread());
  embedded_worker_->TerminateWorkerContext();
}

bool ServiceWorkerGlobalScopeProxy::IsWindowInteractionAllowed() {
  return WorkerGlobalScope()->IsWindowInteractionAllowed();
}

void ServiceWorkerGlobalScopeProxy::PauseEvaluation() {
  WorkerGlobalScope()->PauseEvaluation();
}

void ServiceWorkerGlobalScopeProxy::ResumeEvaluation() {
  WorkerGlobalScope()->ResumeEvaluation();
}

mojom::blink::ServiceWorkerFetchHandlerType
ServiceWorkerGlobalScopeProxy::FetchHandlerType() {
  return WorkerGlobalScope()->FetchHandlerType();
}

bool ServiceWorkerGlobalScopeProxy::HasHidEventHandlers() {
  return WorkerGlobalScope()->HasHidEventHandlers();
}

bool ServiceWorkerGlobalScopeProxy::HasUsbEventHandlers() {
  return WorkerGlobalScope()->HasUsbEventHandlers();
}

void ServiceWorkerGlobalScopeProxy::GetRemoteAssociatedInterface(
    const WebString& name,
    mojo::ScopedInterfaceEndpointHandle handle) {
  WorkerGlobalScope()->GetRemoteAssociatedInterface(name, std::move(handle));
}

blink::AssociatedInterfaceRegistry&
ServiceWorkerGlobalScopeProxy::GetAssociatedInterfaceRegistry() {
  return WorkerGlobalScope()->GetAssociatedInterfaceRegistry();
}

WebServiceWorkerContextClient& ServiceWorkerGlobalScopeProxy::Client() const {
  DCHECK(client_);
  return *client_;
}

ServiceWorkerGlobalScope* ServiceWorkerGlobalScopeProxy::WorkerGlobalScope()
    const {
  DCHECK_CALLED_ON_VALID_THREAD(worker_thread_checker_);
  DCHECK(worker_global_scope_);
  return worker_global_scope_;
}

}  // namespace blink
```