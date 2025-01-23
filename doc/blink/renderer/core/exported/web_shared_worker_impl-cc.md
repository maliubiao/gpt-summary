Response:
Let's break down the thought process to analyze the `web_shared_worker_impl.cc` file and generate the comprehensive explanation.

**1. Understanding the Core Task:**

The request asks for an analysis of a specific Chromium Blink source file related to Shared Workers. The key is to understand its purpose, how it interacts with other parts of the browser (especially JavaScript, HTML, CSS), common errors, and how a user's actions lead to this code being executed.

**2. Initial Skim and Keyword Identification:**

The first step is to quickly read through the code, looking for keywords and patterns. Some immediately stand out:

* `WebSharedWorkerImpl`: This is the main class, suggesting it's the implementation of a web API related to shared workers.
* `SharedWorkerThread`:  Indicates the existence of a separate thread for the worker.
* `mojom::SharedWorkerHostInterfaceBase`:  Points to communication with the browser process (using Mojo).
* `WebSharedWorkerClient`:  Suggests a client interface for interaction.
* `Connect`, `StartWorkerContext`, `TerminateWorkerThread`:  These are core lifecycle methods.
* `ScriptType::kClassic`, `ScriptType::kModule`:  Relates to different types of JavaScript.
* `WebURL`, `WebSecurityOrigin`, `WebContentSecurityPolicy`:  Deals with web content and security.
* Mentions of `FetchClientSettingsObject`, `PolicyContainer`:  Involves loading and security policies.
* `MessagePortDescriptor`: Hints at inter-process communication mechanisms.

**3. Deconstructing the Class and its Methods:**

Now, examine the class methods individually:

* **Constructor & Destructor:**  Standard setup and teardown. Notice the initialization of `SharedWorkerThread`.
* **`TerminateWorkerThread()`:**  Responsible for shutting down the worker thread. The `asked_to_terminate_` flag is important for handling multiple termination requests.
* **`CountFeature()`:**  A telemetry/usage tracking mechanism.
* **`DidFailToFetchClassicScript()`/`DidFailToFetchModuleScript()`:** Error handling for script loading failures.
* **`DidEvaluateTopLevelScript()`:**  Signals that the worker has started executing its main script.
* **`DidCloseWorkerGlobalScope()`:**  Indicates the worker's global scope has been closed.
* **`DidTerminateWorkerThread()`:**  Called after the worker thread is actually terminated. This triggers the client's `WorkerContextDestroyed()` method.
* **`Connect()`:** Handles connection requests from documents. The `pending_channels_` logic is crucial for cases where the worker hasn't fully started yet.
* **`ConnectToChannel()`:**  The actual mechanism to connect a message port to the worker thread.
* **`DispatchPendingConnections()`:**  Sends out queued connection requests once the worker is ready.
* **`ConnectTaskOnWorkerThread()`:**  This method executes on the *worker thread* to handle the connection. It creates a `MessagePort` and sends a connect event. This highlights the cross-thread communication.
* **`StartWorkerContext()`:**  This is the most complex method. It handles the initialization of the worker thread. Key aspects include:
    * Setting up `GlobalScopeCreationParams`:  Contains information needed to create the worker's global scope. Pay attention to the different types of parameters being passed (URLs, security origins, policies, settings).
    * Creating `WorkerSettings`:  Configuration for the worker.
    * Handling different script types (`kClassic`, `kModule`).
    * Initializing DevTools integration.
    * Starting the `SharedWorkerThread`.
* **`TerminateWorkerContext()`:** A simpler termination method.
* **`CreateAndStart()`:**  A static factory method that combines the creation and starting of a `WebSharedWorkerImpl`.

**4. Identifying Relationships with Web Technologies:**

Consider how the functionality of `WebSharedWorkerImpl` relates to JavaScript, HTML, and CSS:

* **JavaScript:**  Shared Workers are a JavaScript API. The file is directly involved in loading and executing JavaScript code within the worker. The handling of script types (`kClassic`, `kModule`) is key. The `Connect` mechanism is how JavaScript in different documents communicates with the worker.
* **HTML:**  HTML uses `<script>` tags with `type="sharedworker"` to initiate the creation of shared workers. The `script_request_url` originates from the HTML. Multiple HTML pages can connect to the same shared worker.
* **CSS:** While not directly involved in parsing or applying CSS, shared workers can fetch resources, which might include CSS. They can also be used to perform tasks that influence the styling of web pages (though this is less direct than the interaction with JavaScript).

**5. Logical Inference and Assumptions:**

Think about the flow of execution and potential scenarios:

* **Input/Output for `Connect()`:**  Input: `connection_request_id`, `port`. Output: A connection established (eventually) in the worker. The `pending_channels_` array acts as a buffer when the worker isn't ready.
* **Input/Output for `StartWorkerContext()`:** Input: Various parameters related to the script, security, and context. Output:  A running shared worker. If script loading fails, there's an error output.
* **Error Scenarios:**  Focus on common issues like incorrect URLs, security violations (CORS), and network failures.

**6. User Actions and Debugging:**

Trace the user actions that lead to this code being involved:

* A user opens an HTML page containing a `<script type="sharedworker">` tag.
* The browser parses the HTML and initiates the creation of the shared worker.
* The browser process communicates with the renderer process (where Blink lives).
* The `WebSharedWorkerImpl` is created and its `StartWorkerContext()` method is called.
* When another page tries to connect to the same shared worker, the `Connect()` method is invoked.

For debugging, think about what could go wrong at each step:

* Script loading failures.
* Connection errors.
* Security policy violations.
* Worker termination issues.

**7. Structuring the Explanation:**

Organize the information logically:

* Start with a high-level overview of the file's purpose.
* Detail the key functionalities.
* Explain the relationships with web technologies.
* Provide concrete examples.
* Describe potential errors and debugging steps.
* Illustrate the user interaction flow.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe focus too much on individual lines of code.
* **Correction:** Shift to understanding the overall workflow and the purpose of different methods.
* **Initial thought:**  Not enough emphasis on the cross-process and cross-thread nature of shared workers.
* **Correction:** Highlight the role of Mojo and the interaction between the main thread and the worker thread.
* **Initial thought:**  Examples are too abstract.
* **Correction:** Provide specific code snippets and user scenarios.

By following these steps, iteratively refining the understanding, and focusing on the high-level purpose and interactions, you can generate a comprehensive and accurate explanation of the given source file.
This C++ source file, `web_shared_worker_impl.cc`, within the Chromium Blink rendering engine, implements the `WebSharedWorkerImpl` class. This class serves as the **Blink-side implementation of the `WebSharedWorker` interface**, which is exposed to the Chromium browser process. It's a crucial component in managing the lifecycle and communication with Shared Workers.

Here's a breakdown of its functions:

**Core Functionality:**

1. **Shared Worker Lifecycle Management:**
   - **Creation and Initialization:**  `WebSharedWorkerImpl` is created when the browser process requests the creation of a shared worker. It initializes a `SharedWorkerThread` which is the actual thread where the worker's JavaScript code will execute.
   - **Starting the Worker Context (`StartWorkerContext`)**: This is the core method that initiates the shared worker. It involves:
     - Setting up parameters for the worker's global scope (URLs, security origins, content security policies, etc.).
     - Creating `WorkerSettings` to configure the worker's environment.
     - Fetching and running the worker's main script (either classic or module script).
     - Setting up DevTools integration for debugging.
   - **Termination (`TerminateWorkerThread`, `TerminateWorkerContext`):**  Handles the graceful and forceful termination of the worker thread.
   - **Context Closure (`DidCloseWorkerGlobalScope`):**  Informs the browser process when the worker's global scope is closed.
   - **Destruction:** Cleans up resources when the shared worker is no longer needed.

2. **Communication with the Browser Process:**
   - Uses Mojo interfaces (`mojom::SharedWorkerHostInterfaceBase`) to communicate with the browser process. This includes:
     - Reporting feature usage (`CountFeature`).
     - Notifying about script load failures (`DidFailToFetchClassicScript`, `DidFailToFetchModuleScript`).
     - Indicating successful script evaluation (`DidEvaluateTopLevelScript`).
     - Signaling when the worker is ready for inspection by DevTools (`OnReadyForInspection`).
     - Informing the browser when a connection is established (`OnConnected`).
     - Notifying when the worker context is closed (`OnContextClosed`).

3. **Handling Connections from Documents:**
   - **`Connect(int connection_request_id, MessagePortDescriptor port)`:** This method is called when a document (e.g., a tab or iframe) attempts to connect to the shared worker.
   - **Pending Connections (`pending_channels_`):** If the worker is not yet fully started, incoming connection requests are queued.
   - **Dispatching Connections (`DispatchPendingConnections`):** Once the worker has started, these queued connections are established.
   - **`ConnectToChannel(int connection_request_id, MessagePortChannel channel)`:**  Sends the message port channel to the worker thread.
   - **`ConnectTaskOnWorkerThread(MessagePortChannel channel)`:**  Executed on the worker thread, this creates a `MessagePort` object within the worker's scope and dispatches a 'connect' event to the worker's JavaScript code.

**Relationship with JavaScript, HTML, and CSS:**

This file is **directly related to JavaScript** through the Shared Worker API.

* **JavaScript:**
    - Shared Workers are a JavaScript API. This file implements the underlying mechanisms that make that API work.
    - The `StartWorkerContext` method fetches and executes JavaScript code.
    - The `Connect` mechanism allows JavaScript code in different documents to communicate with the shared worker via message ports.
    - **Example:**  A JavaScript file `my-worker.js` could be the script loaded by the shared worker. Other JavaScript code in different HTML pages can connect to this worker using `new SharedWorker('my-worker.js')`.

* **HTML:**
    - HTML uses the `<script>` tag with `type="sharedworker"` to initiate the creation of a shared worker. The `script_request_url` passed to `StartWorkerContext` originates from this HTML.
    - **Example:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <title>Page 1</title>
      </head>
      <body>
        <script>
          const myWorker = new SharedWorker('worker.js');
          myWorker.port.start();
          myWorker.port.postMessage('Hello from page 1');
          myWorker.port.onmessage = function(e) {
            console.log('Message received from worker: ' + e.data);
          }
        </script>
      </body>
      </html>
      ```
      In this example, `worker.js` would be the script loaded by the shared worker, and this `WebSharedWorkerImpl` instance would be responsible for managing that worker.

* **CSS:**
    - While not directly involved in parsing or applying CSS, Shared Workers can fetch resources, which might include CSS files.
    - A shared worker could potentially be used to manage shared CSS-related tasks, though this is less common than its use for JavaScript logic.

**Logical Inference (Hypothetical Input and Output):**

**Scenario:** Two browser tabs open the same website, both trying to connect to a shared worker at `worker.js`.

**Input to `WebSharedWorkerImpl`:**

1. **Tab 1:**
   - `StartWorkerContext` called with `script_request_url` pointing to `worker.js`.
   - Later, `Connect` called with `connection_request_id = 1`, and a `MessagePortDescriptor`.
2. **Tab 2:**
   - `Connect` called with `connection_request_id = 2`, and a `MessagePortDescriptor`.

**Internal Logic:**

- When Tab 1 initiates the worker, `StartWorkerContext` will fetch and run `worker.js` on the `SharedWorkerThread`.
- The first `Connect` call from Tab 1 will likely occur before the worker is fully running, so the connection details will be stored in `pending_channels_`.
- The `Connect` call from Tab 2 might also arrive before the worker is running, and its details will be added to `pending_channels_`.
- Once `DidEvaluateTopLevelScript` is called (indicating the worker script has started), `DispatchPendingConnections` will be called.
- `DispatchPendingConnections` will iterate through `pending_channels_` and call `ConnectToChannel` for each pending connection.
- `ConnectToChannel` will post a task to the worker thread (`ConnectTaskOnWorkerThread`) to establish the message port within the worker's scope.
- The browser process will be notified of the successful connections via `host_->OnConnected`.

**Output/Side Effects:**

- Two message ports will be established, one for communication between Tab 1 and the shared worker, and another for Tab 2.
- The JavaScript code within `worker.js` will receive two 'connect' events, one for each connecting tab.

**User or Programming Common Usage Errors:**

1. **Incorrect Worker Script URL:**
   - **User Action:** A developer provides a wrong or inaccessible URL in the `new SharedWorker()` constructor in their JavaScript code.
   - **How it reaches here:** The browser attempts to fetch the script at the given URL. If the fetch fails, `DidFailToFetchClassicScript` or `DidFailToFetchModuleScript` will be called.
   - **Example Error Message (reported to the console):** "SharedWorker creation failed: <URL> couldn't be loaded."

2. **Security Errors (Cross-Origin Restrictions):**
   - **User Action:** A script on one origin attempts to create a shared worker whose script is on a different origin, and the appropriate CORS headers are not present.
   - **How it reaches here:** The browser's security checks will prevent the worker script from loading. This might trigger `DidFailToFetchClassicScript` or `DidFailToFetchModuleScript`.
   - **Example Error Message:** "SharedWorker creation failed: A shared worker on '<origin1>' cannot access scripts on '<origin2>'."

3. **Calling `connect()` before the worker is ready:**
   - **Programming Error:**  While the browser handles this gracefully by queuing connections, a developer might mistakenly assume the worker is immediately ready after `new SharedWorker()`. Trying to send messages too early before the 'connect' event in the worker can lead to confusion if not handled properly.
   - **How it relates here:** The `pending_channels_` mechanism in `WebSharedWorkerImpl` is designed to mitigate this issue.

4. **Uncaught Exceptions in the Worker Script:**
   - **Programming Error:** If the shared worker's JavaScript code throws an uncaught exception during its initial execution, it can lead to the worker terminating.
   - **How it relates here:** While this file doesn't directly handle the JavaScript exception, the worker thread might be terminated as a result, leading to `DidCloseWorkerGlobalScope` being called.

**User Operation Steps to Reach Here (Debugging Clues):**

1. **User Opens a Web Page:** The user navigates to a web page in their browser (e.g., by typing a URL, clicking a link, or opening a bookmark).
2. **HTML Parsing:** The browser's rendering engine (Blink) starts parsing the HTML content of the page.
3. **`<script type="sharedworker">` Encountered:** The HTML parser encounters a `<script>` tag with the `type="sharedworker"` attribute.
4. **Shared Worker Creation Request:** The browser initiates a request to create a shared worker. This request is sent from the renderer process to the browser process.
5. **Browser Process Handles Request:** The browser process receives the request and determines if a shared worker with the given URL already exists.
6. **`WebSharedWorkerImpl` Instantiation (if new worker):** If it's a new shared worker, the browser process instructs the renderer process to create an instance of `WebSharedWorkerImpl`.
7. **`StartWorkerContext` Invocation:** The `StartWorkerContext` method of the newly created `WebSharedWorkerImpl` instance is called to begin the worker's lifecycle. This involves fetching and executing the worker's script.
8. **Another Page Connects (Optional):** If the user opens another page on the same origin that attempts to connect to the same shared worker, the `Connect` method of the existing `WebSharedWorkerImpl` instance will be called.

**Debugging Clues:**

- **Breakpoints:** Set breakpoints in `StartWorkerContext`, `Connect`, `TerminateWorkerThread`, and the `Did*` methods to observe the flow of execution.
- **Logging:** Add `DLOG` statements to track the values of important variables like URLs, security origins, and connection IDs.
- **Browser's Developer Tools (Console & Network Tab):**
    - Check the console for error messages related to shared worker creation or script loading.
    - Use the Network tab to inspect the request for the worker script and verify its status and headers.
    - The "Application" tab (or similar) in developer tools often has a section dedicated to inspecting active workers.
- **`chrome://inspect/#workers`:** This Chrome-specific URL provides a view of active workers and allows you to inspect them using DevTools.

In summary, `web_shared_worker_impl.cc` is a vital component in Blink responsible for managing the lifecycle, execution, and communication of Shared Workers, bridging the gap between the browser process and the worker's JavaScript execution environment. It directly interacts with JavaScript and is initiated based on HTML content, making it a central piece in the web platform's worker infrastructure.

### 提示词
```
这是目录为blink/renderer/core/exported/web_shared_worker_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
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

#include "third_party/blink/renderer/core/exported/web_shared_worker_impl.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "net/storage_access_api/status.h"
#include "services/network/public/mojom/fetch_api.mojom-shared.h"
#include "third_party/blink/public/common/loader/worker_main_script_load_parameters.h"
#include "third_party/blink/public/mojom/browser_interface_broker.mojom-blink.h"
#include "third_party/blink/public/mojom/devtools/devtools_agent.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/fetch_client_settings_object.mojom-blink.h"
#include "third_party/blink/public/mojom/script/script_type.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_network_provider.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_worker_fetch_context.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/frame/csp/conversion_util.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/worker_devtools_params.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/parent_execution_context_task_runners.h"
#include "third_party/blink/renderer/core/workers/shared_worker_content_settings_proxy.h"
#include "third_party/blink/renderer/core/workers/shared_worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/shared_worker_thread.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_public.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

WebSharedWorkerImpl::WebSharedWorkerImpl(
    const blink::SharedWorkerToken& token,
    CrossVariantMojoRemote<mojom::SharedWorkerHostInterfaceBase> host,
    WebSharedWorkerClient* client)
    : reporting_proxy_(MakeGarbageCollected<SharedWorkerReportingProxy>(this)),
      worker_thread_(
          std::make_unique<SharedWorkerThread>(*reporting_proxy_, token)),
      host_(std::move(host)),
      client_(client) {
  DCHECK(IsMainThread());
}

WebSharedWorkerImpl::~WebSharedWorkerImpl() {
  DCHECK(IsMainThread());
}

void WebSharedWorkerImpl::TerminateWorkerThread() {
  DCHECK(IsMainThread());
  if (asked_to_terminate_)
    return;
  asked_to_terminate_ = true;
  pending_channels_.clear();
  worker_thread_->Terminate();
  // DidTerminateWorkerThread() will be called asynchronously.
}

void WebSharedWorkerImpl::CountFeature(WebFeature feature) {
  DCHECK(IsMainThread());
  host_->OnFeatureUsed(feature);
}

void WebSharedWorkerImpl::DidFailToFetchClassicScript() {
  DCHECK(IsMainThread());
  host_->OnScriptLoadFailed("Failed to fetch a worker script.");
  TerminateWorkerThread();
  // DidTerminateWorkerThread() will be called asynchronously.
}

void WebSharedWorkerImpl::DidFailToFetchModuleScript() {
  DCHECK(IsMainThread());
  host_->OnScriptLoadFailed("Failed to fetch a worker script.");
  TerminateWorkerThread();
  // DidTerminateWorkerThread() will be called asynchronously.
}

void WebSharedWorkerImpl::DidEvaluateTopLevelScript(bool success) {
  DCHECK(IsMainThread());
  DCHECK(!running_);
  running_ = true;
  DispatchPendingConnections();
}

void WebSharedWorkerImpl::DidCloseWorkerGlobalScope() {
  DCHECK(IsMainThread());
  host_->OnContextClosed();
  TerminateWorkerThread();
  // DidTerminateWorkerThread() will be called asynchronously.
}

void WebSharedWorkerImpl::DidTerminateWorkerThread() {
  DCHECK(IsMainThread());
  client_->WorkerContextDestroyed();
  // |this| is deleted at this point.
}

void WebSharedWorkerImpl::Connect(int connection_request_id,
                                  MessagePortDescriptor port) {
  DCHECK(IsMainThread());
  if (asked_to_terminate_)
    return;

  blink::MessagePortChannel channel(std::move(port));
  if (running_) {
    ConnectToChannel(connection_request_id, std::move(channel));
  } else {
    // If two documents try to load a SharedWorker at the same time, the
    // mojom::SharedWorker::Connect() for one of the documents can come in
    // before the worker is started. Just queue up the connect and deliver it
    // once the worker starts.
    pending_channels_.emplace_back(connection_request_id, std::move(channel));
  }
}

void WebSharedWorkerImpl::ConnectToChannel(int connection_request_id,
                                           MessagePortChannel channel) {
  DCHECK(IsMainThread());
  PostCrossThreadTask(
      *task_runner_for_connect_event_, FROM_HERE,
      CrossThreadBindOnce(&WebSharedWorkerImpl::ConnectTaskOnWorkerThread,
                          WTF::CrossThreadUnretained(this),
                          std::move(channel)));
  host_->OnConnected(connection_request_id);
}

void WebSharedWorkerImpl::DispatchPendingConnections() {
  DCHECK(IsMainThread());
  for (auto& item : pending_channels_)
    ConnectToChannel(item.first, std::move(item.second));
  pending_channels_.clear();
}

void WebSharedWorkerImpl::ConnectTaskOnWorkerThread(
    MessagePortChannel channel) {
  // Wrap the passed-in channel in a MessagePort, and send it off via a connect
  // event.
  DCHECK(worker_thread_->IsCurrentThread());
  auto* scope = To<SharedWorkerGlobalScope>(worker_thread_->GlobalScope());
  scope->Connect(std::move(channel));
}

void WebSharedWorkerImpl::StartWorkerContext(
    const WebURL& script_request_url,
    mojom::blink::ScriptType script_type,
    network::mojom::CredentialsMode credentials_mode,
    const WebString& name,
    WebSecurityOrigin constructor_origin,
    WebSecurityOrigin origin_from_browser,
    bool is_constructor_secure_context,
    const WebString& user_agent,
    const UserAgentMetadata& ua_metadata,
    const WebVector<WebContentSecurityPolicy>& content_security_policies,
    const WebFetchClientSettingsObject& outside_fetch_client_settings_object,
    const base::UnguessableToken& devtools_worker_token,
    CrossVariantMojoRemote<
        mojom::blink::WorkerContentSettingsProxyInterfaceBase> content_settings,
    CrossVariantMojoRemote<mojom::blink::BrowserInterfaceBrokerInterfaceBase>
        browser_interface_broker,
    bool pause_worker_context_on_start,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<blink::WebPolicyContainer> policy_container,
    scoped_refptr<WebWorkerFetchContext> web_worker_fetch_context,
    ukm::SourceId ukm_source_id,
    bool require_cross_site_request_for_cookies) {
  DCHECK(IsMainThread());
  DCHECK(web_worker_fetch_context);
  CHECK(constructor_origin.Get()->CanAccessSharedWorkers());

  // Creates 'outside settings' used in the "Processing model" algorithm in the
  // HTML spec:
  // https://html.spec.whatwg.org/C/#worker-processing-model
  auto* outside_settings_object =
      MakeGarbageCollected<FetchClientSettingsObjectSnapshot>(
          /*global_object_url=*/script_request_url,
          /*base_url=*/script_request_url, constructor_origin,
          outside_fetch_client_settings_object.referrer_policy,
          outside_fetch_client_settings_object.outgoing_referrer.GetString(),
          CalculateHttpsState(constructor_origin.Get()),
          AllowedByNosniff::MimeTypeCheck::kLaxForWorker,
          outside_fetch_client_settings_object.insecure_requests_policy ==
                  mojom::blink::InsecureRequestsPolicy::kUpgrade
              ? mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests |
                    mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent
              : mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent,
          FetchClientSettingsObject::InsecureNavigationsSet());

  auto worker_settings = std::make_unique<WorkerSettings>(
      false /* disable_reading_from_canvas */,
      false /* strict_mixed_content_checking */,
      true /* allow_running_of_insecure_content */,
      false /* strictly_block_blockable_mixed_content */,
      GenericFontFamilySettings());

  // Some params (e.g. address space) passed to GlobalScopeCreationParams are
  // dummy values. They will be updated after worker script fetch on the worker
  // thread.
  auto creation_params = std::make_unique<GlobalScopeCreationParams>(
      script_request_url, script_type, name, user_agent, ua_metadata,
      std::move(web_worker_fetch_context),
      ConvertToMojoBlink(content_security_policies),
      Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
      outside_settings_object->GetReferrerPolicy(),
      outside_settings_object->GetSecurityOrigin(),
      is_constructor_secure_context, outside_settings_object->GetHttpsState(),
      MakeGarbageCollected<WorkerClients>(),
      std::make_unique<SharedWorkerContentSettingsProxy>(
          std::move(content_settings)),
      nullptr /* inherited_trial_features */, devtools_worker_token,
      std::move(worker_settings), mojom::blink::V8CacheOptions::kDefault,
      nullptr /* worklet_module_response_map */,
      std::move(browser_interface_broker),
      mojo::NullRemote() /* code_cache_host_interface */,
      mojo::NullRemote() /* blob_url_store */, BeginFrameProviderParams(),
      nullptr /* parent_permissions_policy */, base::UnguessableToken(),
      ukm_source_id,
      /*parent_context_token=*/std::nullopt,
      /*parent_cross_origin_isolated_capability=*/false,
      /*parent_is_isolated_context=*/false,
      /*interface_registry=*/nullptr,
      /*agent_group_scheduler_compositor_task_runner=*/nullptr,
      /*top_level_frame_security_origin=*/nullptr,
      /*parent_storage_access_api_status=*/
      net::StorageAccessApiStatus::kNone,
      require_cross_site_request_for_cookies,
      blink::SecurityOrigin::CreateFromUrlOrigin(
          url::Origin(origin_from_browser)));

  auto thread_startup_data = WorkerBackingThreadStartupData::CreateDefault();
  thread_startup_data.atomics_wait_mode =
      WorkerBackingThreadStartupData::AtomicsWaitMode::kAllow;

  auto devtools_params = std::make_unique<WorkerDevToolsParams>();
  devtools_params->devtools_worker_token = devtools_worker_token;
  devtools_params->wait_for_debugger = pause_worker_context_on_start;
  mojo::PendingRemote<mojom::blink::DevToolsAgent> devtools_agent_remote;
  devtools_params->agent_receiver =
      devtools_agent_remote.InitWithNewPipeAndPassReceiver();
  mojo::PendingReceiver<mojom::blink::DevToolsAgentHost>
      devtools_agent_host_receiver =
          devtools_params->agent_host_remote.InitWithNewPipeAndPassReceiver();

  GetWorkerThread()->Start(std::move(creation_params), thread_startup_data,
                           std::move(devtools_params));

  // Capture the task runner for dispatching connect events. This is necessary
  // for avoiding race condition with WorkerScheduler termination induced by
  // close() call on SharedWorkerGlobalScope. See https://crbug.com/1104046 for
  // details.
  //
  // The HTML spec requires to queue a connect event using the DOM manipulation
  // task source.
  // https://html.spec.whatwg.org/C/#shared-workers-and-the-sharedworker-interface
  task_runner_for_connect_event_ =
      GetWorkerThread()->GetTaskRunner(TaskType::kDOMManipulation);

  switch (script_type) {
    case mojom::blink::ScriptType::kClassic:
      GetWorkerThread()->FetchAndRunClassicScript(
          script_request_url, std::move(worker_main_script_load_params),
          std::move(policy_container), outside_settings_object->CopyData(),
          nullptr /* outside_resource_timing_notifier */,
          v8_inspector::V8StackTraceId());
      break;
    case mojom::blink::ScriptType::kModule:
      GetWorkerThread()->FetchAndRunModuleScript(
          script_request_url, std::move(worker_main_script_load_params),
          std::move(policy_container), outside_settings_object->CopyData(),
          nullptr /* outside_resource_timing_notifier */, credentials_mode);
      break;
  }

  // We are now ready to inspect worker thread.
  host_->OnReadyForInspection(std::move(devtools_agent_remote),
                              std::move(devtools_agent_host_receiver));
}

void WebSharedWorkerImpl::TerminateWorkerContext() {
  DCHECK(IsMainThread());
  TerminateWorkerThread();
}

std::unique_ptr<WebSharedWorker> WebSharedWorker::CreateAndStart(
    const blink::SharedWorkerToken& token,
    const WebURL& script_request_url,
    mojom::blink::ScriptType script_type,
    network::mojom::CredentialsMode credentials_mode,
    const WebString& name,
    WebSecurityOrigin constructor_origin,
    WebSecurityOrigin origin_from_browser,
    bool is_constructor_secure_context,
    const WebString& user_agent,
    const UserAgentMetadata& ua_metadata,
    const WebVector<WebContentSecurityPolicy>& content_security_policies,
    const WebFetchClientSettingsObject& outside_fetch_client_settings_object,
    const base::UnguessableToken& devtools_worker_token,
    CrossVariantMojoRemote<
        mojom::blink::WorkerContentSettingsProxyInterfaceBase> content_settings,
    CrossVariantMojoRemote<mojom::blink::BrowserInterfaceBrokerInterfaceBase>
        browser_interface_broker,
    bool pause_worker_context_on_start,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<blink::WebPolicyContainer> policy_container,
    scoped_refptr<WebWorkerFetchContext> web_worker_fetch_context,
    CrossVariantMojoRemote<mojom::SharedWorkerHostInterfaceBase> host,
    WebSharedWorkerClient* client,
    ukm::SourceId ukm_source_id,
    bool require_cross_site_request_for_cookies) {
  auto worker =
      base::WrapUnique(new WebSharedWorkerImpl(token, std::move(host), client));
  worker->StartWorkerContext(
      script_request_url, script_type, credentials_mode, name,
      constructor_origin, origin_from_browser, is_constructor_secure_context,
      user_agent, ua_metadata, content_security_policies,
      outside_fetch_client_settings_object, devtools_worker_token,
      std::move(content_settings), std::move(browser_interface_broker),
      pause_worker_context_on_start, std::move(worker_main_script_load_params),
      std::move(policy_container), std::move(web_worker_fetch_context),
      ukm_source_id, require_cross_site_request_for_cookies);
  return worker;
}

}  // namespace blink
```