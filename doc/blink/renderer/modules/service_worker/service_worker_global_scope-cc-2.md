Response:
The user wants a summary of the functionality of the provided C++ code snippet from `service_worker_global_scope.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class:** The code snippet belongs to the `ServiceWorkerGlobalScope` class. This immediately tells us the code is related to the global scope in which a service worker runs.

2. **Analyze the Methods:**  Go through each method in the snippet and understand its purpose. Look for keywords and parameters that provide clues.

    * `DispatchExtendableMessageEventInternal`:  Handles incoming messages to the service worker. Key elements: origin check, sender agent cluster check.
    * `AbortCallbackForFetchEvent`: Cleans up resources and runs the fetch event callback when a fetch event is aborted.
    * `StartFetchEvent`:  Initiates the processing of a fetch event. Key elements: navigation preload, client ID handling, request creation, dispatching the event.
    * `SetFetchHandlerExistence`:  Indicates whether the service worker has a fetch event handler.
    * `DispatchFetchEventForSubresource`:  Handles fetch events for subresources. Enqueues the event.
    * `Clone`:  Creates a clone of the `ControllerServiceWorker` interface.
    * `InitializeGlobalScope`: Sets up the global scope with necessary information like service worker host, registration, and service worker object.
    * `PauseEvaluation` / `ResumeEvaluation`:  Controls the execution of the service worker script.
    * `DispatchInstallEvent` / `AbortInstallEvent` / `StartInstallEvent`:  Manages the install event lifecycle.
    * `DispatchActivateEvent` / `StartActivateEvent`: Manages the activate event lifecycle.
    * `DispatchBackgroundFetch...Event` series: Handles various events related to background fetch API (abort, click, fail, success).
    * `DispatchExtendableMessageEvent` / `StartExtendableMessageEvent`:  Manages the extendable message event lifecycle.
    * `DispatchFetchEventForMainResource`: Handles fetch events for the main resource. Enqueues the event.
    * `DispatchNotification...Event` series: Handles notification-related events (click, close).
    * `DispatchPushEvent` / `StartPushEvent`: Manages push notification events.
    * `DispatchPushSubscriptionChangeEvent` / `StartPushSubscriptionChangeEvent`: Handles push subscription change events.
    * `DispatchSyncEvent` / `StartSyncEvent`: Manages background sync events.

3. **Identify Key Functionality Areas:** Group the methods based on the features they implement. This leads to categories like:

    * Event Handling (Fetch, Message, Install, Activate, Background Fetch, Notification, Push, Sync)
    * Message Passing
    * Service Worker Lifecycle (Installation, Activation)
    * Fetch API Integration
    * Background Fetch API
    * Notifications API
    * Push API
    * Background Sync API
    * Global Scope Initialization and Control

4. **Look for Connections to Web Standards:** Note any mentions of JavaScript APIs (Fetch API, Notifications API, Push API, Background Sync API) and events (fetch, message, install, activate, etc.).

5. **Identify User/Programming Errors:**  Consider what could go wrong from a developer's perspective. Examples: Incorrect origin checks leading to message errors, not calling `respondWith` in fetch events.

6. **Trace User Actions (Debugging Context):** Think about how a user interaction might trigger these code paths. Examples:  A page making a network request, a website sending a push notification, a user clicking on a notification, a background sync event firing.

7. **Address Specific Instructions:** Make sure to explicitly mention the relationships to JavaScript, HTML, and CSS (where applicable), provide examples, and note any logical inferences with input/output.

8. **Synthesize a Summary:** Combine the identified functionalities and key areas into a concise summary.

9. **Review and Refine:** Ensure the summary is accurate, complete, and easy to understand. Check against the initial prompt to confirm all aspects have been addressed. For example, make sure to mention the "part 3 of 4" instruction and focus the summary accordingly on the functionality *within this specific snippet*. Avoid going into too much detail about the parts not shown.
这是 `blink/renderer/modules/service_worker/service_worker_global_scope.cc` 文件的第三部分，主要负责处理各种发送到 Service Worker 的事件，并执行相应的逻辑。 它的核心功能可以归纳为：

**功能归纳：**

1. **处理 ExtendableMessageEvent:** 接收并分发来自其他上下文（例如页面、其他 Service Worker）的 `message` 事件。它会进行安全检查（例如 origin 校验，sender agent cluster 校验），并根据情况创建 `ExtendableMessageEvent` 或 `ExtendableMessageEvent::CreateError`。

2. **管理 FetchEvent 的生命周期:**
   - 接收并启动 `fetch` 事件，包括主资源请求和子资源请求。
   - 处理导航预加载 (`navigationPreload`).
   - 创建 `FetchEvent` 对象，并关联 `WaitUntilObserver` 和 `FetchRespondWithObserver` 来管理事件的生命周期。
   - 支持竞速网络请求 (`raceNetworkRequest`).
   - 提供 `AbortCallbackForFetchEvent` 用于在 `fetch` 事件被中止时进行清理和回调。

3. **管理 Service Worker 的生命周期事件:**
   - 处理 `install` 事件：创建 `InstallEvent` 并分发。
   - 处理 `activate` 事件：创建 `ExtendableEvent` 并分发。

4. **处理 Background Fetch API 相关的事件:**
   - 处理 `backgroundfetchabort` 事件。
   - 处理 `backgroundfetchclick` 事件。
   - 处理 `backgroundfetchfail` 事件。
   - 处理 `backgroundfetchsuccess` 事件。
   - 为这些事件创建相应的 `BackgroundFetchEvent` 或 `BackgroundFetchUpdateUIEvent` 对象并分发。

5. **处理通知相关的事件:**
   - 处理 `notificationclick` 事件。
   - 处理 `notificationclose` 事件。
   - 为这些事件创建相应的 `NotificationEvent` 对象并分发。

6. **处理推送相关的事件:**
   - 处理 `push` 事件。
   - 处理 `pushsubscriptionchange` 事件。
   - 为这些事件创建相应的 `PushEvent` 或 `PushSubscriptionChangeEvent` 对象并分发。

7. **处理 Background Sync API 相关的事件:**
   - 处理 `sync` 事件。

8. **管理事件队列:**  使用 `event_queue_` 来管理和调度各种事件的执行。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  Service Worker 本身就是用 JavaScript 编写的。这段 C++ 代码负责在 Blink 引擎层面接收并分发事件到 Service Worker 的 JavaScript 代码中。
    * **例子 (FetchEvent):**  当页面上的 JavaScript 代码执行 `fetch('/api/data')` 时，浏览器会拦截这个请求，并将其封装成 `DispatchFetchEventParamsPtr` 传递到这个 C++ 代码中，然后 `StartFetchEvent` 方法会创建对应的 `FetchEvent` JavaScript 对象，并分发到 Service Worker 的 `fetch` 事件监听器中。Service Worker 的 JavaScript 代码可以调用 `event.respondWith()` 来自定义响应。
    * **例子 (MessageEvent):**  当页面上的 JavaScript 使用 `navigator.serviceWorker.controller.postMessage('hello')` 向 Service Worker 发送消息时，这段 C++ 代码的 `DispatchExtendableMessageEventInternal` 会接收到这个消息，并创建一个 `ExtendableMessageEvent` 对象传递给 Service Worker 的 `message` 事件监听器。
    * **例子 (PushEvent):**  当服务器向用户推送消息时，浏览器会唤醒相关的 Service Worker，这段 C++ 代码的 `DispatchPushEvent` 方法会被调用，创建一个 `PushEvent` 对象，并传递给 Service Worker 的 `push` 事件监听器。

* **HTML:**  HTML 中通过 `<script>` 标签注册 Service Worker。当浏览器加载包含 Service Worker 注册的 HTML 页面时，会触发 Service Worker 的安装和激活流程，最终会调用到这段 C++ 代码中的 `DispatchInstallEvent` 和 `DispatchActivateEvent`。

* **CSS:**  CSS 本身不会直接触发这里的代码。但是，Service Worker 可以拦截 CSS 资源的请求（通过 `fetch` 事件），并根据需要修改或缓存 CSS 资源。

**逻辑推理及假设输入与输出:**

* **假设输入 (ExtendableMessageEvent):**
    * `msg.message`: 一个包含字符串 "ping" 的 `SerializedScriptValue`。
    * `msg.sender_origin`:  与 Service Worker 的 origin 相同。
    * `msg.locked_to_sender_agent_cluster`: false。
* **输出 (ExtendableMessageEvent):**
    * 创建一个 `ExtendableMessageEvent` 对象，其 `data` 属性对应 "ping"。
    * 该事件被分发到 Service Worker 的 `message` 事件监听器。

* **假设输入 (FetchEvent - 主资源请求):**
    * 用户在浏览器地址栏输入 `https://example.com/`。
    * 注册了处理该域名的 Service Worker。
* **输出 (FetchEvent - 主资源请求):**
    * `DispatchFetchEventForMainResource` 被调用。
    * 创建一个 `FetchEvent` 对象，其 `request` 属性对应 `https://example.com/` 的请求。
    * 该事件被分发到 Service Worker 的 `fetch` 事件监听器。

**用户或编程常见的使用错误:**

* **在 `fetch` 事件中忘记调用 `event.respondWith()`:**  如果 Service Worker 拦截了一个 `fetch` 事件，但没有调用 `event.respondWith()` 来提供响应，浏览器会等待一段时间后放弃请求，导致页面加载失败或出现错误。这段 C++ 代码中的 `AbortCallbackForFetchEvent` 会在超时后被调用。
* **Origin 校验失败导致 `message` 事件无法传递:** 如果从一个与 Service Worker 不同源的页面发送消息，且 Service Worker 代码中没有做相应的跨域处理，`DispatchExtendableMessageEventInternal` 中的 origin 检查会失败，创建一个 error 事件而不是正常的 message 事件。
* **在 `install` 或 `activate` 事件中执行耗时操作，但未调用 `event.waitUntil()`:**  Service Worker 的安装和激活有时间限制。如果在这些事件的处理函数中执行了耗时的同步操作，可能会导致安装或激活失败。开发者应该使用 `event.waitUntil()` 来延长事件的生命周期，等待异步操作完成。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并访问一个注册了 Service Worker 的网站。**
2. **浏览器检查是否存在与该网站关联的 Service Worker。**
3. **如果 Service Worker 尚未安装，浏览器会下载并解析 Service Worker 的 JavaScript 文件。**
4. **Service Worker 的 JavaScript 代码执行，其中的 `register()` 调用会将 Service Worker 的信息传递给 Blink 引擎。**
5. **Blink 引擎创建 `ServiceWorkerGlobalScope` 对象，并执行 Service Worker 的生命周期事件（例如 `install`）。`DispatchInstallEvent` 方法会被调用。**
6. **如果用户与页面交互，例如点击链接或提交表单，导致网络请求，`DispatchFetchEventForMainResource` 或 `DispatchFetchEventForSubresource` 方法会被调用。**
7. **如果页面使用 `postMessage` 向 Service Worker 发送消息，`DispatchExtendableMessageEvent` 方法会被调用。**
8. **如果网站配置了推送通知，并且用户授权了通知，当服务器推送消息时，`DispatchPushEvent` 方法会被调用。**
9. **如果用户与通知进行交互（点击或关闭），`DispatchNotificationClickEvent` 或 `DispatchNotificationCloseEvent` 方法会被调用。**
10. **如果网站使用了 Background Sync API，当后台同步事件触发时，`DispatchSyncEvent` 方法会被调用。**

这段代码是 Service Worker 运行时的核心，它接收并调度来自浏览器各个模块的事件，并将这些事件传递到 Service Worker 的 JavaScript 代码中执行，从而实现 Service Worker 的各种功能。

### 提示词
```
这是目录为blink/renderer/modules/service_worker/service_worker_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
this, WaitUntilObserver::kMessageerror, event_id);
        event_to_dispatch = ExtendableMessageEvent::CreateError(
            origin, ports, source, observer);
      }
    }
    DispatchExtendableEvent(event_to_dispatch, observer);
    return;
  }

  DCHECK_NE(event->source_info_for_service_worker->version_id,
            mojom::blink::kInvalidServiceWorkerVersionId);
  ::blink::ServiceWorker* source = ::blink::ServiceWorker::From(
      GetExecutionContext(), std::move(event->source_info_for_service_worker));
  // TODO(crbug.com/1018092): Factor out these security checks so they aren't
  // duplicated in so many places.
  if (msg.message->IsOriginCheckRequired()) {
    const SecurityOrigin* target_origin =
        GetExecutionContext()->GetSecurityOrigin();
    if (!msg.sender_origin ||
        !msg.sender_origin->IsSameOriginWith(target_origin)) {
      observer = MakeGarbageCollected<WaitUntilObserver>(
          this, WaitUntilObserver::kMessageerror, event_id);
      event_to_dispatch =
          ExtendableMessageEvent::CreateError(origin, ports, source, observer);
    }
  }
  if (!event_to_dispatch) {
    DCHECK(!msg.locked_to_sender_agent_cluster || msg.sender_agent_cluster_id);
    if (!msg.locked_to_sender_agent_cluster ||
        GetExecutionContext()->IsSameAgentCluster(
            msg.sender_agent_cluster_id)) {
      observer = MakeGarbageCollected<WaitUntilObserver>(
          this, WaitUntilObserver::kMessage, event_id);
      event_to_dispatch = ExtendableMessageEvent::Create(
          std::move(msg.message), origin, ports, source, observer);
    } else {
      observer = MakeGarbageCollected<WaitUntilObserver>(
          this, WaitUntilObserver::kMessageerror, event_id);
      event_to_dispatch =
          ExtendableMessageEvent::CreateError(origin, ports, source, observer);
    }
  }
  DispatchExtendableEvent(event_to_dispatch, observer);
}

void ServiceWorkerGlobalScope::AbortCallbackForFetchEvent(
    int event_id,
    mojom::blink::ServiceWorkerEventStatus status) {
  // Discard a callback for an inflight respondWith() if it still exists.
  auto response_callback_iter = fetch_response_callbacks_.find(event_id);
  if (response_callback_iter != fetch_response_callbacks_.end()) {
    response_callback_iter->value->TakeValue().reset();
    fetch_response_callbacks_.erase(response_callback_iter);
  }
  RemoveItemFromRaceNetworkRequests(event_id);

  // Run the event callback with the error code.
  auto event_callback_iter = fetch_event_callbacks_.find(event_id);
  std::move(event_callback_iter->value).Run(status);
  fetch_event_callbacks_.erase(event_callback_iter);
}

void ServiceWorkerGlobalScope::StartFetchEvent(
    mojom::blink::DispatchFetchEventParamsPtr params,
    base::WeakPtr<CrossOriginResourcePolicyChecker> corp_checker,
    base::TimeTicks created_time,
    int event_id) {
  DCHECK(IsContextThread());
  RecordQueuingTime(created_time);

  // This TRACE_EVENT is used for perf benchmark to confirm if all of fetch
  // events have completed. (crbug.com/736697)
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchFetchEventInternal",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT, "url",
      params->request->url.ElidedString().Utf8());

  // Set up for navigation preload (FetchEvent#preloadResponse) if needed.
  bool navigation_preload_sent = !!params->preload_url_loader_client_receiver;
  if (navigation_preload_sent) {
    To<ServiceWorkerGlobalScopeProxy>(ReportingProxy())
        .SetupNavigationPreload(
            event_id, params->request->url,
            std::move(params->preload_url_loader_client_receiver));
  }

  ScriptState::Scope scope(ScriptController()->GetScriptState());
  auto* wait_until_observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kFetch, event_id);
  auto* respond_with_observer = MakeGarbageCollected<FetchRespondWithObserver>(
      this, event_id, std::move(corp_checker), *params->request,
      wait_until_observer);
  FetchEventInit* event_init = FetchEventInit::Create();
  event_init->setCancelable(true);
  // Note on how clientId / resultingClientID works.
  //
  // Legacy behavior:
  // main resource load -> only resultingClientId.
  // sub resource load -> only clientId.
  // worker script load -> only clientId. (treated as subresource)
  // * PlzDecicatedWorker makes this as main resource load.
  //   We should fix this.
  //
  // Expected behavior:
  // main resource load -> clientId and resultingClientId.
  // sub resource load -> only clientId.
  // worker script load -> clientId and resultingClientId.
  //                       (treated as main resource)
  // * We need to plumb a proper client ID to realize this.
  if (base::FeatureList::IsEnabled(
          features::kServiceWorkerClientIdAlignedWithSpec)) {
    // TODO(crbug.com/1520512): set the meaningful client_id for main resource.
    event_init->setClientId(params->client_id);
    event_init->setResultingClientId(params->request->is_main_resource_load
                                         ? params->resulting_client_id
                                         : String());
  } else {
    bool is_main_resource_load = params->request->is_main_resource_load;
    if (is_main_resource_load &&
        params->request->destination ==
            network::mojom::RequestDestination::kWorker) {
      CHECK(base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
      is_main_resource_load = false;
    }
    event_init->setClientId(is_main_resource_load ? String()
                                                  : params->client_id);
    event_init->setResultingClientId(
        is_main_resource_load ? params->resulting_client_id : String());
  }
  event_init->setIsReload(params->request->is_reload);

  mojom::blink::FetchAPIRequest& fetch_request = *params->request;
  auto stack_string = fetch_request.devtools_stack_id;

  NoteNewFetchEvent(fetch_request);

  if (params->race_network_request_loader_factory &&
      params->request->service_worker_race_network_request_token) {
    InsertNewItemToRaceNetworkRequests(
        event_id,
        params->request->service_worker_race_network_request_token.value(),
        std::move(params->race_network_request_loader_factory),
        params->request->url);
  }

  Request* request = Request::Create(
      ScriptController()->GetScriptState(), std::move(params->request),
      Request::ForServiceWorkerFetchEvent::kTrue);
  request->getHeaders()->SetGuard(Headers::kImmutableGuard);
  event_init->setRequest(request);

  ScriptState* script_state = ScriptController()->GetScriptState();
  FetchEvent* fetch_event = MakeGarbageCollected<FetchEvent>(
      script_state, event_type_names::kFetch, event_init, respond_with_observer,
      wait_until_observer, navigation_preload_sent);
  respond_with_observer->SetEvent(fetch_event);

  if (navigation_preload_sent) {
    // Keep |fetchEvent| until OnNavigationPreloadComplete() or
    // onNavigationPreloadError() will be called.
    pending_preload_fetch_events_.insert(event_id, fetch_event);
  }

  RequestDebugHeaderScope debug_header_scope(this, stack_string);
  DispatchExtendableEventWithRespondWith(fetch_event, wait_until_observer,
                                         respond_with_observer);
}

void ServiceWorkerGlobalScope::SetFetchHandlerExistence(
    FetchHandlerExistence fetch_handler_existence) {
  DCHECK(IsContextThread());
  if (fetch_handler_existence == FetchHandlerExistence::EXISTS) {
    GetThread()->GetWorkerBackingThread().SetForegrounded();
  }
}

void ServiceWorkerGlobalScope::DispatchFetchEventForSubresource(
    mojom::blink::DispatchFetchEventParamsPtr params,
    mojo::PendingRemote<mojom::blink::ServiceWorkerFetchResponseCallback>
        response_callback,
    DispatchFetchEventForSubresourceCallback callback) {
  DCHECK(IsContextThread());
  TRACE_EVENT2("ServiceWorker",
               "ServiceWorkerGlobalScope::DispatchFetchEventForSubresource",
               "url", params->request->url.ElidedString().Utf8(), "queued",
               RequestedTermination() ? "true" : "false");
  base::WeakPtr<CrossOriginResourcePolicyChecker> corp_checker =
      controller_receivers_.current_context()->GetWeakPtr();

  const int event_id = event_queue_->NextEventId();
  fetch_event_callbacks_.Set(event_id, std::move(callback));
  HeapMojoRemote<mojom::blink::ServiceWorkerFetchResponseCallback> remote(this);
  remote.Bind(std::move(response_callback),
              GetThread()->GetTaskRunner(TaskType::kNetworking));
  fetch_response_callbacks_.Set(event_id, WrapDisallowNew(std::move(remote)));

  if (RequestedTermination()) {
    event_queue_->EnqueuePending(
        event_id,
        WTF::BindOnce(&ServiceWorkerGlobalScope::StartFetchEvent,
                      WrapWeakPersistent(this), std::move(params),
                      std::move(corp_checker), base::TimeTicks::Now()),
        WTF::BindOnce(&ServiceWorkerGlobalScope::AbortCallbackForFetchEvent,
                      WrapWeakPersistent(this)),
        std::nullopt);
  } else {
    event_queue_->EnqueueNormal(
        event_id,
        WTF::BindOnce(&ServiceWorkerGlobalScope::StartFetchEvent,
                      WrapWeakPersistent(this), std::move(params),
                      std::move(corp_checker), base::TimeTicks::Now()),
        WTF::BindOnce(&ServiceWorkerGlobalScope::AbortCallbackForFetchEvent,
                      WrapWeakPersistent(this)),
        std::nullopt);
  }
}

void ServiceWorkerGlobalScope::Clone(
    mojo::PendingReceiver<mojom::blink::ControllerServiceWorker> receiver,
    const network::CrossOriginEmbedderPolicy& cross_origin_embedder_policy,
    mojo::PendingRemote<
        network::mojom::blink::CrossOriginEmbedderPolicyReporter>
        coep_reporter) {
  DCHECK(IsContextThread());
  auto checker = std::make_unique<CrossOriginResourcePolicyChecker>(
      cross_origin_embedder_policy, std::move(coep_reporter));

  controller_receivers_.Add(
      std::move(receiver), std::move(checker),
      GetThread()->GetTaskRunner(TaskType::kInternalDefault));
}

void ServiceWorkerGlobalScope::InitializeGlobalScope(
    mojo::PendingAssociatedRemote<mojom::blink::ServiceWorkerHost>
        service_worker_host,
    mojo::PendingAssociatedRemote<mojom::blink::AssociatedInterfaceProvider>
        associated_interfaces_from_browser,
    mojo::PendingAssociatedReceiver<mojom::blink::AssociatedInterfaceProvider>
        associated_interfaces_to_browser,
    mojom::blink::ServiceWorkerRegistrationObjectInfoPtr registration_info,
    mojom::blink::ServiceWorkerObjectInfoPtr service_worker_info,
    mojom::blink::FetchHandlerExistence fetch_hander_existence,
    mojo::PendingReceiver<mojom::blink::ReportingObserver>
        reporting_observer_receiver,
    mojom::blink::AncestorFrameType ancestor_frame_type,
    const blink::BlinkStorageKey& storage_key) {
  DCHECK(IsContextThread());
  DCHECK(!global_scope_initialized_);

  DCHECK(service_worker_host.is_valid());
  DCHECK(!service_worker_host_.is_bound());
  service_worker_host_.Bind(std::move(service_worker_host),
                            GetTaskRunner(TaskType::kInternalDefault));

  remote_associated_interfaces_.Bind(
      std::move(associated_interfaces_from_browser),
      GetTaskRunner(TaskType::kInternalDefault));
  associated_interfaces_receiver_.Bind(
      std::move(associated_interfaces_to_browser),
      GetTaskRunner(TaskType::kInternalDefault));

  // Set ServiceWorkerGlobalScope#registration.
  DCHECK_NE(registration_info->registration_id,
            mojom::blink::kInvalidServiceWorkerRegistrationId);
  DCHECK(registration_info->host_remote.is_valid());
  DCHECK(registration_info->receiver.is_valid());
  registration_ = MakeGarbageCollected<ServiceWorkerRegistration>(
      GetExecutionContext(), std::move(registration_info));

  // Set ServiceWorkerGlobalScope#serviceWorker.
  DCHECK_NE(service_worker_info->version_id,
            mojom::blink::kInvalidServiceWorkerVersionId);
  DCHECK(service_worker_info->host_remote.is_valid());
  DCHECK(service_worker_info->receiver.is_valid());
  service_worker_ = ::blink::ServiceWorker::From(
      GetExecutionContext(), std::move(service_worker_info));

  SetFetchHandlerExistence(fetch_hander_existence);

  ancestor_frame_type_ = ancestor_frame_type;

  if (reporting_observer_receiver) {
    ReportingContext::From(this)->Bind(std::move(reporting_observer_receiver));
  }

  global_scope_initialized_ = true;
  if (!pause_evaluation_)
    ReadyToRunWorkerScript();

  storage_key_ = storage_key;
}

void ServiceWorkerGlobalScope::PauseEvaluation() {
  DCHECK(IsContextThread());
  DCHECK(!global_scope_initialized_);
  DCHECK(!pause_evaluation_);
  pause_evaluation_ = true;
}

void ServiceWorkerGlobalScope::ResumeEvaluation() {
  DCHECK(IsContextThread());
  DCHECK(pause_evaluation_);
  pause_evaluation_ = false;
  if (global_scope_initialized_)
    ReadyToRunWorkerScript();
}

void ServiceWorkerGlobalScope::DispatchInstallEvent(
    DispatchInstallEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  install_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartInstallEvent,
                    WrapWeakPersistent(this)),
      WTF::BindOnce(&ServiceWorkerGlobalScope::AbortInstallEvent,
                    WrapWeakPersistent(this)),
      std::nullopt);
}

void ServiceWorkerGlobalScope::AbortInstallEvent(
    int event_id,
    mojom::blink::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  auto iter = install_event_callbacks_.find(event_id);
  CHECK(iter != install_event_callbacks_.end(), base::NotFatalUntil::M130);
  GlobalFetch::ScopedFetcher* fetcher = GlobalFetch::ScopedFetcher::From(*this);
  std::move(iter->value).Run(status, fetcher->FetchCount());
  install_event_callbacks_.erase(iter);
}

void ServiceWorkerGlobalScope::StartInstallEvent(int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchInstallEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kInstall, event_id);
  Event* event =
      InstallEvent::Create(event_type_names::kInstall,
                           ExtendableEventInit::Create(), event_id, observer);
  SetIsInstalling(true);
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchActivateEvent(
    DispatchActivateEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  activate_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartActivateEvent,
                    WrapWeakPersistent(this)),
      CreateAbortCallback(&activate_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartActivateEvent(int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchActivateEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kActivate, event_id);
  Event* event = ExtendableEvent::Create(
      event_type_names::kActivate, ExtendableEventInit::Create(), observer);
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchBackgroundFetchAbortEvent(
    mojom::blink::BackgroundFetchRegistrationPtr registration,
    DispatchBackgroundFetchAbortEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  background_fetch_abort_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartBackgroundFetchAbortEvent,
                    WrapWeakPersistent(this), std::move(registration)),
      CreateAbortCallback(&background_fetch_abort_event_callbacks_),
      std::nullopt);
}

void ServiceWorkerGlobalScope::StartBackgroundFetchAbortEvent(
    mojom::blink::BackgroundFetchRegistrationPtr registration,
    int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DispatchBackgroundFetchAbortEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kBackgroundFetchAbort, event_id);
  ScriptState* script_state = ScriptController()->GetScriptState();

  // Do not remove this, |scope| is needed by
  // BackgroundFetchEvent::Create which eventually calls ToV8.
  ScriptState::Scope scope(script_state);

  BackgroundFetchEventInit* init = BackgroundFetchEventInit::Create();
  init->setRegistration(MakeGarbageCollected<BackgroundFetchRegistration>(
      registration_, std::move(registration)));

  BackgroundFetchEvent* event = BackgroundFetchEvent::Create(
      event_type_names::kBackgroundfetchabort, init, observer);

  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchBackgroundFetchClickEvent(
    mojom::blink::BackgroundFetchRegistrationPtr registration,
    DispatchBackgroundFetchClickEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  background_fetch_click_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartBackgroundFetchClickEvent,
                    WrapWeakPersistent(this), std::move(registration)),
      CreateAbortCallback(&background_fetch_click_event_callbacks_),
      std::nullopt);
}

void ServiceWorkerGlobalScope::StartBackgroundFetchClickEvent(
    mojom::blink::BackgroundFetchRegistrationPtr registration,
    int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DispatchBackgroundFetchClickEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kBackgroundFetchClick, event_id);

  BackgroundFetchEventInit* init = BackgroundFetchEventInit::Create();
  init->setRegistration(MakeGarbageCollected<BackgroundFetchRegistration>(
      registration_, std::move(registration)));

  BackgroundFetchEvent* event = BackgroundFetchEvent::Create(
      event_type_names::kBackgroundfetchclick, init, observer);

  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchBackgroundFetchFailEvent(
    mojom::blink::BackgroundFetchRegistrationPtr registration,
    DispatchBackgroundFetchFailEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  background_fetch_fail_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartBackgroundFetchFailEvent,
                    WrapWeakPersistent(this), std::move(registration)),
      CreateAbortCallback(&background_fetch_fail_event_callbacks_),
      std::nullopt);
}

void ServiceWorkerGlobalScope::StartBackgroundFetchFailEvent(
    mojom::blink::BackgroundFetchRegistrationPtr registration,
    int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DispatchBackgroundFetchFailEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kBackgroundFetchFail, event_id);

  ScriptState* script_state = ScriptController()->GetScriptState();

  // Do not remove this, |scope| is needed by
  // BackgroundFetchSettledEvent::Create which eventually calls ToV8.
  ScriptState::Scope scope(script_state);

  BackgroundFetchEventInit* init = BackgroundFetchEventInit::Create();
  init->setRegistration(MakeGarbageCollected<BackgroundFetchRegistration>(
      registration_, std::move(registration)));

  BackgroundFetchUpdateUIEvent* event = BackgroundFetchUpdateUIEvent::Create(
      event_type_names::kBackgroundfetchfail, init, observer, registration_);

  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchBackgroundFetchSuccessEvent(
    mojom::blink::BackgroundFetchRegistrationPtr registration,
    DispatchBackgroundFetchSuccessEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  background_fetched_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartBackgroundFetchSuccessEvent,
                    WrapWeakPersistent(this), std::move(registration)),
      CreateAbortCallback(&background_fetched_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartBackgroundFetchSuccessEvent(
    mojom::blink::BackgroundFetchRegistrationPtr registration,
    int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DispatchBackgroundFetchSuccessEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kBackgroundFetchSuccess, event_id);

  ScriptState* script_state = ScriptController()->GetScriptState();

  // Do not remove this, |scope| is needed by
  // BackgroundFetchSettledEvent::Create which eventually calls ToV8.
  ScriptState::Scope scope(script_state);

  BackgroundFetchEventInit* init = BackgroundFetchEventInit::Create();
  init->setRegistration(MakeGarbageCollected<BackgroundFetchRegistration>(
      registration_, std::move(registration)));

  BackgroundFetchUpdateUIEvent* event = BackgroundFetchUpdateUIEvent::Create(
      event_type_names::kBackgroundfetchsuccess, init, observer, registration_);

  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchExtendableMessageEvent(
    mojom::blink::ExtendableMessageEventPtr event,
    DispatchExtendableMessageEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  message_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartExtendableMessageEvent,
                    WrapWeakPersistent(this), std::move(event)),
      CreateAbortCallback(&message_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartExtendableMessageEvent(
    mojom::blink::ExtendableMessageEventPtr event,
    int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DispatchExtendableMessageEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);
  DispatchExtendableMessageEventInternal(event_id, std::move(event));
}

void ServiceWorkerGlobalScope::DispatchFetchEventForMainResource(
    mojom::blink::DispatchFetchEventParamsPtr params,
    mojo::PendingRemote<mojom::blink::ServiceWorkerFetchResponseCallback>
        response_callback,
    DispatchFetchEventForMainResourceCallback callback) {
  DCHECK(IsContextThread());

  const int event_id = event_queue_->NextEventId();
  fetch_event_callbacks_.Set(event_id, std::move(callback));

  HeapMojoRemote<mojom::blink::ServiceWorkerFetchResponseCallback> remote(this);
  remote.Bind(std::move(response_callback),
              GetThread()->GetTaskRunner(TaskType::kNetworking));
  fetch_response_callbacks_.Set(event_id, WrapDisallowNew(std::move(remote)));

  // We can use nullptr as a |corp_checker| for the main resource because it
  // must be the same origin.
  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartFetchEvent,
                    WrapWeakPersistent(this), std::move(params),
                    /*corp_checker=*/nullptr, base::TimeTicks::Now()),
      WTF::BindOnce(&ServiceWorkerGlobalScope::AbortCallbackForFetchEvent,
                    WrapWeakPersistent(this)),
      std::nullopt);
}

void ServiceWorkerGlobalScope::DispatchNotificationClickEvent(
    const String& notification_id,
    mojom::blink::NotificationDataPtr notification_data,
    int action_index,
    const String& reply,
    DispatchNotificationClickEventCallback callback) {
  DCHECK(IsContextThread());

  const int event_id = event_queue_->NextEventId();
  notification_click_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartNotificationClickEvent,
                    WrapWeakPersistent(this), notification_id,
                    std::move(notification_data), action_index, reply),
      CreateAbortCallback(&notification_click_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartNotificationClickEvent(
    String notification_id,
    mojom::blink::NotificationDataPtr notification_data,
    int action_index,
    String reply,
    int event_id) {
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DispatchNotificationClickEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kNotificationClick, event_id);
  NotificationEventInit* event_init = NotificationEventInit::Create();
  if (notification_data->actions.has_value() && 0 <= action_index &&
      action_index < static_cast<int>(notification_data->actions->size())) {
    event_init->setAction((*notification_data->actions)[action_index]->action);
  }
  event_init->setNotification(Notification::Create(
      this, notification_id, std::move(notification_data), true /* showing */));
  event_init->setReply(reply);
  Event* event = NotificationEvent::Create(event_type_names::kNotificationclick,
                                           event_init, observer);
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchNotificationCloseEvent(
    const String& notification_id,
    mojom::blink::NotificationDataPtr notification_data,
    DispatchNotificationCloseEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  notification_close_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartNotificationCloseEvent,
                    WrapWeakPersistent(this), notification_id,
                    std::move(notification_data)),
      CreateAbortCallback(&notification_close_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartNotificationCloseEvent(
    String notification_id,
    mojom::blink::NotificationDataPtr notification_data,
    int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DispatchNotificationCloseEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);
  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kNotificationClose, event_id);
  NotificationEventInit* event_init = NotificationEventInit::Create();
  event_init->setAction(WTF::String());  // initialize as null.
  event_init->setNotification(Notification::Create(this, notification_id,
                                                   std::move(notification_data),
                                                   false /* showing */));
  Event* event = NotificationEvent::Create(event_type_names::kNotificationclose,
                                           event_init, observer);
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchPushEvent(
    const String& payload,
    DispatchPushEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  push_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartPushEvent,
                    WrapWeakPersistent(this), std::move(payload)),
      CreateAbortCallback(&push_event_callbacks_),
      base::Seconds(mojom::blink::kPushEventTimeoutSeconds));
}

void ServiceWorkerGlobalScope::StartPushEvent(String payload, int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchPushEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kPush, event_id);
  Event* event = PushEvent::Create(event_type_names::kPush,
                                   PushMessageData::Create(payload), observer);
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchPushSubscriptionChangeEvent(
    mojom::blink::PushSubscriptionPtr old_subscription,
    mojom::blink::PushSubscriptionPtr new_subscription,
    DispatchPushSubscriptionChangeEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  push_subscription_change_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartPushSubscriptionChangeEvent,
                    WrapWeakPersistent(this), std::move(old_subscription),
                    std::move(new_subscription)),
      CreateAbortCallback(&push_subscription_change_event_callbacks_),
      base::Seconds(mojom::blink::kPushEventTimeoutSeconds));
}

void ServiceWorkerGlobalScope::StartPushSubscriptionChangeEvent(
    mojom::blink::PushSubscriptionPtr old_subscription,
    mojom::blink::PushSubscriptionPtr new_subscription,
    int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DispatchPushSubscriptionChangeEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kPushSubscriptionChange, event_id);
  Event* event = PushSubscriptionChangeEvent::Create(
      event_type_names::kPushsubscriptionchange,
      (new_subscription)
          ? PushSubscription::Create(std::move(new_subscription), registration_)
          : nullptr /* new_subscription*/,
      (old_subscription)
          ? PushSubscription::Create(std::move(old_subscription), registration_)
          : nullptr /* old_subscription*/,
      observer);
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchSyncEvent(
    const String& tag,
    bool last_chance,
    base::TimeDelta timeout,
    DispatchSyncEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  sync_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartSyncEvent,
                    WrapWeakPersistent(this), std::move(tag), last_chance),
      CreateAbortCallback(&sync_event_callbacks_), timeout);
}

void ServiceWorkerGlobalScope::StartSyncEvent(String tag,
                                              bool last_c
```