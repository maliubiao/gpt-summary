Response:
My thinking process to summarize the provided code snippet goes through these steps:

1. **Identify the Core Object:** The code is within the `ServiceWorkerGlobalScope` class. This immediately tells me the focus is on the execution context of a service worker.

2. **Scan for Key Methods and Data Members:** I quickly look for prominent methods and data members to understand the major functionalities. I see things like `OnNavigationPreloadComplete`, `CreateStayAwakeToken`, `GetOrCreateServiceWorker`, `AddEventListenerInternal`, `FetchClassicImportedScript`, and various `DidHandle...Event` methods. These signal core service worker behaviors. Data members like `pending_preload_fetch_events_`, `service_worker_objects_`, and the various event callback lists (`install_event_callbacks_`, `fetch_event_callbacks_`, etc.) reinforce this.

3. **Group Functionalities:** I start grouping related methods and data. For example, the `DidHandle...Event` methods are clearly related to handling different types of events within the service worker lifecycle. Methods dealing with fetching (`FetchClassicImportedScript`, `GetThrottleOptionOverride`) form another group. The `RespondTo...Event` methods are about sending responses back.

4. **Connect to Service Worker Concepts:** I link the identified functionalities to core service worker concepts.
    * **Event Handling:** The numerous `DidHandle...Event` methods directly correspond to the event-driven nature of service workers (install, activate, fetch, push, etc.). The `AddEventListenerInternal` method manages these event listeners.
    * **Fetch API Interception:** The `RespondToFetchEvent` family of methods, along with `OnNavigationPreloadComplete`, clearly relate to the service worker's ability to intercept and handle network requests.
    * **Lifecycle Management:** Methods like `SetIsInstalling`, `OnIdleTimeout`, and `OnRequestedTermination` point to how the service worker's lifecycle is managed.
    * **Communication:** `DispatchExtendableMessageEventInternal` indicates how service workers communicate with other contexts.
    * **Caching:** The mentions of `cache_storage_installed_script_count_` and related histograms hint at the service worker's interaction with the Cache API during installation.

5. **Analyze Specific Code Sections:** I dive deeper into specific code blocks to understand their nuances. For instance, the `AddEventListenerInternal` method has logic to warn about adding listeners after the initial evaluation, which is important for service worker behavior. The `FetchClassicImportedScript` method handles importing scripts differently depending on whether the worker is new or being installed.

6. **Identify Interactions with Web Technologies:** I explicitly look for connections to JavaScript, HTML, and CSS. The event handling mechanism is the primary connection to JavaScript. The ability to intercept `fetch` requests directly relates to how HTML resources (and their associated CSS and JavaScript) are loaded. Navigation preload also ties into optimizing HTML navigation.

7. **Look for Logic and Assumptions:** I examine conditional statements and assertions (`DCHECK`). The code in `FetchClassicImportedScript` makes assumptions about installed scripts. The throttling logic based on the `is_installing_` flag is a key logical decision.

8. **Infer Potential User Errors:**  Based on the code, I can infer potential user errors. The warning in `AddEventListenerInternal` points to a common mistake of dynamically adding event listeners. The `importScripts` check highlights a restriction on importing scripts after installation.

9. **Consider Debugging Scenarios:** I think about how a developer might end up in this code during debugging. Scenarios involving network request interception, lifecycle events, or communication with other contexts are likely entry points. The `TRACE_EVENT` calls are valuable debugging aids.

10. **Synthesize the Summary:** Finally, I combine all the gathered information into a concise summary, emphasizing the key functionalities and their relationships to web technologies, potential errors, and debugging. I organize the summary logically, starting with a high-level overview and then going into more detail about specific areas. For a "part 2" summary, I focus on the functionalities presented *within* the provided snippet.

By following these steps, I can effectively analyze the code and generate a comprehensive and informative summary. The process involves understanding the context, identifying key components, connecting them to relevant concepts, and inferring practical implications.
这是提供的 Blink 引擎源代码文件 `service_worker_global_scope.cc` 的第二部分，主要功能延续了第一部分，继续构建和管理 Service Worker 的全局执行环境。以下是这部分代码的功能归纳：

**核心功能延续与扩展:**

* **处理导航预加载完成事件 (`OnNavigationPreloadComplete`):**  当导航预加载完成时，Service Worker 会收到通知。此函数找到对应的 `FetchEvent` 并通知它预加载已完成，并提供加载相关的信息（如完成时间、编码和解码后的数据长度）。这允许 Service Worker 利用预加载的数据来更快地响应后续的 fetch 请求。

* **创建保持唤醒令牌 (`CreateStayAwakeToken`):**  Service Worker 可以请求保持激活状态，防止其进入空闲状态被终止。此函数创建一个令牌，用于向事件队列表明需要保持 Service Worker 的运行。

* **获取或创建 Service Worker 对象 (`GetOrCreateServiceWorker`):**  根据提供的 `WebServiceWorkerObjectInfo`，此函数查找已存在的 Service Worker 对象。如果不存在，则创建一个新的 `::blink::ServiceWorker` 对象并存储起来。这确保了对相同 Service Worker 版本的引用是唯一的。

* **添加事件监听器 (`AddEventListenerInternal`):**  覆盖了基类的事件监听器添加方法。它增加了额外的检查，如果事件监听器是在 Service Worker 脚本初始评估之后添加的，会发出警告信息到控制台，并记录使用情况（UseCounter）。对于 `fetch` 事件，还会记录更具体的计数。**与 JavaScript 关系密切，因为 `addEventListener` 是 JavaScript 中常用的 API。**

    * **假设输入：** 在 Service Worker 脚本执行后，JavaScript 代码尝试添加 `fetch` 事件监听器。
    * **输出：** 控制台会显示警告信息，并且 Chrome 的 UseCounter 会记录 `kServiceWorkerFetchHandlerAddedAfterInitialization` 和 `kServiceWorkerEventHandlerAddedAfterInitialization` 这两个特征的使用。
    * **用户/编程常见错误：** 尝试在 Service Worker 初始化完成后动态添加关键事件监听器，可能导致预期行为不一致。

* **获取经典导入的脚本 (`FetchClassicImportedScript`):**  负责获取 `importScripts()` 导入的脚本内容。对于已安装的 Service Worker，它会从 `InstalledScriptsManager` 中获取已安装的脚本数据。对于新的 Service Worker，则使用基类的默认行为进行获取和安装。

* **获取节流选项覆盖 (`GetThrottleOptionOverride`):**  在 Service Worker 安装期间，可以对网络请求进行节流。此函数根据 `is_installing_` 状态和 feature flag 返回相应的节流选项。

* **分发可扩展事件 (`DispatchExtendableEvent`, `DispatchExtendableEventWithRespondWith`):**  用于分发需要等待 `waitUntil` 或 `respondWith` 解决的事件（如 `fetch` 事件）。这些函数管理观察者来跟踪事件的分发和完成状态。

* **跟踪对象 (`Trace`):**  用于 Blink 的垃圾回收机制，标记此对象持有的其他需要被跟踪的对象，防止被错误回收。

* **检查是否存在相关的 Fetch 事件 (`HasRelatedFetchEvent`, `HasRangeFetchEvent`):**  用于检查是否有针对特定 URL 的未响应的 fetch 事件。`HasRangeFetchEvent` 进一步检查是否是 range 请求。

* **获取待处理的节流限制 (`GetOutstandingThrottledLimit`):**  返回在 Service Worker 安装期间允许的待处理的节流请求数量限制。

* **判断是否是跨域隔离环境 (`CrossOriginIsolatedCapability`, `IsIsolatedContext`):**  判断当前 Service Worker 是否运行在跨域隔离的环境中。

* **处理 `importScripts` (`importScripts`):** 覆盖了基类的 `importScripts` 方法。添加了额外的检查，如果 Service Worker 已经安装完成，则不允许导入新的脚本，并抛出网络错误异常。 **与 JavaScript 的 `importScripts()` API 直接相关。**

    * **假设输入：** Service Worker 已经成功安装，然后在 JavaScript 代码中调用 `importScripts()` 导入新的脚本。
    * **输出：** Service Worker 会抛出一个 `NetworkError` 类型的 `DOMException`，阻止脚本的导入。
    * **用户/编程常见错误：** 误解 Service Worker 的生命周期，在安装完成后尝试动态导入脚本。

* **创建 Worker 脚本缓存元数据处理器 (`CreateWorkerScriptCachedMetadataHandler`):**  为 Service Worker 脚本创建特定的缓存元数据处理器。

* **处理异常 (`ExceptionThrown`):**  覆盖了基类的异常处理方法。如果存在调试器，则通知调试器发生了异常。

* **统计缓存存储安装的脚本信息 (`CountCacheStorageInstalledScript`):**  记录通过 Cache Storage API 安装的脚本的大小和元数据大小，用于性能分析。

* **处理各种事件完成回调 (`DidHandleInstallEvent`, `DidHandleActivateEvent`, `DidHandleFetchEvent`, 等等):**  这些函数在各种 Service Worker 生命周期事件处理完成后被调用，用于更新 Service Worker 的状态、执行回调函数、记录跟踪信息等。它们分别对应了 `install`, `activate`, `fetch`, `notificationclick`, `push`, `sync`, `paymentrequest` 等不同的 Service Worker 事件。

* **响应 Fetch 事件 (`RespondToFetchEventWithNoResponse`, `RespondToFetchEvent`, `RespondToFetchEventWithResponseStream`):**  当 Service Worker 需要响应 `fetch` 事件时，会调用这些函数将响应发送回浏览器。可以选择不返回响应 (fallback)，返回完整的响应对象，或者返回一个响应流。

* **响应支付相关的事件 (`RespondToAbortPaymentEvent`, `RespondToCanMakePaymentEvent`, `RespondToPaymentRequestEvent`):**  处理与 Payment Handler API 相关的事件的响应。

* **设置安装状态 (`SetIsInstalling`):**  设置 Service Worker 是否正在安装中，并根据状态更新节流选项和调度器的状态。

* **获取 CacheStorage 接口 (`TakeCacheStorage`):**  返回用于访问 Cache Storage API 的 `mojo::PendingRemote`。

* **获取 ServiceWorkerHost 接口 (`GetServiceWorkerHost`):**  返回与当前 Service Worker 关联的 `ServiceWorkerHost` 接口。

* **在事件开始前执行操作 (`OnBeforeStartEvent`):**  在事件开始处理之前设置 Service Worker 的离线模式状态。

* **处理空闲超时 (`OnIdleTimeout`):**  当 Service Worker 空闲超时时被调用，请求终止 Service Worker。

* **处理终止请求的结果 (`OnRequestedTermination`):**  处理 Service Worker 终止请求的结果，如果不会被终止，则会推送一个虚拟任务以保持运行。

* **判断是否请求了终止 (`RequestedTermination`):**  判断事件队列是否因为空闲超时而请求了终止。

* **分发可扩展消息事件 (`DispatchExtendableMessageEventInternal`):**  用于分发通过 `postMessage` 发送的消息事件。它处理消息的解包、端口的纠缠、来源的验证，并创建 `ExtendableMessageEvent` 对象进行分发。 **与 JavaScript 的 `postMessage()` API 相关。**

**与 JavaScript, HTML, CSS 的功能关系举例:**

* **JavaScript:**  `AddEventListenerInternal` 与 JavaScript 的 `addEventListener` API 直接对应，用于注册事件监听器。`importScripts` 方法处理 JavaScript 模块的导入。`postMessage` 方法通过 `DispatchExtendableMessageEventInternal` 进行处理。
* **HTML:** Service Worker 通过拦截 `fetch` 事件来影响 HTML 页面及其资源的加载。例如，Service Worker 可以缓存 HTML 文件，并在离线状态下提供缓存版本。导航预加载旨在加速 HTML 页面的导航。
* **CSS:**  与 HTML 类似，Service Worker 可以拦截 CSS 文件的请求，并提供缓存的版本，或者修改 CSS 响应。

**逻辑推理举例:**

* **假设输入：** 一个 `fetch` 事件被触发，Service Worker 注册了 `fetch` 事件监听器。
* **输出：**  `ServiceWorkerGlobalScope` 会创建一个 `FetchEvent` 对象，并将其放入事件队列。事件循环会执行与该事件关联的 JavaScript 代码。如果 Service Worker 调用了 `respondWith()`，则相关的 `RespondToFetchEvent...` 函数会被调用，将响应发送回浏览器。如果超时未响应，`RespondToFetchEventWithNoResponse` 可能会被调用。

**用户或编程常见的使用错误举例:**

* **在 Service Worker 安装完成后尝试使用 `importScripts` 导入新的脚本。**  如上述 `importScripts` 功能说明。
* **在 Service Worker 脚本初始评估之后才添加关键的事件监听器（如 `fetch`）。**  这可能导致 Service Worker 无法正确拦截和处理事件。
* **在 `fetch` 事件处理函数中，没有调用 `respondWith()` 或 `event.preventDefault()`，导致浏览器默认处理请求。**  这会使得 Service Worker 无法完全控制网络请求。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个注册了 Service Worker 的网页。**
2. **浏览器检测到 Service Worker 的更新或者首次安装。**
3. **浏览器会下载 Service Worker 的脚本。**
4. **浏览器创建一个 `ServiceWorkerGlobalScope` 对象，用于执行 Service Worker 的脚本。**
5. **在脚本执行过程中，可能会调用 `addEventListener` 注册各种事件监听器。** 这会触发 `AddEventListenerInternal`。
6. **当页面发起网络请求时，如果该请求被 Service Worker 管辖，则会触发 `fetch` 事件。**
7. **`ServiceWorkerGlobalScope` 会创建 `FetchEvent` 对象，并调用注册的 `fetch` 事件监听器。**
8. **在 `fetch` 事件处理函数中，开发者可能会使用 `respondWith()` 返回自定义的响应。** 这会导致调用 `RespondToFetchEvent...` 系列的函数。
9. **如果用户执行了某些操作，例如点击通知，则会触发相应的事件，例如 `notificationclick`，并最终调用 `DidHandleNotificationClickEvent`。**
10. **如果开发者在 Service Worker 中使用了 `postMessage` 与其他页面通信，则会触发 `DispatchExtendableMessageEventInternal`。**

通过查看调用堆栈，你可以追踪从浏览器事件（如网络请求、用户交互）到 `ServiceWorkerGlobalScope` 中特定函数的调用路径。 结合 Chrome 开发者工具的 Service Worker 面板和 Network 面板，可以帮助理解 Service Worker 的行为和调试问题。

**归纳一下它的功能 (第 2 部分):**

这部分 `ServiceWorkerGlobalScope` 的代码主要负责以下功能：

* **处理 Service Worker 生命周期中的关键事件完成后的回调。**
* **管理和响应 `fetch` 事件，包括处理导航预加载和提供不同类型的响应。**
* **处理与 Payment Handler API 相关的事件。**
* **提供对 Cache Storage API 的访问。**
* **管理 Service Worker 的安装状态和相关的网络请求节流。**
* **处理 Service Worker 的空闲超时和终止逻辑。**
* **分发和处理 `postMessage` 发送的消息事件。**
* **提供一些辅助功能，如创建保持唤醒令牌、获取 Service Worker 对象、统计安装脚本信息等。**

总的来说，这部分代码延续了 Service Worker 全局执行环境的核心功能，专注于事件处理、网络请求拦截和响应、以及与其他 Web API 的集成。

### 提示词
```
这是目录为blink/renderer/modules/service_worker/service_worker_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
std::move(error));
}

void ServiceWorkerGlobalScope::OnNavigationPreloadComplete(
    int fetch_event_id,
    base::TimeTicks completion_time,
    int64_t encoded_data_length,
    int64_t encoded_body_length,
    int64_t decoded_body_length) {
  DCHECK(IsContextThread());
  FetchEvent* fetch_event = pending_preload_fetch_events_.Take(fetch_event_id);
  DCHECK(fetch_event);
  fetch_event->OnNavigationPreloadComplete(
      this, completion_time, encoded_data_length, encoded_body_length,
      decoded_body_length);
}

std::unique_ptr<ServiceWorkerEventQueue::StayAwakeToken>
ServiceWorkerGlobalScope::CreateStayAwakeToken() {
  return event_queue_->CreateStayAwakeToken();
}

ServiceWorker* ServiceWorkerGlobalScope::GetOrCreateServiceWorker(
    WebServiceWorkerObjectInfo info) {
  if (info.version_id == mojom::blink::kInvalidServiceWorkerVersionId)
    return nullptr;

  auto it = service_worker_objects_.find(info.version_id);
  if (it != service_worker_objects_.end())
    return it->value.Get();

  const int64_t version_id = info.version_id;
  ::blink::ServiceWorker* worker =
      ::blink::ServiceWorker::Create(this, std::move(info));
  service_worker_objects_.Set(version_id, worker);
  return worker;
}

bool ServiceWorkerGlobalScope::AddEventListenerInternal(
    const AtomicString& event_type,
    EventListener* listener,
    const AddEventListenerOptionsResolved* options) {
  if (did_evaluate_script_) {
    String message = String::Format(
        "Event handler of '%s' event must be added on the initial evaluation "
        "of worker script.",
        event_type.Utf8().c_str());
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning, message));
    // Count the update of fetch handlers after the initial evaluation.
    if (event_type == event_type_names::kFetch) {
      UseCounter::Count(
          this, WebFeature::kServiceWorkerFetchHandlerAddedAfterInitialization);
    }
    UseCounter::Count(
        this, WebFeature::kServiceWorkerEventHandlerAddedAfterInitialization);
  }
  return WorkerGlobalScope::AddEventListenerInternal(event_type, listener,
                                                     options);
}

bool ServiceWorkerGlobalScope::FetchClassicImportedScript(
    const KURL& script_url,
    KURL* out_response_url,
    String* out_source_code,
    std::unique_ptr<Vector<uint8_t>>* out_cached_meta_data) {
  // InstalledScriptsManager is used only for starting installed service
  // workers.
  if (installed_scripts_manager_) {
    // All imported scripts must be installed. This is already checked in
    // ServiceWorkerGlobalScope::importScripts().
    DCHECK(installed_scripts_manager_->IsScriptInstalled(script_url));
    std::unique_ptr<InstalledScriptsManager::ScriptData> script_data =
        installed_scripts_manager_->GetScriptData(script_url);
    if (!script_data)
      return false;
    *out_response_url = script_url;
    *out_source_code = script_data->TakeSourceText();
    *out_cached_meta_data = script_data->TakeMetaData();
    // TODO(shimazu): Add appropriate probes for inspector.
    return true;
  }
  // This is a new service worker. Proceed with importing scripts and installing
  // them.
  return WorkerGlobalScope::FetchClassicImportedScript(
      script_url, out_response_url, out_source_code, out_cached_meta_data);
}

ResourceLoadScheduler::ThrottleOptionOverride
ServiceWorkerGlobalScope::GetThrottleOptionOverride() const {
  if (is_installing_ && base::FeatureList::IsEnabled(
                            features::kThrottleInstallingServiceWorker)) {
    return ResourceLoadScheduler::ThrottleOptionOverride::
        kStoppableAsThrottleable;
  }
  return ResourceLoadScheduler::ThrottleOptionOverride::kNone;
}

const AtomicString& ServiceWorkerGlobalScope::InterfaceName() const {
  return event_target_names::kServiceWorkerGlobalScope;
}

void ServiceWorkerGlobalScope::DispatchExtendableEvent(
    Event* event,
    WaitUntilObserver* observer) {
  observer->WillDispatchEvent();
  DispatchEvent(*event);

  // Check if the worker thread is forcibly terminated during the event
  // because of timeout etc.
  observer->DidDispatchEvent(GetThread()->IsForciblyTerminated());
}

void ServiceWorkerGlobalScope::DispatchExtendableEventWithRespondWith(
    Event* event,
    WaitUntilObserver* wait_until_observer,
    RespondWithObserver* respond_with_observer) {
  wait_until_observer->WillDispatchEvent();
  respond_with_observer->WillDispatchEvent();
  DispatchEventResult dispatch_result = DispatchEvent(*event);
  respond_with_observer->DidDispatchEvent(ScriptController()->GetScriptState(),
                                          dispatch_result);
  // false is okay because waitUntil() for events with respondWith() doesn't
  // care about the promise rejection or an uncaught runtime script error.
  wait_until_observer->DidDispatchEvent(false /* event_dispatch_failed */);
}

void ServiceWorkerGlobalScope::Trace(Visitor* visitor) const {
  visitor->Trace(clients_);
  visitor->Trace(registration_);
  visitor->Trace(service_worker_);
  visitor->Trace(service_worker_objects_);
  visitor->Trace(service_worker_host_);
  visitor->Trace(receiver_);
  visitor->Trace(abort_payment_result_callbacks_);
  visitor->Trace(can_make_payment_result_callbacks_);
  visitor->Trace(payment_response_callbacks_);
  visitor->Trace(fetch_response_callbacks_);
  visitor->Trace(pending_preload_fetch_events_);
  visitor->Trace(pending_streaming_upload_fetch_events_);
  visitor->Trace(controller_receivers_);
  visitor->Trace(remote_associated_interfaces_);
  visitor->Trace(associated_interfaces_receiver_);
  WorkerGlobalScope::Trace(visitor);
}

bool ServiceWorkerGlobalScope::HasRelatedFetchEvent(
    const KURL& request_url) const {
  auto it = unresponded_fetch_event_counts_.find(request_url);
  return it != unresponded_fetch_event_counts_.end();
}

bool ServiceWorkerGlobalScope::HasRangeFetchEvent(
    const KURL& request_url) const {
  auto it = unresponded_fetch_event_counts_.find(request_url);
  return it != unresponded_fetch_event_counts_.end() &&
         it->value.range_count > 0;
}

int ServiceWorkerGlobalScope::GetOutstandingThrottledLimit() const {
  return features::kInstallingServiceWorkerOutstandingThrottledLimit.Get();
}

// Note that ServiceWorkers can be for cross-origin iframes, and that it might
// look like an escape from the Permissions-Policy enforced on documents. It is
// safe however, even on platforms without OOPIF  because a ServiceWorker
// controlling a cross-origin iframe would be put in  a different process from
// the page, due to an origin mismatch in their cross-origin isolation.
// See https://crbug.com/1290224 for details.
bool ServiceWorkerGlobalScope::CrossOriginIsolatedCapability() const {
  return Agent::IsCrossOriginIsolated();
}

bool ServiceWorkerGlobalScope::IsIsolatedContext() const {
  // TODO(mkwst): Make a decision here, and spec it.
  return false;
}

void ServiceWorkerGlobalScope::importScripts(const Vector<String>& urls) {
  for (const String& string_url : urls) {
    KURL completed_url = CompleteURL(string_url);
    if (installed_scripts_manager_ &&
        !installed_scripts_manager_->IsScriptInstalled(completed_url)) {
      DCHECK(installed_scripts_manager_->IsScriptInstalled(Url()));
      v8::Isolate* isolate = GetThread()->GetIsolate();
      V8ThrowException::ThrowException(
          isolate,
          V8ThrowDOMException::CreateOrEmpty(
              isolate, DOMExceptionCode::kNetworkError,
              "Failed to import '" + completed_url.ElidedString() +
                  "'. importScripts() of new scripts after service worker "
                  "installation is not allowed."));
      return;
    }
  }
  WorkerGlobalScope::importScripts(urls);
}

CachedMetadataHandler*
ServiceWorkerGlobalScope::CreateWorkerScriptCachedMetadataHandler(
    const KURL& script_url,
    std::unique_ptr<Vector<uint8_t>> meta_data) {
  return MakeGarbageCollected<ServiceWorkerScriptCachedMetadataHandler>(
      this, script_url, std::move(meta_data));
}

void ServiceWorkerGlobalScope::ExceptionThrown(ErrorEvent* event) {
  WorkerGlobalScope::ExceptionThrown(event);
  if (WorkerThreadDebugger* debugger =
          WorkerThreadDebugger::From(GetThread()->GetIsolate()))
    debugger->ExceptionThrown(GetThread(), event);
}

void ServiceWorkerGlobalScope::CountCacheStorageInstalledScript(
    uint64_t script_size,
    uint64_t script_metadata_size) {
  ++cache_storage_installed_script_count_;
  cache_storage_installed_script_total_size_ += script_size;
  cache_storage_installed_script_metadata_total_size_ += script_metadata_size;

  base::UmaHistogramCustomCounts(
      "ServiceWorker.CacheStorageInstalledScript.ScriptSize",
      base::saturated_cast<base::Histogram::Sample>(script_size), 1000, 5000000,
      50);

  if (script_metadata_size) {
    base::UmaHistogramCustomCounts(
        "ServiceWorker.CacheStorageInstalledScript.CachedMetadataSize",
        base::saturated_cast<base::Histogram::Sample>(script_metadata_size),
        1000, 50000000, 50);
  }
}

void ServiceWorkerGlobalScope::DidHandleInstallEvent(
    int install_event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  SetFetchHandlerExistence(HasEventListeners(event_type_names::kFetch)
                               ? FetchHandlerExistence::EXISTS
                               : FetchHandlerExistence::DOES_NOT_EXIST);
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandleInstallEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(install_event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  GlobalFetch::ScopedFetcher* fetcher = GlobalFetch::ScopedFetcher::From(*this);
  RunEventCallback(&install_event_callbacks_, event_queue_.get(),
                   install_event_id, status, fetcher->FetchCount());
}

void ServiceWorkerGlobalScope::DidHandleActivateEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandleActivateEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&activate_event_callbacks_, event_queue_.get(), event_id,
                   status);
}

void ServiceWorkerGlobalScope::DidHandleBackgroundFetchAbortEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DidHandleBackgroundFetchAbortEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&background_fetch_abort_event_callbacks_, event_queue_.get(),
                   event_id, status);
}

void ServiceWorkerGlobalScope::DidHandleBackgroundFetchClickEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DidHandleBackgroundFetchClickEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&background_fetch_click_event_callbacks_, event_queue_.get(),
                   event_id, status);
}

void ServiceWorkerGlobalScope::DidHandleBackgroundFetchFailEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DidHandleBackgroundFetchFailEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&background_fetch_fail_event_callbacks_, event_queue_.get(),
                   event_id, status);
}

void ServiceWorkerGlobalScope::DidHandleBackgroundFetchSuccessEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DidHandleBackgroundFetchSuccessEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&background_fetched_event_callbacks_, event_queue_.get(),
                   event_id, status);
}

void ServiceWorkerGlobalScope::DidHandleExtendableMessageEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DidHandleExtendableMessageEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&message_event_callbacks_, event_queue_.get(), event_id,
                   status);
}

void ServiceWorkerGlobalScope::RespondToFetchEventWithNoResponse(
    int fetch_event_id,
    FetchEvent* fetch_event,
    const KURL& request_url,
    bool range_request,
    std::optional<network::DataElementChunkedDataPipe> request_body,
    base::TimeTicks event_dispatch_time,
    base::TimeTicks respond_with_settled_time) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::RespondToFetchEventWithNoResponse",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(fetch_event_id)),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  // `fetch_response_callbacks_` does not have the entry when the event timed
  // out.
  if (!fetch_response_callbacks_.Contains(fetch_event_id))
    return;
  mojom::blink::ServiceWorkerFetchResponseCallback* response_callback =
      fetch_response_callbacks_.Take(fetch_event_id)->Value().get();

  auto timing = mojom::blink::ServiceWorkerFetchEventTiming::New();
  timing->dispatch_event_time = event_dispatch_time;
  timing->respond_with_settled_time = respond_with_settled_time;

  NoteRespondedToFetchEvent(request_url, range_request);

  if (request_body) {
    pending_streaming_upload_fetch_events_.insert(fetch_event_id, fetch_event);
  }

  response_callback->OnFallback(std::move(request_body), std::move(timing));
}
void ServiceWorkerGlobalScope::OnStreamingUploadCompletion(int fetch_event_id) {
  pending_streaming_upload_fetch_events_.erase(fetch_event_id);
}

void ServiceWorkerGlobalScope::RespondToFetchEvent(
    int fetch_event_id,
    const KURL& request_url,
    bool range_request,
    mojom::blink::FetchAPIResponsePtr response,
    base::TimeTicks event_dispatch_time,
    base::TimeTicks respond_with_settled_time) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::RespondToFetchEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(fetch_event_id)),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  // `fetch_response_callbacks_` does not have the entry when the event timed
  // out.
  if (!fetch_response_callbacks_.Contains(fetch_event_id))
    return;

  mojom::blink::ServiceWorkerFetchResponseCallback* response_callback =
      fetch_response_callbacks_.Take(fetch_event_id)->Value().get();

  auto timing = mojom::blink::ServiceWorkerFetchEventTiming::New();
  timing->dispatch_event_time = event_dispatch_time;
  timing->respond_with_settled_time = respond_with_settled_time;

  NoteRespondedToFetchEvent(request_url, range_request);

  response_callback->OnResponse(std::move(response), std::move(timing));
}

void ServiceWorkerGlobalScope::RespondToFetchEventWithResponseStream(
    int fetch_event_id,
    const KURL& request_url,
    bool range_request,
    mojom::blink::FetchAPIResponsePtr response,
    mojom::blink::ServiceWorkerStreamHandlePtr body_as_stream,
    base::TimeTicks event_dispatch_time,
    base::TimeTicks respond_with_settled_time) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::RespondToFetchEventWithResponseStream",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(fetch_event_id)),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  // `fetch_response_callbacks_` does not have the entry when the event timed
  // out.
  if (!fetch_response_callbacks_.Contains(fetch_event_id))
    return;
  mojom::blink::ServiceWorkerFetchResponseCallback* response_callback =
      fetch_response_callbacks_.Take(fetch_event_id)->Value().get();

  auto timing = mojom::blink::ServiceWorkerFetchEventTiming::New();
  timing->dispatch_event_time = event_dispatch_time;
  timing->respond_with_settled_time = respond_with_settled_time;

  NoteRespondedToFetchEvent(request_url, range_request);

  response_callback->OnResponseStream(
      std::move(response), std::move(body_as_stream), std::move(timing));
}

void ServiceWorkerGlobalScope::DidHandleFetchEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  // This TRACE_EVENT is used for perf benchmark to confirm if all of fetch
  // events have completed. (crbug.com/736697)
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandleFetchEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));

  // Delete the URLLoaderFactory for the RaceNetworkRequest if it's not used.
  RemoveItemFromRaceNetworkRequests(event_id);

  if (!RunEventCallback(&fetch_event_callbacks_, event_queue_.get(), event_id,
                        status)) {
    // The event may have been aborted. Its response callback also needs to be
    // deleted.
    fetch_response_callbacks_.erase(event_id);
  } else {
    // |fetch_response_callback| should be used before settling a promise for
    // waitUntil().
    DCHECK(!fetch_response_callbacks_.Contains(event_id));
  }
}

void ServiceWorkerGlobalScope::DidHandleNotificationClickEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DidHandleNotificationClickEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&notification_click_event_callbacks_, event_queue_.get(),
                   event_id, status);
}

void ServiceWorkerGlobalScope::DidHandleNotificationCloseEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DidHandleNotificationCloseEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&notification_close_event_callbacks_, event_queue_.get(),
                   event_id, status);
}

void ServiceWorkerGlobalScope::DidHandlePushEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandlePushEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&push_event_callbacks_, event_queue_.get(), event_id,
                   status);
}

void ServiceWorkerGlobalScope::DidHandlePushSubscriptionChangeEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker",
      "ServiceWorkerGlobalScope::DidHandlePushSubscriptionChangeEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&push_subscription_change_event_callbacks_,
                   event_queue_.get(), event_id, status);
}

void ServiceWorkerGlobalScope::DidHandleSyncEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandleSyncEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&sync_event_callbacks_, event_queue_.get(), event_id,
                   status);
}

void ServiceWorkerGlobalScope::DidHandlePeriodicSyncEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandlePeriodicSyncEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&periodic_sync_event_callbacks_, event_queue_.get(),
                   event_id, status);
}

void ServiceWorkerGlobalScope::RespondToAbortPaymentEvent(
    int event_id,
    bool payment_aborted) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::RespondToAbortPaymentEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(abort_payment_result_callbacks_.Contains(event_id));
  payments::mojom::blink::PaymentHandlerResponseCallback* result_callback =
      abort_payment_result_callbacks_.Take(event_id)->Value().get();
  result_callback->OnResponseForAbortPayment(payment_aborted);
}

void ServiceWorkerGlobalScope::DidHandleAbortPaymentEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandleAbortPaymentEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  if (RunEventCallback(&abort_payment_event_callbacks_, event_queue_.get(),
                       event_id, status)) {
    abort_payment_result_callbacks_.erase(event_id);
  }
}

void ServiceWorkerGlobalScope::RespondToCanMakePaymentEvent(
    int event_id,
    payments::mojom::blink::CanMakePaymentResponsePtr response) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::RespondToCanMakePaymentEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(can_make_payment_result_callbacks_.Contains(event_id));
  payments::mojom::blink::PaymentHandlerResponseCallback* result_callback =
      can_make_payment_result_callbacks_.Take(event_id)->Value().get();
  result_callback->OnResponseForCanMakePayment(std::move(response));
}

void ServiceWorkerGlobalScope::DidHandleCanMakePaymentEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandleCanMakePaymentEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  if (RunEventCallback(&can_make_payment_event_callbacks_, event_queue_.get(),
                       event_id, status)) {
    can_make_payment_result_callbacks_.erase(event_id);
  }
}

void ServiceWorkerGlobalScope::RespondToPaymentRequestEvent(
    int payment_event_id,
    payments::mojom::blink::PaymentHandlerResponsePtr response) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::RespondToPaymentRequestEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(payment_event_id)),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(payment_response_callbacks_.Contains(payment_event_id));
  payments::mojom::blink::PaymentHandlerResponseCallback* response_callback =
      payment_response_callbacks_.Take(payment_event_id)->Value().get();
  response_callback->OnResponseForPaymentRequest(std::move(response));
}

void ServiceWorkerGlobalScope::DidHandlePaymentRequestEvent(
    int payment_event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandlePaymentRequestEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(payment_event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  if (RunEventCallback(&payment_request_event_callbacks_, event_queue_.get(),
                       payment_event_id, status)) {
    payment_response_callbacks_.erase(payment_event_id);
  }
}

void ServiceWorkerGlobalScope::DidHandleCookieChangeEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandleCookieChangeEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&cookie_change_event_callbacks_, event_queue_.get(),
                   event_id, status);
}

void ServiceWorkerGlobalScope::DidHandleContentDeleteEvent(
    int event_id,
    mojom::ServiceWorkerEventStatus status) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW1(
      "ServiceWorker", "ServiceWorkerGlobalScope::DidHandleContentDeleteEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_IN, "status", MojoEnumToString(status));
  RunEventCallback(&content_delete_callbacks_, event_queue_.get(), event_id,
                   status);
}

void ServiceWorkerGlobalScope::SetIsInstalling(bool is_installing) {
  is_installing_ = is_installing;
  UpdateFetcherThrottleOptionOverride();
  if (is_installing) {
    // Mark the scheduler as "hidden" to enable network throttling while the
    // service worker is installing.
    if (base::FeatureList::IsEnabled(
            features::kThrottleInstallingServiceWorker)) {
      GetThread()->GetScheduler()->OnLifecycleStateChanged(
          scheduler::SchedulingLifecycleState::kHidden);
    }
    return;
  }

  // Disable any network throttling that was enabled while the service worker
  // was in the installing state.
  if (base::FeatureList::IsEnabled(
          features::kThrottleInstallingServiceWorker)) {
    GetThread()->GetScheduler()->OnLifecycleStateChanged(
        scheduler::SchedulingLifecycleState::kNotThrottled);
  }

  // Installing phase is finished; record the stats for the scripts that are
  // stored in Cache storage during installation.
  base::UmaHistogramCounts1000(
      "ServiceWorker.CacheStorageInstalledScript.Count",
      base::saturated_cast<base::Histogram::Sample>(
          cache_storage_installed_script_count_));
  base::UmaHistogramCustomCounts(
      "ServiceWorker.CacheStorageInstalledScript.ScriptTotalSize",
      base::saturated_cast<base::Histogram::Sample>(
          cache_storage_installed_script_total_size_),
      1000, 50000000, 50);

  if (cache_storage_installed_script_metadata_total_size_) {
    base::UmaHistogramCustomCounts(
        "ServiceWorker.CacheStorageInstalledScript.CachedMetadataTotalSize",
        base::saturated_cast<base::Histogram::Sample>(
            cache_storage_installed_script_metadata_total_size_),
        1000, 50000000, 50);
  }
}

mojo::PendingRemote<mojom::blink::CacheStorage>
ServiceWorkerGlobalScope::TakeCacheStorage() {
  return std::move(cache_storage_remote_);
}

mojom::blink::ServiceWorkerHost*
ServiceWorkerGlobalScope::GetServiceWorkerHost() {
  DCHECK(service_worker_host_.is_bound());
  return service_worker_host_.get();
}

void ServiceWorkerGlobalScope::OnBeforeStartEvent(bool is_offline_event) {
  DCHECK(IsContextThread());
  SetIsOfflineMode(is_offline_event);
}

void ServiceWorkerGlobalScope::OnIdleTimeout() {
  DCHECK(IsContextThread());
  // RequestedTermination() returns true if ServiceWorkerEventQueue agrees
  // we should request the host to terminate this worker now.
  DCHECK(RequestedTermination());
  // We use CrossThreadBindOnce() here because the callback may be destroyed on
  // the main thread if the worker thread has already terminated.
  To<ServiceWorkerGlobalScopeProxy>(ReportingProxy())
      .RequestTermination(
          CrossThreadBindOnce(&ServiceWorkerGlobalScope::OnRequestedTermination,
                              WrapCrossThreadWeakPersistent(this)));
}

void ServiceWorkerGlobalScope::OnRequestedTermination(bool will_be_terminated) {
  DCHECK(IsContextThread());
  // This worker will be terminated soon. Ignore the message.
  if (will_be_terminated)
    return;

  // Push a dummy task to run all of queued tasks. This updates the
  // idle timer too.
  event_queue_->EnqueueNormal(
      event_queue_->NextEventId(),
      WTF::BindOnce(&ServiceWorkerEventQueue::EndEvent,
                    WTF::Unretained(event_queue_.get())),
      base::DoNothing(), std::nullopt);
}

bool ServiceWorkerGlobalScope::RequestedTermination() const {
  DCHECK(IsContextThread());
  return event_queue_->did_idle_timeout();
}

void ServiceWorkerGlobalScope::DispatchExtendableMessageEventInternal(
    int event_id,
    mojom::blink::ExtendableMessageEventPtr event) {
  BlinkTransferableMessage msg = std::move(event->message);
  MessagePortArray* ports =
      MessagePort::EntanglePorts(*this, std::move(msg.ports));
  String origin;
  if (!event->source_origin->IsOpaque())
    origin = event->source_origin->ToString();
  WaitUntilObserver* observer = nullptr;
  Event* event_to_dispatch = nullptr;

  if (event->source_info_for_client) {
    mojom::blink::ServiceWorkerClientInfoPtr client_info =
        std::move(event->source_info_for_client);
    DCHECK(!client_info->client_uuid.empty());
    ServiceWorkerClient* source = nullptr;
    if (client_info->client_type == mojom::ServiceWorkerClientType::kWindow)
      source = MakeGarbageCollected<ServiceWorkerWindowClient>(*client_info);
    else
      source = MakeGarbageCollected<ServiceWorkerClient>(*client_info);
    // TODO(crbug.com/1018092): Factor out these security checks so they aren't
    // duplicated in so many places.
    if (msg.message->IsOriginCheckRequired()) {
      const SecurityOrigin* target_origin =
          GetExecutionContext()->GetSecurityOrigin();
      if (!msg.sender_origin ||
          !msg.sender_origin->IsSameOriginWith(target_origin)) {
        observer = MakeGarbageCollected<WaitUntilObserver>(
            this, WaitUntilObserver::kMessageerror, event_id);
        event_to_dispatch = ExtendableMessageEvent::CreateError(
            origin, ports, source, observer);
      }
    }
    if (!event_to_dispatch) {
      if (!msg.locked_to_sender_agent_cluster ||
          GetExecutionContext()->IsSameAgentCluster(
              msg.sender_agent_cluster_id)) {
        observer = MakeGarbageCollected<WaitUntilObserver>(
            this, WaitUntilObserver::kMessage, event_id);
        event_to_dispatch = ExtendableMessageEvent::Create(
            std::move(msg.message), origin, ports, source, observer);
      } else {
        observer = MakeGarbageCollected<WaitUntilObserver>(
```