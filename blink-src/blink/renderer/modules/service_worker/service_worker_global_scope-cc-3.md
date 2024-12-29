Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. This snippet belongs to the `ServiceWorkerGlobalScope` class and focuses on event dispatching within a Service Worker.

Here's a breakdown of the thinking process:

1. **Identify the Core Functionality:** The code primarily deals with dispatching various events to the Service Worker. The function names like `DispatchSyncEvent`, `DispatchPeriodicSyncEvent`, `DispatchFetchEvent` etc., clearly indicate this.

2. **Categorize the Events:**  Group the dispatched events based on their type. I can see sync events, periodic sync events, payment-related events, cookie change events, content delete events, and fetch events.

3. **Analyze Individual Dispatch Functions:** For each event type, understand the flow:
    * **Enqueueing:**  Most dispatch functions start by getting a unique `event_id` and enqueueing a task in an `event_queue_`. This suggests asynchronous processing.
    * **Callback Handling:**  Callbacks are often associated with enqueued events, stored in maps like `periodic_sync_event_callbacks_`.
    * **Event Creation:**  An event object is created (e.g., `SyncEvent::Create`, `PeriodicSyncEvent::Create`).
    * **Observer Pattern:**  `WaitUntilObserver` is frequently used, indicating a mechanism to track when the event processing is complete (likely related to `waitUntil`).
    * **Dispatching:** The event is dispatched using `DispatchExtendableEvent` or `DispatchExtendableEventWithRespondWith`.
    * **Tracing:** `TRACE_EVENT_WITH_FLOW0` calls are present for debugging and performance analysis.

4. **Identify Relationships with Web Technologies:**
    * **JavaScript:** Service Workers are written in JavaScript. The code interacts with JavaScript by dispatching events that trigger JavaScript handlers within the Service Worker scope. The `ExecuteScriptForTest` function directly executes JavaScript code.
    * **HTML:** Service Workers are associated with web pages (HTML documents). They intercept network requests made by the HTML page. The `FetchEvent` is the most prominent example of this interaction.
    * **CSS:** While not directly evident in this snippet, Service Workers can intercept requests for CSS files, allowing for custom caching strategies.

5. **Look for Logic and Assumptions:**
    * **Event Queue:** The code heavily relies on an event queue, implying asynchronous event processing.
    * **Callbacks:** The use of callbacks suggests a non-blocking approach to handling events.
    * **`WaitUntilObserver`:**  This class likely implements the `extendableevent.waitUntil()` functionality in JavaScript.

6. **Identify Potential User Errors:**
    * **Not calling `respondWith` for Fetch Events:** If a fetch event handler doesn't call `respondWith`, the browser might hang waiting for a response.
    * **Errors in `waitUntil` Promises:** Unhandled rejections in promises passed to `waitUntil` can prevent the Service Worker from completing its tasks.

7. **Trace User Actions to Reach This Code:** Think about how a user interaction triggers a Service Worker event. For example, a network request initiates a `FetchEvent`, or a sync registration leads to a `SyncEvent`.

8. **Address the "Part 4 of 4" Instruction:**  Since this is the final part, synthesize the information from the previous parts (though not provided here) and summarize the overall function of the code in the context of the entire file/class. Focus on the event dispatching aspects highlighted in this snippet.

9. **Review and Refine:**  Ensure the explanation is clear, concise, and addresses all aspects of the prompt. Use examples where requested.

**Self-Correction/Refinement during the process:**

* Initially, I might have just listed the dispatch functions. Realizing the prompt asks for *functionality*, I need to explain *what* these functions do and *how* they do it (enqueueing, callbacks, observers, etc.).
* I need to make sure to connect the C++ code to the corresponding JavaScript APIs that developers use in Service Workers.
* The prompt specifically asks for assumptions and input/output. While the code doesn't have explicit "input" in the traditional sense, the *event data* being passed can be considered the input, and the *execution of the event handler* (and potential side effects) the output. For the event queue, the input is the event and the output is the scheduled execution.
* The user error section should focus on common mistakes developers make when working with Service Workers and the events handled by this code.
这是 `blink/renderer/modules/service_worker/service_worker_global_scope.cc` 文件的最后一部分，主要负责**分发各种类型的事件到 Service Worker 的全局作用域**，并处理与这些事件相关的生命周期管理和回调。

**功能归纳:**

总而言之，这部分代码的核心功能是**接收来自 Chromium 浏览器内核的事件通知，并将这些事件转化为可以在 Service Worker JavaScript 代码中处理的事件对象并进行分发。**  它管理着事件的排队、执行、以及等待事件处理完成的机制（通过 `WaitUntilObserver`）。此外，它还处理了一些特定事件的特殊逻辑，例如支付相关的事件。

**与 JavaScript, HTML, CSS 的关系及举例:**

这部分代码是 Service Worker 功能的核心，它将浏览器的底层事件与 JavaScript API 连接起来。

* **JavaScript:**
    * **事件分发:**  `DispatchSyncEvent`, `DispatchPeriodicSyncEvent`, `DispatchFetchEvent` 等函数最终会将事件传递到 Service Worker 的 JavaScript 环境中，触发对应的事件监听器（例如 `self.addEventListener('sync', event => { ... })`）。
        * **例子:** 当浏览器接收到来自服务器的推送消息时，会调用 `DispatchSyncEvent`，这会在 Service Worker 的 JavaScript 代码中触发 `sync` 事件。
    * **`waitUntil`:**  `WaitUntilObserver` 与 JavaScript 中的 `event.waitUntil(promise)` API 相关联。当 Service Worker 的事件处理函数调用 `event.waitUntil()` 时，`WaitUntilObserver` 会跟踪 Promise 的状态，确保 Service Worker 在 Promise 完成之前不会被终止。
        * **例子:** 在 `fetch` 事件的监听器中，如果使用了 `event.respondWith(fetch(event.request))`，`event.waitUntil()` 会隐式地等待 `fetch(event.request)` 返回的 Promise 完成。
    * **Payment API:** `DispatchAbortPaymentEvent`, `DispatchCanMakePaymentEvent`, `DispatchPaymentRequestEvent` 处理了与 Payment Handler API 相关的事件，这些 API 允许 Service Worker 作为支付处理程序。
        * **例子:**  网站调用 `navigator.payment.requestPayment()` 时，浏览器可能会调用 `DispatchPaymentRequestEvent` 来通知已注册的 Payment Handler Service Worker。
    * **CookieChangeEvent:** `DispatchCookieChangeEvent` 将浏览器的 Cookie 变化通知给 Service Worker。
        * **例子:** 当网站设置或删除 Cookie 时，如果注册了 `cookiechange` 事件监听器，Service Worker 就能收到通知。
    * **ContentDeleteEvent:** `DispatchContentDeleteEvent` 用于通知 Service Worker PWA 相关的 content 被删除。
        * **例子:** 用户在操作系统层面卸载了 PWA，可能会触发 `contentdelete` 事件。

* **HTML:**
    * **FetchEvent:**  当 HTML 页面发起网络请求（例如加载图片、脚本、AJAX 请求）时，如果当前作用域下有活动的 Service Worker，`DispatchFetchEvent` 会被调用，允许 Service Worker 拦截和处理这些请求。
        * **例子:**  HTML 中有一个 `<img src="/image.png">` 标签，浏览器在加载这张图片时可能会触发 Service Worker 的 `fetch` 事件。

* **CSS:**
    * **FetchEvent:**  与 HTML 类似，当浏览器请求 CSS 文件时，`DispatchFetchEvent` 也会被调用，Service Worker 可以自定义 CSS 资源的缓存策略。
        * **例子:**  HTML 中引用了一个 `<link rel="stylesheet" href="/style.css">`，浏览器加载 `style.css` 时，Service Worker 可以拦截请求并从缓存中返回。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  浏览器接收到一个新的网络请求，目标 URL 在 Service Worker 的控制范围内。
* **输出:**  `DispatchFetchEvent` 函数会被调用，创建一个 `FetchEvent` 对象，并将该对象分发到 Service Worker 的 JavaScript 环境中。Service Worker 的 `fetch` 事件监听器会接收到这个事件对象。

* **假设输入:**  网站调用了 `navigator.serviceWorker.ready.then(registration => registration.sync.register('my-sync'))`。
* **输出:**  在未来的某个时刻（当网络连接恢复或浏览器认为合适时），浏览器会调用 `DispatchSyncEvent`，并传入 `tag` 为 `'my-sync'` 的信息，触发 Service Worker 的 `sync` 事件监听器。

**用户或编程常见的使用错误举例:**

* **在 `fetch` 事件监听器中忘记调用 `event.respondWith()`:**
    * **错误:**  Service Worker 的 `fetch` 事件监听器没有调用 `event.respondWith()` 来返回一个 `Response` 对象，导致浏览器一直等待响应，页面加载卡住。
    * **用户操作:** 用户点击一个链接或浏览到包含需要加载资源的页面。
    * **调试线索:** 开发者工具的网络面板会显示请求状态为 "Pending"，Service Worker 的日志可能没有错误信息，但事件循环可能被阻塞。
* **在 `waitUntil()` 中传入的 Promise 发生错误或拒绝:**
    * **错误:**  Service Worker 使用 `event.waitUntil()` 来延长事件的生命周期，但传入的 Promise 最终被拒绝，导致 Service Worker 可能过早终止，一些后台任务没有完成。
    * **用户操作:** 用户可能没有直接感知，但一些需要 Service Worker 完成的后台同步或缓存更新可能失败。
    * **调试线索:** 开发者工具的 Application 面板的 Service Workers 部分可能会显示错误信息，或者在控制台中输出 Promise 拒绝的错误。
* **在支付相关的事件中，没有正确处理 `respondWith()`:**
    * **错误:**  对于 `paymentrequest` 事件，Service Worker 需要调用 `respondWith()` 并返回一个包含支付结果的 Promise。如果处理不当，支付流程可能会中断。
    * **用户操作:** 用户在网站上点击支付按钮。
    * **调试线索:** 支付流程失败，浏览器可能会显示错误信息，Service Worker 的日志可能包含与支付 API 相关的错误。

**用户操作是如何一步步的到达这里，作为调试线索 (以 `FetchEvent` 为例):**

1. **用户在浏览器地址栏输入网址或点击链接:** 这会导致浏览器发起一个或多个网络请求，请求 HTML 文件以及相关的资源 (CSS, JavaScript, 图片等)。
2. **浏览器检查当前页面是否被 Service Worker 控制:**  浏览器会查找是否存在与当前页面关联的、处于激活状态的 Service Worker。
3. **如果存在活动的 Service Worker，并且请求的资源在其控制范围内:**  浏览器会将这些网络请求传递给 Service Worker 处理。
4. **Chromium 浏览器内核 (Blink 引擎) 会创建相应的 `FetchEvent` 对象:**  针对每个被 Service Worker 控制的网络请求，Blink 引擎会在内部创建 `FetchEvent` 的数据结构。
5. **`ServiceWorkerGlobalScope::DispatchFetchEvent()` 被调用:** 这部分代码会接收到 Blink 引擎创建的 `FetchEvent` 信息。
6. **事件被加入到 `event_queue_` 中:**  `FetchEvent` 会被添加到 Service Worker 的事件队列中，等待被执行。
7. **事件循环处理事件:** Service Worker 的事件循环会从队列中取出 `FetchEvent`。
8. **`ServiceWorkerGlobalScope::StartFetchEvent()` 被调用:**  该函数会创建实际的 JavaScript `FetchEvent` 对象。
9. **JavaScript `fetch` 事件监听器被触发:** Service Worker 的 JavaScript 代码中注册的 `fetch` 事件监听器会接收到这个 `FetchEvent` 对象，开发者可以在监听器中编写处理网络请求的逻辑。

**调试线索:**

* 在开发者工具的 **Application** 面板的 **Service Workers** 部分，可以查看 Service Worker 的状态，包括是否激活，以及最近的事件日志。
* 在开发者工具的 **Network** 面板，可以查看网络请求的状态，如果请求被 Service Worker 拦截，可以看到请求的发起者是 Service Worker。
* 在开发者工具的 **Console** 面板，可以查看 Service Worker 输出的日志信息，使用 `console.log()` 可以帮助调试 Service Worker 的行为。
* 使用开发者工具的 **Sources** 面板，可以调试 Service Worker 的 JavaScript 代码，设置断点，查看变量的值，逐步执行代码。

总而言之，这部分 `ServiceWorkerGlobalScope.cc` 代码是连接浏览器底层事件和 Service Worker JavaScript 代码的关键桥梁，它负责接收、处理和分发各种类型的事件，使得 Service Worker 能够实现其强大的离线缓存、后台同步、推送通知等功能。

Prompt: 
```
这是目录为blink/renderer/modules/service_worker/service_worker_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
hance,
                                              int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchSyncEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kSync, event_id);
  Event* event =
      SyncEvent::Create(event_type_names::kSync, tag, last_chance, observer);
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchPeriodicSyncEvent(
    const String& tag,
    base::TimeDelta timeout,
    DispatchPeriodicSyncEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  periodic_sync_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartPeriodicSyncEvent,
                    WrapWeakPersistent(this), std::move(tag)),
      CreateAbortCallback(&periodic_sync_event_callbacks_), timeout);
}

void ServiceWorkerGlobalScope::StartPeriodicSyncEvent(String tag,
                                                      int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchPeriodicSyncEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kPeriodicSync, event_id);
  Event* event =
      PeriodicSyncEvent::Create(event_type_names::kPeriodicsync, tag, observer);
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchAbortPaymentEvent(
    mojo::PendingRemote<payments::mojom::blink::PaymentHandlerResponseCallback>
        response_callback,
    DispatchAbortPaymentEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  abort_payment_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartAbortPaymentEvent,
                    WrapWeakPersistent(this), std::move(response_callback)),
      CreateAbortCallback(&abort_payment_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartAbortPaymentEvent(
    mojo::PendingRemote<payments::mojom::blink::PaymentHandlerResponseCallback>
        response_callback,
    int event_id) {
  DCHECK(IsContextThread());
  HeapMojoRemote<payments::mojom::blink::PaymentHandlerResponseCallback> remote(
      this);
  // Payment task need to be processed on the user interaction task
  // runner (TaskType::kUserInteraction).
  // See:
  // https://www.w3.org/TR/payment-request/#user-aborts-the-payment-request-algorithm
  remote.Bind(std::move(response_callback),
              GetThread()->GetTaskRunner(TaskType::kUserInteraction));
  abort_payment_result_callbacks_.Set(event_id,
                                      WrapDisallowNew(std::move(remote)));
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchAbortPaymentEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* wait_until_observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kAbortPayment, event_id);
  AbortPaymentRespondWithObserver* respond_with_observer =
      MakeGarbageCollected<AbortPaymentRespondWithObserver>(
          this, event_id, wait_until_observer);

  Event* event = AbortPaymentEvent::Create(
      event_type_names::kAbortpayment, ExtendableEventInit::Create(),
      respond_with_observer, wait_until_observer);

  DispatchExtendableEventWithRespondWith(event, wait_until_observer,
                                         respond_with_observer);
}

void ServiceWorkerGlobalScope::DispatchCanMakePaymentEvent(
    payments::mojom::blink::CanMakePaymentEventDataPtr event_data,
    mojo::PendingRemote<payments::mojom::blink::PaymentHandlerResponseCallback>
        response_callback,
    DispatchCanMakePaymentEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  can_make_payment_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartCanMakePaymentEvent,
                    WrapWeakPersistent(this), std::move(event_data),
                    std::move(response_callback)),
      CreateAbortCallback(&can_make_payment_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartCanMakePaymentEvent(
    payments::mojom::blink::CanMakePaymentEventDataPtr event_data,
    mojo::PendingRemote<payments::mojom::blink::PaymentHandlerResponseCallback>
        response_callback,
    int event_id) {
  DCHECK(IsContextThread());
  HeapMojoRemote<payments::mojom::blink::PaymentHandlerResponseCallback> remote(
      this);
  // Payment task need to be processed on the user interaction task
  // runner (TaskType::kUserInteraction).
  // See:
  // https://www.w3.org/TR/payment-request/#canmakepayment-method
  remote.Bind(std::move(response_callback),
              GetThread()->GetTaskRunner(TaskType::kUserInteraction));
  can_make_payment_result_callbacks_.Set(event_id,
                                         WrapDisallowNew(std::move(remote)));
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchCanMakePaymentEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* wait_until_observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kCanMakePayment, event_id);
  CanMakePaymentRespondWithObserver* respond_with_observer =
      MakeGarbageCollected<CanMakePaymentRespondWithObserver>(
          this, event_id, wait_until_observer);

  Event* event = CanMakePaymentEvent::Create(
      event_type_names::kCanmakepayment,
      PaymentEventDataConversion::ToCanMakePaymentEventInit(
          ScriptController()->GetScriptState(), std::move(event_data)),
      respond_with_observer, wait_until_observer);

  DispatchExtendableEventWithRespondWith(event, wait_until_observer,
                                         respond_with_observer);
}

void ServiceWorkerGlobalScope::DispatchPaymentRequestEvent(
    payments::mojom::blink::PaymentRequestEventDataPtr event_data,
    mojo::PendingRemote<payments::mojom::blink::PaymentHandlerResponseCallback>
        response_callback,
    DispatchPaymentRequestEventCallback callback) {
  DCHECK(IsContextThread());
  const int event_id = event_queue_->NextEventId();
  payment_request_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartPaymentRequestEvent,
                    WrapWeakPersistent(this), std::move(event_data),
                    std::move(response_callback)),
      CreateAbortCallback(&payment_request_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartPaymentRequestEvent(
    payments::mojom::blink::PaymentRequestEventDataPtr event_data,
    mojo::PendingRemote<payments::mojom::blink::PaymentHandlerResponseCallback>
        response_callback,
    int event_id) {
  DCHECK(IsContextThread());
  HeapMojoRemote<payments::mojom::blink::PaymentHandlerResponseCallback> remote(
      this);
  // Payment task need to be processed on the user interaction task
  // runner (TaskType::kUserInteraction).
  // See:
  // https://www.w3.org/TR/payment-request/#user-accepts-the-payment-request-algorithm
  remote.Bind(std::move(response_callback),
              GetThread()->GetTaskRunner(TaskType::kUserInteraction));
  payment_response_callbacks_.Set(event_id, WrapDisallowNew(std::move(remote)));
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchPaymentRequestEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* wait_until_observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kPaymentRequest, event_id);
  PaymentRequestRespondWithObserver* respond_with_observer =
      PaymentRequestRespondWithObserver::Create(this, event_id,
                                                wait_until_observer);

  // Update respond_with_observer to check for required information specified in
  // the event_data during response validation.
  if (event_data->payment_options) {
    respond_with_observer->set_should_have_payer_name(
        event_data->payment_options->request_payer_name);
    respond_with_observer->set_should_have_payer_email(
        event_data->payment_options->request_payer_email);
    respond_with_observer->set_should_have_payer_phone(
        event_data->payment_options->request_payer_phone);
    respond_with_observer->set_should_have_shipping_info(
        event_data->payment_options->request_shipping);
  }

  // Count standardized payment method identifiers, such as "basic-card" or
  // "tokenized-card". Omit counting the URL-based payment method identifiers,
  // such as "https://bobpay.xyz".
  if (base::ranges::any_of(
          event_data->method_data,
          [](const payments::mojom::blink::PaymentMethodDataPtr& datum) {
            return datum && !datum->supported_method.StartsWith("http");
          })) {
    UseCounter::Count(
        this, WebFeature::kPaymentHandlerStandardizedPaymentMethodIdentifier);
  }

  mojo::PendingRemote<payments::mojom::blink::PaymentHandlerHost>
      payment_handler_host = std::move(event_data->payment_handler_host);
  Event* event = PaymentRequestEvent::Create(
      event_type_names::kPaymentrequest,
      PaymentEventDataConversion::ToPaymentRequestEventInit(
          ScriptController()->GetScriptState(), std::move(event_data)),
      std::move(payment_handler_host), respond_with_observer,
      wait_until_observer, this);

  DispatchExtendableEventWithRespondWith(event, wait_until_observer,
                                         respond_with_observer);
}

void ServiceWorkerGlobalScope::DispatchCookieChangeEvent(
    network::mojom::blink::CookieChangeInfoPtr change,
    DispatchCookieChangeEventCallback callback) {
  const int event_id = event_queue_->NextEventId();
  cookie_change_event_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartCookieChangeEvent,
                    WrapWeakPersistent(this), std::move(change)),
      CreateAbortCallback(&cookie_change_event_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartCookieChangeEvent(
    network::mojom::blink::CookieChangeInfoPtr change,
    int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchCookieChangeEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kCookieChange, event_id);

  HeapVector<Member<CookieListItem>> changed;
  HeapVector<Member<CookieListItem>> deleted;
  CookieChangeEvent::ToEventInfo(change, changed, deleted);
  Event* event = ExtendableCookieChangeEvent::Create(
      event_type_names::kCookiechange, std::move(changed), std::move(deleted),
      observer);

  // TODO(pwnall): Handle handle the case when
  //               (changed.empty() && deleted.empty()).

  // TODO(pwnall): Investigate dispatching this on cookieStore.
  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::DispatchContentDeleteEvent(
    const String& id,
    DispatchContentDeleteEventCallback callback) {
  const int event_id = event_queue_->NextEventId();
  content_delete_callbacks_.Set(event_id, std::move(callback));

  event_queue_->EnqueueNormal(
      event_id,
      WTF::BindOnce(&ServiceWorkerGlobalScope::StartContentDeleteEvent,
                    WrapWeakPersistent(this), id),
      CreateAbortCallback(&content_delete_callbacks_), std::nullopt);
}

void ServiceWorkerGlobalScope::StartContentDeleteEvent(String id,
                                                       int event_id) {
  DCHECK(IsContextThread());
  TRACE_EVENT_WITH_FLOW0(
      "ServiceWorker", "ServiceWorkerGlobalScope::DispatchContentDeleteEvent",
      TRACE_ID_WITH_SCOPE(kServiceWorkerGlobalScopeTraceScope,
                          TRACE_ID_LOCAL(event_id)),
      TRACE_EVENT_FLAG_FLOW_OUT);

  auto* observer = MakeGarbageCollected<WaitUntilObserver>(
      this, WaitUntilObserver::kContentDelete, event_id);

  auto* init = ContentIndexEventInit::Create();
  init->setId(id);

  auto* event = MakeGarbageCollected<ContentIndexEvent>(
      event_type_names::kContentdelete, init, observer);

  DispatchExtendableEvent(event, observer);
}

void ServiceWorkerGlobalScope::Ping(PingCallback callback) {
  DCHECK(IsContextThread());
  std::move(callback).Run();
}

void ServiceWorkerGlobalScope::SetIdleDelay(base::TimeDelta delay) {
  DCHECK(IsContextThread());
  DCHECK(event_queue_);
  event_queue_->SetIdleDelay(delay);
}

void ServiceWorkerGlobalScope::AddKeepAlive() {
  DCHECK(IsContextThread());
  DCHECK(event_queue_);

  // TODO(richardzh): refactor with RAII pattern, as explained in crbug/1399324
  event_queue_->ResetIdleTimeout();
}

void ServiceWorkerGlobalScope::ClearKeepAlive() {
  DCHECK(IsContextThread());
  DCHECK(event_queue_);

  // TODO(richardzh): refactor with RAII pattern, as explained in crbug/1399324
  event_queue_->ResetIdleTimeout();
  event_queue_->CheckEventQueue();
}

void ServiceWorkerGlobalScope::AddMessageToConsole(
    mojom::blink::ConsoleMessageLevel level,
    const String& message) {
  AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kOther, level, message,
      CaptureSourceLocation(/* url= */ "", /* line_number= */ 0,
                            /* column_number= */ 0)));
}

void ServiceWorkerGlobalScope::ExecuteScriptForTest(
    const String& javascript,
    bool wants_result,
    ExecuteScriptForTestCallback callback) {
  ScriptState* script_state = ScriptController()->GetScriptState();
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  // It's safe to use `kDoNotSanitize` because this method is for testing only.
  ClassicScript* script = ClassicScript::CreateUnspecifiedScript(
      javascript, ScriptSourceLocationType::kUnknown,
      SanitizeScriptErrors::kDoNotSanitize);

  v8::TryCatch try_catch(isolate);
  ScriptEvaluationResult result = script->RunScriptOnScriptStateAndReturnValue(
      script_state, ExecuteScriptPolicy::kDoNotExecuteScriptWhenScriptsDisabled,
      V8ScriptRunner::RethrowErrorsOption::Rethrow(String()));

  // If the script throws an error, the returned value is a stringification of
  // the error message.
  if (try_catch.HasCaught()) {
    String exception_string;
    if (try_catch.Message().IsEmpty() || try_catch.Message()->Get().IsEmpty()) {
      exception_string = "Unknown exception while executing script.";
    } else {
      exception_string =
          ToCoreStringWithNullCheck(isolate, try_catch.Message()->Get());
    }
    std::move(callback).Run(base::Value(), std::move(exception_string));
    return;
  }

  // If the script didn't want a result, just return immediately.
  if (!wants_result) {
    std::move(callback).Run(base::Value(), String());
    return;
  }

  // Otherwise, the script should have succeeded, and we return the value from
  // the execution.
  DCHECK_EQ(ScriptEvaluationResult::ResultType::kSuccess,
            result.GetResultType());

  v8::Local<v8::Value> v8_result = result.GetSuccessValue();
  DCHECK(!v8_result.IsEmpty());

  // Only convert the value to a base::Value if it's not null or undefined.
  // Null and undefined are valid results, but will fail to convert using the
  // WebV8ValueConverter. They are accurately represented (though no longer
  // distinguishable) by the empty base::Value.
  if (v8_result->IsNullOrUndefined()) {
    std::move(callback).Run(base::Value(), String());
    return;
  }

  base::Value value;

  // TODO(devlin): Is this thread-safe? Platform::Current() is set during
  // blink initialization and the created V8ValueConverter is constructed
  // without any special access, but it's *possible* a future implementation
  // here would be thread-unsafe (if it relied on member data in Platform).
  std::unique_ptr<WebV8ValueConverter> converter =
      Platform::Current()->CreateWebV8ValueConverter();
  converter->SetDateAllowed(true);
  converter->SetRegExpAllowed(true);

  std::unique_ptr<base::Value> converted_value =
      converter->FromV8Value(v8_result, script_state->GetContext());
  if (!converted_value) {
    std::move(callback).Run(base::Value(),
                            "Failed to convert V8 result from script");
    return;
  }

  std::move(callback).Run(std::move(*converted_value), String());
}

void ServiceWorkerGlobalScope::NoteNewFetchEvent(
    const mojom::blink::FetchAPIRequest& request) {
  int range_increment = request.headers.Contains(http_names::kRange) ? 1 : 0;
  auto it = unresponded_fetch_event_counts_.find(request.url);
  if (it == unresponded_fetch_event_counts_.end()) {
    unresponded_fetch_event_counts_.insert(
        request.url, FetchEventCounts(1, range_increment));
  } else {
    it->value.total_count += 1;
    it->value.range_count += range_increment;
  }
}

void ServiceWorkerGlobalScope::NoteRespondedToFetchEvent(
    const KURL& request_url,
    bool range_request) {
  auto it = unresponded_fetch_event_counts_.find(request_url);
  DCHECK_GE(it->value.total_count, 1);
  it->value.total_count -= 1;
  if (range_request) {
    DCHECK_GE(it->value.range_count, 1);
    it->value.range_count -= 1;
  }
  if (it->value.total_count == 0)
    unresponded_fetch_event_counts_.erase(it);
}

void ServiceWorkerGlobalScope::RecordQueuingTime(base::TimeTicks created_time) {
  base::UmaHistogramMediumTimes("ServiceWorker.FetchEvent.QueuingTime",
                                base::TimeTicks::Now() - created_time);
}

bool ServiceWorkerGlobalScope::IsInFencedFrame() const {
  return GetAncestorFrameType() ==
         mojom::blink::AncestorFrameType::kFencedFrame;
}

void ServiceWorkerGlobalScope::NotifyWebSocketActivity() {
  CHECK(IsContextThread());
  CHECK(event_queue_);

  ScriptState* script_state = ScriptController()->GetScriptState();
  CHECK(script_state);
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8_context = script_state->GetContext();

  bool notify = To<ServiceWorkerGlobalScopeProxy>(ReportingProxy())
                    .ShouldNotifyServiceWorkerOnWebSocketActivity(v8_context);

  if (notify) {
    // TODO(crbug/1399324): refactor with RAII pattern.
    event_queue_->ResetIdleTimeout();
    event_queue_->CheckEventQueue();
  }
}

mojom::blink::ServiceWorkerFetchHandlerType
ServiceWorkerGlobalScope::FetchHandlerType() {
  EventListenerVector* elv = GetEventListeners(event_type_names::kFetch);
  if (!elv) {
    return mojom::blink::ServiceWorkerFetchHandlerType::kNoHandler;
  }

  ScriptState* script_state = ScriptController()->GetScriptState();
  // Do not remove this, |scope| is needed by `GetListenerObject`.
  ScriptState::Scope scope(script_state);

  // TODO(crbug.com/1349613): revisit the way to implement this.
  // The following code returns kEmptyFetchHandler if all handlers are nop.
  for (RegisteredEventListener* e : *elv) {
    EventTarget* et = EventTarget::Create(script_state);
    v8::Local<v8::Value> v =
        To<JSBasedEventListener>(e->Callback())->GetListenerObject(*et);
    if (v.IsEmpty() || !v->IsFunction() ||
        !v.As<v8::Function>()->Experimental_IsNopFunction()) {
      return mojom::blink::ServiceWorkerFetchHandlerType::kNotSkippable;
    }
  }
  AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript,
      mojom::blink::ConsoleMessageLevel::kWarning,
      "Fetch event handler is recognized as no-op. "
      "No-op fetch handler may bring overhead during navigation. "
      "Consider removing the handler if possible."));
  return mojom::blink::ServiceWorkerFetchHandlerType::kEmptyFetchHandler;
}

bool ServiceWorkerGlobalScope::HasHidEventHandlers() {
  HID* hid = Supplement<NavigatorBase>::From<HID>(*navigator());
  return hid ? hid->HasEventListeners() : false;
}

bool ServiceWorkerGlobalScope::HasUsbEventHandlers() {
  USB* usb = Supplement<NavigatorBase>::From<USB>(*navigator());
  return usb ? usb->HasEventListeners() : false;
}

void ServiceWorkerGlobalScope::GetRemoteAssociatedInterface(
    const String& name,
    mojo::ScopedInterfaceEndpointHandle handle) {
  remote_associated_interfaces_->GetAssociatedInterface(
      name, mojo::PendingAssociatedReceiver<mojom::blink::AssociatedInterface>(
                std::move(handle)));
}

bool ServiceWorkerGlobalScope::SetAttributeEventListener(
    const AtomicString& event_type,
    EventListener* listener) {
  // Count the modification of fetch handlers after the initial evaluation.
  if (did_evaluate_script_) {
    if (event_type == event_type_names::kFetch) {
      UseCounter::Count(
          this,
          WebFeature::kServiceWorkerFetchHandlerModifiedAfterInitialization);
    }
    UseCounter::Count(
        this,
        WebFeature::kServiceWorkerEventHandlerModifiedAfterInitialization);
  }
  return WorkerGlobalScope::SetAttributeEventListener(event_type, listener);
}

std::optional<mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>>
ServiceWorkerGlobalScope::FindRaceNetworkRequestURLLoaderFactory(
    const base::UnguessableToken& token) {
  std::unique_ptr<RaceNetworkRequestInfo> result =
      race_network_requests_.Take(String(token.ToString()));
  if (result) {
    race_network_request_fetch_event_ids_.erase(result->fetch_event_id);
    return std::optional<
        mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>>(
        std::move(result->url_loader_factory));
  }
  return std::nullopt;
}

void ServiceWorkerGlobalScope::InsertNewItemToRaceNetworkRequests(
    int fetch_event_id,
    const base::UnguessableToken& token,
    mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>
        url_loader_factory,
    const KURL& request_url) {
  auto race_network_request_token = String(token.ToString());
  auto info = std::make_unique<RaceNetworkRequestInfo>(
      fetch_event_id, race_network_request_token,
      std::move(url_loader_factory));
  race_network_request_fetch_event_ids_.insert(fetch_event_id, info.get());
  auto insert_result = race_network_requests_.insert(race_network_request_token,
                                                     std::move(info));

  // DumpWithoutCrashing if the token is empty, or not inserted as a new entry
  // to |race_network_request_loader_factories_|.
  // TODO(crbug.com/1492640) Remove DumpWithoutCrashing once we collect data
  // and identify the cause.
  static bool has_dumped_without_crashing_for_empty_token = false;
  static bool has_dumped_without_crashing_for_not_new_entry = false;
  if (!has_dumped_without_crashing_for_empty_token && token.is_empty()) {
    has_dumped_without_crashing_for_empty_token = true;
    SCOPED_CRASH_KEY_BOOL("SWGlobalScope", "empty_race_token",
                          token.is_empty());
    SCOPED_CRASH_KEY_STRING64("SWGlobalScope", "race_token_string",
                              token.ToString());
    SCOPED_CRASH_KEY_BOOL("SWGlobalScope", "race_insert_new_entry",
                          insert_result.is_new_entry);
    SCOPED_CRASH_KEY_STRING256("SWGlobalScope", "race_request_url",
                               request_url.GetString().Utf8());
    base::debug::DumpWithoutCrashing();
  }
  if (!has_dumped_without_crashing_for_not_new_entry &&
      !insert_result.is_new_entry) {
    has_dumped_without_crashing_for_not_new_entry = true;
    SCOPED_CRASH_KEY_BOOL("SWGlobalScope", "empty_race_token",
                          token.is_empty());
    SCOPED_CRASH_KEY_STRING64("SWGlobalScope", "race_token_string",
                              token.ToString());
    SCOPED_CRASH_KEY_BOOL("SWGlobalScope", "race_insert_new_entry",
                          insert_result.is_new_entry);
    SCOPED_CRASH_KEY_STRING256("SWGlobalScope", "race_request_url",
                               request_url.GetString().Utf8());
    base::debug::DumpWithoutCrashing();
  }
}

void ServiceWorkerGlobalScope::RemoveItemFromRaceNetworkRequests(
    int fetch_event_id) {
  RaceNetworkRequestInfo* info =
      race_network_request_fetch_event_ids_.Take(fetch_event_id);
  if (info) {
    race_network_requests_.erase(info->token);
  }
}

}  // namespace blink

"""


```