Response:
Let's break down the thought process for analyzing the `service_worker_container.cc` file.

**1. Initial Scan and Purpose Identification:**

* **Keywords:** The filename itself (`service_worker_container.cc`) strongly suggests this file is responsible for managing the Service Worker container within the Blink rendering engine. The `blink/renderer/modules/service_worker/` directory confirms this context.
* **Copyright and Imports:**  A quick glance at the copyright and import statements reveals dependencies on various Blink components like `mojom`, `platform`, `bindings`, `core/dom`, `core/frame`, `modules/service_worker`, and `platform/wtf`. This signals that the file interacts with low-level platform interfaces, JavaScript bindings, DOM manipulation, frame lifecycle, and other service worker related modules.
* **Namespace:** The `namespace blink` indicates this is core Blink code.

**2. Core Functionality Deduction:**

* **Class Name:** The central class `ServiceWorkerContainer` is the main focus.
* **`From()` method:**  The static `From()` method suggests this class is a supplement to `LocalDOMWindow`, meaning each window has an associated `ServiceWorkerContainer`. This implies management of service workers on a per-window basis.
* **Key Methods:**  Methods like `registerServiceWorker`, `getRegistration`, `getRegistrations`, `startMessages`, `ready`, `SetController`, and `ReceiveMessage` strongly point to the core responsibilities of the container:
    * **Registration:**  Managing the process of registering new service workers.
    * **Retrieval:**  Fetching existing registrations.
    * **Communication:** Handling messages between the page and service workers.
    * **Lifecycle:**  Managing the "ready" state and the active controller.

**3. Relationship with JavaScript, HTML, and CSS:**

* **`registerServiceWorker()`:** This method directly corresponds to the JavaScript `navigator.serviceWorker.register()` API. It takes a URL (for the service worker script) and optional scope, which are defined in JavaScript.
* **`getRegistration()` and `getRegistrations()`:** These map to `navigator.serviceWorker.getRegistration()` and `navigator.serviceWorker.getRegistrations()` respectively. JavaScript uses these to query the status of service workers.
* **`onmessage`:** The `setOnmessage()` and `onmessage()` methods connect to the `message` event on the `ServiceWorkerContainer` object, allowing JavaScript to receive messages from service workers.
* **Controller:** The `controller_` member and related `SetController()` method are central to the concept of a controlling service worker, which can intercept network requests for the page (affecting how HTML, CSS, and other resources are loaded).
* **`ready` Promise:**  The `ready()` method provides a JavaScript promise that resolves when a service worker is active for the page, crucial for scenarios where the page relies on the service worker's functionality.

**4. Logic and Assumptions (Hypothetical Input/Output):**

* **`registerServiceWorker("sw.js")`:**
    * **Input:** JavaScript call `navigator.serviceWorker.register("sw.js")`.
    * **Assumptions:** The script `sw.js` exists at the specified relative path, the context is secure, CSP allows the script, and the browser supports service workers.
    * **Output:** A JavaScript promise that resolves with a `ServiceWorkerRegistration` object if successful, or rejects with an error (e.g., network error, script parsing error, security error). Internally, the C++ code would likely interact with the browser's service worker process to fetch and install the script.
* **`navigator.serviceWorker.controller.postMessage("hello")`:**
    * **Input:** JavaScript sends a message to the active service worker.
    * **Assumptions:**  There is an active controller (`navigator.serviceWorker.controller` is not null).
    * **Output:** The `ReceiveMessage()` method in C++ is invoked, and the message is passed to the service worker process. The service worker can then respond with another message, which would trigger the `message` event on the `ServiceWorkerContainer`.

**5. Common Usage Errors:**

* **Insecure Context:** Trying to register a service worker on a non-HTTPS page. The code explicitly checks `execution_context->IsSecureContext()`. The error message generated would indicate this.
* **Incorrect Scope:** Specifying a scope that is outside the allowed path for the service worker. The `ValidateScopeAndScriptURL()` method performs checks, and an appropriate error is generated.
* **CSP Violation:** The service worker script URL violating the page's Content Security Policy. The code checks `csp->AllowWorkerContextFromSource(script_url)`.
* **Invalid Script URL:** Providing a malformed or non-existent URL for the service worker script. This would likely result in a network error during registration.
* **Calling `register()` Before DOMContentLoaded:** Although the code queues messages before DOMContentLoaded, relying on service worker functionality before this event might lead to unexpected behavior or errors in some scenarios if the service worker aims to intercept requests for initial page resources.

**6. User Operations and Debugging:**

* **Navigation:**  The user navigates to a page that includes JavaScript code attempting to register a service worker.
* **Page Load:** The browser parses the HTML, and when it encounters the JavaScript, the `navigator.serviceWorker.register()` call is made, leading to the `ServiceWorkerContainer::registerServiceWorker()` method.
* **Debugging Steps:**
    1. **Set Breakpoints:** Place breakpoints within `ServiceWorkerContainer::registerServiceWorker()`, `GetRegistrationCallback::OnSuccess()`, `GetRegistrationCallback::OnError()`, and `ReceiveMessage()` to trace the execution flow.
    2. **Inspect Variables:** Observe the values of `url`, `options`, `script_url`, `scope_url`, `document_origin`, and the state of the `provider_`.
    3. **Check Error Messages:** Pay close attention to any error messages logged to the console, as they often provide valuable clues about registration failures.
    4. **Network Tab:** Use the browser's developer tools network tab to verify that the service worker script is being fetched correctly and that there are no network errors.
    5. **Application Tab (Service Workers):** The browser's application tab usually has a section for inspecting registered service workers, their status, and any errors. This can help confirm if a registration was successful and identify any issues.
    6. **Browser Internals (chrome://inspect/#service-workers):**  For deeper debugging, the `chrome://inspect/#service-workers` page provides more detailed information about service worker processes and their states.

By following these steps, the aim is to understand the purpose of the file, its interactions with other components, and how it relates to web development concepts, enabling effective debugging and problem-solving.
This C++ source file, `service_worker_container.cc`, within the Chromium Blink engine, implements the **`ServiceWorkerContainer` interface**. This interface is a crucial part of the Service Worker API, a web technology that enables powerful features like offline web applications, background synchronization, and push notifications.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Managing Service Worker Registrations:**
    *   **`registerServiceWorker()`:** This is the core function for registering a new service worker for a given scope. It takes the URL of the service worker script and optional registration options. It handles various checks (security, URL validity, CSP) before initiating the actual registration process.
    *   **`getRegistration()`:** Allows retrieving a specific `ServiceWorkerRegistration` object based on a provided document URL. This helps check if a service worker is already registered for a particular scope.
    *   **`getRegistrations()`:** Returns a list of all `ServiceWorkerRegistration` objects associated with the current origin.

2. **Managing the Active Service Worker Controller:**
    *   **`controller()` (implicit through `controller_` member):**  Represents the currently active `ServiceWorker` that controls the current page. This controller can intercept network requests and handle events for the page.
    *   **`SetController()`:** This internal method updates the `controller_` when a new service worker becomes active or inactive for the page. It also dispatches the `controllerchange` event.

3. **Communication with Service Workers:**
    *   **`startMessages()`:** Ensures the client message queue is enabled, allowing the page to receive messages from service workers.
    *   **`ReceiveMessage()`:** Handles incoming messages from service workers. It checks if the message queue is enabled, queues messages if necessary, and then dispatches the `message` event to the appropriate JavaScript event listeners.
    *   **`setOnmessage()`/`onmessage()`:**  These implement the `onmessage` event handler for the `ServiceWorkerContainer`, allowing JavaScript to register a callback function to receive messages from service workers.

4. **Determining Readiness:**
    *   **`ready()`:** Returns a JavaScript `Promise` that resolves when a service worker is active for the current page. This is useful for ensuring that service worker functionality is available before interacting with it.

5. **Internal Management:**
    *   **Keeping track of `ServiceWorkerRegistration` and `ServiceWorker` objects:** The container maintains internal maps (`service_worker_registration_objects_`, `service_worker_objects_`) to cache and manage these objects.
    *   **Handling DOMContentLoaded:** The container delays message processing until the `DOMContentLoaded` event has fired, ensuring proper initialization.
    *   **Integration with the underlying browser process:** It interacts with the `WebServiceWorkerProvider` (an interface to the browser's service worker implementation) to perform actions like registering and unregistering service workers.

**Relationship with JavaScript, HTML, and CSS:**

The `ServiceWorkerContainer` is a core part of the JavaScript Service Worker API, directly exposed to JavaScript code running within a web page.

*   **JavaScript:**
    *   **`navigator.serviceWorker.register('sw.js')`:** This JavaScript code directly translates to a call to the `ServiceWorkerContainer::registerServiceWorker()` method in this C++ file. The `'sw.js'` string is the `url` parameter.
    *   **`navigator.serviceWorker.getRegistration()` and `navigator.serviceWorker.getRegistrations()`:** These JavaScript calls map to the respective `ServiceWorkerContainer` methods.
    *   **`navigator.serviceWorker.ready.then(...)`:**  This utilizes the `ready()` method to wait for a service worker to become active.
    *   **`navigator.serviceWorker.controller.postMessage('hello')`:**  While the sending of messages happens through the `ServiceWorker` object, the reception of these messages on the page is handled by the `ServiceWorkerContainer` through the `ReceiveMessage()` method and dispatched as a `message` event.
    *   **`navigator.serviceWorker.onmessage = function(event) { ... }`:** This JavaScript code sets the `onmessage` event handler, which is implemented by `ServiceWorkerContainer::setOnmessage()`.

*   **HTML:**
    *   The presence of `<script>` tags in HTML that call the Service Worker API (like `navigator.serviceWorker.register()`) will trigger the functionality implemented in this file.
    *   The service worker itself (the `sw.js` file) can intercept network requests for HTML resources and potentially serve cached versions, affecting how the HTML is loaded and rendered.

*   **CSS:**
    *   Similar to HTML, a service worker can intercept requests for CSS files and serve cached versions, influencing the styling of the page.

**Examples:**

*   **JavaScript Registering a Service Worker:**
    ```javascript
    navigator.serviceWorker.register('/my-service-worker.js', { scope: '/app/' })
      .then(function(registration) {
        console.log('Service Worker registered with scope:', registration.scope);
      })
      .catch(function(error) {
        console.log('Service Worker registration failed:', error);
      });
    ```
    **Internal Processing:** This JavaScript code will eventually lead to a call to `ServiceWorkerContainer::registerServiceWorker()` with `/my-service-worker.js` as the `url` and `/app/` as the `scope` (within the `options`). The C++ code will validate the URLs, security context, and then communicate with the browser process to initiate the registration of the service worker.

*   **JavaScript Receiving a Message:**
    ```javascript
    navigator.serviceWorker.onmessage = function(event) {
      console.log('Received a message from the service worker:', event.data);
    };
    ```
    **Internal Processing:** When the service worker sends a message back to the page, the browser process will notify the `ServiceWorkerContainer`, and the `ReceiveMessage()` method will be invoked. It will create a `MessageEvent` and dispatch it, triggering the JavaScript `onmessage` handler.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `getRegistration()` method:

*   **Hypothetical Input:** JavaScript calls `navigator.serviceWorker.getRegistration('/app/page.html')`.
*   **Assumptions:**
    *   The current page has a `ServiceWorkerContainer`.
    *   The origin of the current page and `/app/page.html` are the same.
    *   A service worker with a scope that covers `/app/page.html` might be registered.
*   **Internal Logic:**
    1. The `ServiceWorkerContainer::getRegistration()` method is called with `/app/page.html` as the `document_url`.
    2. It completes the URL and performs security checks (origin match).
    3. It interacts with the `WebServiceWorkerProvider` to query the browser's service worker registry for a registration that matches the given URL.
    4. The `GetRegistrationCallback` handles the response from the browser process.
*   **Possible Outputs:**
    *   **If a matching registration exists:** The `OnSuccess()` callback will be invoked with information about the registration. A `ServiceWorkerRegistration` object will be created and the JavaScript promise will resolve with this object.
    *   **If no matching registration exists:** The `OnSuccess()` callback will be invoked with an invalid registration ID. The JavaScript promise will resolve with `undefined`.
    *   **If an error occurs (e.g., security error):** The `OnError()` callback will be invoked, and the JavaScript promise will reject with a `ServiceWorkerError`.

**Common Usage Errors:**

*   **Registering a Service Worker on a Non-Secure Context (HTTP):**  The `registerServiceWorker()` method checks `execution_context->IsSecureContext()`. If this check fails, the promise will reject with a security error.
    *   **Example:** A user tries to register a service worker on a page accessed via `http://example.com`. The browser will likely block the registration and the JavaScript promise will be rejected.

*   **Providing an Invalid or Out-of-Scope Script URL:** The `registerServiceWorker()` method performs validation on the script URL.
    *   **Example:**  JavaScript calls `navigator.serviceWorker.register('//another-domain.com/sw.js')`. This will likely fail due to a security error as the script is on a different origin.
    *   **Example:** JavaScript calls `navigator.serviceWorker.register('/somewhere-else/sw.js', { scope: '/app/' })` from a page at `/app/index.html`. If the service worker at `/somewhere-else/sw.js` doesn't have a scope that encompasses `/app/`, the registration might fail or behave unexpectedly.

*   **Calling Service Worker API in an Inappropriate Context:** Some Service Worker APIs are only available in secure contexts or certain types of frames.
    *   **Example:** Trying to register a service worker from within an `<iframe>` that doesn't meet the necessary security requirements might fail.

**User Operation and Debugging Steps:**

Let's consider a user encountering an issue where their service worker is not registering:

1. **User Action:** The user navigates to a web page that attempts to register a service worker using JavaScript like `navigator.serviceWorker.register('/sw.js')`.

2. **Blink Processing:**
    *   The JavaScript engine executes the `register()` call.
    *   This call reaches the `ServiceWorkerContainer::registerServiceWorker()` method in `service_worker_container.cc`.
    *   The method performs several checks:
        *   **Security Context:** `execution_context->IsSecureContext()`
        *   **URL Validity:** Checks if the script URL is valid.
        *   **Scheme Check:** Ensures the protocol (e.g., HTTPS) is allowed for service workers.
        *   **Origin Check:** Verifies the script URL's origin matches the page's origin.
        *   **CSP Check:** Checks if the Content Security Policy allows loading the script as a worker.
        *   **Scope Validation:** Validates the provided scope against the script URL.
        *   **Provider Availability:** Ensures the underlying `WebServiceWorkerProvider` is available.

3. **Potential Issues and Debugging:**

    *   **Issue:** The page is served over HTTP.
        *   **Debugging:**
            *   **Browser Developer Tools (Console):**  The browser will likely log an error message indicating the registration failed due to an insecure context.
            *   **Step Through Code (if possible):**  A developer could set a breakpoint in `ServiceWorkerContainer::registerServiceWorker()` and observe that `execution_context->IsSecureContext()` returns `false`.

    *   **Issue:** The service worker script URL is incorrect (e.g., a typo).
        *   **Debugging:**
            *   **Browser Developer Tools (Network Tab):** The network tab will show a 404 error when trying to fetch the service worker script.
            *   **Browser Developer Tools (Application Tab -> Service Workers):** The browser might show an error indicating the script could not be fetched.

    *   **Issue:** The Content Security Policy is blocking the service worker script.
        *   **Debugging:**
            *   **Browser Developer Tools (Console):** The browser will log a CSP violation error.
            *   **Inspect HTTP Headers:** Check the `Content-Security-Policy` header in the network response for the HTML page.

    *   **Issue:** The scope is incorrectly configured.
        *   **Debugging:**
            *   **Browser Developer Tools (Application Tab -> Service Workers):** The browser might show warnings or errors related to the scope.
            *   **Review the `scope` parameter** passed to `navigator.serviceWorker.register()` in the JavaScript code.

**In summary, `blink/renderer/modules/service_worker/service_worker_container.cc` is a fundamental file in the Chromium rendering engine responsible for implementing the client-side of the Service Worker API. It manages the lifecycle of service worker registrations, handles communication between the page and service workers, and enforces security and validity checks. Understanding its functionality is crucial for web developers working with service workers and for those debugging issues related to them.**

Prompt: 
```
这是目录为blink/renderer/modules/service_worker/service_worker_container.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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
#include "third_party/blink/renderer/modules/service_worker/service_worker_container.h"

#include <memory>
#include <optional>
#include <utility>

#include "third_party/blink/public/mojom/service_worker/service_worker_error_type.mojom-blink.h"
#include "third_party/blink/public/platform/web_fetch_client_settings_object.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/messaging/blink_transferable_message.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/script_type_names.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_error.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_registration.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

void MaybeRecordThirdPartyServiceWorkerUsage(
    ExecutionContext* execution_context) {
  DCHECK(execution_context);
  // ServiceWorkerContainer is only supported on windows.
  LocalDOMWindow* window = To<LocalDOMWindow>(execution_context);
  DCHECK(window);

  if (window->IsCrossSiteSubframe())
    UseCounter::Count(window, WebFeature::kThirdPartyServiceWorker);
}

bool HasFiredDomContentLoaded(const Document& document) {
  return !document.GetTiming().DomContentLoadedEventStart().is_null();
}

mojom::blink::ServiceWorkerUpdateViaCache V8EnumToUpdateViaCache(
    V8ServiceWorkerUpdateViaCache::Enum value) {
  switch (value) {
    case V8ServiceWorkerUpdateViaCache::Enum::kImports:
      return mojom::blink::ServiceWorkerUpdateViaCache::kImports;
    case V8ServiceWorkerUpdateViaCache::Enum::kAll:
      return mojom::blink::ServiceWorkerUpdateViaCache::kAll;
    case V8ServiceWorkerUpdateViaCache::Enum::kNone:
      return mojom::blink::ServiceWorkerUpdateViaCache::kNone;
  }
  NOTREACHED();
}

class GetRegistrationCallback : public WebServiceWorkerProvider::
                                    WebServiceWorkerGetRegistrationCallbacks {
 public:
  explicit GetRegistrationCallback(
      ScriptPromiseResolver<ServiceWorkerRegistration>* resolver)
      : resolver_(resolver) {}

  GetRegistrationCallback(const GetRegistrationCallback&) = delete;
  GetRegistrationCallback& operator=(const GetRegistrationCallback&) = delete;

  ~GetRegistrationCallback() override = default;

  void OnSuccess(WebServiceWorkerRegistrationObjectInfo info) override {
    if (!resolver_->GetExecutionContext() ||
        resolver_->GetExecutionContext()->IsContextDestroyed())
      return;
    if (info.registration_id ==
        mojom::blink::kInvalidServiceWorkerRegistrationId) {
      // Resolve the promise with undefined.
      resolver_->Resolve();
      return;
    }
    resolver_->Resolve(
        ServiceWorkerRegistration::Take(resolver_, std::move(info)));
  }

  void OnError(const WebServiceWorkerError& error) override {
    if (!resolver_->GetExecutionContext() ||
        resolver_->GetExecutionContext()->IsContextDestroyed())
      return;
    resolver_->Reject(ServiceWorkerError::Take(resolver_.Get(), error));
  }

 private:
  Persistent<ScriptPromiseResolver<ServiceWorkerRegistration>> resolver_;
};

}  // namespace

class ServiceWorkerContainer::DomContentLoadedListener final
    : public NativeEventListener {
 public:
  void Invoke(ExecutionContext* execution_context, Event* event) override {
    DCHECK_EQ(event->type(), "DOMContentLoaded");

    LocalDOMWindow& window = *To<LocalDOMWindow>(execution_context);
    DCHECK(HasFiredDomContentLoaded(*window.document()));

    auto* container =
        Supplement<LocalDOMWindow>::From<ServiceWorkerContainer>(window);
    if (!container) {
      // There is no container for some reason, which means there's no message
      // queue to start. Just abort.
      return;
    }

    container->EnableClientMessageQueue();
  }
};

const char ServiceWorkerContainer::kSupplementName[] = "ServiceWorkerContainer";

ServiceWorkerContainer* ServiceWorkerContainer::From(LocalDOMWindow& window) {
  ServiceWorkerContainer* container =
      Supplement<LocalDOMWindow>::From<ServiceWorkerContainer>(window);
  if (!container) {
    // TODO(leonhsl): Figure out whether it's really necessary to create an
    // instance when there's no frame or frame client for |window|.
    container = MakeGarbageCollected<ServiceWorkerContainer>(window);
    Supplement<LocalDOMWindow>::ProvideTo(window, container);
    if (window.GetFrame() && window.GetFrame()->Client()) {
      std::unique_ptr<WebServiceWorkerProvider> provider =
          window.GetFrame()->Client()->CreateServiceWorkerProvider();
      if (provider) {
        provider->SetClient(container);
        container->provider_ = std::move(provider);
      }
    }
  }
  return container;
}

ServiceWorkerContainer* ServiceWorkerContainer::CreateForTesting(
    LocalDOMWindow& window,
    std::unique_ptr<WebServiceWorkerProvider> provider) {
  ServiceWorkerContainer* container =
      MakeGarbageCollected<ServiceWorkerContainer>(window);
  container->provider_ = std::move(provider);
  return container;
}

ServiceWorkerContainer::~ServiceWorkerContainer() {
  DCHECK(!provider_);
}

void ServiceWorkerContainer::ContextDestroyed() {
  if (provider_) {
    provider_->SetClient(nullptr);
    provider_ = nullptr;
  }
  controller_ = nullptr;
}

void ServiceWorkerContainer::Trace(Visitor* visitor) const {
  visitor->Trace(controller_);
  visitor->Trace(ready_);
  visitor->Trace(dom_content_loaded_observer_);
  visitor->Trace(service_worker_registration_objects_);
  visitor->Trace(service_worker_objects_);
  EventTarget::Trace(visitor);
  Supplement<LocalDOMWindow>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

ScriptPromise<ServiceWorkerRegistration>
ServiceWorkerContainer::registerServiceWorker(
    ScriptState* script_state,
    const String& url,
    const RegistrationOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<ServiceWorkerRegistration>>(
          script_state);
  auto promise = resolver->Promise();
  auto callbacks = std::make_unique<CallbackPromiseAdapter<
      ServiceWorkerRegistration, ServiceWorkerErrorForUpdate>>(resolver);

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  MaybeRecordThirdPartyServiceWorkerUsage(execution_context);

  // The IDL definition is expected to restrict service worker to secure
  // contexts.
  CHECK(execution_context->IsSecureContext());

  scoped_refptr<const SecurityOrigin> document_origin =
      execution_context->GetSecurityOrigin();
  KURL page_url = KURL(NullURL(), document_origin->ToString());
  if (!SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers(
          page_url.Protocol())) {
    callbacks->OnError(WebServiceWorkerError(
        mojom::blink::ServiceWorkerErrorType::kType,
        String("Failed to register a ServiceWorker: The URL protocol of the "
               "current origin ('" +
               document_origin->ToString() + "') is not supported.")));
    return promise;
  }

  KURL script_url = execution_context->CompleteURL(url);
  script_url.RemoveFragmentIdentifier();

  if (!SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers(
          script_url.Protocol())) {
    callbacks->OnError(WebServiceWorkerError(
        mojom::blink::ServiceWorkerErrorType::kType,
        String("Failed to register a ServiceWorker: The URL protocol of the "
               "script ('" +
               script_url.GetString() + "') is not supported.")));
    return promise;
  }

  if (!document_origin->CanRequest(script_url)) {
    scoped_refptr<const SecurityOrigin> script_origin =
        SecurityOrigin::Create(script_url);
    callbacks->OnError(
        WebServiceWorkerError(mojom::blink::ServiceWorkerErrorType::kSecurity,
                              String("Failed to register a ServiceWorker: The "
                                     "origin of the provided scriptURL ('" +
                                     script_origin->ToString() +
                                     "') does not match the current origin ('" +
                                     document_origin->ToString() + "').")));
    return promise;
  }

  KURL scope_url;
  if (options->hasScope())
    scope_url = execution_context->CompleteURL(options->scope());
  else
    scope_url = KURL(script_url, "./");
  scope_url.RemoveFragmentIdentifier();

  if (!SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers(
          scope_url.Protocol())) {
    callbacks->OnError(WebServiceWorkerError(
        mojom::blink::ServiceWorkerErrorType::kType,
        String("Failed to register a ServiceWorker: The URL protocol of the "
               "scope ('" +
               scope_url.GetString() + "') is not supported.")));
    return promise;
  }

  if (!document_origin->CanRequest(scope_url)) {
    scoped_refptr<const SecurityOrigin> scope_origin =
        SecurityOrigin::Create(scope_url);
    callbacks->OnError(
        WebServiceWorkerError(mojom::blink::ServiceWorkerErrorType::kSecurity,
                              String("Failed to register a ServiceWorker: The "
                                     "origin of the provided scope ('" +
                                     scope_origin->ToString() +
                                     "') does not match the current origin ('" +
                                     document_origin->ToString() + "').")));
    return promise;
  }

  if (!provider_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError,
        "Failed to register a ServiceWorker: "
        "The document is in an invalid "
        "state."));
    return promise;
  }
  WebString web_error_message;
  if (!provider_->ValidateScopeAndScriptURL(scope_url, script_url,
                                            &web_error_message)) {
    callbacks->OnError(WebServiceWorkerError(
        mojom::blink::ServiceWorkerErrorType::kType,
        WebString::FromUTF8("Failed to register a ServiceWorker: " +
                            web_error_message.Utf8())));
    return promise;
  }

  ContentSecurityPolicy* csp = execution_context->GetContentSecurityPolicy();
  if (csp) {
    if (!csp->AllowWorkerContextFromSource(script_url)) {
      callbacks->OnError(WebServiceWorkerError(
          mojom::blink::ServiceWorkerErrorType::kSecurity,
          String(
              "Failed to register a ServiceWorker: The provided scriptURL ('" +
              script_url.GetString() +
              "') violates the Content Security Policy.")));
      return promise;
    }
  }

  mojom::blink::ServiceWorkerUpdateViaCache update_via_cache =
      V8EnumToUpdateViaCache(options->updateViaCache().AsEnum());
  mojom::blink::ScriptType script_type =
      Script::V8WorkerTypeToScriptType(options->type().AsEnum());

  WebFetchClientSettingsObject fetch_client_settings_object(
      execution_context->Fetcher()
          ->GetProperties()
          .GetFetchClientSettingsObject());

  // Defer register() from a prerendered page until page activation.
  // https://wicg.github.io/nav-speculation/prerendering.html#patch-service-workers
  if (GetExecutionContext()->IsWindow()) {
    Document* document = To<LocalDOMWindow>(GetExecutionContext())->document();
    if (document->IsPrerendering()) {
      document->AddPostPrerenderingActivationStep(WTF::BindOnce(
          &ServiceWorkerContainer::RegisterServiceWorkerInternal,
          WrapWeakPersistent(this), scope_url, script_url,
          std::move(script_type), update_via_cache,
          std::move(fetch_client_settings_object), std::move(callbacks)));
      return promise;
    }
  }

  RegisterServiceWorkerInternal(
      scope_url, script_url, std::move(script_type), update_via_cache,
      std::move(fetch_client_settings_object), std::move(callbacks));
  return promise;
}

void ServiceWorkerContainer::RegisterServiceWorkerInternal(
    const KURL& scope_url,
    const KURL& script_url,
    std::optional<mojom::blink::ScriptType> script_type,
    mojom::blink::ServiceWorkerUpdateViaCache update_via_cache,
    WebFetchClientSettingsObject fetch_client_settings_object,
    std::unique_ptr<CallbackPromiseAdapter<ServiceWorkerRegistration,
                                           ServiceWorkerErrorForUpdate>>
        callbacks) {
  if (!provider_)
    return;
  provider_->RegisterServiceWorker(
      scope_url, script_url, *script_type, update_via_cache,
      std::move(fetch_client_settings_object), std::move(callbacks));
}

ScriptPromise<ServiceWorkerRegistration>
ServiceWorkerContainer::getRegistration(ScriptState* script_state,
                                        const String& document_url) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<ServiceWorkerRegistration>>(
          script_state);
  auto promise = resolver->Promise();

  ExecutionContext* execution_context = ExecutionContext::From(script_state);

  // The IDL definition is expected to restrict service worker to secure
  // contexts.
  CHECK(execution_context->IsSecureContext());

  scoped_refptr<const SecurityOrigin> document_origin =
      execution_context->GetSecurityOrigin();
  KURL page_url = KURL(NullURL(), document_origin->ToString());
  if (!SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers(
          page_url.Protocol())) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kSecurityError,
        "Failed to get a ServiceWorkerRegistration: The URL protocol of the "
        "current origin ('" +
            document_origin->ToString() + "') is not supported."));
    return promise;
  }

  KURL completed_url = execution_context->CompleteURL(document_url);
  completed_url.RemoveFragmentIdentifier();
  if (!document_origin->CanRequest(completed_url)) {
    scoped_refptr<const SecurityOrigin> document_url_origin =
        SecurityOrigin::Create(completed_url);
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kSecurityError,
        "Failed to get a ServiceWorkerRegistration: The "
        "origin of the provided documentURL ('" +
            document_url_origin->ToString() +
            "') does not match the current origin ('" +
            document_origin->ToString() + "')."));
    return promise;
  }

  if (!provider_) {
    resolver->Reject(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kInvalidStateError,
                                           "Failed to get a "
                                           "ServiceWorkerRegistration: The "
                                           "document is in an invalid state."));
    return promise;
  }
  provider_->GetRegistration(
      completed_url, std::make_unique<GetRegistrationCallback>(resolver));

  return promise;
}

ScriptPromise<IDLSequence<ServiceWorkerRegistration>>
ServiceWorkerContainer::getRegistrations(ScriptState* script_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<ServiceWorkerRegistration>>>(
      script_state);
  auto promise = resolver->Promise();

  if (!provider_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError,
        "Failed to get ServiceWorkerRegistration objects: "
        "The document is in an invalid state."));
    return promise;
  }

  ExecutionContext* execution_context = ExecutionContext::From(script_state);

  // The IDL definition is expected to restrict service worker to secure
  // contexts.
  CHECK(execution_context->IsSecureContext());

  scoped_refptr<const SecurityOrigin> document_origin =
      execution_context->GetSecurityOrigin();
  KURL page_url = KURL(NullURL(), document_origin->ToString());
  if (!SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers(
          page_url.Protocol())) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kSecurityError,
        "Failed to get ServiceWorkerRegistration objects: The URL protocol of "
        "the current origin ('" +
            document_origin->ToString() + "') is not supported."));
    return promise;
  }

  provider_->GetRegistrations(
      std::make_unique<CallbackPromiseAdapter<ServiceWorkerRegistrationArray,
                                              ServiceWorkerError>>(resolver));

  return promise;
}

// https://w3c.github.io/ServiceWorker/#dom-serviceworkercontainer-startmessages
void ServiceWorkerContainer::startMessages() {
  // "startMessages() method must enable the context object’s client message
  // queue if it is not enabled."
  EnableClientMessageQueue();
}

ScriptPromise<ServiceWorkerRegistration> ServiceWorkerContainer::ready(
    ScriptState* caller_state,
    ExceptionState& exception_state) {
  if (!GetExecutionContext())
    return EmptyPromise();

  if (!caller_state->World().IsMainWorld()) {
    // FIXME: Support .ready from isolated worlds when
    // ScriptPromiseProperty can vend Promises in isolated worlds.
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "'ready' is only supported in pages.");
    return EmptyPromise();
  }

  if (!ready_) {
    ready_ = CreateReadyProperty();
    if (provider_) {
      provider_->GetRegistrationForReady(
          WTF::BindOnce(&ServiceWorkerContainer::OnGetRegistrationForReady,
                        WrapPersistent(this)));
    }
  }

  return ready_->Promise(caller_state->World());
}

void ServiceWorkerContainer::SetController(
    WebServiceWorkerObjectInfo info,
    bool should_notify_controller_change) {
  if (!GetExecutionContext())
    return;
  controller_ = ServiceWorker::From(GetExecutionContext(), std::move(info));
  if (controller_) {
    MaybeRecordThirdPartyServiceWorkerUsage(GetExecutionContext());
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kServiceWorkerControlledPage);
  }
  if (should_notify_controller_change)
    DispatchEvent(*Event::Create(event_type_names::kControllerchange));
}

void ServiceWorkerContainer::ReceiveMessage(WebServiceWorkerObjectInfo source,
                                            TransferableMessage message) {
  auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext());
  if (!window)
    return;
  // ServiceWorkerContainer is only supported on documents.
  auto* document = window->document();
  DCHECK(document);

  if (!is_client_message_queue_enabled_) {
    if (!HasFiredDomContentLoaded(*document)) {
      // Wait for DOMContentLoaded. This corresponds to the specification steps
      // for "Parsing HTML documents": "The end" at
      // https://html.spec.whatwg.org/C/#the-end:
      //
      // 1. Fire an event named DOMContentLoaded at the Document object, with
      // its bubbles attribute initialized to true.
      // 2. Enable the client message queue of the ServiceWorkerContainer object
      // whose associated service worker client is the Document object's
      // relevant settings object.
      if (!dom_content_loaded_observer_) {
        dom_content_loaded_observer_ =
            MakeGarbageCollected<DomContentLoadedListener>();
        document->addEventListener(event_type_names::kDOMContentLoaded,
                                   dom_content_loaded_observer_.Get(), false);
      }
      queued_messages_.emplace_back(std::make_unique<MessageFromServiceWorker>(
          std::move(source), std::move(message)));
      // The messages will be dispatched once EnableClientMessageQueue() is
      // called.
      return;
    }

    // DOMContentLoaded was fired already, so enable the queue.
    EnableClientMessageQueue();
  }

  DispatchMessageEvent(std::move(source), std::move(message));
}

void ServiceWorkerContainer::CountFeature(mojom::WebFeature feature) {
  if (!GetExecutionContext())
    return;
  if (!Deprecation::IsDeprecated(feature))
    UseCounter::Count(GetExecutionContext(), feature);
  else
    Deprecation::CountDeprecation(GetExecutionContext(), feature);
}

ExecutionContext* ServiceWorkerContainer::GetExecutionContext() const {
  return GetSupplementable()->GetExecutionContext();
}

const AtomicString& ServiceWorkerContainer::InterfaceName() const {
  return event_target_names::kServiceWorkerContainer;
}

void ServiceWorkerContainer::setOnmessage(EventListener* listener) {
  SetAttributeEventListener(event_type_names::kMessage, listener);
  // https://w3c.github.io/ServiceWorker/#dom-serviceworkercontainer-onmessage:
  // "The first time the context object’s onmessage IDL attribute is set, its
  // client message queue must be enabled."
  EnableClientMessageQueue();
}

EventListener* ServiceWorkerContainer::onmessage() {
  return GetAttributeEventListener(event_type_names::kMessage);
}

ServiceWorkerRegistration*
ServiceWorkerContainer::GetOrCreateServiceWorkerRegistration(
    WebServiceWorkerRegistrationObjectInfo info) {
  if (info.registration_id == mojom::blink::kInvalidServiceWorkerRegistrationId)
    return nullptr;

  auto it = service_worker_registration_objects_.find(info.registration_id);
  if (it != service_worker_registration_objects_.end()) {
    ServiceWorkerRegistration* registration = it->value;
    registration->Attach(std::move(info));
    return registration;
  }

  const int64_t registration_id = info.registration_id;
  ServiceWorkerRegistration* registration =
      MakeGarbageCollected<ServiceWorkerRegistration>(
          GetSupplementable()->GetExecutionContext(), std::move(info));
  service_worker_registration_objects_.Set(registration_id, registration);
  return registration;
}

ServiceWorker* ServiceWorkerContainer::GetOrCreateServiceWorker(
    WebServiceWorkerObjectInfo info) {
  if (info.version_id == mojom::blink::kInvalidServiceWorkerVersionId)
    return nullptr;

  auto it = service_worker_objects_.find(info.version_id);
  if (it != service_worker_objects_.end())
    return it->value.Get();

  const int64_t version_id = info.version_id;
  ServiceWorker* worker = ServiceWorker::Create(
      GetSupplementable()->GetExecutionContext(), std::move(info));
  service_worker_objects_.Set(version_id, worker);
  return worker;
}

ServiceWorkerContainer::ServiceWorkerContainer(LocalDOMWindow& window)
    : Supplement<LocalDOMWindow>(window),
      ExecutionContextLifecycleObserver(&window) {}

ServiceWorkerContainer::ReadyProperty*
ServiceWorkerContainer::CreateReadyProperty() {
  return MakeGarbageCollected<ReadyProperty>(GetExecutionContext());
}

void ServiceWorkerContainer::EnableClientMessageQueue() {
  dom_content_loaded_observer_ = nullptr;
  if (is_client_message_queue_enabled_) {
    DCHECK(queued_messages_.empty());
    return;
  }
  is_client_message_queue_enabled_ = true;
  Vector<std::unique_ptr<MessageFromServiceWorker>> messages;
  messages.swap(queued_messages_);
  for (auto& message : messages) {
    DispatchMessageEvent(std::move(message->source),
                         std::move(message->message));
  }
}

void ServiceWorkerContainer::DispatchMessageEvent(
    WebServiceWorkerObjectInfo source,
    TransferableMessage message) {
  DCHECK(is_client_message_queue_enabled_);

  auto msg =
      BlinkTransferableMessage::FromTransferableMessage(std::move(message));
  MessagePortArray* ports =
      MessagePort::EntanglePorts(*GetExecutionContext(), std::move(msg.ports));
  ServiceWorker* service_worker =
      ServiceWorker::From(GetExecutionContext(), std::move(source));
  Event* event = nullptr;
  // TODO(crbug.com/1018092): Factor out these security checks so they aren't
  // duplicated in so many places.
  if (msg.message->IsOriginCheckRequired()) {
    const SecurityOrigin* target_origin =
        GetExecutionContext()->GetSecurityOrigin();
    if (!msg.sender_origin ||
        !msg.sender_origin->IsSameOriginWith(target_origin)) {
      event = MessageEvent::CreateError(
          GetExecutionContext()->GetSecurityOrigin()->ToString(),
          service_worker);
    }
  }
  if (!event) {
    auto* context = GetExecutionContext();
    if ((!msg.locked_to_sender_agent_cluster ||
         context->IsSameAgentCluster(msg.sender_agent_cluster_id)) &&
        msg.message->CanDeserializeIn(context)) {
      event = MessageEvent::Create(ports, std::move(msg.message),
                                   context->GetSecurityOrigin()->ToString(),
                                   String() /* lastEventId */, service_worker);
    } else {
      event = MessageEvent::CreateError(
          context->GetSecurityOrigin()->ToString(), service_worker);
    }
  }
  // Schedule the event to be dispatched on the correct task source:
  // https://w3c.github.io/ServiceWorker/#dfn-client-message-queue
  EnqueueEvent(*event, TaskType::kServiceWorkerClientMessage);
}

void ServiceWorkerContainer::OnGetRegistrationForReady(
    WebServiceWorkerRegistrationObjectInfo info) {
  DCHECK_EQ(ready_->GetState(), ReadyProperty::kPending);

  ready_->Resolve(GetOrCreateServiceWorkerRegistration(std::move(info)));
}

}  // namespace blink

"""

```