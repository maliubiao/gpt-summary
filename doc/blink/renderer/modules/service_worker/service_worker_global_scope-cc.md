Response:
The user wants to understand the functionality of the `service_worker_global_scope.cc` file in the Chromium Blink engine. They are particularly interested in its relationship with Javascript, HTML, and CSS, logical reasoning within the code, common user errors, and how a user action might lead to this code being executed. Finally, they need a summary of the file's functions based on the provided code snippet (part 1 of 4).

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Functionality:** The filename and the included headers (`service_worker_global_scope.h`, various `mojom` files related to service workers, fetch, etc.) immediately suggest that this file implements the core logic for the service worker's global scope. This is the environment in which the service worker's Javascript code executes.

2. **Analyze Key Components:**  Scan the code for significant elements:
    * **Class Definition:** `ServiceWorkerGlobalScope` is the central class. Its constructors and methods will define the functionality.
    * **Inheritance:** It inherits from `WorkerGlobalScope`, indicating shared functionality with other web workers.
    * **Member Variables:** These represent the state and resources managed by the `ServiceWorkerGlobalScope`. Pay attention to variables like `event_queue_`, `installed_scripts_manager_`, `cache_storage_remote_`, `registration_`, `service_worker_`, and the various event-related maps.
    * **Methods:**  Focus on methods related to:
        * Script loading and execution (`FetchAndRunClassicScript`, `FetchAndRunModuleScript`, `LoadAndRunInstalledClassicScript`, `RunClassicScript`, `EvaluateClassicScript`, `DidFetchClassicScript`, `DidReceiveResponseForClassicScript`, `DidEvaluateScript`).
        * Event handling (`OnNavigationPreloadResponse`, `OnNavigationPreloadError`, the `event_queue_`).
        * Interactions with the browser process (`BindServiceWorker`, `BindControllerServiceWorker`, methods calling `GetServiceWorkerHost()`).
        * Core service worker APIs (`skipWaiting`, `clients`, `registration`, `serviceWorker`).
    * **Included Headers:** These provide context about the dependencies and the functionalities the class interacts with (e.g., `fetch`, `notifications`, `push_messaging`, `cache_storage`).

3. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The primary function of a service worker is to execute JavaScript code. This file manages the environment for that execution. Look for code that loads, evaluates, and runs scripts. Events like `fetch`, `install`, `activate`, `push`, etc., are triggered by browser events and handled by JavaScript code within this scope.
    * **HTML:** Service workers are registered and associated with a specific scope within an HTML document. This file manages the lifecycle and execution of the service worker for that scope. The `registration()` method provides access to the service worker's registration information, which is linked to the HTML page.
    * **CSS:** While service workers don't directly manipulate CSS, they can intercept network requests for CSS files (via the `fetch` event) and potentially modify or serve them from the cache.

4. **Identify Logical Reasoning:** Look for conditional statements (`if`, `else`), loops (though less common in this initialization phase), and how different parts of the code interact based on flags or conditions. The logic for choosing between loading installed scripts vs. fetching from the network is a good example. The handling of different event types and their associated callbacks also involves logical flow.

5. **Consider User/Programming Errors:** Think about common mistakes developers make when working with service workers:
    * Incorrect script URLs.
    * Errors in the service worker's JavaScript code.
    * Issues with caching strategies leading to unexpected behavior.
    * Not handling events correctly (e.g., forgetting `event.respondWith()`).
    * Problems with the service worker's lifecycle (installation, activation).

6. **Trace User Operations (Debugging Clues):**  Think about the sequence of actions a user takes that would involve a service worker:
    * Visiting a website that has a registered service worker.
    * The browser checks for updates to the service worker.
    * If an update is found, the new service worker is installed.
    * The new service worker activates and takes control of the page.
    * The service worker intercepts network requests.
    * The service worker receives push notifications.

7. **Structure the Response:** Organize the information clearly, addressing each point in the user's request:
    * Start with a high-level summary of the file's purpose.
    * Explain the key functionalities, providing code examples or references where appropriate.
    * Detail the relationships with JavaScript, HTML, and CSS with concrete examples.
    * Illustrate logical reasoning with a specific scenario.
    * List common user errors related to service workers.
    * Outline the user actions that could lead to this code being executed.
    * Conclude with a concise summary of the file's functions based on the provided snippet.

8. **Refine and Review:** Ensure the explanation is accurate, easy to understand, and directly answers the user's questions. Check for any jargon that needs clarification. Since this is part 1 of 4, focus the summary specifically on the functionalities evident in this part.

By following these steps, the detailed and informative answer provided earlier can be constructed. The process involves understanding the code's context within the larger Chromium project and connecting its functionality to the web development concepts the user is familiar with.
这是 `blink/renderer/modules/service_worker/service_worker_global_scope.cc` 文件的第一部分代码，它主要负责 **实现 Service Worker 的全局作用域 (ServiceWorkerGlobalScope)**。  Service Worker 的全局作用域是 Service Worker 脚本执行的环境，提供了访问各种 Service Worker API 的能力。

以下是对其功能的归纳：

**主要功能:**

1. **作为 Service Worker 脚本的执行环境:**  `ServiceWorkerGlobalScope` 类定义了 Service Worker 脚本运行时的全局对象，它继承自 `WorkerGlobalScope`，共享了 Web Worker 的一些基础功能。

2. **管理 Service Worker 的生命周期:**  代码中包含了与 Service Worker 生命周期相关的逻辑，例如：
   - **脚本的加载和执行:**  `FetchAndRunClassicScript`, `FetchAndRunModuleScript`, `LoadAndRunInstalledClassicScript`, `RunClassicScript` 等方法负责从网络或缓存加载 Service Worker 脚本并执行。
   - **脚本执行完成后的处理:** `DidEvaluateScript` 方法在脚本执行完成后被调用，用于记录指标和启动事件队列。
   - **跳过等待:** `skipWaiting` 方法允许激活一个新的 Service Worker，跳过等待状态。

3. **提供 Service Worker API 的实现:**  该文件实现了 Service Worker 规范中定义的全局 API，例如：
   - **`clients` 属性:**  通过 `clients()` 方法返回 `ServiceWorkerClients` 对象，允许 Service Worker 与控制的客户端进行交互。
   - **`registration` 属性:** 通过 `registration()` 方法返回 `ServiceWorkerRegistration` 对象，提供对 Service Worker 注册信息的访问。
   - **`serviceWorker` 属性:** 通过 `serviceWorker()` 方法返回代表当前 Service Worker 实例的 `::blink::ServiceWorker` 对象。

4. **处理 Service Worker 事件:**  代码中可以看到与处理各种 Service Worker 事件相关的逻辑，例如：
   - **Fetch 事件:** `OnNavigationPreloadResponse`, `OnNavigationPreloadError` 等方法处理与导航预加载相关的 Fetch 事件响应。
   - **事件队列管理:**  `event_queue_` 成员变量和相关方法负责管理待处理的 Service Worker 事件，并按照顺序执行。

5. **与浏览器进程通信:**  通过 `mojo` 接口与浏览器进程进行通信，例如：
   - **绑定 ServiceWorker 接口:** `BindServiceWorker` 方法用于绑定 `mojom::blink::ServiceWorker` 接口，允许浏览器进程控制 Service Worker 的生命周期。
   - **绑定 ControllerServiceWorker 接口:** `BindControllerServiceWorker` 方法用于绑定 `mojom::blink::ControllerServiceWorker` 接口，用于启动阶段的控制。
   - **调用 ServiceWorkerHost:**  代码中通过 `GetServiceWorkerHost()` 获取到与浏览器进程通信的接口，用于执行一些浏览器侧的操作，例如 `SkipWaiting`。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**  `ServiceWorkerGlobalScope` 是 Service Worker JavaScript 代码执行的上下文。例如，当 Service Worker 脚本中注册了 `fetch` 事件监听器时，浏览器会将匹配的请求传递给 `ServiceWorkerGlobalScope`，然后执行监听器中的 JavaScript 代码。
   ```javascript
   // Service Worker 脚本示例
   self.addEventListener('fetch', event => {
     console.log('拦截到一个 fetch 请求:', event.request.url);
     // ... 可以进行缓存、网络请求等操作
   });
   ```

* **HTML:**  HTML 页面通过 JavaScript 注册 Service Worker。注册成功后，浏览器会创建 `ServiceWorkerGlobalScope` 的实例来执行该 Service Worker 的脚本。`registration()` 方法返回的 `ServiceWorkerRegistration` 对象关联着 HTML 页面注册的 Service Worker 信息。
   ```javascript
   // HTML 页面中的 JavaScript 示例
   navigator.serviceWorker.register('/sw.js').then(registration => {
     console.log('Service Worker 注册成功:', registration);
   });
   ```

* **CSS:**  虽然 Service Worker 不直接操作 CSS，但它可以拦截对 CSS 文件的请求（通过 `fetch` 事件），并根据需要提供缓存的 CSS 文件或从网络获取最新的 CSS 文件。
   ```javascript
   // Service Worker 脚本示例
   self.addEventListener('fetch', event => {
     if (event.request.url.endsWith('.css')) {
       event.respondWith(
         caches.match(event.request).then(response => {
           return response || fetch(event.request);
         })
       );
     }
   });
   ```

**逻辑推理 (假设输入与输出):**

假设用户在浏览器中访问了一个注册了 Service Worker 的网页。当浏览器检测到 Service Worker 的脚本有更新时，它会执行以下逻辑：

* **输入:** 新版本的 Service Worker 脚本的 URL。
* **`FetchAndRunClassicScript` 或 `FetchAndRunModuleScript`:**  `ServiceWorkerGlobalScope` 会调用这些方法之一来获取新版本的脚本。
* **假设输入:** 脚本下载成功。
* **`DidFetchClassicScript` 或相关方法:**  下载成功后，这些方法会被调用。
* **`RunClassicScript`:**  `ServiceWorkerGlobalScope` 调用此方法来执行脚本。
* **`DidEvaluateScript`:** 脚本执行完成后，此方法被调用，启动事件队列。
* **输出:**  新的 Service Worker 实例被创建并进入等待状态，等待旧的 Service Worker 不再被使用。

**用户或编程常见的使用错误举例:**

* **脚本 URL 错误:**  如果在 HTML 中注册 Service Worker 时，提供的脚本 URL 不正确，浏览器将无法找到并加载 Service Worker 脚本，导致 `ServiceWorkerGlobalScope` 无法正确创建和初始化。
* **Service Worker 脚本中发生语法错误:**  如果 Service Worker 脚本中存在 JavaScript 语法错误，当 `RunClassicScript` 或相关方法执行脚本时，会抛出异常，导致 Service Worker 安装失败。
* **在 `fetch` 事件中没有调用 `event.respondWith()`:**  如果在 `fetch` 事件监听器中忘记调用 `event.respondWith()`，浏览器将不知道如何处理该请求，可能导致页面加载失败或出现意外行为。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户首次访问一个包含 Service Worker 注册代码的网页:** 浏览器会解析 HTML，执行 JavaScript 代码，包括 Service Worker 的注册代码 (`navigator.serviceWorker.register('/sw.js')`)。
2. **浏览器发起对 Service Worker 脚本的请求:**  浏览器会根据注册时提供的 URL 请求 Service Worker 的脚本 (`sw.js`)。
3. **Blink 引擎的网络模块处理请求:**  Blink 的网络模块会下载 Service Worker 的脚本。
4. **Service Worker 脚本下载完成后，Blink 引擎创建 `ServiceWorkerGlobalScope` 实例:**  `ServiceWorkerGlobalScope::Create` 方法会被调用。
5. **`FetchAndRunClassicScript` (或 `FetchAndRunModuleScript`) 被调用:**  开始加载和执行 Service Worker 的脚本。
6. **脚本执行过程中，会调用各种 `ServiceWorkerGlobalScope` 的方法:** 例如，注册事件监听器，初始化缓存等。

**总结 (基于第一部分代码的功能):**

`blink/renderer/modules/service_worker/service_worker_global_scope.cc` 的第一部分主要负责 **创建和初始化 Service Worker 的全局作用域**，包括：

* **加载和执行 Service Worker 脚本 (经典脚本和模块脚本)。**
* **管理 Service Worker 的基本生命周期，例如脚本的获取和执行完成后的处理。**
* **提供访问 Service Worker 核心 API (如 `clients`, `registration`, `serviceWorker`) 的入口。**
* **建立与浏览器进程的通信通道 (通过 `mojo` 接口)。**
* **初步处理与 Service Worker 事件相关的逻辑 (例如导航预加载)。**

总而言之，这部分代码是 Service Worker 运行的核心基础，为 Service Worker 脚本的执行和与浏览器的交互奠定了基础。

Prompt: 
```
这是目录为blink/renderer/modules/service_worker/service_worker_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

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

#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope.h"

#include <memory>
#include <utility>

#include "base/debug/dump_without_crashing.h"
#include "base/feature_list.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/network/public/cpp/cross_origin_embedder_policy.h"
#include "services/network/public/mojom/cookie_manager.mojom-blink.h"
#include "services/network/public/mojom/cross_origin_embedder_policy.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/notifications/notification.mojom-blink.h"
#include "third_party/blink/public/mojom/push_messaging/push_messaging.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_fetch_response_callback.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_stream_handle.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/mojom/worker/subresource_loader_updater.mojom.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_error.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_v8_value_converter.h"
#include "third_party/blink/renderer/bindings/core/v8/callback_promise_adapter.h"
#include "third_party/blink/renderer/bindings/core/v8/js_based_event_listener.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_background_fetch_event_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_content_index_event_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_notification_event_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_request_event_init.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/global_fetch.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/request_debug_header_scope.h"
#include "third_party/blink/renderer/core/inspector/worker_inspector_controller.h"
#include "third_party/blink/renderer/core/inspector/worker_thread_debugger.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/core/loader/worker_resource_timing_notifier_impl.h"
#include "third_party/blink/renderer/core/messaging/blink_transferable_message.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_script_url.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/worker_backing_thread.h"
#include "third_party/blink/renderer/core/workers/worker_classic_script_loader.h"
#include "third_party/blink/renderer/core/workers/worker_clients.h"
#include "third_party/blink/renderer/core/workers/worker_reporting_proxy.h"
#include "third_party/blink/renderer/modules/background_fetch/background_fetch_event.h"
#include "third_party/blink/renderer/modules/background_fetch/background_fetch_registration.h"
#include "third_party/blink/renderer/modules/background_fetch/background_fetch_update_ui_event.h"
#include "third_party/blink/renderer/modules/background_sync/periodic_sync_event.h"
#include "third_party/blink/renderer/modules/background_sync/sync_event.h"
#include "third_party/blink/renderer/modules/content_index/content_index_event.h"
#include "third_party/blink/renderer/modules/cookie_store/cookie_change_event.h"
#include "third_party/blink/renderer/modules/cookie_store/extendable_cookie_change_event.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/hid/hid.h"
#include "third_party/blink/renderer/modules/notifications/notification.h"
#include "third_party/blink/renderer/modules/notifications/notification_event.h"
#include "third_party/blink/renderer/modules/payments/abort_payment_event.h"
#include "third_party/blink/renderer/modules/payments/abort_payment_respond_with_observer.h"
#include "third_party/blink/renderer/modules/payments/can_make_payment_event.h"
#include "third_party/blink/renderer/modules/payments/can_make_payment_respond_with_observer.h"
#include "third_party/blink/renderer/modules/payments/payment_event_data_conversion.h"
#include "third_party/blink/renderer/modules/payments/payment_request_event.h"
#include "third_party/blink/renderer/modules/payments/payment_request_respond_with_observer.h"
#include "third_party/blink/renderer/modules/push_messaging/push_event.h"
#include "third_party/blink/renderer/modules/push_messaging/push_message_data.h"
#include "third_party/blink/renderer/modules/push_messaging/push_subscription_change_event.h"
#include "third_party/blink/renderer/modules/service_worker/cross_origin_resource_policy_checker.h"
#include "third_party/blink/renderer/modules/service_worker/extendable_event.h"
#include "third_party/blink/renderer/modules/service_worker/extendable_message_event.h"
#include "third_party/blink/renderer/modules/service_worker/fetch_event.h"
#include "third_party/blink/renderer/modules/service_worker/fetch_respond_with_observer.h"
#include "third_party/blink/renderer/modules/service_worker/install_event.h"
#include "third_party/blink/renderer/modules/service_worker/respond_with_observer.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_client.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_clients.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope_proxy.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_module_tree_client.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_registration.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_script_cached_metadata_handler.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_thread.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_window_client.h"
#include "third_party/blink/renderer/modules/service_worker/wait_until_observer.h"
#include "third_party/blink/renderer/modules/service_worker/web_service_worker_fetch_context_impl.h"
#include "third_party/blink/renderer/modules/webusb/usb.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_response_headers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

namespace {

constexpr char kServiceWorkerGlobalScopeTraceScope[] =
    "ServiceWorkerGlobalScope";

void DidSkipWaiting(ScriptPromiseResolver<IDLUndefined>* resolver,
                    bool success) {
  // Per spec the promise returned by skipWaiting() can never reject.
  if (!success) {
    resolver->Detach();
    return;
  }
  resolver->Resolve();
}

// Creates a callback which takes an |event_id| and |status|, which calls the
// given event's callback with the given status and removes it from |map|.
template <typename MapType, typename... Args>
ServiceWorkerEventQueue::AbortCallback CreateAbortCallback(MapType* map,
                                                           Args&&... args) {
  return WTF::BindOnce(
      [](MapType* map, Args&&... args, int event_id,
         mojom::blink::ServiceWorkerEventStatus status) {
        auto iter = map->find(event_id);
        CHECK(iter != map->end(), base::NotFatalUntil::M130);
        std::move(iter->value).Run(status, std::forward<Args>(args)...);
        map->erase(iter);
      },
      WTF::Unretained(map), std::forward<Args>(args)...);
}

// Finds an event callback keyed by |event_id| from |map|, and runs the callback
// with |args|. Returns true if the callback was found and called, otherwise
// returns false.
template <typename MapType, typename... Args>
bool RunEventCallback(MapType* map,
                      ServiceWorkerEventQueue* event_queue,
                      int event_id,
                      Args&&... args) {
  auto iter = map->find(event_id);
  // The event may have been aborted.
  if (iter == map->end())
    return false;
  std::move(iter->value).Run(std::forward<Args>(args)...);
  map->erase(iter);
  event_queue->EndEvent(event_id);
  return true;
}

template <typename T>
static std::string MojoEnumToString(T mojo_enum) {
  std::ostringstream oss;
  oss << mojo_enum;
  return oss.str();
}

}  // namespace

ServiceWorkerGlobalScope* ServiceWorkerGlobalScope::Create(
    ServiceWorkerThread* thread,
    std::unique_ptr<GlobalScopeCreationParams> creation_params,
    std::unique_ptr<ServiceWorkerInstalledScriptsManager>
        installed_scripts_manager,
    mojo::PendingRemote<mojom::blink::CacheStorage> cache_storage_remote,
    base::TimeTicks time_origin,
    const ServiceWorkerToken& service_worker_token) {
#if DCHECK_IS_ON()
  // If the script is being loaded via script streaming, the script is not yet
  // loaded.
  if (installed_scripts_manager && installed_scripts_manager->IsScriptInstalled(
                                       creation_params->script_url)) {
    // CSP headers, referrer policy, and origin trial tokens will be provided by
    // the InstalledScriptsManager in EvaluateClassicScript().
    DCHECK(creation_params->outside_content_security_policies.empty());
    DCHECK_EQ(network::mojom::ReferrerPolicy::kDefault,
              creation_params->referrer_policy);
    DCHECK(creation_params->inherited_trial_features->empty());
  }
#endif  // DCHECK_IS_ON()

  InterfaceRegistry* interface_registry = creation_params->interface_registry;
  return MakeGarbageCollected<ServiceWorkerGlobalScope>(
      std::move(creation_params), thread, std::move(installed_scripts_manager),
      std::move(cache_storage_remote), time_origin, service_worker_token,
      interface_registry);
}

ServiceWorkerGlobalScope::ServiceWorkerGlobalScope(
    std::unique_ptr<GlobalScopeCreationParams> creation_params,
    ServiceWorkerThread* thread,
    std::unique_ptr<ServiceWorkerInstalledScriptsManager>
        installed_scripts_manager,
    mojo::PendingRemote<mojom::blink::CacheStorage> cache_storage_remote,
    base::TimeTicks time_origin,
    const ServiceWorkerToken& service_worker_token,
    InterfaceRegistry* interface_registry)
    : WorkerGlobalScope(std::move(creation_params), thread, time_origin, true),
      interface_registry_(interface_registry),
      installed_scripts_manager_(std::move(installed_scripts_manager)),
      cache_storage_remote_(std::move(cache_storage_remote)),
      token_(service_worker_token) {
  // Create the event queue. At this point its timer is not started. It will be
  // started by DidEvaluateScript().
  //
  // We are using TaskType::kInternalDefault for the idle callback, and it can
  // be paused or throttled. This should work for now because we don't throttle
  // or pause service worker threads, while it may cause not calling idle
  // callback. We need to revisit this once we want to implement pausing
  // service workers, but basically that won't be big problem because we have
  // ping-pong timer and that will kill paused service workers.
  event_queue_ = std::make_unique<ServiceWorkerEventQueue>(
      WTF::BindRepeating(&ServiceWorkerGlobalScope::OnBeforeStartEvent,
                         WrapWeakPersistent(this)),
      WTF::BindRepeating(&ServiceWorkerGlobalScope::OnIdleTimeout,
                         WrapWeakPersistent(this)),
      GetTaskRunner(TaskType::kInternalDefault));

  CoreInitializer::GetInstance().InitServiceWorkerGlobalScope(*this);
}

ServiceWorkerGlobalScope::~ServiceWorkerGlobalScope() = default;

bool ServiceWorkerGlobalScope::ShouldInstallV8Extensions() const {
  return Platform::Current()->AllowScriptExtensionForServiceWorker(
      WebSecurityOrigin(GetSecurityOrigin()));
}

// https://w3c.github.io/ServiceWorker/#update
void ServiceWorkerGlobalScope::FetchAndRunClassicScript(
    const KURL& script_url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<PolicyContainer> policy_container,
    const FetchClientSettingsObjectSnapshot& outside_settings_object,
    WorkerResourceTimingNotifier& outside_resource_timing_notifier,
    const v8_inspector::V8StackTraceId& stack_id) {
  DCHECK(!IsContextPaused());

  // policy_container_host could be null for registration restored from old DB
  if (policy_container)
    SetPolicyContainer(std::move(policy_container));

  if (installed_scripts_manager_) {
    // This service worker is installed. Load and run the installed script.
    LoadAndRunInstalledClassicScript(script_url, stack_id);
    return;
  }

  // Step 9. "Switching on job's worker type, run these substeps with the
  // following options:"
  // "classic: Fetch a classic worker script given job's serialized script url,
  // job's client, "serviceworker", and the to-be-created environment settings
  // object for this service worker."
  auto context_type = mojom::blink::RequestContextType::SERVICE_WORKER;
  auto destination = network::mojom::RequestDestination::kServiceWorker;

  // "To perform the fetch given request, run the following steps:"
  // Step 9.1. "Append `Service-Worker`/`script` to request's header list."
  // Step 9.2. "Set request's cache mode to "no-cache" if any of the following
  // are true:"
  // Step 9.3. "Set request's service-workers mode to "none"."
  // The browser process takes care of these steps.

  // Step 9.4. "If the is top-level flag is unset, then return the result of
  // fetching request."
  // This step makes sense only when the worker type is "module". For classic
  // script fetch, the top-level flag is always set.

  // Step 9.5. "Set request's redirect mode to "error"."
  // The browser process takes care of this step.

  // Step 9.6. "Fetch request, and asynchronously wait to run the remaining
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
          &ServiceWorkerGlobalScope::DidReceiveResponseForClassicScript,
          WrapWeakPersistent(this), WrapPersistent(classic_script_loader)),
      WTF::BindOnce(&ServiceWorkerGlobalScope::DidFetchClassicScript,
                    WrapWeakPersistent(this),
                    WrapPersistent(classic_script_loader), stack_id),
      RejectCoepUnsafeNone(false), {}, CreateUniqueIdentifier());
}

void ServiceWorkerGlobalScope::FetchAndRunModuleScript(
    const KURL& module_url_record,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<PolicyContainer> policy_container,
    const FetchClientSettingsObjectSnapshot& outside_settings_object,
    WorkerResourceTimingNotifier& outside_resource_timing_notifier,
    network::mojom::CredentialsMode credentials_mode,
    RejectCoepUnsafeNone reject_coep_unsafe_none) {
  DCHECK(IsContextThread());
  DCHECK(!reject_coep_unsafe_none);

  // policy_container_host could be null for registration restored from old DB
  if (policy_container)
    SetPolicyContainer(std::move(policy_container));

  if (worker_main_script_load_params) {
    SetWorkerMainScriptLoadingParametersForModules(
        std::move(worker_main_script_load_params));
  }
  ModuleScriptCustomFetchType fetch_type =
      installed_scripts_manager_
          ? ModuleScriptCustomFetchType::kInstalledServiceWorker
          : ModuleScriptCustomFetchType::kWorkerConstructor;

  // Count instantiation of a service worker using a module script as a proxy %
  // of page loads use a service worker with a module script.
  CountWebDXFeature(WebDXFeature::kJsModulesServiceWorkers);

  FetchModuleScript(module_url_record, outside_settings_object,
                    outside_resource_timing_notifier,
                    mojom::blink::RequestContextType::SERVICE_WORKER,
                    network::mojom::RequestDestination::kServiceWorker,
                    credentials_mode, fetch_type,
                    MakeGarbageCollected<ServiceWorkerModuleTreeClient>(
                        ScriptController()->GetScriptState()));
}

void ServiceWorkerGlobalScope::Dispose() {
  DCHECK(IsContextThread());
  controller_receivers_.Clear();
  event_queue_.reset();
  service_worker_host_.reset();
  receiver_.reset();
  WorkerGlobalScope::Dispose();
}

InstalledScriptsManager*
ServiceWorkerGlobalScope::GetInstalledScriptsManager() {
  return installed_scripts_manager_.get();
}

void ServiceWorkerGlobalScope::GetAssociatedInterface(
    const String& name,
    mojo::PendingAssociatedReceiver<mojom::blink::AssociatedInterface>
        receiver) {
  mojo::ScopedInterfaceEndpointHandle handle = receiver.PassHandle();
  associated_inteface_registy_.TryBindInterface(name.Utf8(), &handle);
}

void ServiceWorkerGlobalScope::DidEvaluateScript() {
  DCHECK(!did_evaluate_script_);
  did_evaluate_script_ = true;

  int number_of_fetch_handlers =
      NumberOfEventListeners(event_type_names::kFetch);
  if (number_of_fetch_handlers > 1) {
    UseCounter::Count(this, WebFeature::kMultipleFetchHandlersInServiceWorker);
  }
  base::UmaHistogramCounts1000("ServiceWorker.NumberOfRegisteredFetchHandlers",
                               number_of_fetch_handlers);
  event_queue_->Start();
}

AssociatedInterfaceRegistry&
ServiceWorkerGlobalScope::GetAssociatedInterfaceRegistry() {
  return associated_inteface_registy_;
}

void ServiceWorkerGlobalScope::DidReceiveResponseForClassicScript(
    WorkerClassicScriptLoader* classic_script_loader) {
  DCHECK(IsContextThread());
  probe::DidReceiveScriptResponse(this, classic_script_loader->Identifier());
}

// https://w3c.github.io/ServiceWorker/#update
void ServiceWorkerGlobalScope::DidFetchClassicScript(
    WorkerClassicScriptLoader* classic_script_loader,
    const v8_inspector::V8StackTraceId& stack_id) {
  DCHECK(IsContextThread());

  // Step 9. "If the algorithm asynchronously completes with null, then:"
  if (classic_script_loader->Failed()) {
    // Step 9.1. "Invoke Reject Job Promise with job and TypeError."
    // Step 9.2. "If newestWorker is null, invoke Clear Registration algorithm
    // passing registration as its argument."
    // Step 9.3. "Invoke Finish Job with job and abort these steps."
    // The browser process takes care of these steps.
    ReportingProxy().DidFailToFetchClassicScript();
    // Close the worker global scope to terminate the thread.
    close();
    return;
  }
  // The app cache ID is not used.
  ReportingProxy().DidFetchScript();
  probe::ScriptImported(this, classic_script_loader->Identifier(),
                        classic_script_loader->SourceText());

  // Step 10. "If hasUpdatedResources is false, then:"
  //   Step 10.1. "Invoke Resolve Job Promise with job and registration."
  //   Steo 10.2. "Invoke Finish Job with job and abort these steps."
  // Step 11. "Let worker be a new service worker."
  // Step 12. "Set worker's script url to job's script url, worker's script
  // resource to script, worker's type to job's worker type, and worker's
  // script resource map to updatedResourceMap."
  // Step 13. "Append url to worker's set of used scripts."
  // The browser process takes care of these steps.

  // Step 14. "Set worker's script resource's HTTPS state to httpsState."
  // This is done in the constructor of WorkerGlobalScope.

  // Step 15. "Set worker's script resource's referrer policy to
  // referrerPolicy."
  auto referrer_policy = network::mojom::ReferrerPolicy::kDefault;
  if (!classic_script_loader->GetReferrerPolicy().IsNull()) {
    SecurityPolicy::ReferrerPolicyFromHeaderValue(
        classic_script_loader->GetReferrerPolicy(),
        kDoNotSupportReferrerPolicyLegacyKeywords, &referrer_policy);
  }

  // Step 16. "Invoke Run Service Worker algorithm given worker, with the force
  // bypass cache for importscripts flag set if job’s force bypass cache flag
  // is set, and with the following callback steps given evaluationStatus:"
  RunClassicScript(
      classic_script_loader->ResponseURL(), referrer_policy,
      classic_script_loader->GetContentSecurityPolicy()
          ? mojo::Clone(classic_script_loader->GetContentSecurityPolicy()
                            ->GetParsedPolicies())
          : Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
      classic_script_loader->OriginTrialTokens(),
      classic_script_loader->SourceText(),
      classic_script_loader->ReleaseCachedMetadata(), stack_id);
}

// https://w3c.github.io/ServiceWorker/#run-service-worker-algorithm
void ServiceWorkerGlobalScope::Initialize(
    const KURL& response_url,
    network::mojom::ReferrerPolicy response_referrer_policy,
    Vector<network::mojom::blink::ContentSecurityPolicyPtr> response_csp,
    const Vector<String>* response_origin_trial_tokens) {
  // Step 4.5. "Set workerGlobalScope's url to serviceWorker's script url."
  InitializeURL(response_url);

  // Step 4.6. "Set workerGlobalScope's HTTPS state to serviceWorker's script
  // resource's HTTPS state."
  // This is done in the constructor of WorkerGlobalScope.

  // Step 4.7. "Set workerGlobalScope's referrer policy to serviceWorker's
  // script resource's referrer policy."
  SetReferrerPolicy(response_referrer_policy);

  // This is quoted from the "Content Security Policy" algorithm in the service
  // workers spec:
  // "Whenever a user agent invokes Run Service Worker algorithm with a service
  // worker serviceWorker:
  // - If serviceWorker's script resource was delivered with a
  //   Content-Security-Policy HTTP header containing the value policy, the
  //   user agent must enforce policy for serviceWorker.
  // - If serviceWorker's script resource was delivered with a
  //   Content-Security-Policy-Report-Only HTTP header containing the value
  //   policy, the user agent must monitor policy for serviceWorker."
  InitContentSecurityPolicyFromVector(std::move(response_csp));
  BindContentSecurityPolicyToExecutionContext();

  OriginTrialContext::AddTokens(this, response_origin_trial_tokens);

  // TODO(nhiroki): Clarify mappings between the steps 4.8-4.11 and
  // implementation.

  // This should be called after OriginTrialContext::AddTokens() to install
  // origin trial features in JavaScript's global object.
  ScriptController()->PrepareForEvaluation();
}

void ServiceWorkerGlobalScope::LoadAndRunInstalledClassicScript(
    const KURL& script_url,
    const v8_inspector::V8StackTraceId& stack_id) {
  DCHECK(IsContextThread());

  DCHECK(installed_scripts_manager_);
  DCHECK(installed_scripts_manager_->IsScriptInstalled(script_url));

  // GetScriptData blocks until the script is received from the browser.
  std::unique_ptr<InstalledScriptsManager::ScriptData> script_data =
      installed_scripts_manager_->GetScriptData(script_url);
  if (!script_data) {
    ReportingProxy().DidFailToFetchClassicScript();
    // This will eventually initiate worker thread termination. See
    // ServiceWorkerGlobalScopeProxy::DidCloseWorkerGlobalScope() for details.
    close();
    return;
  }
  ReportingProxy().DidLoadClassicScript();

  auto referrer_policy = network::mojom::ReferrerPolicy::kDefault;
  if (!script_data->GetReferrerPolicy().IsNull()) {
    SecurityPolicy::ReferrerPolicyFromHeaderValue(
        script_data->GetReferrerPolicy(),
        kDoNotSupportReferrerPolicyLegacyKeywords, &referrer_policy);
  }

  RunClassicScript(script_url, referrer_policy,
                   ParseContentSecurityPolicyHeaders(
                       script_data->GetContentSecurityPolicyResponseHeaders()),
                   script_data->CreateOriginTrialTokens().get(),
                   script_data->TakeSourceText(), script_data->TakeMetaData(),
                   stack_id);
}

// https://w3c.github.io/ServiceWorker/#run-service-worker-algorithm
void ServiceWorkerGlobalScope::RunClassicScript(
    const KURL& response_url,
    network::mojom::ReferrerPolicy response_referrer_policy,
    Vector<network::mojom::blink::ContentSecurityPolicyPtr> response_csp,
    const Vector<String>* response_origin_trial_tokens,
    const String& source_code,
    std::unique_ptr<Vector<uint8_t>> cached_meta_data,
    const v8_inspector::V8StackTraceId& stack_id) {
  // Step 4.5-4.11 are implemented in Initialize().
  Initialize(response_url, response_referrer_policy, std::move(response_csp),
             response_origin_trial_tokens);

  // Step 4.12. "Let evaluationStatus be the result of running the classic
  // script script if script is a classic script, otherwise, the result of
  // running the module script script if script is a module script."
  EvaluateClassicScript(response_url, source_code, std::move(cached_meta_data),
                        stack_id);
}

ServiceWorkerClients* ServiceWorkerGlobalScope::clients() {
  if (!clients_)
    clients_ = ServiceWorkerClients::Create();
  return clients_.Get();
}

ServiceWorkerRegistration* ServiceWorkerGlobalScope::registration() {
  return registration_.Get();
}

::blink::ServiceWorker* ServiceWorkerGlobalScope::serviceWorker() {
  return service_worker_.Get();
}

ScriptPromise<IDLUndefined> ServiceWorkerGlobalScope::skipWaiting(
    ScriptState* script_state) {
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  // FIXME: short-term fix, see details at:
  // https://codereview.chromium.org/535193002/.
  if (!execution_context)
    return EmptyPromise();

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  GetServiceWorkerHost()->SkipWaiting(
      WTF::BindOnce(&DidSkipWaiting, WrapPersistent(resolver)));
  return resolver->Promise();
}

void ServiceWorkerGlobalScope::BindServiceWorker(
    mojo::PendingReceiver<mojom::blink::ServiceWorker> receiver) {
  DCHECK(IsContextThread());
  DCHECK(!receiver_.is_bound());
  // TODO(falken): Consider adding task types for "the handle fetch task source"
  // and "handle functional event task source" defined in the service worker
  // spec and use them when dispatching events.
  receiver_.Bind(std::move(receiver),
                 GetThread()->GetTaskRunner(TaskType::kInternalDefault));
}

void ServiceWorkerGlobalScope::BindControllerServiceWorker(
    mojo::PendingReceiver<mojom::blink::ControllerServiceWorker> receiver) {
  DCHECK(IsContextThread());
  DCHECK(controller_receivers_.empty());
  // This receiver won't get any FetchEvents because it's used only for
  // bootstrapping, and the actual clients connect over Clone() later. kNone is
  // passed as COEP value as a placeholder.
  //
  // TODO(falken): Consider adding task types for "the handle fetch task source"
  // and "handle functional event task source" defined in the service worker
  // spec and use them when dispatching events.
  controller_receivers_.Add(
      std::move(receiver), /*context=*/nullptr,
      GetThread()->GetTaskRunner(TaskType::kInternalDefault));
}

void ServiceWorkerGlobalScope::OnNavigationPreloadResponse(
    int fetch_event_id,
    std::unique_ptr<WebURLResponse> response,
    mojo::ScopedDataPipeConsumerHandle data_pipe) {
  DCHECK(IsContextThread());
  auto it = pending_preload_fetch_events_.find(fetch_event_id);
  CHECK(it != pending_preload_fetch_events_.end(), base::NotFatalUntil::M130);
  FetchEvent* fetch_event = it->value.Get();
  DCHECK(fetch_event);
  fetch_event->OnNavigationPreloadResponse(ScriptController()->GetScriptState(),
                                           std::move(response),
                                           std::move(data_pipe));
}

void ServiceWorkerGlobalScope::OnNavigationPreloadError(
    int fetch_event_id,
    std::unique_ptr<WebServiceWorkerError> error) {
  DCHECK(IsContextThread());
  FetchEvent* fetch_event = pending_preload_fetch_events_.Take(fetch_event_id);
  DCHECK(fetch_event);
  // Display an error message to the console directly.
  if (error->mode == WebServiceWorkerError::Mode::kShownInConsole) {
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kWorker,
        mojom::ConsoleMessageLevel::kError, error->message));
  }
  // Reject the preloadResponse promise.
  fetch_event->OnNavigationPreloadError(ScriptController()->GetScriptState(),
                                       
"""


```