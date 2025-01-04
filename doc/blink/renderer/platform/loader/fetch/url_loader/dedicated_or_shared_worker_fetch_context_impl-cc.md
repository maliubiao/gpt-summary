Response:
Let's break down the thought process for analyzing this C++ file and generating the descriptive summary.

1. **Understand the Goal:** The primary goal is to understand the functionality of `dedicated_or_shared_worker_fetch_context_impl.cc` within the Chromium Blink rendering engine. This involves identifying its core purpose, its interactions with other parts of the system (especially JavaScript, HTML, and CSS), and potential usage pitfalls.

2. **Initial Scan and Keyword Identification:**  Start by quickly scanning the file for prominent keywords and class names. This immediately reveals:
    * `DedicatedOrSharedWorkerFetchContextImpl`:  This is the central class and suggests handling network requests (fetching) within the context of dedicated or shared web workers.
    * `URLLoaderFactory`: This points to the core responsibility of creating objects that perform the actual network loading.
    * `ServiceWorker`:  Mentions of `ServiceWorkerContainerHostInterfaceBase`, `ServiceWorkerSubresourceLoaderFactory`, and `ControllerServiceWorkerMode` indicate interaction with service workers.
    * `Throttles`:  `URLLoaderThrottleProvider` and `WebSocketHandshakeThrottleProvider` suggest mechanisms for controlling or modifying network requests.
    * `ResourceRequest`: This is a fundamental type representing a network request.
    * `RendererPreferences`: Indicates the class is influenced by browser settings.
    * `CloneForNestedWorker`: Suggests support for nested workers.

3. **Deconstruct the Core Class (`DedicatedOrSharedWorkerFetchContextImpl`):**
    * **Constructor:**  Note the various dependencies being passed in (URLLoaderFactories, Service Worker interfaces, throttle providers, etc.). This gives clues about the context in which this class operates.
    * **`InitializeOnWorkerThread`:** This method is crucial as it sets up the core functionality on the worker thread, including creating the `URLLoaderFactory`.
    * **`GetURLLoaderFactory`:**  A key method for obtaining the factory responsible for creating loaders.
    * **`CreateURLLoader` (within the inner `Factory` class):** This is where the decision is made about *which* `URLLoader` to create, handling the service worker interception logic. Pay close attention to the `CanCreateServiceWorkerURLLoader` method.
    * **Service Worker Related Methods:**  Methods like `SetServiceWorkerURLLoaderFactory`, `OnControllerChanged`, `ResetServiceWorkerURLLoaderFactory` are clearly focused on integrating with the service worker lifecycle.
    * **Cloning Methods:** `CloneForNestedWorkerDeprecated` and `CloneForNestedWorker` highlight support for creating new fetch contexts for nested workers. Note the differences in how service workers are handled in these two cases (likely due to the PlzDedicatedWorker feature).
    * **Preference Methods:** `NotifyUpdate`, `GetAcceptLanguages` indicate the class respects user preferences.
    * **Throttling Methods:** `CreateThrottles`, `CreateWebSocketHandshakeThrottle` demonstrate how network requests can be intercepted and modified.
    * **Request Modification:** `WillSendRequest`, `FinalizeRequest` show how requests can be altered before being sent.
    * **Information Storage:**  Variables like `site_for_cookies_`, `top_frame_origin_`, `ancestor_frame_token_` store important contextual information.

4. **Analyze the Inner `Factory` Class:**  This class is a specialized `URLLoaderFactory` that adds service worker awareness.
    * **Service Worker Interception Logic:** The `CanCreateServiceWorkerURLLoader` method is central. Understand the conditions under which a request will be routed through the service worker.
    * **Delegation:**  The `CreateURLLoader` method delegates to either the regular `loader_factory_` or the `service_worker_loader_factory_`.

5. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  Web workers are a JavaScript API. This class is responsible for handling network requests initiated by worker scripts. Service workers are also closely tied to JavaScript.
    * **HTML:**  Workers are often created from HTML pages. The resources fetched by workers (images, scripts, data) are related to HTML content. The `site_for_cookies` and `top_frame_origin` are also related to the HTML context.
    * **CSS:** While less direct, workers might fetch CSS resources, and service workers can intercept requests for CSS files.

6. **Look for Logic and Potential Issues:**
    * **Service Worker Interception Logic:**  Carefully examine the conditions in `CanCreateServiceWorkerURLLoader`. Consider edge cases (e.g., `blob:` URLs, `skip_service_worker`).
    * **Cloning:** Understand how the cloning process works, especially regarding the service worker container host and loader factories.
    * **Thread Safety:** The comments about background threads in `ResetServiceWorkerURLLoaderFactory` suggest potential concurrency concerns.
    * **Error Handling:**  While not explicitly detailed in this snippet, consider what might go wrong (e.g., service worker unavailable, network errors).

7. **Infer Assumptions and Potential Input/Output:**
    * **Input:** Network requests initiated by worker scripts (URLs, headers, methods). Service worker state (controlled/uncontrolled). Renderer preferences.
    * **Output:** Creation of `URLLoader` objects. Decisions about whether to involve a service worker. Modifications to network requests.

8. **Consider User/Programming Errors:**
    * **Service Worker Misconfiguration:** Incorrect service worker scope or registration can lead to unexpected interception behavior.
    * **CORS Issues:** Workers are subject to CORS, and this class likely plays a role in enforcing it. Incorrect CORS headers on the server can cause failures.
    * **Incorrect `skip_service_worker` Usage:**  Forcing a bypass when it's not intended.
    * **Nested Worker Complexities:**  Understanding the implications of cloned fetch contexts for nested workers can be tricky.

9. **Structure the Output:** Organize the findings into clear categories: Functionality, Relationship to Web Technologies, Logic/Assumptions, User Errors. Use specific examples where possible. Focus on explaining *why* something is the way it is.

10. **Refine and Review:**  Read through the generated summary to ensure clarity, accuracy, and completeness. Check for any ambiguities or areas that could be explained better. For example, initially, I might just say "handles service worker requests."  Refining this would be to explain *how* it handles them (through a separate `URLLoaderFactory`) and *under what conditions*.

By following these steps, we can systematically analyze the code and produce a comprehensive and informative summary like the example provided in the initial prompt.
这个C++源代码文件 `dedicated_or_shared_worker_fetch_context_impl.cc` 是 Chromium Blink 渲染引擎中，专门为 **专用 Worker (Dedicated Worker)** 和 **共享 Worker (Shared Worker)** 处理网络请求（Fetch）上下文实现的核心组件。 它的主要功能是：

**核心功能：管理 Worker 的网络请求上下文**

1. **创建和配置 URLLoaderFactory:**  它负责创建 `URLLoaderFactory`，这是 Blink 中用于发起和管理网络请求的关键类。这个 Factory 会被 Worker 使用来加载各种资源，例如脚本、数据、图片等。

2. **Service Worker 集成:**  它深度集成了 Service Worker 的机制。
    * **判断是否需要通过 Service Worker 处理请求:**  它会根据当前 Worker 的状态（是否被 Service Worker 控制）以及请求的特性（例如 URL 协议、`skip_service_worker` 标志）来决定是否需要将请求路由到 Service Worker 进行处理。
    * **创建 Service Worker 专用的 URLLoaderFactory:** 如果需要通过 Service Worker 处理请求，它会创建一个特殊的 `URLLoaderFactory`，该 Factory 会将请求发送给关联的 Service Worker 进行拦截和处理。
    * **管理 Service Worker 控制状态的变化:** 当 Worker 的控制 Service Worker 发生变化时，它会更新内部状态并重新设置 `URLLoaderFactory`。

3. **请求拦截和修改:**  它提供了一些机制来拦截和修改 Worker 发出的网络请求：
    * **`WillSendRequest`:**  允许在请求发送前修改 URL (尽管示例代码中 `g_rewrite_url` 默认是空的)。
    * **`FinalizeRequest`:**  在请求最终发送前添加一些标准的 HTTP 头，例如 "Do-Not-Track" (如果用户启用了) 和处理 Referrer 信息。

4. **请求节流 (Throttling):**  它使用 `URLLoaderThrottleProvider` 和 `WebSocketHandshakeThrottleProvider` 来为网络请求和 WebSocket 连接创建节流器 (throttles)。节流器可以用来限制请求的并发数量、延迟请求等。

5. **克隆上下文:**  它支持为嵌套的 Worker 创建新的 FetchContext，并适当地继承或隔离父 Worker 的网络配置和 Service Worker 关联。

6. **处理渲染器偏好设置:** 它会根据渲染器的偏好设置 (例如是否启用 "Do-Not-Track"、是否发送 Referrer 等) 来配置网络请求。

7. **资源加载信息通知:** 它使用 `ResourceLoadInfoNotifier` 来收集和报告资源加载的相关信息。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  这个文件是 Worker 执行网络请求的核心支撑。Worker 中的 JavaScript 代码使用 Fetch API 或者 XMLHttpRequest 发起的网络请求，最终会通过这里创建的 `URLLoaderFactory` 来完成。Service Workers 本身也是用 JavaScript 编写的，这个文件负责将 Worker 的网络请求导向 Service Worker 进行处理。

    * **举例:**  一个 Dedicated Worker 的 JavaScript 代码使用 `fetch('/api/data')` 发起请求。`DedicatedOrSharedWorkerFetchContextImpl` 会决定这个请求是否应该被 Service Worker 拦截。如果 Service Worker 注册并控制了该 Worker 的作用域，请求会被路由到 Service Worker 的 `fetch` 事件监听器。

* **HTML:**  Worker 通常由 HTML 页面创建。这个文件处理的网络请求是为了加载 Worker 所需的资源，这些资源可能包括 JavaScript 脚本 (用于 Worker 的逻辑)，以及 Worker 需要处理的数据，这些数据可能与 HTML 页面展示的内容相关。

    * **举例:**  HTML 中创建了一个 Dedicated Worker： `const worker = new Worker('worker.js');`。 当 `worker.js` 内部执行 `fetch('image.png')` 时， `DedicatedOrSharedWorkerFetchContextImpl` 负责加载 `image.png`。

* **CSS:** 虽然 Worker 主要处理 JavaScript 和数据，但 Worker 也有可能发起加载 CSS 文件的请求，例如在一些特定的场景下需要动态加载样式。

    * **举例:**  一个 Worker 脚本可能会下载一个包含样式规则的 JSON 文件，然后将其应用到主线程的文档中。这个下载 JSON 文件的请求会经过 `DedicatedOrSharedWorkerFetchContextImpl` 处理。或者，如果 Service Worker 负责处理所有图片请求，而 CSS 中引用了图片，那么加载这些图片的请求也会通过这里的 Service Worker 逻辑。

**逻辑推理与假设输入输出：**

**假设输入:**

1. 一个 Dedicated Worker 发起了一个 `fetch('https://example.com/data.json')` 的请求。
2. 该 Worker 的作用域被一个 Service Worker 控制。
3. 请求没有设置 `request.mode = 'no-cors'` 也没有设置 `request.credentials = 'omit'`。
4. 请求的 URL 属于 Service Worker 的拦截范围。

**逻辑推理:**

* `CanCreateServiceWorkerURLLoader` 会判断：
    * `service_worker_loader_factory_` 已被设置 (因为 Service Worker 已注册)。
    * 请求的 URL 是 HTTPS。
    * `request.skip_service_worker` 为 false (默认情况)。
    * 因此，返回 `true`。
* `CreateURLLoader` 会使用 `service_worker_loader_factory_` 来创建 `URLLoader`。
* 这个 `URLLoader` 会将请求发送到 Service Worker 进程。
* Service Worker 的 `fetch` 事件监听器会被触发，Service Worker 可以选择返回缓存的响应，或者发起一个新的网络请求。

**假设输出:**

* 创建一个 `URLLoader` 对象，该对象的目标是 Service Worker。
* 最终的网络请求（如果 Service Worker 发起）会由 Service Worker 的网络栈处理，而不是直接由 Worker 的网络栈处理。

**用户或编程常见的使用错误：**

1. **Service Worker 作用域配置错误:**  开发者可能错误地配置了 Service Worker 的作用域，导致 Worker 的请求没有被预期的 Service Worker 拦截。

    * **举例:**  Service Worker 的作用域是 `/app/`，但 Worker 脚本运行在 `/` 路径下，那么 Worker 发起的 `/api/data` 请求就不会被该 Service Worker 拦截。

2. **Service Worker 未正确注册或激活:** 如果 Service Worker 没有正确注册或者还没有激活，`service_worker_loader_factory_` 可能为空，导致预期被 Service Worker 处理的请求直接透传，可能出现错误或性能问题。

3. **在需要 Service Worker 处理的请求上设置了 `skip_service_worker`:**  开发者可能错误地在某些请求上设置了 `request.mode = 'no-cors'` 或类似的选项，导致绕过了 Service Worker 的处理逻辑，这可能不是期望的行为。

4. **对嵌套 Worker 的 Service Worker 行为理解不足:**  嵌套 Worker 的 Service Worker 行为可能与预期不同，开发者需要理解 Fetch Context 的克隆机制以及 Service Worker 的继承规则。

5. **CORS 配置错误导致 Service Worker 无法拦截或处理请求:**  如果服务器的 CORS 配置不正确，Service Worker 尝试拦截和修改请求可能会失败。

总而言之，`dedicated_or_shared_worker_fetch_context_impl.cc` 是 Blink 中连接 Worker 和网络请求的关键枢纽，特别是与 Service Worker 的集成部分非常重要，直接影响了 Worker 如何加载资源以及如何利用 Service Worker 提供的能力。理解这个文件的功能对于调试 Worker 和 Service Worker 相关的网络问题至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/dedicated_or_shared_worker_fetch_context_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/dedicated_or_shared_worker_fetch_context_impl.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/ranges/algorithm.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/loader_constants.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_fetch_handler_bypass_option.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_object.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_provider.mojom.h"
#include "third_party/blink/public/platform/child_url_loader_factory_bundle.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_provider_context.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/url_loader_throttle_provider.h"
#include "third_party/blink/public/platform/weak_wrapper_resource_load_info_notifier.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/public/platform/websocket_handshake_throttle_provider.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "url/url_constants.h"

namespace blink {

DedicatedOrSharedWorkerFetchContextImpl::RewriteURLFunction g_rewrite_url =
    nullptr;

namespace {

// Runs on a background thread created in ResetServiceWorkerURLLoaderFactory().
void CreateServiceWorkerSubresourceLoaderFactory(
    CrossVariantMojoRemote<mojom::ServiceWorkerContainerHostInterfaceBase>
        service_worker_container_host,
    const WebString& client_id,
    std::unique_ptr<network::PendingSharedURLLoaderFactory> fallback_factory,
    mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver,
    scoped_refptr<base::SequencedTaskRunner> task_runner) {
  Platform::Current()->CreateServiceWorkerSubresourceLoaderFactory(
      std::move(service_worker_container_host), client_id,
      std::move(fallback_factory), std::move(receiver), std::move(task_runner));
}

}  // namespace

// An implementation of URLLoaderFactory that is aware of service workers. In
// the usual case, it creates a loader that uses |loader_factory_|. But if the
// worker fetch context is controlled by a service worker, it creates a loader
// that uses |service_worker_loader_factory_| for requests that should be
// intercepted by the service worker.
class DedicatedOrSharedWorkerFetchContextImpl::Factory
    : public URLLoaderFactory {
 public:
  Factory(scoped_refptr<network::SharedURLLoaderFactory> loader_factory,
          const Vector<String>& cors_exempt_header_list,
          base::WaitableEvent* terminate_sync_load_event)
      : URLLoaderFactory(std::move(loader_factory),
                         cors_exempt_header_list,
                         terminate_sync_load_event) {}
  Factory(const Factory&) = delete;
  Factory& operator=(const Factory&) = delete;
  ~Factory() override = default;

  std::unique_ptr<URLLoader> CreateURLLoader(
      const network::ResourceRequest& request,
      scoped_refptr<base::SingleThreadTaskRunner> freezable_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
      mojo::PendingRemote<mojom::blink::KeepAliveHandle> keep_alive_handle,
      BackForwardCacheLoaderHelper* back_forward_cache_loader_helper,
      Vector<std::unique_ptr<URLLoaderThrottle>> throttles) override {
    DCHECK(freezable_task_runner);
    DCHECK(unfreezable_task_runner);

    // Create our own URLLoader to route the request to the controller service
    // worker.
    scoped_refptr<network::SharedURLLoaderFactory> loader_factory =
        CanCreateServiceWorkerURLLoader(request)
            ? service_worker_loader_factory_
            : loader_factory_;

    return std::make_unique<URLLoader>(
        cors_exempt_header_list_, terminate_sync_load_event_,
        std::move(freezable_task_runner), std::move(unfreezable_task_runner),
        std::move(loader_factory), std::move(keep_alive_handle),
        back_forward_cache_loader_helper, std::move(throttles));
  }

  void SetServiceWorkerURLLoaderFactory(
      mojo::PendingRemote<network::mojom::URLLoaderFactory>
          service_worker_loader_factory) {
    if (!service_worker_loader_factory) {
      service_worker_loader_factory_ = nullptr;
      return;
    }
    service_worker_loader_factory_ =
        base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
            std::move(service_worker_loader_factory));
  }

  base::WeakPtr<Factory> GetWeakPtr() { return weak_ptr_factory_.GetWeakPtr(); }

 private:
  bool CanCreateServiceWorkerURLLoader(
      const network::ResourceRequest& request) {
    // TODO(horo): Unify this code path with
    // ServiceWorkerNetworkProviderForFrame::CreateURLLoader that is used
    // for document cases.

    // We need the service worker loader factory populated in order to create
    // our own URLLoader for subresource loading via a service worker.
    if (!service_worker_loader_factory_)
      return false;

    // If the URL is not http(s) or otherwise allowed, do not intercept the
    // request. Schemes like 'blob' and 'file' are not eligible to be
    // intercepted by service workers.
    // TODO(falken): Let ServiceWorkerSubresourceLoaderFactory handle the
    // request and move this check there (i.e., for such URLs, it should use
    // its fallback factory).
    if (!request.url.SchemeIsHTTPOrHTTPS() &&
        !Platform::Current()->OriginCanAccessServiceWorkers(request.url)) {
      return false;
    }

    // If `skip_service_worker` is true, no need to intercept the request.
    if (request.skip_service_worker) {
      return false;
    }

    return true;
  }

  scoped_refptr<network::SharedURLLoaderFactory> service_worker_loader_factory_;
  base::WeakPtrFactory<Factory> weak_ptr_factory_{this};
};

DedicatedOrSharedWorkerFetchContextImpl::
    DedicatedOrSharedWorkerFetchContextImpl(
        const RendererPreferences& renderer_preferences,
        mojo::PendingReceiver<mojom::blink::RendererPreferenceWatcher>
            preference_watcher_receiver,
        mojo::PendingReceiver<mojom::blink::ServiceWorkerWorkerClient>
            service_worker_client_receiver,
        mojo::PendingRemote<mojom::blink::ServiceWorkerWorkerClientRegistry>
            pending_service_worker_worker_client_registry,
        CrossVariantMojoRemote<mojom::ServiceWorkerContainerHostInterfaceBase>
            service_worker_container_host,
        std::unique_ptr<network::PendingSharedURLLoaderFactory>
            pending_loader_factory,
        std::unique_ptr<network::PendingSharedURLLoaderFactory>
            pending_fallback_factory,
        mojo::PendingReceiver<mojom::blink::SubresourceLoaderUpdater>
            pending_subresource_loader_updater,
        std::unique_ptr<URLLoaderThrottleProvider> throttle_provider,
        std::unique_ptr<WebSocketHandshakeThrottleProvider>
            websocket_handshake_throttle_provider,
        Vector<String> cors_exempt_header_list,
        mojo::PendingRemote<mojom::ResourceLoadInfoNotifier>
            pending_resource_load_info_notifier)
    : service_worker_client_receiver_(
          std::move(service_worker_client_receiver)),
      pending_service_worker_worker_client_registry_(
          std::move(pending_service_worker_worker_client_registry)),
      pending_loader_factory_(std::move(pending_loader_factory)),
      pending_fallback_factory_(std::move(pending_fallback_factory)),
      service_worker_container_host_(std::move(service_worker_container_host)),
      pending_subresource_loader_updater_(
          std::move(pending_subresource_loader_updater)),
      renderer_preferences_(renderer_preferences),
      preference_watcher_pending_receiver_(
          std::move(preference_watcher_receiver)),
      throttle_provider_(std::move(throttle_provider)),
      websocket_handshake_throttle_provider_(
          std::move(websocket_handshake_throttle_provider)),
      cors_exempt_header_list_(std::move(cors_exempt_header_list)),
      pending_resource_load_info_notifier_(
          std::move(pending_resource_load_info_notifier)) {}

scoped_refptr<WebDedicatedOrSharedWorkerFetchContext>
DedicatedOrSharedWorkerFetchContextImpl::CloneForNestedWorkerDeprecated(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK(!base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));

  mojo::PendingReceiver<mojom::blink::ServiceWorkerWorkerClient>
      service_worker_client_receiver;
  mojo::PendingRemote<mojom::blink::ServiceWorkerWorkerClientRegistry>
      service_worker_worker_client_registry;
  if (service_worker_worker_client_registry_) {
    mojo::PendingRemote<mojom::blink::ServiceWorkerWorkerClient>
        service_worker_client;
    service_worker_client_receiver =
        service_worker_client.InitWithNewPipeAndPassReceiver();
    service_worker_worker_client_registry_->RegisterWorkerClient(
        std::move(service_worker_client));
    service_worker_worker_client_registry_->CloneWorkerClientRegistry(
        service_worker_worker_client_registry.InitWithNewPipeAndPassReceiver());
  }

  CrossVariantMojoRemote<mojom::ServiceWorkerContainerHostInterfaceBase>
      cloned_service_worker_container_host;
  if (service_worker_container_host_) {
    std::tie(service_worker_container_host_,
             cloned_service_worker_container_host) =
        Platform::Current()->CloneServiceWorkerContainerHost(
            std::move(service_worker_container_host_));
  }

  // |pending_subresource_loader_updater| is not used for
  // non-PlzDedicatedWorker.
  scoped_refptr<DedicatedOrSharedWorkerFetchContextImpl> new_context =
      CloneForNestedWorkerInternal(
          std::move(service_worker_client_receiver),
          std::move(service_worker_worker_client_registry),
          std::move(cloned_service_worker_container_host),
          loader_factory_->Clone(), fallback_factory_->Clone(),
          /*pending_subresource_loader_updater=*/mojo::NullReceiver(),
          std::move(task_runner));
  new_context->controller_service_worker_mode_ =
      controller_service_worker_mode_;

  return new_context;
}

scoped_refptr<WebDedicatedOrSharedWorkerFetchContext>
DedicatedOrSharedWorkerFetchContextImpl::CloneForNestedWorker(
    WebServiceWorkerProviderContext* service_worker_provider_context,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_loader_factory,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_fallback_factory,
    CrossVariantMojoReceiver<mojom::SubresourceLoaderUpdaterInterfaceBase>
        pending_subresource_loader_updater,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK(base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
  DCHECK(pending_loader_factory);
  DCHECK(pending_fallback_factory);
  DCHECK(task_runner);

  if (!service_worker_provider_context) {
    return CloneForNestedWorkerInternal(
        /*service_worker_client_receiver=*/mojo::NullReceiver(),
        /*service_worker_worker_client_registry=*/mojo::NullRemote(),
        /*container_host=*/
        CrossVariantMojoRemote<
            mojom::ServiceWorkerContainerHostInterfaceBase>(),
        std::move(pending_loader_factory), std::move(pending_fallback_factory),
        std::move(pending_subresource_loader_updater), std::move(task_runner));
  }

  mojo::PendingRemote<mojom::blink::ServiceWorkerWorkerClientRegistry>
      service_worker_worker_client_registry;
  service_worker_provider_context
      ->BindServiceWorkerWorkerClientRegistryReceiver(
          service_worker_worker_client_registry
              .InitWithNewPipeAndPassReceiver());

  mojo::PendingRemote<mojom::blink::ServiceWorkerWorkerClient> worker_client;
  mojo::PendingReceiver<mojom::blink::ServiceWorkerWorkerClient>
      service_worker_client_receiver =
          worker_client.InitWithNewPipeAndPassReceiver();
  service_worker_provider_context->BindServiceWorkerWorkerClientRemote(
      std::move(worker_client));

  CrossVariantMojoRemote<mojom::ServiceWorkerContainerHostInterfaceBase>
      service_worker_container_host =
          service_worker_provider_context->CloneRemoteContainerHost();

  scoped_refptr<DedicatedOrSharedWorkerFetchContextImpl> new_context =
      CloneForNestedWorkerInternal(
          std::move(service_worker_client_receiver),
          std::move(service_worker_worker_client_registry),
          std::move(service_worker_container_host),
          std::move(pending_loader_factory),
          std::move(pending_fallback_factory),
          std::move(pending_subresource_loader_updater),
          std::move(task_runner));
  new_context->controller_service_worker_mode_ =
      service_worker_provider_context->GetControllerServiceWorkerMode();

  return new_context;
}

void DedicatedOrSharedWorkerFetchContextImpl::SetAncestorFrameToken(
    const LocalFrameToken& token) {
  ancestor_frame_token_ = token;
}

void DedicatedOrSharedWorkerFetchContextImpl::set_site_for_cookies(
    const net::SiteForCookies& site_for_cookies) {
  site_for_cookies_ = site_for_cookies;
}

void DedicatedOrSharedWorkerFetchContextImpl::set_top_frame_origin(
    const WebSecurityOrigin& top_frame_origin) {
  top_frame_origin_ = top_frame_origin;
}

void DedicatedOrSharedWorkerFetchContextImpl::SetTerminateSyncLoadEvent(
    base::WaitableEvent* terminate_sync_load_event) {
  DCHECK(!terminate_sync_load_event_);
  terminate_sync_load_event_ = terminate_sync_load_event;
}

void DedicatedOrSharedWorkerFetchContextImpl::InitializeOnWorkerThread(
    AcceptLanguagesWatcher* watcher) {
  DCHECK(!receiver_.is_bound());
  DCHECK(!preference_watcher_receiver_.is_bound());

  loader_factory_ = network::SharedURLLoaderFactory::Create(
      std::move(pending_loader_factory_));
  fallback_factory_ = network::SharedURLLoaderFactory::Create(
      std::move(pending_fallback_factory_));
  subresource_loader_updater_.Bind(
      std::move(pending_subresource_loader_updater_));

  if (service_worker_client_receiver_.is_valid())
    receiver_.Bind(std::move(service_worker_client_receiver_));

  if (pending_service_worker_worker_client_registry_) {
    service_worker_worker_client_registry_.Bind(
        std::move(pending_service_worker_worker_client_registry_));
  }

  if (preference_watcher_pending_receiver_.is_valid()) {
    preference_watcher_receiver_.Bind(
        std::move(preference_watcher_pending_receiver_));
  }

  if (pending_resource_load_info_notifier_) {
    resource_load_info_notifier_.Bind(
        std::move(pending_resource_load_info_notifier_));
    resource_load_info_notifier_.set_disconnect_handler(
        base::BindOnce(&DedicatedOrSharedWorkerFetchContextImpl::
                           ResetWeakWrapperResourceLoadInfoNotifier,
                       base::Unretained(this)));
  }

  accept_languages_watcher_ = watcher;

  DCHECK(loader_factory_);
  DCHECK(!web_loader_factory_);
  web_loader_factory_ = std::make_unique<Factory>(
      loader_factory_, cors_exempt_header_list_, terminate_sync_load_event_);

  ResetServiceWorkerURLLoaderFactory();
}

URLLoaderFactory*
DedicatedOrSharedWorkerFetchContextImpl::GetURLLoaderFactory() {
  return web_loader_factory_.get();
}

std::unique_ptr<URLLoaderFactory>
DedicatedOrSharedWorkerFetchContextImpl::WrapURLLoaderFactory(
    CrossVariantMojoRemote<network::mojom::URLLoaderFactoryInterfaceBase>
        url_loader_factory) {
  return std::make_unique<URLLoaderFactory>(
      base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
          std::move(url_loader_factory)),
      cors_exempt_header_list_, terminate_sync_load_event_);
}

std::optional<WebURL> DedicatedOrSharedWorkerFetchContextImpl::WillSendRequest(
    const WebURL& url) {
  if (g_rewrite_url) {
    return g_rewrite_url(url.GetString().Utf8(), false);
  }
  return std::nullopt;
}

void DedicatedOrSharedWorkerFetchContextImpl::FinalizeRequest(
    WebURLRequest& request) {
  if (renderer_preferences_.enable_do_not_track) {
    request.SetHttpHeaderField(WebString::FromUTF8(kDoNotTrackHeader), "1");
  }

  auto url_request_extra_data = base::MakeRefCounted<WebURLRequestExtraData>();
  request.SetURLRequestExtraData(std::move(url_request_extra_data));

  if (!renderer_preferences_.enable_referrers) {
    request.SetReferrerString(WebString());
    request.SetReferrerPolicy(network::mojom::ReferrerPolicy::kNever);
  }
}

WebVector<std::unique_ptr<URLLoaderThrottle>>
DedicatedOrSharedWorkerFetchContextImpl::CreateThrottles(
    const network::ResourceRequest& request) {
  if (throttle_provider_) {
    return throttle_provider_->CreateThrottles(ancestor_frame_token_, request);
  }
  return {};
}

mojom::ControllerServiceWorkerMode
DedicatedOrSharedWorkerFetchContextImpl::GetControllerServiceWorkerMode()
    const {
  return controller_service_worker_mode_;
}

void DedicatedOrSharedWorkerFetchContextImpl::SetIsOnSubframe(
    bool is_on_sub_frame) {
  is_on_sub_frame_ = is_on_sub_frame;
}

bool DedicatedOrSharedWorkerFetchContextImpl::IsOnSubframe() const {
  return is_on_sub_frame_;
}

net::SiteForCookies DedicatedOrSharedWorkerFetchContextImpl::SiteForCookies()
    const {
  return site_for_cookies_;
}

std::optional<WebSecurityOrigin>
DedicatedOrSharedWorkerFetchContextImpl::TopFrameOrigin() const {
  // TODO(jkarlin): set_top_frame_origin is only called for dedicated workers.
  // Determine the top-frame-origin of a shared worker as well. See
  // https://crbug.com/918868.
  return top_frame_origin_;
}

void DedicatedOrSharedWorkerFetchContextImpl::SetSubresourceFilterBuilder(
    std::unique_ptr<WebDocumentSubresourceFilter::Builder>
        subresource_filter_builder) {
  subresource_filter_builder_ = std::move(subresource_filter_builder);
}

std::unique_ptr<WebDocumentSubresourceFilter>
DedicatedOrSharedWorkerFetchContextImpl::TakeSubresourceFilter() {
  if (!subresource_filter_builder_)
    return nullptr;
  return std::move(subresource_filter_builder_)->Build();
}

std::unique_ptr<WebSocketHandshakeThrottle>
DedicatedOrSharedWorkerFetchContextImpl::CreateWebSocketHandshakeThrottle(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  if (!websocket_handshake_throttle_provider_)
    return nullptr;
  return websocket_handshake_throttle_provider_->CreateThrottle(
      ancestor_frame_token_, std::move(task_runner));
}

void DedicatedOrSharedWorkerFetchContextImpl::SetIsOfflineMode(
    bool is_offline_mode) {
  // Worker doesn't support offline mode. There should be no callers.
  NOTREACHED();
}

void DedicatedOrSharedWorkerFetchContextImpl::OnControllerChanged(
    mojom::ControllerServiceWorkerMode mode) {
  set_controller_service_worker_mode(mode);
  ResetServiceWorkerURLLoaderFactory();
}

void DedicatedOrSharedWorkerFetchContextImpl::
    set_controller_service_worker_mode(
        mojom::ControllerServiceWorkerMode mode) {
  controller_service_worker_mode_ = mode;
}

void DedicatedOrSharedWorkerFetchContextImpl::set_client_id(
    const WebString& client_id) {
  client_id_ = client_id;
}

WebString DedicatedOrSharedWorkerFetchContextImpl::GetAcceptLanguages() const {
  return WebString::FromUTF8(renderer_preferences_.accept_languages);
}

std::unique_ptr<ResourceLoadInfoNotifierWrapper>
DedicatedOrSharedWorkerFetchContextImpl::
    CreateResourceLoadInfoNotifierWrapper() {
  // If |resource_load_info_notifier_| is unbound, we will create
  // ResourceLoadInfoNotifierWrapper without wrapping a ResourceLoadInfoNotifier
  // and only collect histograms.
  if (!resource_load_info_notifier_) {
    return std::make_unique<ResourceLoadInfoNotifierWrapper>(
        /*resource_load_info_notifier=*/nullptr);
  }

  if (!weak_wrapper_resource_load_info_notifier_) {
    weak_wrapper_resource_load_info_notifier_ =
        std::make_unique<WeakWrapperResourceLoadInfoNotifier>(
            resource_load_info_notifier_.get());
  }
  return std::make_unique<ResourceLoadInfoNotifierWrapper>(
      weak_wrapper_resource_load_info_notifier_->AsWeakPtr());
}

DedicatedOrSharedWorkerFetchContextImpl::
    ~DedicatedOrSharedWorkerFetchContextImpl() = default;

scoped_refptr<DedicatedOrSharedWorkerFetchContextImpl>
DedicatedOrSharedWorkerFetchContextImpl::CloneForNestedWorkerInternal(
    mojo::PendingReceiver<mojom::blink::ServiceWorkerWorkerClient>
        service_worker_client_receiver,
    mojo::PendingRemote<mojom::blink::ServiceWorkerWorkerClientRegistry>
        service_worker_worker_client_registry,
    CrossVariantMojoRemote<mojom::ServiceWorkerContainerHostInterfaceBase>
        service_worker_container_host,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_loader_factory,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_fallback_factory,
    mojo::PendingReceiver<mojom::blink::SubresourceLoaderUpdater>
        pending_subresource_loader_updater,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  mojo::PendingRemote<mojom::ResourceLoadInfoNotifier>
      pending_resource_load_info_notifier;
  if (resource_load_info_notifier_) {
    resource_load_info_notifier_->Clone(
        pending_resource_load_info_notifier.InitWithNewPipeAndPassReceiver());
  }

  mojo::PendingRemote<mojom::blink::RendererPreferenceWatcher>
      preference_watcher;
  auto new_context = base::AdoptRef(new DedicatedOrSharedWorkerFetchContextImpl(
      renderer_preferences_,
      preference_watcher.InitWithNewPipeAndPassReceiver(),
      std::move(service_worker_client_receiver),
      std::move(service_worker_worker_client_registry),
      std::move(service_worker_container_host),
      std::move(pending_loader_factory), std::move(pending_fallback_factory),
      std::move(pending_subresource_loader_updater),
      throttle_provider_ ? throttle_provider_->Clone() : nullptr,
      websocket_handshake_throttle_provider_
          ? websocket_handshake_throttle_provider_->Clone(
                std::move(task_runner))
          : nullptr,
      cors_exempt_header_list_,
      std::move(pending_resource_load_info_notifier)));
  new_context->is_on_sub_frame_ = is_on_sub_frame_;
  new_context->ancestor_frame_token_ = ancestor_frame_token_;
  new_context->site_for_cookies_ = site_for_cookies_;
  new_context->top_frame_origin_ = top_frame_origin_;
  child_preference_watchers_.Add(std::move(preference_watcher));
  return new_context;
}

void DedicatedOrSharedWorkerFetchContextImpl::
    ResetServiceWorkerURLLoaderFactory() {
  if (!web_loader_factory_)
    return;
  if (GetControllerServiceWorkerMode() !=
      mojom::ControllerServiceWorkerMode::kControlled) {
    web_loader_factory_->SetServiceWorkerURLLoaderFactory(mojo::NullRemote());
    return;
  }
  if (!service_worker_container_host_)
    return;

  mojo::PendingRemote<network::mojom::URLLoaderFactory>
      service_worker_url_loader_factory;
  CrossVariantMojoRemote<mojom::ServiceWorkerContainerHostInterfaceBase>
      cloned_service_worker_container_host;
  std::tie(service_worker_container_host_,
           cloned_service_worker_container_host) =
      Platform::Current()->CloneServiceWorkerContainerHost(
          std::move(service_worker_container_host_));

  // To avoid potential dead-lock while synchronous loading, create the
  // SubresourceLoaderFactory on a background thread.
  auto task_runner = base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN});
  task_runner->PostTask(
      FROM_HERE,
      base::BindOnce(
          &CreateServiceWorkerSubresourceLoaderFactory,
          std::move(cloned_service_worker_container_host), client_id_,
          fallback_factory_->Clone(),
          service_worker_url_loader_factory.InitWithNewPipeAndPassReceiver(),
          task_runner));
  web_loader_factory_->SetServiceWorkerURLLoaderFactory(
      std::move(service_worker_url_loader_factory));
}

void DedicatedOrSharedWorkerFetchContextImpl::UpdateSubresourceLoaderFactories(
    std::unique_ptr<PendingURLLoaderFactoryBundle>
        subresource_loader_factories) {
  auto subresource_loader_factory_bundle =
      base::MakeRefCounted<ChildURLLoaderFactoryBundle>(
          std::make_unique<ChildPendingURLLoaderFactoryBundle>(
              std::move(subresource_loader_factories)));
  loader_factory_ = network::SharedURLLoaderFactory::Create(
      subresource_loader_factory_bundle->Clone());
  fallback_factory_ = network::SharedURLLoaderFactory::Create(
      subresource_loader_factory_bundle->Clone());
  web_loader_factory_ = std::make_unique<Factory>(
      loader_factory_, cors_exempt_header_list_, terminate_sync_load_event_);
  ResetServiceWorkerURLLoaderFactory();
}

void DedicatedOrSharedWorkerFetchContextImpl::NotifyUpdate(
    const RendererPreferences& new_prefs) {
  if (accept_languages_watcher_ &&
      renderer_preferences_.accept_languages != new_prefs.accept_languages)
    accept_languages_watcher_->NotifyUpdate();
  renderer_preferences_ = new_prefs;
  for (auto& watcher : child_preference_watchers_)
    watcher->NotifyUpdate(new_prefs);
}

void DedicatedOrSharedWorkerFetchContextImpl::
    ResetWeakWrapperResourceLoadInfoNotifier() {
  weak_wrapper_resource_load_info_notifier_.reset();
}

// static
scoped_refptr<WebDedicatedOrSharedWorkerFetchContext>
WebDedicatedOrSharedWorkerFetchContext::Create(
    WebServiceWorkerProviderContext* provider_context,
    const RendererPreferences& renderer_preferences,
    CrossVariantMojoReceiver<mojom::RendererPreferenceWatcherInterfaceBase>
        watcher_receiver,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_loader_factory,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_fallback_factory,
    CrossVariantMojoReceiver<mojom::SubresourceLoaderUpdaterInterfaceBase>
        pending_subresource_loader_updater,
    const WebVector<WebString>& web_cors_exempt_header_list,
    mojo::PendingRemote<mojom::ResourceLoadInfoNotifier>
        pending_resource_load_info_notifier) {
  mojo::PendingReceiver<mojom::blink::ServiceWorkerWorkerClient>
      service_worker_client_receiver;
  mojo::PendingRemote<mojom::blink::ServiceWorkerWorkerClientRegistry>
      service_worker_worker_client_registry;
  CrossVariantMojoRemote<mojom::ServiceWorkerContainerHostInterfaceBase>
      service_worker_container_host;
  // Some sandboxed iframes are not allowed to use service worker so don't have
  // a real service worker provider, so the provider context is null.
  if (provider_context) {
    provider_context->BindServiceWorkerWorkerClientRegistryReceiver(
        service_worker_worker_client_registry.InitWithNewPipeAndPassReceiver());

    mojo::PendingRemote<mojom::blink::ServiceWorkerWorkerClient> worker_client;
    service_worker_client_receiver =
        worker_client.InitWithNewPipeAndPassReceiver();
    provider_context->BindServiceWorkerWorkerClientRemote(
        std::move(worker_client));

    service_worker_container_host =
        provider_context->CloneRemoteContainerHost();
  }

  Vector<String> cors_exempt_header_list(
      base::checked_cast<wtf_size_t>(web_cors_exempt_header_list.size()));
  base::ranges::transform(web_cors_exempt_header_list,
                          cors_exempt_header_list.begin(),
                          &WebString::operator WTF::String);

  scoped_refptr<DedicatedOrSharedWorkerFetchContextImpl> worker_fetch_context =
      base::AdoptRef(new DedicatedOrSharedWorkerFetchContextImpl(
          renderer_preferences, std::move(watcher_receiver),
          std::move(service_worker_client_receiver),
          std::move(service_worker_worker_client_registry),
          std::move(service_worker_container_host),
          std::move(pending_loader_factory),
          std::move(pending_fallback_factory),
          std::move(pending_subresource_loader_updater),
          Platform::Current()->CreateURLLoaderThrottleProviderForWorker(
              URLLoaderThrottleProviderType::kWorker),
          Platform::Current()->CreateWebSocketHandshakeThrottleProvider(),
          std::move(cors_exempt_header_list),
          std::move(pending_resource_load_info_notifier)));
  if (provider_context) {
    worker_fetch_context->set_controller_service_worker_mode(
        provider_context->GetControllerServiceWorkerMode());
    worker_fetch_context->set_client_id(provider_context->client_id());
  } else {
    worker_fetch_context->set_controller_service_worker_mode(
        mojom::ControllerServiceWorkerMode::kNoController);
  }
  return worker_fetch_context;
}

// static
void WebDedicatedOrSharedWorkerFetchContext::InstallRewriteURLFunction(
    RewriteURLFunction rewrite_url) {
  CHECK(!g_rewrite_url);
  g_rewrite_url = rewrite_url;
}

}  // namespace blink

"""

```