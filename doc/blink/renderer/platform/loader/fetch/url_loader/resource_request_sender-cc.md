Response:
Let's break down the thought process for analyzing the `ResourceRequestSender.cc` file.

**1. Initial Understanding of the File's Purpose:**

* **File Path:** `blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.cc`. The key terms are "loader," "fetch," "url_loader," and "resource_request_sender." This immediately suggests the file is responsible for *sending* resource requests using the `URLLoader` mechanism in Blink.

* **Copyright and Includes:** The copyright notice confirms it's a Chromium/Blink file. The `#include` directives give a broad overview of the dependencies. We see things related to:
    * **Base Library:** `base/` (threading, memory management, logging, metrics)
    * **Networking:** `net/`, `services/network/` (handling HTTP requests, errors, URLs)
    * **Blink Specific:** `third_party/blink/public/` and `third_party/blink/renderer/platform/` (core Blink types, loader infrastructure)
    * **Mojo:** `mojo/` (inter-process communication)

**2. Core Functionality Identification - The "What":**

* **`SendSync()`:** The name screams "synchronous request." The parameters confirm this: `SyncLoadResponse`, `base::WaitableEvent`. This function must handle sending a request and blocking until the response is received. The presence of redirects within the synchronous context is interesting.

* **`SendAsync()`:**  The counterpart to `SendSync()`, clearly handling asynchronous requests. It takes a `ResourceRequestClient` to handle callbacks, and involves `URLLoaderThrottle`s and `CodeCacheHost`.

* **`Cancel()`:**  A fundamental operation - stopping an ongoing request.

* **`Freeze()`:**  A less common but important function, likely related to debugging or specific loading scenarios where pausing a request is needed.

* **`DidChangePriority()`:**  Modifying the priority of a pending request.

* **Internal Helpers/Data Structures:** The `PendingRequestInfo` struct is crucial. It holds the state of an individual request. The helper functions like `CheckSchemeForReferrerPolicy` and `RedirectRequiresLoaderRestart` provide insights into request processing logic.

**3. Connecting to Web Technologies - The "Why" and "How":**

* **JavaScript, HTML, CSS are *Resources*:**  The core function is fetching resources. JavaScript files, HTML documents, CSS stylesheets, images, fonts, etc., are all resources loaded by the browser. Therefore, this code is *directly* involved in making the web work.

* **Examples:** To illustrate the connection:
    * **JavaScript:** `SendAsync()` is used when a `<script>` tag is encountered or when `fetch()` is called.
    * **HTML:**  Loading the initial HTML document for a page uses this. Resources referenced within the HTML (images, scripts, stylesheets) also use this.
    * **CSS:**  Loading CSS files linked via `<link>` or embedded within `<style>` tags.

* **Specific Interactions:**
    * **Referrer Policy:**  `CheckSchemeForReferrerPolicy` shows a direct tie-in to a web standard that controls how referrer information is sent.
    * **CORS:** The `cors_exempt_header_list` parameter in `SendAsync()` indicates involvement in Cross-Origin Resource Sharing.
    * **Caching:** The `CodeCacheHost` and `CodeCacheFetcher` point to optimizations for caching compiled code (like JavaScript).
    * **Redirects:** How redirects are handled is a fundamental part of HTTP and web navigation.

**4. Logic and Assumptions - The "If/Then":**

* **Synchronous Logic:**  The `while (context_for_redirect)` loop in `SendSync()` demonstrates the logic for handling redirects in a synchronous manner. The `WaitableEvent` is the key mechanism for blocking. *Hypothetical Input/Output:* If a request results in a 302 redirect, the loop will iterate, processing the redirect information and potentially sending a new request.

* **Asynchronous Logic:**  The callbacks (`OnReceivedResponse`, `OnReceivedRedirect`, `OnRequestComplete`) are central to the asynchronous nature of `SendAsync()`. The `pending_tasks_` queue indicates deferred execution.

**5. Common Errors - The "Watch Out":**

* **Incorrect `referrer_policy`:** The check in `CheckSchemeForReferrerPolicy` highlights a potential developer error that could lead to information leakage.
* **Synchronous requests on the main thread:**  The documentation for synchronous XHR is important to recall. Blocking the main thread leads to a frozen UI.
* **CORS configuration:** Incorrectly configured CORS headers on the server can lead to requests failing, and understanding how Blink handles these requests is relevant.

**Self-Correction/Refinement During Analysis:**

* **Initial Focus:** Might initially focus solely on the request sending part.
* **Correction:** Realize the importance of redirect handling, caching, and error handling within the file.
* **Further Refinement:**  Understand the significance of the `PendingRequestInfo` struct as the central state manager for each request. Recognize the threading implications of `SendSync()` and the use of `PostCrossThreadTask`.

By following this breakdown, starting with the high-level purpose and gradually digging into the details, including code snippets, connecting to web technologies, inferring logic, and considering potential errors, we can arrive at a comprehensive understanding of the `ResourceRequestSender.cc` file.
这个文件 `resource_request_sender.cc` 在 Chromium 的 Blink 渲染引擎中，负责**发起和管理资源请求**。 它是连接 Blink 的资源加载机制和 Chromium 的网络栈的关键组件。

以下是它的主要功能：

**1. 发起资源请求:**

* **`SendSync()`:**  用于**同步**地发送资源请求。这意味着调用线程会阻塞，直到请求完成（包括重定向）。这通常用于某些特定的内部场景，**不推荐在主线程上使用，因为它会冻结用户界面**。
* **`SendAsync()`:** 用于**异步**地发送资源请求。这是最常用的方式。请求会在后台发送，并通过回调通知请求状态和数据。

**2. 管理资源请求的生命周期:**

* 创建和配置 `network::ResourceRequest` 对象，包含请求的 URL、方法（GET、POST 等）、头部信息、凭据等。
* 使用 Chromium 的 `ThrottlingURLLoader` 来执行网络请求。`ThrottlingURLLoader` 提供了请求节流、优先级管理等功能。
* 管理请求的状态，例如是否已完成、是否发生错误。
* 处理重定向：当服务器返回重定向响应时，`ResourceRequestSender` 会根据情况选择继续请求（跟随重定向）或取消请求。

**3. 与网络栈交互:**

* 使用 `network::SharedURLLoaderFactory` 创建 `ThrottlingURLLoader`。`SharedURLLoaderFactory` 是 Chromium 网络服务的抽象工厂。
* 处理来自网络栈的响应，包括响应头、响应体以及错误信息。
* 将网络栈的信息转换成 Blink 需要的格式，并通过 `ResourceRequestClient` 回调通知 Blink。

**4. 整合其他 Blink 组件:**

* **`URLLoaderThrottle`:**  在发送请求前和接收响应后，允许插入自定义逻辑来修改请求或响应。例如，添加或修改头部、取消请求等。
* **`CodeCacheHost` 和 `CodeCacheFetcher`:**  用于优化代码资源的加载，例如 JavaScript 和 WASM。它可以尝试从缓存中获取代码，或者在网络请求完成后缓存代码。
* **`ResourceRequestClient`:**  这是一个接口，由请求的发起者（例如文档加载器、Worker）实现。`ResourceRequestSender` 使用这个接口来通知请求的各个阶段，例如收到响应、重定向、完成等。
* **`ResourceLoadInfoNotifierWrapper`:** 用于通知有关资源加载的信息，用于性能监控和开发者工具。

**5. 优先级管理:**

* 允许设置请求的优先级 (`net::RequestPriority`)，以便 Chromium 的网络栈可以根据优先级调度请求。

**6. 请求取消:**

* 提供 `Cancel()` 方法来取消正在进行的请求。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ResourceRequestSender` 是 Blink 加载各种 Web 资源的核心组件，因此与 JavaScript、HTML 和 CSS 的功能息息相关。

* **JavaScript:**
    * 当浏览器遇到 `<script src="...">` 标签时，或者 JavaScript 代码中调用了 `fetch()` 或 `XMLHttpRequest` 等 API 发起网络请求时，Blink 会使用 `ResourceRequestSender` 来加载 JavaScript 文件。
    * **假设输入:**  HTML 中包含 `<script src="script.js"></script>`。
    * **输出:** `ResourceRequestSender` 会创建一个 `network::ResourceRequest` 对象，其 URL 指向 `script.js`，然后调用 `SendAsync()` 发起请求。网络请求完成后，接收到的 JavaScript 代码会传递给 JavaScript 引擎执行。

* **HTML:**
    * 当用户在浏览器中输入 URL 或点击链接时，Blink 会使用 `ResourceRequestSender` 来加载 HTML 文档。
    * **假设输入:** 用户访问 `https://example.com/index.html`。
    * **输出:** `ResourceRequestSender` 会创建一个针对 `https://example.com/index.html` 的 `network::ResourceRequest` 对象，并调用 `SendAsync()` 发起请求。接收到的 HTML 内容会被解析并构建 DOM 树。

* **CSS:**
    * 当浏览器遇到 `<link rel="stylesheet" href="...">` 标签时，或者在 HTML 中嵌入 `<style>` 标签并引用外部 CSS 文件时（例如 `@import url("style.css");`），Blink 会使用 `ResourceRequestSender` 来加载 CSS 文件。
    * **假设输入:** HTML 中包含 `<link rel="stylesheet" href="style.css">`。
    * **输出:** `ResourceRequestSender` 会创建一个针对 `style.css` 的 `network::ResourceRequest` 对象，并调用 `SendAsync()` 发起请求。接收到的 CSS 代码会被解析并构建 CSSOM 树，用于渲染页面的样式。

**逻辑推理的假设输入与输出:**

* **假设输入 (异步请求重定向):**
    1. JavaScript 代码执行 `fetch("https://redirect-server.com/page")`。
    2. `redirect-server.com/page` 返回 HTTP 302 重定向到 `https://final-server.com/content.html`。
* **输出:**
    1. `ResourceRequestSender` 首先向 `https://redirect-server.com/page` 发起请求。
    2. `OnReceivedRedirect()` 回调会被调用，处理重定向信息。
    3. `ResourceRequestSender` 会创建一个新的请求，目标是 `https://final-server.com/content.html`。
    4. `SendAsync()` 再次被调用，发起对最终 URL 的请求。
    5. 最终，`OnReceivedResponse()` 回调会被调用，携带 `https://final-server.com/content.html` 的内容。

**涉及用户或编程常见的使用错误及举例说明:**

* **在主线程上使用 `SendSync()`:** 这会导致浏览器 UI 冻结，用户无法操作，直到同步请求完成。
    * **错误示例 (不应该在主线程上执行):**
      ```javascript
      // 这会在主线程上同步阻塞，导致页面卡顿
      let xhr = new XMLHttpRequest();
      xhr.open('GET', 'https://example.com/data', false); // 第三个参数 false 表示同步
      xhr.send();
      ```
    * **正确做法:** 使用异步请求：
      ```javascript
      fetch('https://example.com/data')
        .then(response => response.json())
        .then(data => {
          // 处理数据
        });
      ```

* **CORS (跨域资源共享) 配置错误:** 如果服务器没有正确配置 CORS 头部，浏览器会阻止跨域请求，`ResourceRequestSender` 会收到错误信息。
    * **错误示例:**  一个运行在 `https://example.com` 的页面尝试请求 `https://api.otherdomain.com/data`，但 `api.otherdomain.com` 的响应头中没有包含允许 `https://example.com` 访问的 `Access-Control-Allow-Origin` 头部。
    * **结果:**  `ResourceRequestSender` 会收到一个 CORS 错误，并且 JavaScript 的 `fetch()` 或 `XMLHttpRequest` 会抛出异常。开发者需要在服务器端配置正确的 CORS 头部来解决这个问题。

* **不正确的 Referrer Policy 配置:**  开发者可能错误地配置了 Referrer Policy，导致在某些情况下发送了不期望的 Referrer 信息，或者阻止了必要的 Referrer 信息的发送。 `ResourceRequestSender` 中的 `CheckSchemeForReferrerPolicy` 函数就用于检查是否存在潜在的 Referrer Policy 错误。

总而言之，`resource_request_sender.cc` 是 Blink 引擎中一个至关重要的文件，它负责实际的网络资源请求的发送和管理，直接影响着网页的加载和渲染过程，并与 JavaScript、HTML 和 CSS 的加载紧密相关。 开发者在使用 Web 技术时，很多行为最终都会通过这个组件与底层的网络交互。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.h"

#include <utility>

#include "base/compiler_specific.h"
#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/referrer_policy.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/cpp/url_util.h"
#include "services/network/public/mojom/fetch_api.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/client_hints/client_hints.h"
#include "third_party/blink/public/common/loader/inter_process_time_ticks_converter.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/common/loader/resource_type_util.h"
#include "third_party/blink/public/common/loader/throttling_url_loader.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/resource_load_info.mojom-shared.h"
#include "third_party/blink/public/mojom/navigation/renderer_eviction_reason.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_request_util.h"
#include "third_party/blink/renderer/platform/loader/fetch/code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/code_cache_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/mojo_url_loader_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/sync_load_context.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/sync_load_response.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/ref_counted.h"

namespace WTF {

template <>
struct CrossThreadCopier<
    blink::WebVector<std::unique_ptr<blink::URLLoaderThrottle>>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = blink::WebVector<std::unique_ptr<blink::URLLoaderThrottle>>;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<net::NetworkTrafficAnnotationTag>
    : public CrossThreadCopierPassThrough<net::NetworkTrafficAnnotationTag> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = net::NetworkTrafficAnnotationTag;
  static const Type& Copy(const Type& traffic_annotation) {
    return traffic_annotation;
  }
};

template <>
struct CrossThreadCopier<blink::WebVector<blink::WebString>>
    : public CrossThreadCopierPassThrough<blink::WebVector<blink::WebString>> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

#if BUILDFLAG(IS_WIN)
// Converts |time| from a remote to local TimeTicks, overwriting the original
// value.
void RemoteToLocalTimeTicks(const InterProcessTimeTicksConverter& converter,
                            base::TimeTicks* time) {
  RemoteTimeTicks remote_time = RemoteTimeTicks::FromTimeTicks(*time);
  *time = converter.ToLocalTimeTicks(remote_time).ToTimeTicks();
}
#endif

void CheckSchemeForReferrerPolicy(const network::ResourceRequest& request) {
  if ((request.referrer_policy ==
           ReferrerUtils::GetDefaultNetReferrerPolicy() ||
       request.referrer_policy ==
           net::ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE) &&
      request.referrer.SchemeIsCryptographic() &&
      !url::Origin::Create(request.url).opaque() &&
      !network::IsUrlPotentiallyTrustworthy(request.url)) {
    LOG(FATAL) << "Trying to send secure referrer for insecure request "
               << "without an appropriate referrer policy.\n"
               << "URL = " << request.url << "\n"
               << "URL's Origin = "
               << url::Origin::Create(request.url).Serialize() << "\n"
               << "Referrer = " << request.referrer;
  }
}

// Determines if the loader should be restarted on a redirect using
// ThrottlingURLLoader::FollowRedirectForcingRestart.
bool RedirectRequiresLoaderRestart(const GURL& original_url,
                                   const GURL& redirect_url) {
  // Restart is needed if the URL is no longer handled by network service.
  if (network::IsURLHandledByNetworkService(original_url)) {
    return !network::IsURLHandledByNetworkService(redirect_url);
  }

  // If URL wasn't originally handled by network service, restart is needed if
  // schemes are different.
  return original_url.scheme_piece() != redirect_url.scheme_piece();
}

}  // namespace

ResourceRequestSender::ResourceRequestSender() = default;

ResourceRequestSender::~ResourceRequestSender() = default;

void ResourceRequestSender::SendSync(
    std::unique_ptr<network::ResourceRequest> request,
    const net::NetworkTrafficAnnotationTag& traffic_annotation,
    uint32_t loader_options,
    SyncLoadResponse* response,
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
    WebVector<std::unique_ptr<URLLoaderThrottle>> throttles,
    base::TimeDelta timeout,
    const Vector<String>& cors_exempt_header_list,
    base::WaitableEvent* terminate_sync_load_event,
    mojo::PendingRemote<mojom::blink::BlobRegistry> download_to_blob_registry,
    scoped_refptr<ResourceRequestClient> client,
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper) {
  CheckSchemeForReferrerPolicy(*request);

  DCHECK(loader_options & network::mojom::kURLLoadOptionSynchronous);
  DCHECK(request->load_flags & net::LOAD_IGNORE_LIMITS);

  std::unique_ptr<network::PendingSharedURLLoaderFactory> pending_factory =
      url_loader_factory->Clone();
  base::WaitableEvent redirect_or_response_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);

  // Prepare the configured throttles for use on a separate thread.
  for (const auto& throttle : throttles) {
    throttle->DetachFromCurrentSequence();
  }

  // A task is posted to a separate thread to execute the request so that
  // this thread may block on a waitable event. It is safe to pass raw
  // pointers to on-stack objects as this stack frame will
  // survive until the request is complete.
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      base::ThreadPool::CreateSingleThreadTaskRunner({});
  SyncLoadContext* context_for_redirect = nullptr;
  PostCrossThreadTask(
      *task_runner, FROM_HERE,
      WTF::CrossThreadBindOnce(
          &SyncLoadContext::StartAsyncWithWaitableEvent, std::move(request),
          task_runner, traffic_annotation, loader_options,
          std::move(pending_factory), std::move(throttles),
          CrossThreadUnretained(response),
          CrossThreadUnretained(&context_for_redirect),
          CrossThreadUnretained(&redirect_or_response_event),
          CrossThreadUnretained(terminate_sync_load_event), timeout,
          std::move(download_to_blob_registry), cors_exempt_header_list,
          std::move(resource_load_info_notifier_wrapper)));

  // `redirect_or_response_event` will signal when each redirect completes, and
  // when the final response is complete.
  redirect_or_response_event.Wait();

  while (context_for_redirect) {
    DCHECK(response->redirect_info);

    using RefCountedOptionalStringVector =
        base::RefCountedData<std::optional<std::vector<std::string>>>;
    const scoped_refptr<RefCountedOptionalStringVector> removed_headers =
        base::MakeRefCounted<RefCountedOptionalStringVector>();
    using RefCountedOptionalHttpRequestHeaders =
        base::RefCountedData<std::optional<net::HttpRequestHeaders>>;
    const scoped_refptr<RefCountedOptionalHttpRequestHeaders> modified_headers =
        base::MakeRefCounted<RefCountedOptionalHttpRequestHeaders>();
    client->OnReceivedRedirect(
        *response->redirect_info, response->head.Clone(),
        /*follow_redirect_callback=*/
        WTF::BindOnce(
            [](scoped_refptr<RefCountedOptionalStringVector>
                   removed_headers_out,
               scoped_refptr<RefCountedOptionalHttpRequestHeaders>
                   modified_headers_out,
               std::vector<std::string> removed_headers,
               net::HttpRequestHeaders modified_headers) {
              removed_headers_out->data = std::move(removed_headers);
              modified_headers_out->data = std::move(modified_headers);
            },
            removed_headers, modified_headers));
    // `follow_redirect_callback` can't be asynchronously called for synchronous
    // requests because the current thread will be blocked by
    // `redirect_or_response_event.Wait()` call. So we check `HasOneRef()` here
    // to ensure that `follow_redirect_callback` is not kept alive.
    CHECK(removed_headers->HasOneRef());
    redirect_or_response_event.Reset();
    if (removed_headers->data.has_value()) {
      task_runner->PostTask(
          FROM_HERE, base::BindOnce(&SyncLoadContext::FollowRedirect,
                                    base::Unretained(context_for_redirect),
                                    std::move(*removed_headers->data),
                                    std::move(*modified_headers->data)));
    } else {
      task_runner->PostTask(
          FROM_HERE, base::BindOnce(&SyncLoadContext::CancelRedirect,
                                    base::Unretained(context_for_redirect)));
    }
    redirect_or_response_event.Wait();
  }
}

int ResourceRequestSender::SendAsync(
    std::unique_ptr<network::ResourceRequest> request,
    scoped_refptr<base::SequencedTaskRunner> loading_task_runner,
    const net::NetworkTrafficAnnotationTag& traffic_annotation,
    uint32_t loader_options,
    const Vector<String>& cors_exempt_header_list,
    scoped_refptr<ResourceRequestClient> client,
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
    WebVector<std::unique_ptr<URLLoaderThrottle>> throttles,
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper,
    CodeCacheHost* code_cache_host,
    base::OnceCallback<void(mojom::blink::RendererEvictionReason)>
        evict_from_bfcache_callback,
    base::RepeatingCallback<void(size_t)>
        did_buffer_load_while_in_bfcache_callback) {
  loading_task_runner_ = loading_task_runner;
  CheckSchemeForReferrerPolicy(*request);

#if BUILDFLAG(IS_ANDROID)
  // TODO(crbug.com/1286053): This used to be a DCHECK asserting "Main frame
  // shouldn't come here", but after removing and re-landing the DCHECK later it
  // started tripping in some teses. Was the DCHECK invalid or is there a bug
  // somewhere?
  if (!(request->is_outermost_main_frame &&
        IsRequestDestinationFrame(request->destination))) {
    // Having the favicon request extend user gesture carryover doesn't make
    // sense and causes flakiness in tests when the async favicon request
    // unexpectedly extends the navigation chain.
    if (request->has_user_gesture && !request->is_favicon) {
      resource_load_info_notifier_wrapper
          ->NotifyUpdateUserGestureCarryoverInfo();
    }
  }
#endif
  if (code_cache_host) {
    used_code_cache_fetcher_ = true;
    code_cache_fetcher_ = CodeCacheFetcher::TryCreateAndStart(
        *request, *code_cache_host,
        WTF::BindOnce(&ResourceRequestSender::DidReceiveCachedCode,
                      weak_factory_.GetWeakPtr()));
  }

  // Compute a unique request_id for this renderer process.
  int request_id = GenerateRequestId();
  request_info_ = std::make_unique<PendingRequestInfo>(
      std::move(client), request->destination, KURL(request->url),
      std::move(resource_load_info_notifier_wrapper));

  request_info_->resource_load_info_notifier_wrapper
      ->NotifyResourceLoadInitiated(request_id, request->url, request->method,
                                    request->referrer,
                                    request_info_->request_destination,
                                    request->priority, request->is_ad_tagged);

  auto url_loader_client = std::make_unique<MojoURLLoaderClient>(
      this, loading_task_runner, url_loader_factory->BypassRedirectChecks(),
      request->url, std::move(evict_from_bfcache_callback),
      std::move(did_buffer_load_while_in_bfcache_callback));

  std::vector<std::string> std_cors_exempt_header_list(
      cors_exempt_header_list.size());
  base::ranges::transform(cors_exempt_header_list,
                          std_cors_exempt_header_list.begin(),
                          [](const WebString& h) { return h.Latin1(); });
  std::unique_ptr<ThrottlingURLLoader> url_loader =
      ThrottlingURLLoader::CreateLoaderAndStart(
          std::move(url_loader_factory), throttles.ReleaseVector(), request_id,
          loader_options, request.get(), url_loader_client.get(),
          traffic_annotation, std::move(loading_task_runner),
          std::make_optional(std_cors_exempt_header_list));

  // The request may be canceled by `ThrottlingURLLoader::CreateAndStart()`, in
  // which case `DeletePendingRequest()` has reset the `request_info_` to
  // nullptr and `this` will be destroyed by `DeleteSoon()`. If so, just return
  // the `request_id`.
  if (!request_info_) {
    return request_id;
  }

  request_info_->url_loader = std::move(url_loader);
  request_info_->url_loader_client = std::move(url_loader_client);

  return request_id;
}

void ResourceRequestSender::Cancel(
    scoped_refptr<base::SequencedTaskRunner> task_runner) {
  // Cancel the request if it didn't complete, and clean it up so the bridge
  // will receive no more messages.
  DeletePendingRequest(std::move(task_runner));
}

void ResourceRequestSender::Freeze(LoaderFreezeMode mode) {
  if (!request_info_) {
    DLOG(ERROR) << "unknown request";
    return;
  }
  if (mode != LoaderFreezeMode::kNone) {
    request_info_->ignore_for_histogram = true;
    request_info_->freeze_mode = mode;
    request_info_->url_loader_client->Freeze(mode);
  } else if (request_info_->freeze_mode != LoaderFreezeMode::kNone) {
    request_info_->freeze_mode = LoaderFreezeMode::kNone;
    request_info_->url_loader_client->Freeze(LoaderFreezeMode::kNone);
    loading_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&ResourceRequestSender::MaybeRunPendingTasks,
                                  weak_factory_.GetWeakPtr()));
    FollowPendingRedirect(request_info_.get());
  }
}

void ResourceRequestSender::DidChangePriority(net::RequestPriority new_priority,
                                              int intra_priority_value) {
  if (!request_info_) {
    DLOG(ERROR) << "unknown request";
    return;
  }

  request_info_->url_loader->SetPriority(new_priority, intra_priority_value);
}

void ResourceRequestSender::DeletePendingRequest(
    scoped_refptr<base::SequencedTaskRunner> task_runner) {
  if (!request_info_) {
    return;
  }

  if (request_info_->net_error == net::ERR_IO_PENDING) {
    request_info_->net_error = net::ERR_ABORTED;
    request_info_->resource_load_info_notifier_wrapper
        ->NotifyResourceLoadCanceled(request_info_->net_error);
  }

  // Cancel loading.
  request_info_->url_loader.reset();

  // Clear URLLoaderClient to stop receiving further Mojo IPC from the browser
  // process.
  request_info_->url_loader_client.reset();

  // Always delete the `request_info_` asyncly so that cancelling the request
  // doesn't delete the request context which the `request_info_->client` points
  // to while its response is still being handled.
  task_runner->DeleteSoon(FROM_HERE, request_info_.release());
}

ResourceRequestSender::PendingRequestInfo::PendingRequestInfo(
    scoped_refptr<ResourceRequestClient> client,
    network::mojom::RequestDestination request_destination,
    const KURL& request_url,
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper)
    : client(std::move(client)),
      request_destination(request_destination),
      url(request_url),
      response_url(request_url),
      local_request_start(base::TimeTicks::Now()),
      resource_load_info_notifier_wrapper(
          std::move(resource_load_info_notifier_wrapper)) {}

ResourceRequestSender::PendingRequestInfo::~PendingRequestInfo() = default;

void ResourceRequestSender::FollowPendingRedirect(
    PendingRequestInfo* request_info) {
  if (request_info->has_pending_redirect) {
    request_info->has_pending_redirect = false;
    // net::URLRequest clears its request_start on redirect, so should we.
    request_info->local_request_start = base::TimeTicks::Now();
    // Redirect URL may not be handled by the network service, so force a
    // restart in case another URLLoaderFactory should handle the URL.
    if (request_info->redirect_requires_loader_restart) {
      request_info->modified_headers.Clear();
      request_info->url_loader->FollowRedirectForcingRestart();
    } else {
      std::vector<std::string> removed_headers(
          request_info_->removed_headers.size());
      base::ranges::transform(request_info_->removed_headers,
                              removed_headers.begin(), &WebString::Ascii);
      request_info->url_loader->FollowRedirect(
          removed_headers, request_info->modified_headers,
          {} /* modified_cors_exempt_headers */);
      request_info->modified_headers.Clear();
    }
  }
}

void ResourceRequestSender::OnTransferSizeUpdated(int32_t transfer_size_diff) {
  if (ShouldDeferTask()) {
    pending_tasks_.emplace_back(
        WTF::BindOnce(&ResourceRequestSender::OnTransferSizeUpdated,
                      weak_factory_.GetWeakPtr(), transfer_size_diff));
    return;
  }

  DCHECK_GT(transfer_size_diff, 0);
  if (!request_info_) {
    return;
  }

  // TODO(yhirano): Consider using int64_t in
  // ResourceRequestClient::OnTransferSizeUpdated.
  request_info_->client->OnTransferSizeUpdated(transfer_size_diff);
  if (!request_info_) {
    return;
  }
  request_info_->resource_load_info_notifier_wrapper
      ->NotifyResourceTransferSizeUpdated(transfer_size_diff);
}

void ResourceRequestSender::OnUploadProgress(int64_t position, int64_t size) {
  if (ShouldDeferTask()) {
    pending_tasks_.emplace_back(
        WTF::BindOnce(&ResourceRequestSender::OnUploadProgress,
                      weak_factory_.GetWeakPtr(), position, size));
    return;
  }
  if (!request_info_) {
    return;
  }

  request_info_->client->OnUploadProgress(position, size);
}

void ResourceRequestSender::OnReceivedResponse(
    network::mojom::URLResponseHeadPtr response_head,
    mojo::ScopedDataPipeConsumerHandle body,
    std::optional<mojo_base::BigBuffer> cached_metadata,
    base::TimeTicks response_ipc_arrival_time) {
  if (code_cache_fetcher_ && cached_metadata) {
    code_cache_fetcher_->DidReceiveCachedMetadataFromUrlLoader();
    code_cache_fetcher_.reset();
    MaybeRunPendingTasks();
  }

  if (ShouldDeferTask()) {
    latency_critical_operation_deferred_ = true;
    pending_tasks_.push_back(WTF::BindOnce(
        &ResourceRequestSender::OnReceivedResponse, weak_factory_.GetWeakPtr(),
        std::move(response_head), std::move(body), std::move(cached_metadata),
        response_ipc_arrival_time));
    return;
  }
  TRACE_EVENT0("loading", "ResourceRequestSender::OnReceivedResponse");
  if (!request_info_) {
    return;
  }
  request_info_->local_response_start = response_ipc_arrival_time;
  request_info_->remote_request_start =
      response_head->load_timing.request_start;
  // Now that response_start has been set, we can properly set the TimeTicks in
  // the URLResponseHead.
  base::TimeTicks remote_response_start =
      ToLocalURLResponseHead(*request_info_, *response_head);
  if (!request_info_->ignore_for_histogram &&
      !remote_response_start.is_null()) {
    base::UmaHistogramTimes("Blink.ResourceRequest.ResponseDelay2",
                            response_ipc_arrival_time - remote_response_start);
  }
  request_info_->load_timing_info = response_head->load_timing;

  if (code_cache_fetcher_) {
    CHECK(!cached_metadata);
    cached_metadata =
        code_cache_fetcher_->TakeCodeCacheForResponse(*response_head);
  }

  request_info_->client->OnReceivedResponse(
      response_head.Clone(), std::move(body), std::move(cached_metadata));
  if (!request_info_) {
    return;
  }

  request_info_->resource_load_info_notifier_wrapper
      ->NotifyResourceResponseReceived(std::move(response_head));
}

void ResourceRequestSender::OnReceivedRedirect(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr response_head,
    base::TimeTicks redirect_ipc_arrival_time) {
  if (ShouldDeferTask()) {
    latency_critical_operation_deferred_ = true;
    pending_tasks_.emplace_back(WTF::BindOnce(
        &ResourceRequestSender::OnReceivedRedirect, weak_factory_.GetWeakPtr(),
        redirect_info, std::move(response_head), redirect_ipc_arrival_time));
    return;
  }
  TRACE_EVENT0("loading", "ResourceRequestSender::OnReceivedRedirect");
  if (!request_info_) {
    return;
  }
  CHECK(request_info_->url_loader);

  if (code_cache_fetcher_) {
    code_cache_fetcher_->SetCurrentUrl(KURL(redirect_info.new_url));
  }

  request_info_->local_response_start = redirect_ipc_arrival_time;
  request_info_->remote_request_start =
      response_head->load_timing.request_start;
  request_info_->redirect_requires_loader_restart =
      RedirectRequiresLoaderRestart(GURL(request_info_->response_url),
                                    redirect_info.new_url);

  base::TimeTicks remote_response_start =
      ToLocalURLResponseHead(*request_info_, *response_head);
  if (!request_info_->ignore_for_histogram &&
      !remote_response_start.is_null()) {
    UmaHistogramTimes(
        "Blink.ResourceRequest.RedirectDelay2",
        request_info_->local_response_start - remote_response_start);
  }

  auto callback = WTF::BindOnce(
      &ResourceRequestSender::OnFollowRedirectCallback,
      weak_factory_.GetWeakPtr(), redirect_info, response_head.Clone());
  request_info_->client->OnReceivedRedirect(
      redirect_info, std::move(response_head), std::move(callback));
}

void ResourceRequestSender::OnFollowRedirectCallback(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr response_head,
    std::vector<std::string> removed_headers,
    net::HttpRequestHeaders modified_headers) {
  // DeletePendingRequest() may have cleared request_info_.
  if (!request_info_) {
    return;
  }
  if (request_info_->net_error != net::ERR_IO_PENDING) {
    // The request has been completed.
    return;
  }

  // TODO(yoav): If request_info doesn't change above, we could avoid this
  // copy.
  WebVector<WebString> vector(removed_headers.size());
  base::ranges::transform(removed_headers, vector.begin(),
                          &WebString::FromASCII);
  request_info_->removed_headers = vector;
  request_info_->response_url = KURL(redirect_info.new_url);
  request_info_->has_pending_redirect = true;
  request_info_->resource_load_info_notifier_wrapper
      ->NotifyResourceRedirectReceived(redirect_info, std::move(response_head));
  request_info_->modified_headers.MergeFrom(modified_headers);

  if (request_info_->freeze_mode == LoaderFreezeMode::kNone) {
    FollowPendingRedirect(request_info_.get());
  }
}

void ResourceRequestSender::OnRequestComplete(
    const network::URLLoaderCompletionStatus& status,
    base::TimeTicks complete_ipc_arrival_time) {
  if (ShouldDeferTask()) {
    latency_critical_operation_deferred_ = true;
    pending_tasks_.emplace_back(WTF::BindOnce(
        &ResourceRequestSender::OnRequestComplete, weak_factory_.GetWeakPtr(),
        status, complete_ipc_arrival_time));
    return;
  }
  TRACE_EVENT0("loading", "ResourceRequestSender::OnRequestComplete");

  if (!request_info_) {
    return;
  }
  request_info_->net_error = status.error_code;

  request_info_->resource_load_info_notifier_wrapper
      ->NotifyResourceLoadCompleted(status);

  ResourceRequestClient* client = request_info_->client.get();

  network::URLLoaderCompletionStatus renderer_status(status);
  if (status.completion_time.is_null()) {
    // No completion timestamp is provided, leave it as is.
  } else if (request_info_->remote_request_start.is_null() ||
             request_info_->load_timing_info.request_start.is_null()) {
    // We cannot convert the remote time to a local time, let's use the current
    // timestamp. This happens when
    //  - We get an error before OnReceivedRedirect or OnReceivedResponse is
    //    called, or
    //  - Somehow such a timestamp was missing in the LoadTimingInfo.
    renderer_status.completion_time = complete_ipc_arrival_time;
  } else {
    // We have already converted the request start timestamp, let's use that
    // conversion information.
    // Note: We cannot create a InterProcessTimeTicksConverter with
    // (local_request_start, now, remote_request_start, remote_completion_time)
    // as that may result in inconsistent timestamps.
    renderer_status.completion_time =
        std::min(status.completion_time - request_info_->remote_request_start +
                     request_info_->load_timing_info.request_start,
                 complete_ipc_arrival_time);
  }

  if (!request_info_->ignore_for_histogram) {
    const net::LoadTimingInfo& timing_info = request_info_->load_timing_info;
    if (!timing_info.request_start.is_null()) {
      UmaHistogramTimes(
          "Blink.ResourceRequest.StartDelay2",
          timing_info.request_start - request_info_->local_request_start);
    }
    if (!renderer_status.completion_time.is_null()) {
      UmaHistogramTimes(
          "Blink.ResourceRequest.CompletionDelay2",
          complete_ipc_arrival_time - renderer_status.completion_time);
    }
  }

  if (used_code_cache_fetcher_) {
    base::UmaHistogramBoolean(
        "Blink.ResourceRequest.DeferedRequestWaitingOnCodeCache",
        latency_critical_operation_deferred_);
  }
  // The request ID will be removed from our pending list in the destructor.
  // Normally, dispatching this message causes the reference-counted request to
  // die immediately.
  // TODO(kinuko): Revisit here. This probably needs to call
  // request_info_->client but the past attempt to change it seems to have
  // caused crashes. (crbug.com/547047)
  client->OnCompletedRequest(renderer_status);
}

base::TimeTicks ResourceRequestSender::ToLocalURLResponseHead(
    const PendingRequestInfo& request_info,
    network::mojom::URLResponseHead& response_head) const {
  base::TimeTicks remote_response_start = response_head.response_start;
  if (base::TimeTicks::IsConsistentAcrossProcesses() ||
      request_info.local_request_start.is_null() ||
      request_info.local_response_start.is_null() ||
      response_head.request_start.is_null() ||
      remote_response_start.is_null() ||
      response_head.load_timing.request_start.is_null()) {
    return remote_response_start;
  }

#if BUILDFLAG(IS_WIN)
  // This code below can only be reached on Windows as the
  // base::TimeTicks::IsConsistentAcrossProcesses() above always returns true
  // except on Windows platform.
  InterProcessTimeTicksConverter converter(
      LocalTimeTicks::FromTimeTicks(request_info.local_request_start),
      LocalTimeTicks::FromTimeTicks(request_info.local_response_start),
      RemoteTimeTicks::FromTimeTicks(response_head.request_start),
      RemoteTimeTicks::FromTimeTicks(remote_response_start));

  net::LoadTimingInfo* load_timing = &response_head.load_timing;
  RemoteToLocalTimeTicks(converter, &load_timing->request_start);
  RemoteToLocalTimeTicks(converter, &load_timing->proxy_resolve_start);
  RemoteToLocalTimeTicks(converter, &load_timing->proxy_resolve_end);
  RemoteToLocalTimeTicks(converter,
                         &load_timing->connect_timing.domain_lookup_start);
  RemoteToLocalTimeTicks(converter,
                         &load_timing->connect_timing.domain_lookup_end);
  RemoteToLocalTimeTicks(converter, &load_timing->connect_timing.connect_start);
  RemoteToLocalTimeTicks(converter, &load_timing->connect_timing.connect_end);
  RemoteToLocalTimeTicks(converter, &load_timing->connect_timing.ssl_start);
  RemoteToLocalTimeTicks(converter, &load_timing->connect_timing.ssl_end);
  RemoteToLocalTimeTicks(converter, &load_timing->send_start);
  RemoteToLocalTimeTicks(converter, &load_timing->send_end);
  RemoteToLocalTimeTicks(converter, &load_timing->receive_headers_start);
  RemoteToLocalTimeTicks(converter, &load_timing->receive_headers_end);
  RemoteToLocalTimeTicks(converter, &load_timing->push_start);
  RemoteToLocalTimeTicks(converter, &load_timing->push_end);
  RemoteToLocalTimeTicks(converter, &load_timing->service_worker_start_time);
  RemoteToLocalTimeTicks(converter, &load_timing->service_worker_ready_time);
  RemoteToLocalTimeTicks(converter, &load_timing->service_worker_fetch_start);
  RemoteToLocalTimeTicks(converter,
                         &load_timing->service_worker_respond_with_settled);
  RemoteToLocalTimeTicks(converter, &remote_response_start);
#endif
  return remote_response_start;
}

void ResourceRequestSender::DidReceiveCachedCode() {
  MaybeRunPendingTasks();
}

bool ResourceRequestSender::ShouldDeferTask() const {
  return (code_cache_fetcher_ && code_cache_fetcher_->is_waiting()) ||
         !pending_tasks_.empty();
}

void ResourceRequestSender::MaybeRunPendingTasks() {
  if (!request_info_ ||
      (code_cache_fetcher_ && code_cache_fetcher_->is_waiting()) ||
      (request_info_->freeze_mode != LoaderFreezeMode::kNone)) {
    return;
  }

  WTF::Vector<base::OnceClosure> tasks = std::move(pending_tasks_);
  for (auto& task : tasks) {
    std::move(task).Run();
  }
}

}  // namespace blink
```