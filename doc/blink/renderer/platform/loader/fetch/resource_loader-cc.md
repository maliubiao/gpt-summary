Response:
The user wants a summary of the `ResourceLoader::cc` file's functionality within the Chromium Blink rendering engine. I need to identify the core responsibilities of this class based on the provided code snippet.

Here's a breakdown of the thinking process:

1. **Identify the Class:** The primary focus is the `ResourceLoader` class.

2. **Examine Includes:** The included headers provide clues about the class's dependencies and interactions. Keywords like "fetch," "loader," "resource," "network," "cache," "cors," "permissions," and "javascript/html/css" can help pinpoint related functionality.

3. **Analyze Member Variables:**  Member variables reveal the state managed by the class. Things like `fetcher_`, `scheduler_`, `resource_`, `response_body_loader_`, and `network_resource_request_` are crucial indicators of the class's role.

4. **Scrutinize Key Methods:**  Methods like `Start()`, `Run()`, `DidReceiveResponse()`, `DidReceiveData()`, `DidFinishLoading()`, `DidFail()`, and `Cancel()` are central to the resource loading lifecycle. Understanding their purpose is essential.

5. **Look for Interactions with Web Technologies:**  The code mentions "javascript," "html," and "css" indirectly through concepts like "CORS," "permissions policy," and the types of resources being loaded (images, stylesheets, scripts).

6. **Identify Logic and Decision Points:**  Conditional statements and function calls within the methods reveal the decision-making process of the `ResourceLoader`. For example, the checks for synchronous vs. asynchronous loading and the handling of redirects.

7. **Consider Potential Errors:**  The `DidFail()` method and the `Cancel()` method highlight error handling. The code also includes checks and assertions, hinting at potential issues.

8. **Focus on the "What," not the "How":** The goal is to summarize the *functionality*, not to provide a detailed implementation walkthrough.

Based on this analysis, here's a potential outline of the key functionalities:

* **Initiating Resource Loading:** Starting network requests.
* **Managing the Loading Lifecycle:** Handling different stages like starting, receiving data, finishing, and failing.
* **Interacting with the Network Layer:** Creating `network::ResourceRequest` objects and using `URLLoader`.
* **Handling Responses:** Processing received data and headers.
* **Managing Caching:**  Interactions with the cache, including cache-aware loading.
* **Dealing with Redirects:** Following redirects and handling related security checks.
* **Enforcing Security Policies:**  Considering CORS and Permissions Policy.
* **Working with Different Resource Types:** Implicitly handles various types like images, scripts, stylesheets.
* **Supporting Synchronous and Asynchronous Requests:** Handling both modes.
* **Providing Progress Updates:**  Tracking the progress of the download.
* **Error Handling and Cancellation:** Managing failures and user-initiated cancellations.
* **Integration with the Scheduler:** Using `ResourceLoadScheduler` for managing request execution.

Now, let's translate this outline into a concise summary suitable for the first part of a three-part explanation.
`blink/renderer/platform/loader/fetch/resource_loader.cc` 文件的主要功能是 **负责加载网络资源**。它是 Blink 渲染引擎中处理资源请求的核心组件之一，负责发起请求，管理请求的生命周期，接收响应数据，并处理加载过程中的各种事件和错误。

具体来说，其功能可以归纳为以下几点：

1. **发起网络请求:**
   - 根据 `Resource` 对象中包含的 `ResourceRequest` 信息，创建底层的网络请求 (`network::ResourceRequest`)。
   - 使用 `URLLoader` 发起实际的网络请求。

2. **管理加载生命周期:**
   - 处理请求的开始、接收响应头、接收数据、完成加载和加载失败等各个阶段。
   - 维护加载状态，例如是否正在加载 (`IsLoading`)，是否已完成 (`finished_`)。

3. **接收和处理响应:**
   - 接收来自网络的响应头 (`WebURLResponse`)。
   - 通过 `ResponseBodyLoader` 接收响应体数据。
   - 将接收到的数据传递给 `Resource` 对象。

4. **处理重定向:**
   - 接收服务器的重定向响应。
   - 执行安全检查（例如 CORS，CSP）。
   - 决定是否跟随重定向。
   - 创建新的 `ResourceRequest` 并重新发起请求。

5. **处理错误和取消:**
   - 处理网络错误、CORS 错误、权限错误等各种加载失败的情况。
   - 提供取消加载的功能 (`Cancel`)。

6. **与调度器交互:**
   - 使用 `ResourceLoadScheduler` 来管理请求的优先级和执行顺序。
   - 根据系统资源和优先级调整请求的执行。

7. **处理缓存:**
   - 与缓存系统交互，根据缓存策略决定是否从缓存加载资源或更新缓存。
   - 支持缓存感知加载 (`cache-aware loading`)。

8. **集成各种特性:**
   - 支持 `keepalive` 请求。
   - 处理混合内容自动升级。
   - 收集加载相关的指标 (UKM, UMA)。
   - 遵守权限策略 (`Permissions Policy`)。

**与 JavaScript, HTML, CSS 的功能关系举例说明:**

`ResourceLoader` 直接负责加载构成网页的各种资源，包括 JavaScript 文件、HTML 文档和 CSS 样式表。

* **JavaScript:** 当浏览器解析 HTML 遇到 `<script src="...">` 标签时，`ResourceLoader` 会被调用来加载指定的 JavaScript 文件。加载完成后，JavaScript 代码才能被解析和执行。
    * **假设输入:** HTML 中包含 `<script src="script.js"></script>`，`script.js` 位于服务器上。
    * **输出:** `ResourceLoader` 成功下载 `script.js` 的内容，并将其传递给 JavaScript 引擎进行处理。

* **HTML:**  当用户导航到一个新的网页时，`ResourceLoader` 负责下载 HTML 文档。浏览器会解析下载的 HTML 来构建 DOM 树。
    * **假设输入:** 用户在地址栏输入 `https://example.com` 并回车。
    * **输出:** `ResourceLoader` 下载 `https://example.com` 的 HTML 内容，浏览器开始解析并渲染页面。

* **CSS:** 当浏览器解析 HTML 遇到 `<link rel="stylesheet" href="style.css">` 标签时，`ResourceLoader` 会被调用来加载 CSS 样式表。加载完成后，CSS 规则会被应用于 DOM 树，影响页面的样式。
    * **假设输入:** HTML 中包含 `<link rel="stylesheet" href="style.css">`，`style.css` 位于服务器上。
    * **输出:** `ResourceLoader` 成功下载 `style.css` 的内容，浏览器使用这些样式来渲染页面元素。

**逻辑推理的假设输入与输出:**

* **假设输入:** 一个跨域的图片请求，没有设置 CORS 头。
* **输出:** `ResourceLoader` 会在接收到响应后，根据 CORS 规范检查响应头。如果缺少必要的 CORS 头，`ResourceLoader` 会阻止图片的加载，并可能在控制台输出 CORS 错误信息。

* **假设输入:** 一个 HTTPS 页面尝试加载 HTTP 的脚本。
* **输出:** `ResourceLoader` 会根据混合内容策略阻止 HTTP 脚本的加载，并可能在控制台输出混合内容错误信息。

**涉及用户或者编程常见的使用错误举例说明:**

* **CORS 配置错误:**  后端服务器没有正确配置 CORS 头，导致前端 JavaScript 代码无法跨域请求资源。用户会在开发者工具的控制台中看到 CORS 相关的错误信息，例如 "CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource."

* **混合内容错误:** 开发者在 HTTPS 页面中引入了 HTTP 资源，例如图片或脚本。浏览器出于安全考虑会阻止这些混合内容，用户可能会看到部分资源无法加载，控制台会显示混合内容警告或错误。

**功能归纳 (第 1 部分):**

总而言之，`blink/renderer/platform/loader/fetch/resource_loader.cc` 的核心功能是 **作为 Blink 渲染引擎中加载网络资源的关键模块，负责发起、管理和完成各种类型的资源请求，并处理加载过程中的安全策略、缓存机制和错误情况，为页面的正常渲染提供基础支持。**

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/resource_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007, 2010, 2011 Apple Inc. All rights reserved.
 *           (C) 2007 Graham Dennis (graham.dennis@gmail.com)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"

#include <algorithm>
#include <optional>
#include <utility>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/checked_math.h"
#include "base/rand_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/unguessable_token.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "net/base/load_flags.h"
#include "services/metrics/public/cpp/metrics_utils.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/network/public/cpp/cross_origin_embedder_policy.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/blocked_by_response_reason.mojom-shared.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "third_party/blink/public/common/client_hints/client_hints.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/platform/back_forward_cache_utils.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/cors/cors_error_string.h"
#include "third_party/blink/renderer/platform/loader/fetch/back_forward_cache_loader_helper.h"
#include "third_party/blink/renderer/platform/loader/fetch/code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/console_logger.h"
#include "third_party/blink/renderer/platform/loader/fetch/detachable_use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_context.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/shared_buffer_bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/background_response_processor.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/request_conversion.h"
#include "third_party/blink/renderer/platform/loader/mixed_content_autoupgrade_status.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "url/url_constants.h"

namespace blink {

namespace {

enum class RequestOutcome { kSuccess, kFail };

const char* RequestOutcomeToString(RequestOutcome outcome) {
  switch (outcome) {
    case RequestOutcome::kSuccess:
      return "Success";
    case RequestOutcome::kFail:
      return "Fail";
  }
}

// The sampling rate for UKM recording. A value of 0.1 corresponds to a
// sampling rate of 10%.
constexpr double kUkmSamplingRate = 0.1;

bool IsThrottlableRequestContext(mojom::blink::RequestContextType context) {
  // Requests that could run long should not be throttled as they
  // may stay there forever and avoid other requests from making
  // progress.
  // See https://crbug.com/837771 for the sample breakages.
  return context != mojom::blink::RequestContextType::EVENT_SOURCE &&
         context != mojom::blink::RequestContextType::FETCH &&
         context != mojom::blink::RequestContextType::XML_HTTP_REQUEST &&
         context != mojom::blink::RequestContextType::VIDEO &&
         context != mojom::blink::RequestContextType::AUDIO;
}

void LogMixedAutoupgradeMetrics(blink::MixedContentAutoupgradeStatus status,
                                std::optional<int> response_or_error_code,
                                ukm::SourceId source_id,
                                ukm::UkmRecorder* recorder,
                                Resource* resource) {
  UMA_HISTOGRAM_ENUMERATION("MixedAutoupgrade.ResourceRequest.Status", status);
  switch (status) {
    case MixedContentAutoupgradeStatus::kStarted:
      UMA_HISTOGRAM_ENUMERATION("MixedAutoupgrade.ResourceRequest.Start.Type",
                                resource->GetType());
      break;
    case MixedContentAutoupgradeStatus::kFailed:
      UMA_HISTOGRAM_ENUMERATION("MixedAutoupgrade.ResourceRequest.Failure.Type",
                                resource->GetType());
      UMA_HISTOGRAM_BOOLEAN("MixedAutoupgrade.ResourceRequest.Failure.IsAd",
                            resource->GetResourceRequest().IsAdResource());
      break;
    case MixedContentAutoupgradeStatus::kResponseReceived:
      UMA_HISTOGRAM_ENUMERATION(
          "MixedAutoupgrade.ResourceRequest.Response.Type",
          resource->GetType());
  };
  ukm::builders::MixedContentAutoupgrade_ResourceRequest builder(source_id);
  builder.SetStatus(static_cast<int64_t>(status));
  if (response_or_error_code.has_value()) {
    base::UmaHistogramSparse(
        "MixedAutoupgrade.ResourceRequest.ErrorOrResponseCode",
        response_or_error_code.value());
    builder.SetCode(response_or_error_code.value());
  }
  builder.Record(recorder);
}

bool RequestContextObserveResponse(mojom::blink::RequestContextType type) {
  switch (type) {
    case mojom::blink::RequestContextType::PING:
    case mojom::blink::RequestContextType::BEACON:
    case mojom::blink::RequestContextType::CSP_REPORT:
      return true;

    default:
      return false;
  }
}

SchedulingPolicy::Feature GetFeatureFromRequestContextType(
    mojom::blink::RequestContextType type) {
  switch (type) {
    case mojom::blink::RequestContextType::FETCH:
      return SchedulingPolicy::Feature::kOutstandingNetworkRequestFetch;
    case mojom::blink::RequestContextType::XML_HTTP_REQUEST:
      return SchedulingPolicy::Feature::kOutstandingNetworkRequestXHR;
    default:
      return SchedulingPolicy::Feature::kOutstandingNetworkRequestOthers;
  }
}

std::optional<mojom::WebFeature> PreflightResultToWebFeature(
    network::mojom::PrivateNetworkAccessPreflightResult result) {
  using Result = network::mojom::PrivateNetworkAccessPreflightResult;

  switch (result) {
    case Result::kNone:
      return std::nullopt;
    case Result::kError:
      return mojom::WebFeature::kPrivateNetworkAccessPreflightError;
    case Result::kSuccess:
      return mojom::WebFeature::kPrivateNetworkAccessPreflightSuccess;
    case Result::kWarning:
      return mojom::WebFeature::kPrivateNetworkAccessPreflightWarning;
  }
}

bool ShouldActivateCacheAwareLoading(const ResourceFetcher* fetcher,
                                     const Resource* resource) {
  if (resource->Options().cache_aware_loading_enabled !=
      kIsCacheAwareLoadingEnabled) {
    return false;
  }

  // Synchronous requests are not supported.
  if (resource->Options().synchronous_policy == kRequestSynchronously) {
    return false;
  }

  // Don't activate on Resource revalidation.
  if (resource->IsCacheValidator()) {
    return false;
  }

  // Don't activate if cache policy is explicitly set.
  if (resource->GetResourceRequest().GetCacheMode() !=
      mojom::blink::FetchCacheMode::kDefault) {
    return false;
  }

  // Don't activate if the page is controlled by service worker.
  if (fetcher->IsControlledByServiceWorker() !=
      mojom::blink::ControllerServiceWorkerMode::kNoController) {
    return false;
  }
  return true;
}

std::unique_ptr<network::ResourceRequest> CreateNetworkRequest(
    const ResourceRequestHead& request_head,
    ResourceRequestBody& request_body) {
  auto network_resource_request = std::make_unique<network::ResourceRequest>();
  scoped_refptr<EncodedFormData> form_body = request_body.FormBody();
  PopulateResourceRequest(request_head, std::move(request_body),
                          network_resource_request.get());
  if (form_body) {
    request_body = ResourceRequestBody(std::move(form_body));
  }
  return network_resource_request;
}

}  // namespace

ResourceLoader::ResourceLoader(ResourceFetcher* fetcher,
                               ResourceLoadScheduler* scheduler,
                               Resource* resource,
                               ContextLifecycleNotifier* context,
                               ResourceRequestBody request_body,
                               uint32_t inflight_keepalive_bytes)
    : scheduler_client_id_(ResourceLoadScheduler::kInvalidClientId),
      fetcher_(fetcher),
      scheduler_(scheduler),
      resource_(resource),
      request_body_(std::move(request_body)),
      inflight_keepalive_bytes_(inflight_keepalive_bytes),
      is_cache_aware_loading_activated_(
          ShouldActivateCacheAwareLoading(fetcher, resource)),
      progress_receiver_(this, context),
      cancel_timer_(fetcher_->GetTaskRunner(),
                    this,
                    &ResourceLoader::CancelTimerFired) {
  DCHECK(resource_);
  DCHECK(fetcher_);

  // Some requests should not block the page from entering the BackForwardCache.
  // If they are keepalive request && their responses are not observable to web
  // content, we can have them survive without breaking web content when the
  // page is put into BackForwardCache.
  const auto& request = resource_->GetResourceRequest();
  auto request_context = request.GetRequestContext();
  if (auto* frame_or_worker_scheduler = fetcher->GetFrameOrWorkerScheduler()) {
    if (!base::FeatureList::IsEnabled(
            features::kBackForwardCacheWithKeepaliveRequest) &&
        request.GetKeepalive()) {
      frame_or_worker_scheduler->RegisterStickyFeature(
          SchedulingPolicy::Feature::kKeepaliveRequest,
          {SchedulingPolicy::DisableBackForwardCache()});
    } else if (!RequestContextObserveResponse(request_context)) {
      // Only when this feature is turned on and the loading tasks keep being
      // processed and the data is queued up on the renderer, a page can stay in
      // BackForwardCache with network requests.
      if (!IsInflightNetworkRequestBackForwardCacheSupportEnabled()) {
        feature_handle_for_scheduler_ =
            frame_or_worker_scheduler->RegisterFeature(
                GetFeatureFromRequestContextType(request_context),
                {SchedulingPolicy::DisableBackForwardCache()});
      }
    }
  }

  resource_->SetLoader(this);
}

ResourceLoader::~ResourceLoader() = default;

void ResourceLoader::Trace(Visitor* visitor) const {
  visitor->Trace(fetcher_);
  visitor->Trace(scheduler_);
  visitor->Trace(resource_);
  visitor->Trace(response_body_loader_);
  visitor->Trace(data_pipe_completion_notifier_);
  visitor->Trace(cancel_timer_);
  visitor->Trace(progress_receiver_);
  ResourceLoadSchedulerClient::Trace(visitor);
}

void ResourceLoader::Start() {
  const ResourceRequestHead& request = resource_->GetResourceRequest();

  if (request.GetKeepalive()) {
    FetchUtils::LogFetchKeepAliveRequestMetric(
        request.GetRequestContext(),
        FetchUtils::FetchKeepAliveRequestState::kStarted,
        fetcher_->GetProperties().IsDetached());
  }

  if (!resource_->Url().ProtocolIsData()) {
    network_resource_request_ = CreateNetworkRequest(request, request_body_);
    if (is_cache_aware_loading_activated_) {
      // Override cache policy for cache-aware loading. If this request fails, a
      // reload with original request will be triggered in DidFail().
      network_resource_request_->load_flags |= net::LOAD_ONLY_FROM_CACHE;
    }
    loader_ = fetcher_->CreateURLLoader(
        *network_resource_request_, resource_->Options(),
        resource_->GetResourceRequest().GetRequestContext(),
        resource_->GetResourceRequest().GetRenderBlockingBehavior(),
        resource_->GetResourceRequest()
            .GetServiceWorkerRaceNetworkRequestToken(),
        resource_->GetResourceRequest().IsFromOriginDirtyStyleSheet());
    task_runner_for_body_loader_ = loader_->GetTaskRunnerForBodyLoader();
  } else {
    // ResourceLoader doesn't support DownloadToBlob option for data URL. This
    // logic is implemented inside XMLHttpRequest.
    CHECK(!resource_->GetResourceRequest().DownloadToBlob());
    task_runner_for_body_loader_ = fetcher_->GetTaskRunner();
  }

  DCHECK_EQ(ResourceLoadScheduler::kInvalidClientId, scheduler_client_id_);
  auto throttle_option = ResourceLoadScheduler::ThrottleOption::kThrottleable;

  // Synchronous requests should not work with throttling or stopping. Also,
  // disables throttling for the case that can be used for aka long-polling
  // requests, but allows stopping for long-polling requests. We don't want
  // to throttle a request with keepalive set because such a request is
  // expected to work even when a frame is freezed/detached.
  // Top level frame main resource loads are also not throttleable or
  // stoppable. We also disable throttling and stopping for non-http[s]
  // requests.
  if (resource_->Options().synchronous_policy == kRequestSynchronously ||
      request.GetKeepalive() || !request.Url().ProtocolIsInHTTPFamily()) {
    throttle_option =
        ResourceLoadScheduler::ThrottleOption::kCanNotBeStoppedOrThrottled;
  } else if (!IsThrottlableRequestContext(request.GetRequestContext())) {
    throttle_option = ResourceLoadScheduler::ThrottleOption::kStoppable;
  }

  if (request.IsAutomaticUpgrade()) {
    LogMixedAutoupgradeMetrics(MixedContentAutoupgradeStatus::kStarted,
                               std::nullopt, request.GetUkmSourceId(),
                               fetcher_->UkmRecorder(), resource_);
  }
  if (resource_->GetResourceRequest().IsDownloadToNetworkCacheOnly()) {
    // The download-to-cache requests are throttled in net/, they are fire-and
    // forget, and cannot unregister properly from the scheduler once they are
    // finished.
    throttle_option =
        ResourceLoadScheduler::ThrottleOption::kCanNotBeStoppedOrThrottled;
  }
  scheduler_->Request(this, throttle_option, request.Priority(),
                      request.IntraPriorityValue(), &scheduler_client_id_);
}

void ResourceLoader::DidStartLoadingResponseBodyInternal(
    BytesConsumer& bytes_consumer) {
  DCHECK(!response_body_loader_);
  ResponseBodyLoaderClient& response_body_loader_client = *this;
  response_body_loader_ = MakeGarbageCollected<ResponseBodyLoader>(
      bytes_consumer, response_body_loader_client, task_runner_for_body_loader_,
      fetcher_->GetBackForwardCacheLoaderHelper());
  resource_->ResponseBodyReceived(*response_body_loader_,
                                  task_runner_for_body_loader_);
  if (response_body_loader_->IsDrained()) {
    // When streaming, unpause virtual time early to prevent deadlocking
    // against stream consumer in case stream has backpressure enabled.
    resource_->VirtualTimePauser().UnpauseVirtualTime();
  } else {
    response_body_loader_->Start();
  }
}

void ResourceLoader::Run() {
  // TODO(crbug.com/1169032): Manage cookies' capability control here for the
  // Prerender2.
  StartFetch();
}

void ResourceLoader::DidReceiveDecodedData(
    const String& data,
    std::unique_ptr<ParkableStringImpl::SecureDigest> digest) {
  resource_->DidReceiveDecodedData(data, std::move(digest));
}

void ResourceLoader::DidFinishLoadingBody() {
  has_seen_end_of_body_ = true;

  const ResourceResponse& response = resource_->GetResponse();
  if (deferred_finish_loading_info_) {
    DidFinishLoading(deferred_finish_loading_info_->response_end_time,
                     response.EncodedDataLength(), response.EncodedBodyLength(),
                     response.DecodedBodyLength());
  }
}

void ResourceLoader::DidFailLoadingBody() {
  DidFail(WebURLError(ResourceError::Failure(resource_->Url())),
          base::TimeTicks::Now(), 0, 0, 0);
}

void ResourceLoader::DidCancelLoadingBody() {
  Cancel();
}

void ResourceLoader::StartFetch() {
  DCHECK_NE(ResourceLoadScheduler::kInvalidClientId, scheduler_client_id_);
  if (resource_->Options().synchronous_policy == kRequestSynchronously &&
      fetcher_->GetProperties().FreezeMode() != LoaderFreezeMode::kNone) {
    // TODO(yuzus): Evict bfcache if necessary.
    Cancel();
    return;
  }

  SetDefersLoading(fetcher_->GetProperties().FreezeMode());

  if (resource_->Options().synchronous_policy == kRequestSynchronously) {
    RequestSynchronously();
  } else {
    RequestAsynchronously();
  }
}

void ResourceLoader::Release(
    ResourceLoadScheduler::ReleaseOption option,
    const ResourceLoadScheduler::TrafficReportHints& hints) {
  DCHECK_NE(ResourceLoadScheduler::kInvalidClientId, scheduler_client_id_);
  bool released = scheduler_->Release(scheduler_client_id_, option, hints);
  DCHECK(released);
  scheduler_client_id_ = ResourceLoadScheduler::kInvalidClientId;
  feature_handle_for_scheduler_.reset();
}

void ResourceLoader::Restart() {
  const ResourceRequestHead& request = resource_->GetResourceRequest();
  CHECK_EQ(resource_->Options().synchronous_policy, kRequestAsynchronously);
  CHECK(!network_resource_request_);
  CHECK(!resource_->Url().ProtocolIsData());
  network_resource_request_ = CreateNetworkRequest(request, request_body_);
  loader_ = fetcher_->CreateURLLoader(
      *network_resource_request_, resource_->Options(),
      resource_->GetResourceRequest().GetRequestContext(),
      resource_->GetResourceRequest().GetRenderBlockingBehavior(),
      resource_->GetResourceRequest().GetServiceWorkerRaceNetworkRequestToken(),
      resource_->GetResourceRequest().IsFromOriginDirtyStyleSheet());
  task_runner_for_body_loader_ = loader_->GetTaskRunnerForBodyLoader();
  StartFetch();
}

void ResourceLoader::SetDefersLoading(LoaderFreezeMode mode) {
  freeze_mode_ = mode;

  if (response_body_loader_) {
    if (mode != LoaderFreezeMode::kNone &&
        !response_body_loader_->IsSuspended()) {
      response_body_loader_->Suspend(mode);
      if (mode == LoaderFreezeMode::kBufferIncoming) {
        response_body_loader_
            ->EvictFromBackForwardCacheIfDrainedAsBytesConsumer();
      }
    }
    if (mode == LoaderFreezeMode::kNone &&
        response_body_loader_->IsSuspended()) {
      response_body_loader_->Resume();
    }
  }

  if (defers_handling_data_url_) {
    if (freeze_mode_ == LoaderFreezeMode::kNone) {
      defers_handling_data_url_ = false;
      GetLoadingTaskRunner()->PostTask(
          FROM_HERE, WTF::BindOnce(&ResourceLoader::HandleDataUrl,
                                   WrapWeakPersistent(this)));
    }
  }

  if (loader_) {
    loader_->Freeze(mode);
  }
  if (mode != LoaderFreezeMode::kNone) {
    resource_->VirtualTimePauser().UnpauseVirtualTime();
  } else {
    resource_->VirtualTimePauser().PauseVirtualTime();
  }
}

void ResourceLoader::DidChangePriority(ResourceLoadPriority load_priority,
                                       int intra_priority_value) {
  if (scheduler_->IsRunning(scheduler_client_id_)) {
    DCHECK_NE(ResourceLoadScheduler::kInvalidClientId, scheduler_client_id_);
    if (loader_) {
      loader_->DidChangePriority(
          static_cast<WebURLRequest::Priority>(load_priority),
          intra_priority_value);
    }
  } else {
    scheduler_->SetPriority(scheduler_client_id_, load_priority,
                            intra_priority_value);
  }
}

void ResourceLoader::ScheduleCancel() {
  if (!cancel_timer_.IsActive()) {
    cancel_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
  }
}

void ResourceLoader::CancelTimerFired(TimerBase*) {
  if (IsLoading() && !resource_->HasClientsOrObservers()) {
    Cancel();
  }
}

void ResourceLoader::Cancel() {
  HandleError(
      ResourceError::CancelledError(resource_->LastResourceRequest().Url()));
}

bool ResourceLoader::IsLoading() const {
  return !finished_;
}

void ResourceLoader::CancelForRedirectAccessCheckError(
    const KURL& new_url,
    ResourceRequestBlockedReason blocked_reason) {
  resource_->WillNotFollowRedirect();

  if (IsLoading()) {
    HandleError(
        ResourceError::CancelledDueToAccessCheckError(new_url, blocked_reason));
  }
}

static bool IsManualRedirectFetchRequest(const ResourceRequestHead& request) {
  return request.GetRedirectMode() == network::mojom::RedirectMode::kManual &&
         request.GetRequestContext() == mojom::blink::RequestContextType::FETCH;
}

bool ResourceLoader::WillFollowRedirect(
    const WebURL& new_url,
    const net::SiteForCookies& new_site_for_cookies,
    const WebString& new_referrer,
    network::mojom::ReferrerPolicy new_referrer_policy,
    const WebString& new_method,
    const WebURLResponse& passed_redirect_response,
    bool& has_devtools_request_id,
    std::vector<std::string>* removed_headers,
    net::HttpRequestHeaders& modified_headers,
    bool insecure_scheme_was_upgraded) {
  DCHECK(!passed_redirect_response.IsNull());

  if (passed_redirect_response.HasAuthorizationCoveredByWildcardOnPreflight()) {
    fetcher_->GetUseCounter().CountDeprecation(
        mojom::WebFeature::kAuthorizationCoveredByWildcard);
  }

  CountPrivateNetworkAccessPreflightResult(
      passed_redirect_response.PrivateNetworkAccessPreflightResult());

  if (resource_->GetResourceRequest().HttpHeaderFields().Contains(
          http_names::kAuthorization) &&
      !SecurityOrigin::AreSameOrigin(resource_->LastResourceRequest().Url(),
                                     new_url)) {
    fetcher_->GetUseCounter().CountUse(
        mojom::WebFeature::kAuthorizationCrossOrigin);
  }

  // TODO(https://crbug.com/471397, https://crbug.com/1406737): Reconsider
  // the placement of this code, together with the //net counterpart.
  if (removed_headers) {
    // Step 13 of https://fetch.spec.whatwg.org/#http-redirect-fetch
    if (base::FeatureList::IsEnabled(
            features::kRemoveAuthroizationOnCrossOriginRedirect) &&
        !SecurityOrigin::AreSameOrigin(resource_->LastResourceRequest().Url(),
                                       new_url)) {
      removed_headers->push_back(net::HttpRequestHeaders::kAuthorization);
    }
    FindClientHintsToRemove(Context().GetPermissionsPolicy(),
                            GURL(new_url.GetString().Utf8()), removed_headers);
  }

  if (is_cache_aware_loading_activated_) {
    // Fail as cache miss if cached response is a redirect.
    HandleError(
        ResourceError::CacheMissError(resource_->LastResourceRequest().Url()));
    return false;
  }

  const ResourceRequestHead& initial_request = resource_->GetResourceRequest();
  if (initial_request.GetRedirectMode() ==
      network::mojom::RedirectMode::kError) {
    // The network::cors::CorsURLLoader would reject the redirect in any case,
    // but we reject the redirect here because otherwise we would see confusing
    // errors such as MixedContent errors in the console during redirect
    // handling.
    HandleError(ResourceError::Failure(new_url));
    return false;
  }

  std::unique_ptr<ResourceRequest> new_request =
      resource_->LastResourceRequest().CreateRedirectRequest(
          new_url, new_method, new_site_for_cookies, new_referrer,
          new_referrer_policy,
          !passed_redirect_response.WasFetchedViaServiceWorker());

  ResourceType resource_type = resource_->GetType();

  // The following parameters never change during the lifetime of a request.
  mojom::blink::RequestContextType request_context =
      initial_request.GetRequestContext();
  network::mojom::RequestDestination request_destination =
      initial_request.GetRequestDestination();
  network::mojom::RequestMode request_mode = initial_request.GetMode();
  network::mojom::CredentialsMode credentials_mode =
      initial_request.GetCredentialsMode();

  const ResourceLoaderOptions& options = resource_->Options();

  const ResourceResponse& redirect_response(
      passed_redirect_response.ToResourceResponse());

  const KURL& url_before_redirects = initial_request.Url();

  if (!IsManualRedirectFetchRequest(initial_request)) {
    bool unused_preload = resource_->IsUnusedPreload();

    // Don't send security violation reports for unused preloads.
    ReportingDisposition reporting_disposition =
        unused_preload ? ReportingDisposition::kSuppressReporting
                       : ReportingDisposition::kReport;

    // The network stack might have upgraded to https an http URL. Report-only
    // CSP must be checked with the url prior to that upgrade.
    KURL new_url_prior_upgrade = new_url;
    if (insecure_scheme_was_upgraded && new_url.ProtocolIs(url::kHttpsScheme)) {
      new_url_prior_upgrade.SetProtocol(url::kHttpScheme);
    }

    // CanRequest() checks only enforced CSP, so check report-only here to
    // ensure that violations are sent.
    Context().CheckCSPForRequest(
        request_context, request_destination, new_url_prior_upgrade, options,
        reporting_disposition, url_before_redirects,
        ResourceRequest::RedirectStatus::kFollowedRedirect);

    std::optional<ResourceRequestBlockedReason> blocked_reason =
        Context().CanRequest(resource_type, *new_request, new_url, options,
                             reporting_disposition,
                             new_request->GetRedirectInfo());

    if (Context().CalculateIfAdSubresource(
            *new_request, std::nullopt /* alias_url */, resource_type,
            options.initiator_info)) {
      new_request->SetIsAdResource();
    }

    if (blocked_reason) {
      CancelForRedirectAccessCheckError(new_url, blocked_reason.value());
      return false;
    }

    if (resource_type == ResourceType::kImage &&
        fetcher_->ShouldDeferImageLoad(new_url)) {
      CancelForRedirectAccessCheckError(new_url,
                                        ResourceRequestBlockedReason::kOther);
      return false;
    }
  }

  fetcher_->RecordResourceTimingOnRedirect(resource_.Get(), redirect_response,
                                           new_url);

  // The following two calls may rewrite the new_request->Url() to
  // something else not for rejecting redirect but for other reasons.
  // E.g. WebFrameTestClient::WillSendRequest() and
  // RenderFrameImpl::WillSendRequest(). We should reflect the
  // rewriting but currently we cannot. So, compare new_request->Url() and
  // new_url after calling them, and return false to make the redirect fail on
  // mismatch.

  WebScopedVirtualTimePauser unused_virtual_time_pauser;
  // TODO(yoichio): Have PrepareRequest use ResourceRequestHead.
  Context().PrepareRequest(*new_request, resource_->MutableOptions(),
                           unused_virtual_time_pauser, resource_->GetType());
  DCHECK(!new_request->HttpBody());
  if (auto* observer = fetcher_->GetResourceLoadObserver()) {
    observer->WillSendRequest(
        *new_request, redirect_response, resource_->GetType(), options,
        initial_request.GetRenderBlockingBehavior(), resource_);
  }

  // First-party cookie logic moved from DocumentLoader in Blink to
  // net::URLRequest in the browser. Assert that Blink didn't try to change it
  // to something else.
  DCHECK(new_request->SiteForCookies().IsEquivalent(new_site_for_cookies));

  // The following parameters never change during the lifetime of a request.
  DCHECK_EQ(new_request->GetRequestContext(), request_context);
  DCHECK_EQ(new_request->GetMode(), request_mode);
  DCHECK_EQ(new_request->GetCredentialsMode(), credentials_mode);

  // If `Shared-Storage-Writable` eligibity has changed, update the headers.
  bool previous_shared_storage_writable_eligible =
      resource_->LastResourceRequest().GetSharedStorageWritableEligible();
  bool new_shared_storage_writable_eligible =
      new_request->GetSharedStorageWritableEligible();
  if (new_shared_storage_writable_eligible !=
      previous_shared_storage_writable_eligible) {
    if (new_shared_storage_writable_eligible) {
      CHECK(new_request->GetSharedStorageWritableOptedIn());
      modified_headers.SetHeader(http_names::kSecSharedStorageWritable.Ascii(),
                                 "?1");
    } else if (removed_headers) {
      removed_headers->push_back(http_names::kSecSharedStorageWritable.Ascii());
    }
  }

  if (new_request->Url() != KURL(new_url)) {
    CancelForRedirectAccessCheckError(new_request->Url(),
                                      ResourceRequestBlockedReason::kOther);
    return false;
  }

  if (!resource_->WillFollowRedirect(*new_request, redirect_response)) {
    CancelForRedirectAccessCheckError(new_request->Url(),
                                      ResourceRequestBlockedReason::kOther);
    return false;
  }

  has_devtools_request_id = !new_request->GetDevToolsId().IsNull();
  return true;
}

void ResourceLoader::DidSendData(uint64_t bytes_sent,
                   
"""


```