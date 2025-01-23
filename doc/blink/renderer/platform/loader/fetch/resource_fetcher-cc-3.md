Response:
The user wants a summary of the functionalities of the `ResourceFetcher` class in Chromium's Blink rendering engine, based on a code snippet from the `resource_fetcher.cc` file. The summary should cover its relations to Javascript, HTML, and CSS, logical reasoning with input/output examples, common usage errors, and serve as part 4 of a 5-part analysis.

Here's a breakdown of how to approach this:

1. **Identify Key Functions:** Scan the provided code snippet for method names and their actions. Focus on what each function does.
2. **Infer Overall Role:** Based on the functions, determine the main purpose of the `ResourceFetcher`. It seems related to fetching and managing resources.
3. **Connect to Web Technologies:** Analyze how the identified functionalities relate to the fetching of Javascript, HTML, and CSS files. Look for cues like resource types or processing steps.
4. **Logical Reasoning:**  For certain functions, create hypothetical scenarios to illustrate their behavior with specific inputs and outputs.
5. **Common Errors:** Think about how developers might misuse the resource fetching mechanisms or what could go wrong during the fetching process.
6. **Context from Surrounding Code:** Since this is part 4 of 5, consider what might have been covered in the previous parts and what might be left for the final part. This will help in framing the summary correctly.
7. **Synthesize the Summary:** Combine the findings into a concise and informative summary of the `ResourceFetcher`'s role.

**Detailed Breakdown of the Code Snippet:**

* **`HandleUnusedPreloads()`:** This function deals with preloaded resources that weren't used, suggesting an optimization mechanism.
* **`HandleLoaderFinish()`:** This is a central function called when a resource load completes successfully. It updates metrics, handles multipart resources, manages resource timing, deals with preload cache, and potentially triggers speculative image decoding.
* **`HandleLoaderError()`:** This handles resource loading failures, including updating metrics, managing resource timing, and potentially removing preloads.
* **`MoveResourceLoaderToNonBlocking()`:**  This suggests different ways of loading resources, blocking or non-blocking.
* **`StartLoad()`:** This function initiates the loading of a resource, handling different scenarios (preloads, different blocking policies).
* **`ScheduleLoadingPotentiallyUnusedPreload()`:** Another function related to optimizing preloads by deferring their loading.
* **`StartLoadAndFinishIfFailed()` and `ScheduleStartLoadAndFinishIfFailed()`:** These handle the actual starting of deferred preloads, with error handling.
* **`RemoveResourceLoader()`:** Cleans up after a resource load is finished or failed.
* **`StopFetching()`:** Halts ongoing resource fetches.
* **`SetDefersLoading()`:**  Allows pausing or resuming resource loading.
* **`UpdateAllImageResourcePriorities()`:**  Optimizes the loading order of images based on visibility and other factors.
* **`GetCacheIdentifier()`:** Determines how resources are cached.
* **`GetSubresourceBundleToken()` and `GetSubresourceBundleSourceUrl()`:**  Relate to fetching resources from web bundles.
* **`EmulateLoadStartedForInspector()`:**  Used for developer tools to simulate resource loading.
* **`PrepareForLeakDetection()`:**  Helps with identifying memory leaks related to resource loading.
* **`StopFetchingInternal()` and `StopFetchingIncludingKeepaliveLoaders()`:** Implement the stopping of resource fetches, with options for keep-alive connections.
* **`ScheduleStaleRevalidate()` and `RevalidateStaleResource()`:**  Mechanisms to refresh cached resources.
* **`GetBlobRegistry()`:** Accesses the blob registry for handling binary data.
* **`GetFrameOrWorkerScheduler()`:**  Accesses the scheduler for managing tasks.
* **`PopulateAndAddResourceTimingInfo()`:**  Gathers and reports performance timing data for resources.
* **`GetMatchingBundle()`:** Finds the web bundle associated with a given URL.
* **`CancelWebBundleSubresourceLoadersFor()`:** Cancels loads of resources from a specific web bundle.
* **`MaybeSaveResourceToStrongReference()`:**  Potentially saves frequently used resources in memory for faster access.
* **`MaybeStartSpeculativeImageDecode()` and `SpeculativeImageDecodeFinished()`:** Implement speculative decoding of images for improved rendering performance.
* **`OnMemoryPressure()`:** Handles memory pressure events by releasing cached resources.
* **`MaybeRecordLCPPSubresourceMetrics()`:**  Collects metrics related to the Largest Contentful Paint.
* **`MarkEarlyHintConsumedIfNeeded()`:** Tracks the usage of resources hinted by early hints.
* **`IsPotentiallyUnusedPreload()`:** Determines if a preloaded resource might not be needed.

Based on this analysis, I can now construct the summary.
这是 `blink/renderer/platform/loader/fetch/resource_fetcher.cc` 文件的第 4 部分，主要涵盖了 `ResourceFetcher` 类中关于 **处理资源加载完成、错误、启动加载、管理预加载、以及一些优化和辅助功能** 的实现细节。

以下是其功能的归纳：

**核心资源加载流程管理:**

* **处理加载完成 (`HandleLoaderFinish`)**:
    * 更新子资源加载的统计信息（数量，是否通过 Service Worker 加载）。
    * 如果被 Service Worker 控制，记录子资源加载是通过 Service Worker 处理还是回退到网络。
    * 更新全局的子资源加载统计信息。
    * 管理 keep-alive 连接的字节数。
    * 对于 multipart 资源，处理第一个 part 加载完成的情况。
    * 清理 `ResourceLoader` 对象。
    * 从 `resource_timing_info_map_` 获取并填充资源加载的性能数据（Resource Timing API）。
    * 如果响应不是 206 并且没有 Range 请求头，则将该资源从预加载缓存中移除。
    * 对于正常完成的加载 (`kDidFinishLoading`)：
        * 标记资源加载完成。
        * 如果是图片资源且来自缓存，并且启用了 `kSpeculativeImageDecodes` 特性，则将其加入到推测解码的候选队列。
        * 如果资源允许 stale-while-revalidate 并且网络层请求了重新验证，则安排重新验证。
    * 通知 `ResourceLoadObserver` 资源加载完成。
    * 可能将资源保存到强引用缓存中。
* **处理加载错误 (`HandleLoaderError`)**:
    * 更新 keep-alive 连接的字节数。
    * 清理 `ResourceLoader` 对象。
    * 从 `resource_timing_info_map_` 获取并填充资源加载的性能数据（Resource Timing API）。
    * 如果是因为 HTTP 错误取消的预加载，则不再重新请求该资源。
    * 如果遇到证书透明度要求的错误，则记录相关的 UseCounter。
    * 标记资源加载失败。
    * 通知 `ResourceLoadObserver` 资源加载失败。
* **将 ResourceLoader 移动到非阻塞队列 (`MoveResourceLoaderToNonBlocking`)**: 用于处理例如 multipart 资源加载的场景。
* **启动资源加载 (`StartLoad`)**:
    * 可以指定是否为潜在未使用的预加载。
    * 也可以指定请求体、图片加载阻塞策略和渲染阻塞行为。
    * 检查是否需要阻止子资源的加载。
    * 通知 `ResourceLoadObserver` 即将发送请求。
    * 管理 keep-alive 连接的字节数限制。
    * 创建 `ResourceLoader` 对象。
    * 根据资源类型和加载策略，将其添加到阻塞或非阻塞的加载器队列。
    * 暂停资源的虚拟时间。
    * 记录性能相关的发起者信息。
    * 启动 `ResourceLoader`。
    * 通知资源开始加载。

**预加载管理和优化:**

* **安排加载潜在未使用的预加载 (`ScheduleLoadingPotentiallyUnusedPreload`)**: 将可能未使用的预加载资源延迟加载，以优化初始加载性能。可以根据不同的特性配置选择不同的延迟加载策略（postTask 或基于 LCP Timing Predictor）。
* **启动加载并在失败时完成 (`StartLoadAndFinishIfFailed`, `ScheduleStartLoadAndFinishIfFailed`)**: 用于实际启动延迟的预加载，并在加载失败时将其标记为错误。
* **移除 ResourceLoader (`RemoveResourceLoader`)**: 当资源加载完成或失败时，从相应的加载器队列中移除。

**停止加载:**

* **停止资源获取 (`StopFetching`)**: 停止所有非 keep-alive 的资源加载。
* **设置延迟加载 (`SetDefersLoading`)**: 暂停或恢复所有阻塞和非阻塞的资源加载。

**图像加载优先级优化:**

* **更新所有图像资源的优先级 (`UpdateAllImageResourcePriorities`)**:  根据图像的可见性和其他因素动态调整图像资源的加载优先级，以优化渲染性能。这部分代码还涉及到一个关于图像加载优先级优化的 Feature Flag (`kImageLoadingPrioritizationFix`)。

**缓存管理:**

* **获取缓存标识符 (`GetCacheIdentifier`)**:  根据是否跳过 Service Worker 以及是否存在 Archive 或 Subresource Web Bundle 来确定资源的缓存标识符。
* **获取 Subresource Bundle 的 Token 和源 URL (`GetSubresourceBundleToken`, `GetSubresourceBundleSourceUrl`)**: 用于从 Web Bundle 中加载资源。

**开发者工具支持:**

* **模拟 Inspector 的加载开始事件 (`EmulateLoadStartedForInspector`)**: 用于在开发者工具中模拟资源加载的开始，以便进行调试和性能分析。

**内存管理和泄漏检测:**

* **准备泄漏检测 (`PrepareForLeakDetection`)**: 停止所有加载器，包括 keep-alive 的加载器，以避免影响泄漏检测的计数。

**内部停止加载:**

* **内部停止获取 (`StopFetchingInternal`)**: 提供更细粒度的停止加载控制，可以指定是否包含 keep-alive 的加载器。
* **停止所有加载 (包括 Keep-alive) (`StopFetchingIncludingKeepaliveLoaders`)**: 停止所有正在进行的资源加载，包括 keep-alive 的连接。

**Stale-While-Revalidate 支持:**

* **安排 Stale-While-Revalidate (`ScheduleStaleRevalidate`)**:  当资源允许 stale-while-revalidate 并且网络层指示需要重新验证时，安排重新验证请求。
* **重新验证过期的资源 (`RevalidateStaleResource`)**:  实际发起对过期资源的重新验证请求。

**其他辅助功能:**

* **获取 BlobRegistry (`GetBlobRegistry`)**: 用于处理 Blob 对象。
* **获取 Frame 或 Worker 的调度器 (`GetFrameOrWorkerScheduler`)**: 获取用于执行任务的调度器。
* **填充并添加资源时间信息 (`PopulateAndAddResourceTimingInfo`)**:  创建并添加到全局的资源时间信息列表，用于 Resource Timing API。
* **获取匹配的 Bundle (`GetMatchingBundle`)**:  查找与给定 URL 匹配的 Subresource Web Bundle。
* **取消 Web Bundle 子资源的加载 (`CancelWebBundleSubresourceLoadersFor`)**: 取消特定 Web Bundle 下的所有子资源加载。
* **可能将资源保存到强引用 (`MaybeSaveResourceToStrongReference`)**:  如果满足特定条件（例如资源大小），则将资源保存到强引用缓存中以提高访问速度。这是一个内存优化策略，可以通过 Feature Flag 控制。
* **可能开始推测性图像解码 (`MaybeStartSpeculativeImageDecode`, `SpeculativeImageDecodeFinished`)**:  如果启用了 `kSpeculativeImageDecodes` 特性，并且有符合条件的图片，则开始推测性地解码图像，以提高渲染性能。
* **处理内存压力 (`OnMemoryPressure`)**:  当系统内存压力过大时，可以释放强引用缓存中的资源。
* **可能记录 LCPP 子资源指标 (`MaybeRecordLCPPSubresourceMetrics`)**: 记录与 Largest Contentful Paint (LCP) 相关的子资源优先级提升指标。
* **根据需要标记 Early Hint 为已使用 (`MarkEarlyHintConsumedIfNeeded`)**:  检查通过 Early Hints 预加载的资源是否被实际使用。
* **判断是否为潜在未使用的预加载 (`IsPotentiallyUnusedPreload`)**:  判断给定的资源是否有可能是一个未被使用的预加载资源。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:** 当 JavaScript 代码请求加载一个新的脚本文件 (`<script src="...">`) 或通过 `fetch()` API 发起请求时，`ResourceFetcher` 负责处理这些请求，下载 JavaScript 文件。`HandleLoaderFinish` 会在 JavaScript 文件下载完成后被调用。
* **HTML:** 当浏览器解析 HTML 页面并遇到 `<img>`, `<link rel="stylesheet">`, `<script>` 等标签时，`ResourceFetcher` 会被调用来获取相应的图片、CSS 文件和 JavaScript 文件。`StartLoad` 会被调用来启动这些资源的加载。
* **CSS:** 当浏览器解析到 `<link rel="stylesheet">` 标签时，`ResourceFetcher` 会下载 CSS 文件。`HandleLoaderError` 会在 CSS 文件下载失败时被调用。`UpdateAllImageResourcePriorities` 可能会在 CSS 加载完成后，影响到页面中图片的加载优先级，因为 CSS 可能会改变元素的可见性。

**逻辑推理的假设输入与输出举例:**

**假设输入:** 一个 HTML 页面包含一个很大的图片和一个小的 JavaScript 文件，并且使用了 `<link rel="preload">` 预加载了这个图片。

**场景 1: 预加载未被使用**

* **输入:**  页面加载完成，但用户在图片渲染前就离开了页面。
* **输出:** `HandleUnusedPreloads` 被调用，`unused_preloads` 列表中包含该图片的 URL。回调函数被执行，通知 LCPP host 哪些预加载未被使用。

**场景 2: 图片加载完成**

* **输入:** 图片成功下载。
* **输出:** `HandleLoaderFinish` 被调用，`resource` 参数指向该图片资源。子资源加载统计信息更新，资源时间信息被收集，如果启用了推测解码，该图片可能会加入解码队列。

**场景 3: JavaScript 加载失败**

* **输入:** JavaScript 文件下载失败 (例如 404 错误)。
* **输出:** `HandleLoaderError` 被调用，`resource` 参数指向该 JavaScript 资源，`error` 参数包含错误信息。资源加载状态被设置为错误，`ResourceLoadObserver` 收到加载失败的通知。

**用户或编程常见的使用错误举例:**

* **预加载了但从未使用的资源:**  开发者可能使用了 `<link rel="preload">` 预加载了资源，但在后续的页面渲染过程中并没有实际使用该资源。`ResourceFetcher` 会通过 `HandleUnusedPreloads` 检测到这种情况，但这仍然会浪费用户的带宽。
* **错误的 keep-alive 配置:**  如果开发者错误地配置了 HTTP 的 keep-alive 头，可能导致连接无法正确关闭，`ResourceFetcher` 中的 `inflight_keepalive_bytes_` 可能会超出限制，导致后续请求失败。
* **不正确的缓存控制策略:**  开发者可能设置了不恰当的缓存控制头，导致资源无法被有效缓存或需要频繁重新验证，`ResourceFetcher` 的缓存管理功能可能无法发挥最佳效果。

总结来说，`ResourceFetcher` 是 Blink 引擎中负责资源获取和管理的关键组件，它处理了从发起请求到加载完成（或失败）的整个生命周期，并包含了诸如预加载优化、优先级控制、缓存管理等重要功能，直接关系到 Web 页面的加载性能和用户体验。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_fetcher.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
State::kWarnedUnused;
  }

  // Notify the unused preload list to the LCPP host.
  std::move(callback).Run(std::move(unused_preloads));
}

void ResourceFetcher::HandleLoaderFinish(Resource* resource,
                                         base::TimeTicks response_end,
                                         LoaderFinishType type,
                                         uint32_t inflight_keepalive_bytes) {
  DCHECK(resource);

  // kRaw might not be subresource, and we do not need them.
  if (resource->GetType() != ResourceType::kRaw) {
    ++subresource_load_metrics_.number_of_subresources_loaded;
    if (resource->GetResponse().WasFetchedViaServiceWorker()) {
      ++subresource_load_metrics_
            .number_of_subresource_loads_handled_by_service_worker;
    }
  }

  if (IsControlledByServiceWorker() ==
      mojom::blink::ControllerServiceWorkerMode::kControlled) {
    if (resource->GetResponse().WasFetchedViaServiceWorker()) {
      base::UmaHistogramEnumeration("ServiceWorker.Subresource.Handled.Type2",
                                    resource->GetType());
    } else {
      base::UmaHistogramEnumeration(
          "ServiceWorker.Subresource.Fallbacked.Type2", resource->GetType());
    }
    UpdateServiceWorkerSubresourceMetrics(
        resource->GetType(),
        resource->GetResponse().WasFetchedViaServiceWorker(),
        resource->GetResponse().GetServiceWorkerRouterInfo());
  }

  context_->UpdateSubresourceLoadMetrics(subresource_load_metrics_);

  DCHECK_LE(inflight_keepalive_bytes, inflight_keepalive_bytes_);
  inflight_keepalive_bytes_ -= inflight_keepalive_bytes;

  ResourceLoader* loader = resource->Loader();
  if (type == kDidFinishFirstPartInMultipart) {
    // When loading a multipart resource, make the loader non-block when
    // finishing loading the first part.
    MoveResourceLoaderToNonBlocking(loader);
  } else {
    RemoveResourceLoader(loader);
    DCHECK(!non_blocking_loaders_.Contains(loader));
  }
  DCHECK(!loaders_.Contains(loader));

  const int64_t encoded_data_length =
      resource->GetResponse().EncodedDataLength();

  PendingResourceTimingInfo info = resource_timing_info_map_.Take(resource);
  if (!info.is_null()) {
    if (resource->GetResponse().ShouldPopulateResourceTiming()) {
      PopulateAndAddResourceTimingInfo(resource, std::move(info), response_end);
    }
  }

  resource->VirtualTimePauser().UnpauseVirtualTime();

  // A response should not serve partial content if it was not requested via a
  // Range header: https://fetch.spec.whatwg.org/#main-fetch so keep it out
  // of the preload cache in case of a non-206 response (which generates an
  // error).
  if (resource->GetResponse().GetType() ==
          network::mojom::FetchResponseType::kOpaque &&
      resource->GetResponse().HasRangeRequested() &&
      !resource->GetResourceRequest().HttpHeaderFields().Contains(
          http_names::kRange)) {
    RemovePreload(resource);
  }

  if (type == kDidFinishLoading) {
    resource->Finish(response_end, freezable_task_runner_.get());
    if (resource->GetType() == ResourceType::kImage &&
        resource->GetContentStatus() == ResourceStatus::kCached &&
        base::FeatureList::IsEnabled(features::kSpeculativeImageDecodes)) {
      speculative_decode_candidate_images_.insert(resource);
      MaybeStartSpeculativeImageDecode();
    }

    // Since this resource came from the network stack we only schedule a stale
    // while revalidate request if the network asked us to. If we called
    // ShouldRevalidateStaleResponse here then the resource would be checking
    // the freshness based on current time. It is possible that the resource
    // is fresh at the time of the network stack handling but not at the time
    // handling here and we should not be forcing a revalidation in that case.
    // eg. network stack returning a resource with max-age=0.
    if (resource->GetResourceRequest().AllowsStaleResponse() &&
        resource->StaleRevalidationRequested()) {
      ScheduleStaleRevalidate(resource);
    }
  }
  if (resource_load_observer_) {
    DCHECK(!IsDetached());
    resource_load_observer_->DidFinishLoading(
        resource->InspectorId(), response_end, encoded_data_length,
        resource->GetResponse().DecodedBodyLength());
  }
  MaybeSaveResourceToStrongReference(resource);
}

void ResourceFetcher::HandleLoaderError(Resource* resource,
                                        base::TimeTicks finish_time,
                                        const ResourceError& error,
                                        uint32_t inflight_keepalive_bytes) {
  DCHECK(resource);

  DCHECK_LE(inflight_keepalive_bytes, inflight_keepalive_bytes_);
  inflight_keepalive_bytes_ -= inflight_keepalive_bytes;

  RemoveResourceLoader(resource->Loader());
  PendingResourceTimingInfo info = resource_timing_info_map_.Take(resource);

  if (!info.is_null()) {
    if (resource->GetResourceRequest().Url().ProtocolIsInHTTPFamily() ||
        (resource->GetResourceRequest().GetWebBundleTokenParams() &&
         resource->GetResourceRequest()
             .GetWebBundleTokenParams()
             ->bundle_url.IsValid())) {
      PopulateAndAddResourceTimingInfo(resource, std::move(info), finish_time);
    }
  }

  resource->VirtualTimePauser().UnpauseVirtualTime();
  // If the preload was cancelled due to an HTTP error, we don't want to request
  // the resource a second time.
  if (error.IsCancellation() && !error.IsCancelledFromHttpError()) {
    RemovePreload(resource);
  }
  if (network_utils::IsCertificateTransparencyRequiredError(
          error.ErrorCode())) {
    use_counter_->CountUse(
        mojom::WebFeature::kCertificateTransparencyRequiredErrorOnResourceLoad);
  }
  resource->FinishAsError(error, freezable_task_runner_.get());
  if (resource_load_observer_) {
    DCHECK(!IsDetached());
    resource_load_observer_->DidFailLoading(
        resource->LastResourceRequest().Url(), resource->InspectorId(), error,
        resource->GetResponse().EncodedDataLength(),
        ResourceLoadObserver::IsInternalRequest(
            resource->Options().initiator_info.name ==
            fetch_initiator_type_names::kInternal));
  }
}

void ResourceFetcher::MoveResourceLoaderToNonBlocking(ResourceLoader* loader) {
  DCHECK(loader);
  DCHECK(loaders_.Contains(loader));
  non_blocking_loaders_.insert(loader);
  loaders_.erase(loader);
}

bool ResourceFetcher::StartLoad(Resource* resource,
                                bool is_potentially_unused_preload) {
  CHECK(resource->GetType() == ResourceType::kFont ||
        resource->GetType() == ResourceType::kImage ||
        is_potentially_unused_preload);
  // Currently the metrics collection codes are duplicated here and in
  // UpdateMemoryCacheStats() because we have two calling paths for triggering a
  // load here and RequestResource().
  // TODO(https://crbug.com/1376866): Consider merging the duplicated code.
  if (resource->GetType() == ResourceType::kFont) {
    base::UmaHistogramEnumeration(
        RESOURCE_HISTOGRAM_PREFIX "Font",
        RevalidationPolicyForMetrics::kPreviouslyDeferredLoad);
  } else if (resource->GetType() == ResourceType::kImage) {
    base::UmaHistogramEnumeration(
        RESOURCE_HISTOGRAM_PREFIX "Image",
        RevalidationPolicyForMetrics::kPreviouslyDeferredLoad);
  }
  return StartLoad(resource, ResourceRequestBody(),
                   ImageLoadBlockingPolicy::kDefault,
                   RenderBlockingBehavior::kNonBlocking);
}

bool ResourceFetcher::StartLoad(
    Resource* resource,
    ResourceRequestBody request_body,
    ImageLoadBlockingPolicy policy,
    RenderBlockingBehavior render_blocking_behavior) {
  DCHECK(resource);
  DCHECK(resource->StillNeedsLoad());

  ResourceLoader* loader = nullptr;

  {
    // Forbids JavaScript/revalidation until start()
    // to prevent unintended state transitions.
    Resource::RevalidationStartForbiddenScope
        revalidation_start_forbidden_scope(resource);
    ScriptForbiddenScope script_forbidden_scope;

    if (properties_->ShouldBlockLoadingSubResource() && IsMainThread()) {
      MemoryCache::Get()->Remove(resource);
      return false;
    }

    const ResourceRequestHead& request_head = resource->GetResourceRequest();

    if (resource_load_observer_) {
      DCHECK(!IsDetached());
      ResourceRequest request(request_head);
      request.SetHttpBody(request_body.FormBody());
      ResourceResponse response;
      resource_load_observer_->WillSendRequest(
          request, response, resource->GetType(), resource->Options(),
          render_blocking_behavior, resource);
    }

    using QuotaType = decltype(inflight_keepalive_bytes_);
    QuotaType size = 0;
    if (request_head.GetKeepalive() && request_body.FormBody()) {
      auto original_size = request_body.FormBody()->SizeInBytes();
      DCHECK_LE(inflight_keepalive_bytes_, kKeepaliveInflightBytesQuota);
      if (original_size > std::numeric_limits<QuotaType>::max()) {
        return false;
      }
      size = static_cast<QuotaType>(original_size);
      if (kKeepaliveInflightBytesQuota - inflight_keepalive_bytes_ < size) {
        return false;
      }

      inflight_keepalive_bytes_ += size;
    }

    loader = MakeGarbageCollected<ResourceLoader>(
        this, scheduler_, resource, context_lifecycle_notifier_,
        std::move(request_body), size);
    // Preload requests should not block the load event. IsLinkPreload()
    // actually continues to return true for Resources matched from the preload
    // cache that must block the load event, but that is OK because this method
    // is not responsible for promoting matched preloads to load-blocking. This
    // is handled by MakePreloadedResourceBlockOnloadIfNeeded().
    if (!resource->IsLinkPreload() &&
        resource->IsLoadEventBlockingResourceType() &&
        policy != ImageLoadBlockingPolicy::kForceNonBlockingLoad) {
      loaders_.insert(loader);
    } else {
      non_blocking_loaders_.insert(loader);
    }
    resource->VirtualTimePauser().PauseVirtualTime();

    StorePerformanceTimingInitiatorInformation(resource,
                                               render_blocking_behavior);
  }

  loader->Start();

  {
    Resource::RevalidationStartForbiddenScope
        revalidation_start_forbidden_scope(resource);
    ScriptForbiddenScope script_forbidden_scope;

    // NotifyStartLoad() shouldn't cause AddClient/RemoveClient().
    Resource::ProhibitAddRemoveClientInScope
        prohibit_add_remove_client_in_scope(resource);
    if (!resource->IsLoaded()) {
      resource->NotifyStartLoad();
    }
  }
  return true;
}

void ResourceFetcher::ScheduleLoadingPotentiallyUnusedPreload(
    Resource* resource) {
  // Check the resource is already scheduled to start load or not.
  PreloadKey key(resource->Url(), resource->GetType());
  auto it = deferred_preloads_.find(key);
  if (it != deferred_preloads_.end() && it->value == resource) {
    return;
  }
  deferred_preloads_.insert(key, resource);

  switch (features::kLcppDeferUnusedPreloadTiming.Get()) {
    case features::LcppDeferUnusedPreloadTiming::kPostTask:
      ScheduleStartLoadAndFinishIfFailed(
          resource, /*is_potentially_unused_preload=*/true);
      break;
    case features::LcppDeferUnusedPreloadTiming::kLcpTimingPredictor:
      context_->AddLcpPredictedCallback(
          WTF::BindOnce(&ResourceFetcher::StartLoadAndFinishIfFailed,
                        WrapWeakPersistent(this), WrapWeakPersistent(resource),
                        /*is_potentially_unused_preload=*/true));
      break;
    case features::LcppDeferUnusedPreloadTiming::
        kLcpTimingPredictorWithPostTask:
      context_->AddLcpPredictedCallback(
          WTF::BindOnce(&ResourceFetcher::ScheduleStartLoadAndFinishIfFailed,
                        WrapWeakPersistent(this), WrapWeakPersistent(resource),
                        /*is_potentially_unused_preload=*/true));
      break;
  }
}

void ResourceFetcher::StartLoadAndFinishIfFailed(
    Resource* resource,
    bool is_potentially_unused_preload) {
  if (!resource) {
    return;
  }

  if (is_potentially_unused_preload) {
    RecordDeferUnusedPreloadHistograms(resource);
  }

  if (!resource->StillNeedsLoad()) {
    // When `resource` does not need load anymore, the resource load was already
    // started by a subsequent resource request.
    return;
  }
  if (!StartLoad(resource, is_potentially_unused_preload)) {
    resource->FinishAsError(ResourceError::CancelledError(resource->Url()),
                            freezable_task_runner_.get());
  }
}

void ResourceFetcher::ScheduleStartLoadAndFinishIfFailed(
    Resource* resource,
    bool is_potentially_unused_preload) {
  freezable_task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(&ResourceFetcher::StartLoadAndFinishIfFailed,
                    WrapWeakPersistent(this), WrapWeakPersistent(resource),
                    is_potentially_unused_preload));
}

void ResourceFetcher::RemoveResourceLoader(ResourceLoader* loader) {
  DCHECK(loader);

  if (loaders_.Contains(loader)) {
    loaders_.erase(loader);
  } else if (non_blocking_loaders_.Contains(loader)) {
    non_blocking_loaders_.erase(loader);
  } else {
    NOTREACHED();
  }

  if (loaders_.empty() && non_blocking_loaders_.empty()) {
    keepalive_loaders_task_handle_.Cancel();
  }
}

void ResourceFetcher::StopFetching() {
  StopFetchingInternal(StopFetchingTarget::kExcludingKeepaliveLoaders);
}

void ResourceFetcher::SetDefersLoading(LoaderFreezeMode mode) {
  for (const auto& loader : non_blocking_loaders_) {
    loader->SetDefersLoading(mode);
  }
  for (const auto& loader : loaders_) {
    loader->SetDefersLoading(mode);
  }
}

void ResourceFetcher::UpdateAllImageResourcePriorities() {
  TRACE_EVENT0(
      "blink",
      "ResourceLoadPriorityOptimizer::updateAllImageResourcePriorities");

  // Force all images to update their LastComputedPriority.
  for (Resource* resource : speculative_decode_candidate_images_) {
    resource->PriorityFromObservers();
  }
  speculative_decode_candidate_images_.erase_if(
      [](const WeakMember<Resource>& resource) -> bool {
        return resource->LastComputedPriority().visibility ==
               ResourcePriority::kNotVisible;
      });
  MaybeStartSpeculativeImageDecode();

  HeapVector<Member<Resource>> to_be_removed;
  for (Resource* resource : not_loaded_image_resources_) {
    if (resource->IsLoaded()) {
      to_be_removed.push_back(resource);
      continue;
    }

    if (!resource->IsLoading()) {
      continue;
    }

    auto priorities = resource->PriorityFromObservers();
    ResourcePriority resource_priority = priorities.first;
    ResourceLoadPriority computed_load_priority = ComputeLoadPriority(
        ResourceType::kImage, resource->GetResourceRequest(),
        resource_priority.visibility, FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kNotSpeculative,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false, std::nullopt, std::nullopt,
        resource_priority.is_lcp_resource);

    ResourcePriority resource_priority_excluding_image_loader =
        priorities.second;
    ResourceLoadPriority computed_load_priority_excluding_image_loader =
        ComputeLoadPriority(
            ResourceType::kImage, resource->GetResourceRequest(),
            resource_priority_excluding_image_loader.visibility,
            FetchParameters::DeferOption::kNoDefer,
            FetchParameters::SpeculativePreloadType::kNotSpeculative,
            RenderBlockingBehavior::kNonBlocking,
            mojom::blink::ScriptType::kClassic, false, std::nullopt,
            std::nullopt,
            resource_priority_excluding_image_loader.is_lcp_resource);

    // When enabled, `priority` is used, which considers the resource priority
    // via ImageLoader, i.e. ImageResourceContent
    // -> ImageLoader (as ImageResourceObserver)
    // -> LayoutImageResource
    // -> LayoutObject.
    //
    // The same priority is considered in `priority_excluding_image_loader` via
    // ImageResourceContent
    // -> LayoutObject (as ImageResourceObserver),
    // but the LayoutObject might be not registered yet as an
    // ImageResourceObserver while loading.
    // See https://crbug.com/1369823 for details.
    static const bool fix_enabled =
        base::FeatureList::IsEnabled(features::kImageLoadingPrioritizationFix);

    if (computed_load_priority !=
        computed_load_priority_excluding_image_loader) {
      // Mark pages affected by this fix for performance evaluation.
      use_counter_->CountUse(
          WebFeature::kEligibleForImageLoadingPrioritizationFix);
    }
    if (!fix_enabled) {
      resource_priority = resource_priority_excluding_image_loader;
      computed_load_priority = computed_load_priority_excluding_image_loader;
    }

    // Only boost the priority of an image, never lower it. This ensures that
    // there isn't priority churn if images move in and out of the viewport, or
    // are displayed more than once, both in and out of the viewport.
    if (computed_load_priority <= resource->GetResourceRequest().Priority()) {
      continue;
    }

    DCHECK_GT(computed_load_priority,
              resource->GetResourceRequest().Priority());
    resource->DidChangePriority(computed_load_priority,
                                resource_priority.intra_priority_value);
    TRACE_EVENT_NESTABLE_ASYNC_INSTANT1(
        TRACE_DISABLED_BY_DEFAULT("network"), "ResourcePrioritySet",
        TRACE_ID_WITH_SCOPE("BlinkResourceID",
                            TRACE_ID_LOCAL(resource->InspectorId())),
        "data", CreateTracedValueWithPriority(computed_load_priority));
    DCHECK(!IsDetached());
    resource_load_observer_->DidChangePriority(
        resource->InspectorId(), computed_load_priority,
        resource_priority.intra_priority_value);
  }

  not_loaded_image_resources_.RemoveAll(to_be_removed);
  // Explicitly free the backing store to not regress memory.
  // TODO(bikineev): Revisit when young generation is done.
  to_be_removed.clear();
}

String ResourceFetcher::GetCacheIdentifier(const KURL& url,
                                           bool skip_service_worker) const {
  if (!skip_service_worker &&
      properties_->GetControllerServiceWorkerMode() !=
          mojom::ControllerServiceWorkerMode::kNoController) {
    return String::Number(properties_->ServiceWorkerId());
  }

  // Requests that can be satisfied via `archive_` (i.e. MHTML) or
  // `subresource_web_bundles_` should not participate in the global caching,
  // but should use a bundle/mhtml-specific cache.
  if (archive_) {
    return archive_->GetCacheIdentifier();
  }

  SubresourceWebBundle* bundle = GetMatchingBundle(url);
  if (bundle) {
    return bundle->GetCacheIdentifier();
  }

  return MemoryCache::DefaultCacheIdentifier();
}

std::optional<base::UnguessableToken>
ResourceFetcher::GetSubresourceBundleToken(const KURL& url) const {
  SubresourceWebBundle* bundle = GetMatchingBundle(url);
  if (!bundle) {
    return std::nullopt;
  }
  return bundle->WebBundleToken();
}

std::optional<KURL> ResourceFetcher::GetSubresourceBundleSourceUrl(
    const KURL& url) const {
  SubresourceWebBundle* bundle = GetMatchingBundle(url);
  if (!bundle) {
    return std::nullopt;
  }
  return bundle->GetBundleUrl();
}

void ResourceFetcher::EmulateLoadStartedForInspector(
    Resource* resource,
    mojom::blink::RequestContextType request_context,
    network::mojom::RequestDestination request_destination,
    const AtomicString& initiator_name) {
  base::AutoReset<bool> r(&is_in_request_resource_, true);

  const KURL& url = resource->Url();
  if (CachedResource(url)) {
    return;
  }

  if (ResourceHasBeenEmulatedLoadStartedForInspector(url)) {
    return;
  }

  if (resource->ErrorOccurred()) {
    // We should ideally replay the error steps, but we cannot.
    return;
  }

  if (base::FeatureList::IsEnabled(
          features::kEmulateLoadStartedForInspectorOncePerResource)) {
    // Update the emulated load started for inspector resources map with the
    // resource so that future emulations of the same resource won't happen.
    String resource_url = MemoryCache::RemoveFragmentIdentifierIfNeeded(url);
    emulated_load_started_for_inspector_resources_map_.Set(resource_url,
                                                           resource);
  }

  ResourceRequest resource_request(url);
  resource_request.SetRequestContext(request_context);
  resource_request.SetRequestDestination(request_destination);
  if (!resource_request.PriorityHasBeenSet()) {
    resource_request.SetPriority(ComputeLoadPriority(
        resource->GetType(), resource_request, ResourcePriority::kNotVisible));
  }
  resource_request.SetPriorityIncremental(
      ShouldLoadIncremental(resource->GetType()));
  resource_request.SetReferrerString(Referrer::NoReferrer());
  resource_request.SetReferrerPolicy(network::mojom::ReferrerPolicy::kNever);
  resource_request.SetInspectorId(CreateUniqueIdentifier());

  ResourceLoaderOptions options = resource->Options();
  options.initiator_info.name = initiator_name;
  FetchParameters params(std::move(resource_request), options);
  ResourceRequest last_resource_request(resource->LastResourceRequest());
  Context().CanRequest(resource->GetType(), last_resource_request,
                       last_resource_request.Url(), params.Options(),
                       ReportingDisposition::kReport,
                       last_resource_request.GetRedirectInfo());
  if (resource->GetStatus() == ResourceStatus::kNotStarted ||
      resource->GetStatus() == ResourceStatus::kPending) {
    // If the loading has not started, then we return here because loading
    // related events will be reported to the ResourceLoadObserver. If the
    // loading is ongoing, then we return here too because the loading
    // activity is merged.
    return;
  }
  DCHECK_EQ(resource->GetStatus(), ResourceStatus::kCached);
  DidLoadResourceFromMemoryCache(resource, params.GetResourceRequest(),
                                 false /* is_static_data */,
                                 params.GetRenderBlockingBehavior());
}

void ResourceFetcher::PrepareForLeakDetection() {
  // Stop loaders including keepalive ones that may persist after page
  // navigation and thus affect instance counters of leak detection.
  StopFetchingIncludingKeepaliveLoaders();
}

void ResourceFetcher::StopFetchingInternal(StopFetchingTarget target) {
  // TODO(toyoshim): May want to suspend scheduler while canceling loaders so
  // that the cancellations below do not awake unnecessary scheduling.

  HeapVector<Member<ResourceLoader>> loaders_to_cancel;
  for (const auto& loader : non_blocking_loaders_) {
    if (target == StopFetchingTarget::kIncludingKeepaliveLoaders ||
        !loader->ShouldBeKeptAliveWhenDetached()) {
      loaders_to_cancel.push_back(loader);
    }
  }
  for (const auto& loader : loaders_) {
    if (target == StopFetchingTarget::kIncludingKeepaliveLoaders ||
        !loader->ShouldBeKeptAliveWhenDetached()) {
      loaders_to_cancel.push_back(loader);
    }
  }

  for (const auto& loader : loaders_to_cancel) {
    if (loaders_.Contains(loader) || non_blocking_loaders_.Contains(loader)) {
      loader->Cancel();
    }
  }
}

void ResourceFetcher::StopFetchingIncludingKeepaliveLoaders() {
  StopFetchingInternal(StopFetchingTarget::kIncludingKeepaliveLoaders);
}

void ResourceFetcher::ScheduleStaleRevalidate(Resource* stale_resource) {
  if (stale_resource->StaleRevalidationStarted()) {
    return;
  }
  stale_resource->SetStaleRevalidationStarted();
  freezable_task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(&ResourceFetcher::RevalidateStaleResource,
                    WrapWeakPersistent(this), WrapPersistent(stale_resource)));
}

void ResourceFetcher::RevalidateStaleResource(Resource* stale_resource) {
  // Creating FetchParams from Resource::GetResourceRequest doesn't create
  // the exact same request as the original one, while for revalidation
  // purpose this is probably fine.
  // TODO(dtapuska): revisit this when we have a better way to re-dispatch
  // requests.
  ResourceRequest request;
  request.CopyHeadFrom(stale_resource->GetResourceRequest());
  // TODO(https://crbug.com/1405800): investigate whether it's correct to use a
  // null `world` in the ResourceLoaderOptions below.
  FetchParameters params(std::move(request),
                         ResourceLoaderOptions(/*world=*/nullptr));
  params.SetStaleRevalidation(true);
  params.MutableResourceRequest().SetSkipServiceWorker(true);
  // Stale revalidation resource requests should be very low regardless of
  // the |type|.
  params.MutableResourceRequest().SetPriority(ResourceLoadPriority::kVeryLow);
  RawResource::Fetch(
      params, this,
      MakeGarbageCollected<StaleRevalidationResourceClient>(stale_resource));
}

mojom::blink::BlobRegistry* ResourceFetcher::GetBlobRegistry() {
  if (!blob_registry_remote_.is_bound()) {
    Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
        blob_registry_remote_.BindNewPipeAndPassReceiver(
            freezable_task_runner_));
  }
  return blob_registry_remote_.get();
}

FrameOrWorkerScheduler* ResourceFetcher::GetFrameOrWorkerScheduler() {
  return frame_or_worker_scheduler_.get();
}

void ResourceFetcher::PopulateAndAddResourceTimingInfo(
    Resource* resource,
    const PendingResourceTimingInfo& pending_info,
    base::TimeTicks response_end) {
  if (resource->GetResourceRequest().IsFromOriginDirtyStyleSheet()) {
    return;
  }

  // Resource timing entries that correspond to resources fetched by extensions
  // are precluded.
  if (resource->Options().world_for_csp &&
      resource->Options().world_for_csp->IsIsolatedWorld()) {
    return;
  }

  AtomicString initiator_type = resource->IsPreloadedByEarlyHints()
                                    ? AtomicString(kEarlyHintsInitiatorType)
                                    : pending_info.initiator_type;

  const KURL& initial_url =
      resource->GetResourceRequest().GetRedirectInfo().has_value()
          ? resource->GetResourceRequest().GetRedirectInfo()->original_url
          : resource->GetResourceRequest().Url();

  mojom::blink::ResourceTimingInfoPtr info = CreateResourceTimingInfo(
      pending_info.start_time, initial_url, &resource->GetResponse());
  if (info->allow_timing_details) {
    info->last_redirect_end_time = pending_info.redirect_end_time;
  }
  info->render_blocking_status = pending_info.render_blocking_behavior ==
                                 RenderBlockingBehavior::kBlocking;
  info->response_end = response_end;
  // Store LCP breakdown timings for images.
  if (resource->GetType() == ResourceType::kImage) {
    // The resource_load_timing may be null in tests.
    if (ResourceLoadTiming* resource_load_timing =
            resource->GetResponse().GetResourceLoadTiming()) {
      resource_load_timing->SetDiscoveryTime(info->start_time);
      resource_load_timing->SetResponseEnd(response_end);
    }
  }

  Context().AddResourceTiming(std::move(info), initiator_type);
}

SubresourceWebBundle* ResourceFetcher::GetMatchingBundle(
    const KURL& url) const {
  return subresource_web_bundles_
             ? subresource_web_bundles_->GetMatchingBundle(url)
             : nullptr;
}

void ResourceFetcher::CancelWebBundleSubresourceLoadersFor(
    const base::UnguessableToken& web_bundle_token) {
  // Copy to avoid concurrent iteration and modification.
  auto loaders = loaders_;
  for (const auto& loader : loaders) {
    loader->CancelIfWebBundleTokenMatches(web_bundle_token);
  }
  auto non_blocking_loaders = non_blocking_loaders_;
  for (const auto& loader : non_blocking_loaders) {
    loader->CancelIfWebBundleTokenMatches(web_bundle_token);
  }
}

void ResourceFetcher::MaybeSaveResourceToStrongReference(Resource* resource) {
  if (!base::FeatureList::IsEnabled(features::kMemoryCacheStrongReference)) {
    return;
  }

  const size_t total_size_threshold = static_cast<size_t>(
      features::kMemoryCacheStrongReferenceTotalSizeThresholdParam.Get());
  const size_t resource_size_threshold = static_cast<size_t>(
      features::kMemoryCacheStrongReferenceResourceSizeThresholdParam.Get());
  const size_t resource_size =
      static_cast<size_t>(resource->GetResponse().DecodedBodyLength());
  const bool size_is_small_enough = resource_size <= resource_size_threshold &&
                                    resource_size <= total_size_threshold;

  if (!size_is_small_enough) {
    return;
  }

  const SecurityOrigin* settings_object_origin =
      properties_->GetFetchClientSettingsObject().GetSecurityOrigin();
  if (!ShouldResourceBeKeptStrongReference(resource, settings_object_origin)) {
    return;
  }

  if (base::FeatureList::IsEnabled(
          features::kResourceFetcherStoresStrongReferences)) {
    // If the size would take us over, don't store it.
    if (document_resource_strong_refs_total_size_ + resource_size >
        total_size_threshold) {
      return;
    }
    document_resource_strong_refs_.insert(resource);
    document_resource_strong_refs_total_size_ += resource_size;
    freezable_task_runner_->PostDelayedTask(
        FROM_HERE,
        WTF::BindOnce(&ResourceFetcher::RemoveResourceStrongReference,
                      WrapWeakPersistent(this), WrapWeakPersistent(resource)),
        GetResourceStrongReferenceTimeout(resource, *use_counter_));
  } else {
    MemoryCache::Get()->SaveStrongReference(resource);
  }
}

void ResourceFetcher::MaybeStartSpeculativeImageDecode() {
  CHECK(base::FeatureList::IsEnabled(features::kSpeculativeImageDecodes) ||
        !speculative_decode_in_flight_);
  CHECK(base::FeatureList::IsEnabled(features::kSpeculativeImageDecodes) ||
        speculative_decode_candidate_images_.empty());
  if (speculative_decode_in_flight_) {
    return;
  }
  // Find the highest priority image to decode.
  Resource* image_to_decode = nullptr;
  for (Resource* resource : speculative_decode_candidate_images_) {
    const ResourcePriority& priority = resource->LastComputedPriority();
    if (priority.visibility != ResourcePriority::kVisible) {
      continue;
    }
    if (!image_to_decode ||
        CompareResourcePriorities(
            priority, image_to_decode->LastComputedPriority()) > 0) {
      image_to_decode = resource;
    }
  }
  if (image_to_decode) {
    speculative_decode_candidate_images_.erase(image_to_decode);
    Context().StartSpeculativeImageDecode(
        image_to_decode,
        WTF::BindOnce(&ResourceFetcher::SpeculativeImageDecodeFinished,
                      WrapWeakPersistent(this)));
    speculative_decode_in_flight_ = true;
  }
}

void ResourceFetcher::SpeculativeImageDecodeFinished() {
  speculative_decode_in_flight_ = false;
  MaybeStartSpeculativeImageDecode();
}

void ResourceFetcher::OnMemoryPressure(
    base::MemoryPressureListener::MemoryPressureLevel level) {
  if (base::FeatureList::IsEnabled(
          features::kReleaseResourceStrongReferencesOnMemoryPressure)) {
    document_resource_strong_refs_.clear();
    document_resource_strong_refs_total_size_ = 0;
  }
}

void ResourceFetcher::MaybeRecordLCPPSubresourceMetrics(
    const KURL& document_url) {
  if (!document_url.IsValid() || !document_url.ProtocolIsInHTTPFamily()) {
    return;
  }

  if (!properties_->IsOutermostMainFrame()) {
    return;
  }

  if (!context_->DoesLCPPHaveAnyHintData()) {
    return;
  }

  base::UmaHistogramCounts100(
      "Blink.LCPP.PotentiallyLCPResourcePriorityBoosts2",
      potentially_lcp_resource_priority_boosts_);
}

void ResourceFetcher::MarkEarlyHintConsumedIfNeeded(
    uint64_t inspector_id,
    Resource* resource,
    const ResourceResponse& response) {
  const KURL& initial_url =
      resource->GetResourceRequest().GetRedirectInfo().has_value()
          ? resource->GetResourceRequest().GetRedirectInfo()->original_url
          : resource->GetResourceRequest().Url();
  auto iter = unused_early_hints_preloaded_resources_.find(initial_url);
  if (iter != unused_early_hints_preloaded_resources_.end()) {
    unused_early_hints_preloaded_resources_.erase(iter);
    // The network service may not reuse the response fetched by the early hints
    // due to cache control policies.
    if (!response.NetworkAccessed() &&
        (!response.WasFetchedViaServiceWorker() ||
         response.IsServiceWorkerPassThrough())) {
      resource->SetIsPreloadedByEarlyHints();
    }
  }
}

bool ResourceFetcher::IsPotentiallyUnusedPreload(
    ResourceType type,
    const FetchParameters& params) const {
  static const bool kDeferUnusedPreload =
      b
```