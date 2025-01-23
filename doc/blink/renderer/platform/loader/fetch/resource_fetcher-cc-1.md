Response:
The user wants a summary of the functionality of the provided C++ code snippet from the `resource_fetcher.cc` file in the Chromium Blink engine.

I need to identify the key operations and responsibilities of the `ResourceFetcher` class based on the code.

Specifically, I should look for:
- How it handles resource requests.
- Its interaction with caching mechanisms.
- Its relation to JavaScript, HTML, and CSS (if any).
- Logical deductions with example inputs and outputs.
- Common user/programming errors related to its functionality.

The request specifies this is part 2 of 5, so I should focus on summarizing the functionality presented in this specific snippet.

**High-level plan:**

1. Identify the main methods and their purpose within the provided code.
2. Analyze how these methods contribute to the overall resource fetching process.
3. Look for connections to web technologies (JavaScript, HTML, CSS).
4. Infer potential logical outcomes based on method execution.
5. Identify potential misuse or common errors.
根据提供的代码片段，`ResourceFetcher` 的功能可以归纳为以下几点：

**核心功能：管理和执行资源获取请求**

这个代码片段主要展示了 `ResourceFetcher` 类处理资源请求的核心逻辑，包括检查缓存、创建资源对象、确定加载策略以及启动加载等环节。

**具体功能点：**

1. **优先级调整 (AdjustPriorityForLCPBoost):**  根据是否为潜在 LCP (Largest Contentful Paint) 元素以及图片大小，调整资源加载的优先级。
    *   **与 HTML/CSS 的关系：**  LCP 是衡量用户体验的关键指标，通常与页面上的主要图片或文本块相关。这个功能通过识别这些重要资源并提升其加载优先级，来优化页面加载速度，从而提升用户体验。
    *   **举例说明：** 如果一个 `<img>` 标签被认为是 LCP 元素（例如通过 `loading="eager"` 属性或者渲染引擎的启发式判断），并且是一个小尺寸图片，那么其加载优先级可能会被提升，以便更快地显示出来。
    *   **假设输入与输出：**
        *   **假设输入：** `is_potentially_lcp_element = true`, `is_small_image = true`, `priority_so_far = ResourceLoadPriority::kLow`
        *   **预期输出：** `new_priority = ResourceLoadPriority::kHigh` (假设 LCP 提升策略是将优先级提升到最高)
        *   **假设输入：** `is_potentially_lcp_element = false`, `is_small_image = true`, `priority_so_far = ResourceLoadPriority::kLow`
        *   **预期输出：** `new_priority = ResourceLoadPriority::kLow` (优先级保持不变)

2. **构造函数和析构函数:** 初始化和清理 `ResourceFetcher` 的实例，包括设置各种依赖项（如任务运行器、计数器、调度器等）。

3. **状态查询 (IsDetached):**  检查 `ResourceFetcher` 是否已分离，这可能表示其关联的上下文（例如 Document）已被销毁。

4. **缓存访问 (CachedResource, ResourceHasBeenEmulatedLoadStartedForInspector):**  提供访问已缓存资源的接口。`CachedResource` 用于获取实际缓存的资源，而 `ResourceHasBeenEmulatedLoadStartedForInspector`  用于调试，判断 Inspector 是否模拟启动了资源的加载。

5. **移动资源强引用 (MoveResourceStrongReferences):**  用于管理对资源的强引用，这在资源管理和垃圾回收中很重要。

6. **Service Worker 控制状态查询 (IsControlledByServiceWorker):**  判断资源加载是否受 Service Worker 控制。
    *   **与 JavaScript 的关系：** Service Worker 是使用 JavaScript 编写的，可以拦截和处理网络请求，包括资源加载。

7. **确定加载策略 (GetDeferPolicy):**  根据资源类型和请求参数，判断是否应该延迟加载资源。
    *   **与 HTML/CSS/JavaScript 的关系：**  此功能会根据资源类型（例如字体、图片、脚本）和相关的 HTML 属性或请求头（例如 `<link rel="preload">`、`loading="lazy"`）来决定是否延迟加载。
    *   **举例说明：**
        *   **假设输入：** `type = ResourceType::kFont`, `params.IsLinkPreload() = false`
        *   **预期输出：** `DeferPolicy::kDefer` (非预加载的字体默认延迟加载)
        *   **假设输入：** `type = ResourceType::kImage`, `params.GetImageRequestBehavior() = FetchParameters::ImageRequestBehavior::kDeferImageLoad`
        *   **预期输出：** `DeferPolicy::kDefer` (显式指示延迟加载图片)

8. **判断资源加载状态 (ResourceAlreadyLoadStarted, ResourceNeedsLoad):**  检查资源是否已经开始加载，以及是否需要加载。

9. **处理内存缓存加载 (DidLoadResourceFromMemoryCache):**  当资源从内存缓存加载时执行的操作，包括通知观察者、记录性能数据等。
    *   **与 HTML/CSS/JavaScript 的关系：**  内存缓存可以加速静态资源的加载，如图片、样式表和脚本文件。

10. **为静态数据创建资源 (CreateResourceForStaticData):**  为 data URL 或 MHTML 档案中的资源创建资源对象。
    *   **与 HTML/CSS/JavaScript 的关系：**  data URL 可以将小型的图片、样式或脚本直接嵌入到 HTML 中。MHTML 档案则包含了整个网页及其资源。
    *   **常见使用错误：**  data URL 的内容编码错误或 MIME 类型不匹配会导致资源加载失败。

11. **处理被阻止的请求 (ResourceForBlockedRequest):**  当资源请求因为某些原因被阻止时，创建相应的资源对象并标记为错误状态。
    *   **常见使用错误：**  CSP (Content Security Policy) 配置错误可能导致资源被阻止加载。

12. **调整预加载资源的阻塞行为 (MakePreloadedResourceBlockOnloadIfNeeded):**  根据后续请求的需求，调整预加载资源的加载阻塞行为。
    *   **与 HTML 的关系：**  `<link rel="preload">` 用于预加载资源，这个功能确保在需要时，预加载的资源能够阻塞页面的渲染。

13. **将加载策略映射到指标 (MapToPolicyForMetrics):**  将内部的加载策略映射到用于性能指标记录的枚举值。

14. **更新内存缓存统计信息 (UpdateMemoryCacheStats):**  记录与内存缓存相关的统计信息，用于性能分析。

15. **判断是否包含预加载资源 (ContainsAsPreload) 和移除预加载资源 (RemovePreload):** 管理预加载的资源。

16. **为透明占位符图片更新请求 (UpdateRequestForTransparentPlaceholderImage):**  对于使用透明占位符优化的图片加载，修改请求参数。

17. **为 WebBundle 准备请求 (PrepareRequestForWebBundle):**  如果资源属于 WebBundle，则设置相应的请求参数。

18. **获取或创建 SubresourceWebBundleList 和 UkmRecorder:**  用于管理 WebBundle 和记录用户体验指标 (Ukm)。

19. **核心资源请求处理 (RequestResource):**  处理资源请求的入口点，包含了各种准备工作、缓存检查、加载策略确定和资源创建等步骤。

**与 JavaScript, HTML, CSS 的功能关系举例说明：**

*   **JavaScript:** 当 JavaScript 代码发起一个 `fetch()` 请求或者动态创建 `<img>` 标签时，`ResourceFetcher` 会被调用来处理这些请求。`IsControlledByServiceWorker` 方法会检查是否有 Service Worker 拦截了这些请求。
*   **HTML:**  当浏览器解析 HTML 文档时，遇到 `<img>`、`<link>`、`<script>` 等标签时，会创建相应的资源请求，并由 `ResourceFetcher` 处理。`GetDeferPolicy` 方法会根据 `loading="lazy"` 等 HTML 属性决定是否延迟加载图片。
*   **CSS:**  当浏览器解析 CSS 样式表时，遇到 `@import` 或 `url()` 引用外部资源（如图片、字体）时，也会创建资源请求并由 `ResourceFetcher` 处理。`AdjustPriorityForLCPBoost` 可能影响 CSS 中引用的背景图片的加载优先级。

**逻辑推理的假设输入与输出举例说明：**

在上述功能点中已提供。

**涉及用户或者编程常见的使用错误举例说明：**

*   **data URL 使用错误：**  手动创建 data URL 时，可能会出现 base64 编码错误或 MIME 类型设置不当，导致 `CreateResourceForStaticData` 解析失败。
*   **CSP 配置错误：**  如果 CSP 配置不当，阻止了某些资源的加载，`ResourceFetcher` 会调用 `ResourceForBlockedRequest` 创建错误状态的资源。用户可能会在开发者工具的控制台中看到 CSP 报错信息。
*   **预加载使用不当：**  过度或不必要地使用 `<link rel="preload">` 可能会导致某些资源优先级过高，反而影响其他关键资源的加载，虽然 `ResourceFetcher` 试图优化，但错误的使用方式仍可能导致性能问题。

总而言之，这段代码展示了 `ResourceFetcher` 如何在 Blink 渲染引擎中扮演着资源加载管理者的角色，它与 HTML、CSS 和 JavaScript 的资源加载行为紧密相关，并通过缓存、优先级调整和策略控制来优化网页的加载性能。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_fetcher.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ost &&
      context_->DoesLCPPHaveLcpElementLocatorHintData()) {
    new_priority = priority_so_far;
  }

  // Only records HTTP family URLs (e.g. Exclude data URLs).
  if (resource_request.Url().ProtocolIsInHTTPFamily()) {
    MaybeRecordBoostImagePriorityReason(priority_so_far != new_priority,
                                        is_potentially_lcp_element,
                                        is_small_image);
  }

  return new_priority;
}

ResourceFetcher::ResourceFetcher(const ResourceFetcherInit& init)
    : properties_(*init.properties),
      context_(init.context),
      freezable_task_runner_(init.freezable_task_runner),
      unfreezable_task_runner_(init.unfreezable_task_runner),
      use_counter_(init.use_counter
                       ? init.use_counter
                       : MakeGarbageCollected<DetachableUseCounter>(nullptr)),
      console_logger_(init.console_logger
                          ? init.console_logger
                          : MakeGarbageCollected<DetachableConsoleLogger>()),
      loader_factory_(init.loader_factory),
      scheduler_(MakeGarbageCollected<ResourceLoadScheduler>(
          init.initial_throttling_policy,
          init.throttle_option_override,
          *properties_,
          init.frame_or_worker_scheduler,
          *console_logger_,
          init.loading_behavior_observer)),
      back_forward_cache_loader_helper_(init.back_forward_cache_loader_helper),
      archive_(init.archive),
      resource_timing_report_timer_(
          freezable_task_runner_,
          this,
          &ResourceFetcher::ResourceTimingReportTimerFired),
      frame_or_worker_scheduler_(
          init.frame_or_worker_scheduler
              ? init.frame_or_worker_scheduler->GetWeakPtr()
              : nullptr),
      blob_registry_remote_(init.context_lifecycle_notifier),
      context_lifecycle_notifier_(init.context_lifecycle_notifier),
      auto_load_images_(true),
      allow_stale_resources_(false),
      image_fetched_(false),
      transparent_image_optimization_enabled_(base::FeatureList::IsEnabled(
          features::kSimplifyLoadingTransparentPlaceholderImage)),
      speculative_decode_in_flight_(false) {
  InstanceCounters::IncrementCounter(InstanceCounters::kResourceFetcherCounter);

  // Determine the number of images that should get a boosted priority and the
  // pixel area threshold for determining "small" images.
  // TODO(http://crbug.com/1431169): Change these to constexpr after the
  // experiments determine appropriate values.
  if (base::FeatureList::IsEnabled(features::kBoostImagePriority)) {
    boosted_image_target_ = features::kBoostImagePriorityImageCount.Get();
    small_image_max_size_ = features::kBoostImagePriorityImageSize.Get();
  }

  if (IsMainThread()) {
    MainThreadFetchersSet().insert(this);
    MemoryPressureListenerRegistry::Instance().RegisterClient(this);
  }
}

ResourceFetcher::~ResourceFetcher() {
  InstanceCounters::DecrementCounter(InstanceCounters::kResourceFetcherCounter);
}

bool ResourceFetcher::IsDetached() const {
  return properties_->IsDetached();
}

Resource* ResourceFetcher::CachedResource(const KURL& resource_url) const {
  if (resource_url.IsEmpty()) {
    return nullptr;
  }
  KURL url = MemoryCache::RemoveFragmentIdentifierIfNeeded(resource_url);
  const auto it = cached_resources_map_.find(url);
  if (it == cached_resources_map_.end()) {
    return nullptr;
  }
  return it->value.Get();
}

bool ResourceFetcher::ResourceHasBeenEmulatedLoadStartedForInspector(
    const KURL& resource_url) const {
  if (resource_url.IsEmpty()) {
    return false;
  }
  KURL url = MemoryCache::RemoveFragmentIdentifierIfNeeded(resource_url);
  const auto it = emulated_load_started_for_inspector_resources_map_.find(url);
  if (it == emulated_load_started_for_inspector_resources_map_.end()) {
    return false;
  }
  return true;
}

const HeapHashSet<Member<Resource>>
ResourceFetcher::MoveResourceStrongReferences() {
  document_resource_strong_refs_total_size_ = 0;
  return std::move(document_resource_strong_refs_);
}

mojom::ControllerServiceWorkerMode
ResourceFetcher::IsControlledByServiceWorker() const {
  return properties_->GetControllerServiceWorkerMode();
}

ResourceFetcher::DeferPolicy ResourceFetcher::GetDeferPolicy(
    ResourceType type,
    const FetchParameters& params) const {
  // Defer a font load until it is actually needed unless this is a link
  // preload.
  if (type == ResourceType::kFont && !params.IsLinkPreload()) {
    return DeferPolicy::kDefer;
  }

  // Defer loading images when:
  // - images are disabled.
  // - image loading is disabled and the image is not a data url.
  // - instructed to defer loading images from network.
  if (type == ResourceType::kImage &&
      (ShouldDeferImageLoad(params.Url()) ||
       params.GetImageRequestBehavior() ==
           FetchParameters::ImageRequestBehavior::kDeferImageLoad)) {
    return DeferPolicy::kDefer;
  }

  // Check if the resource is marked as a potentially unused preload request.
  if (IsPotentiallyUnusedPreload(type, params)) {
    return DeferPolicy::kDeferAndSchedule;
  }

  return DeferPolicy::kNoDefer;
}

bool ResourceFetcher::ResourceAlreadyLoadStarted(Resource* resource,
                                                 RevalidationPolicy policy) {
  return policy == RevalidationPolicy::kUse && resource &&
         !resource->StillNeedsLoad();
}

bool ResourceFetcher::ResourceNeedsLoad(Resource* resource,
                                        RevalidationPolicy policy,
                                        DeferPolicy defer_policy) const {
  switch (defer_policy) {
    case DeferPolicy::kNoDefer:
      // MHTML documents should not trigger actual loads (i.e. all resource
      // requests should be fulfilled by the MHTML archive).
      return !archive_ && !ResourceAlreadyLoadStarted(resource, policy);
    case DeferPolicy::kDefer:
    case DeferPolicy::kDeferAndSchedule:
      return false;
  }
}

void ResourceFetcher::DidLoadResourceFromMemoryCache(
    Resource* resource,
    const ResourceRequest& request,
    bool is_static_data,
    RenderBlockingBehavior render_blocking_behavior) {
  if (IsDetached() || !resource_load_observer_) {
    return;
  }

  if (!is_static_data) {
    MarkEarlyHintConsumedIfNeeded(request.InspectorId(), resource,
                                  resource->GetResponse());
  }

  // Only call ResourceLoadObserver callbacks for placeholder images when
  // devtools is opened to get maximum performance.
  // TODO(crbug.com/41496436): Explore optimizing this in general for
  // `is_static_data`.
  if (!IsSimplifyLoadingTransparentPlaceholderImageEnabled() ||
      (request.GetKnownTransparentPlaceholderImageIndex() == kNotFound) ||
      (resource_load_observer_->InterestedInAllRequests())) {
    resource_load_observer_->WillSendRequest(
        request, ResourceResponse() /* redirects */, resource->GetType(),
        resource->Options(), render_blocking_behavior, resource);
    resource_load_observer_->DidReceiveResponse(
        request.InspectorId(), request, resource->GetResponse(), resource,
        ResourceLoadObserver::ResponseSource::kFromMemoryCache);
    if (resource->EncodedSize() > 0) {
      resource_load_observer_->DidReceiveData(
          request.InspectorId(),
          base::SpanOrSize<const char>(resource->EncodedSize()));
    }
    resource_load_observer_->DidFinishLoading(
        request.InspectorId(), base::TimeTicks(), 0,
        resource->GetResponse().DecodedBodyLength());
  }

  if (!is_static_data) {
    base::TimeTicks now = base::TimeTicks::Now();
    ResourceResponse final_response = resource->GetResponse();
    final_response.SetResourceLoadTiming(nullptr);
    final_response.SetEncodedDataLength(0);
    // Resources loaded from memory cache should be reported the first time
    // they're used.
    KURL initial_url =
        resource->GetResourceRequest().GetRedirectInfo().has_value()
            ? resource->GetResourceRequest().GetRedirectInfo()->original_url
            : resource->GetResourceRequest().Url();
    mojom::blink::ResourceTimingInfoPtr info =
        CreateResourceTimingInfo(now, initial_url, &final_response);
    info->response_end = now;
    info->render_blocking_status =
        render_blocking_behavior == RenderBlockingBehavior::kBlocking;

    // Create a ResourceLoadTiming object and store LCP breakdown timings for
    // images.
    if (resource->GetType() == ResourceType::kImage) {
      // The resource_load_timing may be null in tests.
      if (ResourceLoadTiming* resource_load_timing =
              resource->GetResponse().GetResourceLoadTiming()) {
        resource_load_timing->SetDiscoveryTime(info->start_time);
        resource_load_timing->SetSendStart(info->start_time);
        resource_load_timing->SetResponseEnd(info->start_time);
      }
    }

    AtomicString initiator_type = resource->IsPreloadedByEarlyHints()
                                      ? AtomicString(kEarlyHintsInitiatorType)
                                      : resource->Options().initiator_info.name;
    // If the fetch originated from user agent CSS we do not emit a resource
    // timing entry.
    if (initiator_type != fetch_initiator_type_names::kUacss) {
      scheduled_resource_timing_reports_.push_back(
          ScheduledResourceTimingInfo{std::move(info), initiator_type});

      if (!resource_timing_report_timer_.IsActive()) {
        resource_timing_report_timer_.StartOneShot(base::TimeDelta(),
                                                   FROM_HERE);
      }
    }
  }
}

Resource* ResourceFetcher::CreateResourceForStaticData(
    const FetchParameters& params,
    const ResourceFactory& factory) {
  const KURL& url = params.GetResourceRequest().Url();
  DCHECK(url.ProtocolIsData() || archive_);

  if (!archive_ && factory.GetType() == ResourceType::kRaw) {
    return nullptr;
  }

  const String cache_identifier = GetCacheIdentifier(
      url, params.GetResourceRequest().GetSkipServiceWorker());
  // Most off-main-thread resource fetches use Resource::kRaw and don't reach
  // this point, but off-main-thread module fetches might.
  if (IsMainThread()) {
    if (Resource* old_resource =
            MemoryCache::Get()->ResourceForURL(url, cache_identifier)) {
      // There's no reason to re-parse if we saved the data from the previous
      // parse.
      if (params.Options().data_buffering_policy != kDoNotBufferData) {
        return old_resource;
      }
      MemoryCache::Get()->Remove(old_resource);
    }
  }

  ResourceResponse response;
  scoped_refptr<SharedBuffer> data;
  if (IsSimplifyLoadingTransparentPlaceholderImageEnabled() &&
      (params.GetResourceRequest().GetKnownTransparentPlaceholderImageIndex() !=
       kNotFound)) {
    // Skip the construction of `data`, since we won't use it.

    // We can defer the construction of `response`, but that would result in
    // `ImageResource` instantiation even in the data url parse failure
    // cases. Probably that's okay.
    // TODO(crbug.com/41496436): Revisit this.
  } else if (url.ProtocolIsData()) {
    int result;
    std::tie(result, response, data) = network_utils::ParseDataURL(
        url, params.GetResourceRequest().HttpMethod(),
        params.GetResourceRequest().GetUkmSourceId(), UkmRecorder());
    if (result != net::OK) {
      return nullptr;
    }
    // TODO(yhirano): Consider removing this.
    if (!IsSupportedMimeType(response.MimeType().Utf8())) {
      return nullptr;
    }
  } else {
    ArchiveResource* archive_resource =
        archive_->SubresourceForURL(params.Url());
    // The archive doesn't contain the resource, the request must be
    // aborted.
    if (!archive_resource) {
      return nullptr;
    }
    data = archive_resource->Data();
    response.SetCurrentRequestUrl(url);
    response.SetMimeType(archive_resource->MimeType());
    response.SetExpectedContentLength(data->size());
    response.SetTextEncodingName(archive_resource->TextEncoding());
    response.SetFromArchive(true);
  }

  Resource* resource = factory.Create(
      params.GetResourceRequest(), params.Options(), params.DecoderOptions());
  switch (resource->GetStatus()) {
    case ResourceStatus::kNotStarted:
      // We should not reach here on the transparent placeholder image
      // fast-path.
      CHECK(!IsSimplifyLoadingTransparentPlaceholderImageEnabled() ||
            (params.GetResourceRequest()
                 .GetKnownTransparentPlaceholderImageIndex() == kNotFound));

      // The below code, with the exception of `NotifyStartLoad()` and
      // `Finish()`, is the same as in
      // `CreateResourceForTransparentPlaceholderImage()`.
      resource->NotifyStartLoad();
      // FIXME: We should provide a body stream here.
      resource->ResponseReceived(response);
      resource->SetDataBufferingPolicy(kBufferData);
      if (data->size()) {
        resource->SetResourceBuffer(data);
      }
      resource->SetCacheIdentifier(cache_identifier);
      resource->Finish(base::TimeTicks(), freezable_task_runner_.get());
      break;

    case ResourceStatus::kCached:
      // The constructed resource already has a synthetic response set.

      // We should only reach here on the transparent placeholder image
      // fast-path.
      CHECK(IsSimplifyLoadingTransparentPlaceholderImageEnabled());
      CHECK_NE(params.GetResourceRequest()
                   .GetKnownTransparentPlaceholderImageIndex(),
               kNotFound);

      use_counter_->CountUse(
          WebFeature::kSimplifyLoadingTransparentPlaceholderImage);

      // There shouldn't be any `ResourceClient`s that need to be
      // notified of synthetic response received steps.
      CHECK(!resource->HasClientsOrObservers());
      break;

    default:
      CHECK(false) << "Unexpected resource status: "
                   << (int)resource->GetStatus();
  }

  AddToMemoryCacheIfNeeded(params, resource);
  return resource;
}

Resource* ResourceFetcher::ResourceForBlockedRequest(
    const FetchParameters& params,
    const ResourceFactory& factory,
    ResourceRequestBlockedReason blocked_reason,
    ResourceClient* client) {
  Resource* resource = factory.Create(
      params.GetResourceRequest(), params.Options(), params.DecoderOptions());
  if (client) {
    client->SetResource(resource, freezable_task_runner_.get());
  }
  resource->FinishAsError(ResourceError::CancelledDueToAccessCheckError(
                              params.Url(), blocked_reason),
                          freezable_task_runner_.get());
  return resource;
}

void ResourceFetcher::MakePreloadedResourceBlockOnloadIfNeeded(
    Resource* resource,
    const FetchParameters& params) {
  // TODO(yoav): Test that non-blocking resources (video/audio/track) continue
  // to not-block even after being preloaded and discovered.
  if (resource && resource->Loader() &&
      resource->IsLoadEventBlockingResourceType() &&
      resource->IsLinkPreload() && !params.IsLinkPreload() &&
      non_blocking_loaders_.Contains(resource->Loader())) {
    non_blocking_loaders_.erase(resource->Loader());
    loaders_.insert(resource->Loader());
    if (resource_load_observer_) {
      resource_load_observer_->DidChangeRenderBlockingBehavior(resource,
                                                               params);
    }
  }
}

ResourceFetcher::RevalidationPolicyForMetrics
ResourceFetcher::MapToPolicyForMetrics(RevalidationPolicy policy,
                                       Resource* resource,
                                       DeferPolicy defer_policy) {
  switch (defer_policy) {
    case DeferPolicy::kNoDefer:
      break;
    case DeferPolicy::kDefer:
    case DeferPolicy::kDeferAndSchedule:
      if (!ResourceAlreadyLoadStarted(resource, policy)) {
        return RevalidationPolicyForMetrics::kDefer;
      }
      break;
  }
  // A resource in memory cache but not yet loaded is a deferred resource
  // created in previous loads.
  if (policy == RevalidationPolicy::kUse && resource->StillNeedsLoad()) {
    return RevalidationPolicyForMetrics::kPreviouslyDeferredLoad;
  }
  switch (policy) {
    case RevalidationPolicy::kUse:
      return RevalidationPolicyForMetrics::kUse;
    case RevalidationPolicy::kRevalidate:
      return RevalidationPolicyForMetrics::kRevalidate;
    case RevalidationPolicy::kReload:
      return RevalidationPolicyForMetrics::kReload;
    case RevalidationPolicy::kLoad:
      return RevalidationPolicyForMetrics::kLoad;
  }
}

void ResourceFetcher::UpdateMemoryCacheStats(
    Resource* resource,
    RevalidationPolicyForMetrics policy,
    const FetchParameters& params,
    const ResourceFactory& factory,
    bool is_static_data,
    bool same_top_frame_site_resource_cached) const {
  // Do not count static data or data not associated with the MemoryCache.
  if (is_static_data || !IsMainThread()) {
    return;
  }

  if (params.IsSpeculativePreload() || params.IsLinkPreload()) {
    RecordResourceHistogram("Preload.", factory.GetType(), policy);
  } else {
    RecordResourceHistogram("", factory.GetType(), policy);
  }

  // Aims to count Resource only referenced from MemoryCache (i.e. what would be
  // dead if MemoryCache holds weak references to Resource). Currently we check
  // references to Resource from ResourceClient and `preloads_` only, because
  // they are major sources of references.
  if (resource && !resource->IsAlive() && !ContainsAsPreload(resource)) {
    RecordResourceHistogram("Dead.", factory.GetType(), policy);
  }

  // Async (and defer) scripts may have more cache misses, track them
  // separately. See https://crbug.com/1043679 for context.
  if (params.Defer() != FetchParameters::DeferOption::kNoDefer &&
      factory.GetType() == ResourceType::kScript) {
    UMA_HISTOGRAM_ENUMERATION(RESOURCE_HISTOGRAM_PREFIX "AsyncScript", policy);
  }
}

bool ResourceFetcher::ContainsAsPreload(Resource* resource) const {
  auto it = preloads_.find(PreloadKey(resource->Url(), resource->GetType()));
  return it != preloads_.end() && it->value == resource;
}

void ResourceFetcher::RemovePreload(Resource* resource) {
  auto it = preloads_.find(PreloadKey(resource->Url(), resource->GetType()));
  if (it == preloads_.end()) {
    return;
  }
  if (it->value == resource) {
    preloads_.erase(it);
  }
}

std::optional<ResourceRequestBlockedReason>
ResourceFetcher::UpdateRequestForTransparentPlaceholderImage(
    FetchParameters& params) {
  ResourceRequest& resource_request = params.MutableResourceRequest();
  // Should only be called if request has transparent-placholder-image.
  DCHECK(IsSimplifyLoadingTransparentPlaceholderImageEnabled() &&
         (resource_request.GetKnownTransparentPlaceholderImageIndex() !=
          kNotFound));
  // Since we are not actually sending the request to the server,
  // we skip construction of the full ResourceRequest for performance,
  // and only set the properties needed for observer callbacks.
  // TODO(crbug.com/41496436): We need additional work to expand to
  // generic data urls.
  resource_request.SetPriority(ResourceLoadPriority::kLow);
  SetReferrer(resource_request, properties_->GetFetchClientSettingsObject());

  // We check the report-only and enforced headers here to ensure we report
  // and block things we ought to block.
  if (Context().CheckAndEnforceCSPForRequest(
          resource_request.GetRequestContext(),
          resource_request.GetRequestDestination(), params.Url(),
          params.Options(), ReportingDisposition::kReport, params.Url(),
          ResourceRequestHead::RedirectStatus::kNoRedirect) ==
      ResourceRequestBlockedReason::kCSP) {
    return ResourceRequestBlockedReason::kCSP;
  }

  return std::nullopt;
}

KURL ResourceFetcher::PrepareRequestForWebBundle(
    ResourceRequest& resource_request) const {
  if (resource_request.GetWebBundleTokenParams()) {
    DCHECK_EQ(resource_request.GetRequestDestination(),
              network::mojom::RequestDestination::kWebBundle);
    return KURL();
  }
  if (SubresourceWebBundle* bundle =
          GetMatchingBundle(resource_request.Url())) {
    resource_request.SetWebBundleTokenParams(
        ResourceRequestHead::WebBundleTokenParams(bundle->GetBundleUrl(),
                                                  bundle->WebBundleToken(),
                                                  mojo::NullRemote()));

    // Skip the service worker for a short term solution.
    // TODO(crbug.com/1240424): Figure out the ideal design of the service
    // worker integration.
    resource_request.SetSkipServiceWorker(true);
  }
  if (resource_request.Url().Protocol() == "uuid-in-package" &&
      resource_request.GetWebBundleTokenParams()) {
    // We use the bundle URL for uuid-in-package: resources for security
    // checks.
    return resource_request.GetWebBundleTokenParams()->bundle_url;
  }
  return KURL();
}

SubresourceWebBundleList*
ResourceFetcher::GetOrCreateSubresourceWebBundleList() {
  if (subresource_web_bundles_) {
    return subresource_web_bundles_.Get();
  }
  subresource_web_bundles_ = MakeGarbageCollected<SubresourceWebBundleList>();
  return subresource_web_bundles_.Get();
}

ukm::MojoUkmRecorder* ResourceFetcher::UkmRecorder() {
  if (ukm_recorder_) {
    return ukm_recorder_.get();
  }

  mojo::Remote<ukm::mojom::UkmRecorderFactory> factory;
  Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
      factory.BindNewPipeAndPassReceiver());
  ukm_recorder_ = ukm::MojoUkmRecorder::Create(*factory);

  return ukm_recorder_.get();
}

Resource* ResourceFetcher::RequestResource(FetchParameters& params,
                                           const ResourceFactory& factory,
                                           ResourceClient* client) {
  base::AutoReset<bool> r(&is_in_request_resource_, true);

  // If detached, we do very early return here to skip all processing below.
  if (properties_->IsDetached()) {
    return ResourceForBlockedRequest(
        params, factory, ResourceRequestBlockedReason::kOther, client);
  }

  if (resource_load_observer_) {
    resource_load_observer_->DidStartRequest(params, factory.GetType());
  }

  // Otherwise, we assume we can send network requests and the fetch client's
  // settings object's origin is non-null.
  DCHECK(properties_->GetFetchClientSettingsObject().GetSecurityOrigin());

  uint64_t identifier = CreateUniqueIdentifier();
  ResourceRequest& resource_request = params.MutableResourceRequest();
  resource_request.SetInspectorId(identifier);
  resource_request.SetFromOriginDirtyStyleSheet(
      params.IsFromOriginDirtyStyleSheet());
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1(
      TRACE_DISABLED_BY_DEFAULT("network"), "ResourceLoad",
      TRACE_ID_WITH_SCOPE("BlinkResourceID", TRACE_ID_LOCAL(identifier)), "url",
      resource_request.Url());
  absl::Cleanup record_times = [start = base::TimeTicks::Now(), &params] {
    base::TimeDelta elapsed = base::TimeTicks::Now() - start;
    base::UmaHistogramMicrosecondsTimes("Blink.Fetch.RequestResourceTime2",
                                        elapsed);
    if (params.Url().ProtocolIsData()) {
      base::UmaHistogramMicrosecondsTimes(
          "Blink.Fetch.RequestResourceTime2.Data", elapsed);
      if (params.GetResourceRequest()
              .GetKnownTransparentPlaceholderImageIndex() != kNotFound) {
        base::UmaHistogramMicrosecondsTimes(
            "Blink.Fetch.RequestResourceTime2.TransparentPlaceholderImage",
            elapsed);
      }
    }
    if (params.IsSpeculativePreload() || params.IsLinkPreload()) {
      base::UmaHistogramMicrosecondsTimes(
          "Blink.Fetch.RequestResourceTime2.Preload", elapsed);
    }
  };
  TRACE_EVENT1("blink,blink.resource", "ResourceFetcher::requestResource",
               "url", params.Url().ElidedString().Utf8());

  // |resource_request|'s origin can be null here, corresponding to the "client"
  // value in the spec. In that case client's origin is used.
  if (!resource_request.RequestorOrigin()) {
    resource_request.SetRequestorOrigin(
        properties_->GetFetchClientSettingsObject().GetSecurityOrigin());
  }

  const ResourceType resource_type = factory.GetType();

  WebScopedVirtualTimePauser pauser;

  ResourcePrepareHelper prepare_helper(*this, params, factory);
  std::optional<ResourceRequestBlockedReason> blocked_reason =
      prepare_helper.PrepareRequestForCacheAccess(pauser);
  if (blocked_reason) {
    auto* resource = ResourceForBlockedRequest(params, factory,
                                               blocked_reason.value(), client);
    StorePerformanceTimingInitiatorInformation(
        resource, params.GetRenderBlockingBehavior());
    auto info = resource_timing_info_map_.Take(resource);
    if (!info.is_null()) {
      PopulateAndAddResourceTimingInfo(resource, info,
                                       /*response_end=*/base::TimeTicks::Now());
    }
    return resource;
  }

  Resource* resource = nullptr;
  RevalidationPolicy policy = RevalidationPolicy::kLoad;

  bool is_data_url = resource_request.Url().ProtocolIsData();
  bool is_static_data = is_data_url || archive_;
  bool is_stale_revalidation = params.IsStaleRevalidation();
  DeferPolicy defer_policy = GetDeferPolicy(resource_type, params);
  // MHTML archives do not load from the network and must load immediately. Data
  // urls can also load immediately, except in cases when they should be
  // deferred.
  if (!is_stale_revalidation &&
      (archive_ || (is_data_url && defer_policy != DeferPolicy::kDefer))) {
    prepare_helper.UpgradeForLoaderIfNecessary(pauser);
    resource = CreateResourceForStaticData(params, factory);
    if (resource) {
      policy =
          DetermineRevalidationPolicy(resource_type, params, *resource, true);
    } else if (!is_data_url && archive_) {
      // Abort the request if the archive doesn't contain the resource, except
      // in the case of data URLs which might have resources such as fonts that
      // need to be decoded only on demand. These data URLs are allowed to be
      // processed using the normal ResourceFetcher machinery.
      return ResourceForBlockedRequest(
          params, factory, ResourceRequestBlockedReason::kOther, client);
    }
  }

  bool same_top_frame_site_resource_cached = false;
  bool in_cached_resources_map = cached_resources_map_.Contains(
      MemoryCache::RemoveFragmentIdentifierIfNeeded(params.Url()));

  if (!is_stale_revalidation && !resource) {
    if (!prepare_helper.WasUpgradeForLoaderCalled() &&
        preloads_.find(PreloadKey(params.Url(), resource_type)) !=
            preloads_.end()) {
      prepare_helper.UpgradeForLoaderIfNecessary(pauser);
    }
    resource = MatchPreload(params, resource_type);
    if (resource) {
      policy = RevalidationPolicy::kUse;
      prepare_helper.UpgradeForLoaderIfNecessary(pauser);
      // If |params| is for a blocking resource and a preloaded resource is
      // found, we may need to make it block the onload event.
      MakePreloadedResourceBlockOnloadIfNeeded(resource, params);
    } else if (IsMainThread()) {
      resource = MemoryCache::Get()->ResourceForURL(
          params.Url(),
          GetCacheIdentifier(
              params.Url(),
              params.GetResourceRequest().GetSkipServiceWorker()));
      if (resource) {
        policy = DetermineRevalidationPolicy(resource_type, params, *resource,
                                             is_static_data);
        scoped_refptr<const SecurityOrigin> top_frame_origin =
            resource_request.TopFrameOrigin();
        if (top_frame_origin) {
          same_top_frame_site_resource_cached =
              resource->AppendTopFrameSiteForMetrics(*top_frame_origin);
        }
      }
    }
  }
  if (!prepare_helper.WasUpgradeForLoaderCalled() &&
      policy != RevalidationPolicy::kUse) {
    prepare_helper.UpgradeForLoaderIfNecessary(pauser);
  }

  UpdateMemoryCacheStats(
      resource, MapToPolicyForMetrics(policy, resource, defer_policy), params,
      factory, is_static_data, same_top_frame_site_resource_cached);

  switch (policy) {
    case RevalidationPolicy::kReload:
      MemoryCache::Get()->Remove(resource);
      [[fallthrough]];
    case RevalidationPolicy::kLoad:
      resource = CreateResourceForLoading(params, factory);
      break;
    case RevalidationPolicy::kRevalidate:
      InitializeRevalidation(resource_request, resource);
      break;
    case RevalidationPolicy::kUse:
      if (resource_request.AllowsStaleResponse() &&
          resource->ShouldRevalidateStaleResponse(*use_counter_)) {
        ScheduleStaleRevalidate(resource);
      }
      if (resource->GetType() == ResourceType::kImage &&
          resource->GetContentStatus() == ResourceStatus::kCached &&
          base::FeatureList::IsEnabled(features::kSpeculativeImageDecodes)) {
        speculative_decode_candidate_images_.insert(resource);
        MaybeStartSpeculativeImageDecode();
      }
      break;
  }
  DCHECK(resource);
  DCHECK_EQ(resource->GetType(), resource_type);

  // in_cached_resources_map is checked to detect Resources shared across
  // Documents, in the same way as features::kScopeMemoryCachePerContext.
  if (!is_static_data && policy == RevalidationPolicy::kUse &&
      !in_cached_resources_map) {
    base::UmaHistogramEnumeration(kCrossDocumentCachedResource,
                                  resource->GetType());
  }

  if (policy != RevalidationPolicy::kUse) {
    resource->VirtualTimePauser() = std::move(pauser);
  }

  if (client) {
    client->SetResource(resource, freezable_task_runner_.get());
  }

  // Increase the priority of an existing request if the new request is
  // of a higher priority.
  // This can happen in a lot of cases but a common one is if a resource is
  // preloaded at a low priority but then the resource itself requires a
  // high-priority load.
  if (resource_request.Priority() > resource->GetResourceRequest().Priority()) {
    resource->DidChangePriority(resource_request.Priority(), 0);
  }

  // If only the fragment identifiers differ, it is the same resource.
  DCHECK(EqualIgnoringFragmentIdentifier(resource->Url(), params.Url()));
  if (policy == RevalidationPolicy::kUse &&
      resource->GetStatus() == ResourceStatus::kCached &&
      !in_cached_resources_map) {
    // Loaded from MemoryCache.
    DidLoadResourceFromMemoryCache(resource, resource_request, is_static_data,
                                   params.GetRenderBlockingBehavior());
  }
  if (!is_stale_revalidation) {
    String resource_url =
        MemoryCache::RemoveFragmentIdentifierIfNeeded(params.Url());
    cached_resources_map_.Set(resource_url, resource);
    MaybeSaveResourceToStrongReference(resource);
    if (PriorityObserverMapCreated() &&
        PriorityObservers()->Contains(resource_url)) {
      // Resolve the promise.
      std::move(PriorityObservers()->Take(resource_url))
          .Run(static_cast<int>(
              resource->GetResourceRequest().InitialPriority()));
    }
  }

  // Image loaders are by default added to |loaders_|, and are therefore
  // load-blocking. Lazy loaded images that are eventually fetched, however,
  // should always be added to |non_blocking_loaders_|, as they are never
  // load-blocking.
  ImageLoadBlockingPolicy load_blocking_policy =
      ImageLoadBlockingPolicy::kDefault;
  if (resource->GetType() == ResourceType::kImage) {
    not_loaded_image_resources_.insert(resource);
    if (params.GetImageRequestBehavior() ==
        FetchParameters::ImageRequestBehavior::kNonBlockingImage) {
      load_blocking_policy = ImageLoadBlockingPolicy::kForceNonBlockingLoad;
    }
  }

  // Returns with an existing resource if the resource does not need to start
  // loading immediately. If revalidation policy was determined as |Revalidate|,
  // the resource was already initialized for the revalidation here, but won't
  // start loading.
  const bool needs_load = ResourceNeedsLoad(resource, policy, defer_policy);
  if (needs_load) {
    // If a load is necessary, force upgrade so that the resource width is
    // updated. This is a bit heavyweight, and could be optimized by adding
    // a new function specifically to add the width.
    prepare_helper.UpgradeForLoaderIfNecessary(pauser);
  }

  // The resource width can change after the request was initially created.
  if (prepare_helper.WasUpgradeForLoaderCalled()) {
    resource->UpdateResourceWidth(
        resource_request.HttpHeaderField(AtomicString("sec-ch-width")));
  }

  if (needs_load) {
    if (!StartLoad(resource,
                   std::move(params.MutableResourceRequest().MutableBody()),
                   load_blocking_policy, params.GetRenderBlockingBehavior())) {
      resource->F
```