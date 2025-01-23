Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. I need to extract the key operations performed by the `ResourceFetcher` class based on this code. The prompt also asks for connections to JavaScript, HTML, and CSS, examples of logical reasoning with input/output, common usage errors, and explicitly states this is part 3 of 5.

Here's a breakdown of the code's functionality:

1. **Resource Management:** The code clearly deals with fetching and managing resources. Keywords like `Resource`, `ResourceRequest`, `MemoryCache`, `Preload`, `Load` are prominent.
2. **Revalidation Logic:**  A significant portion focuses on determining when to reuse cached resources (`RevalidationPolicy`). This involves checking cache headers, integrity, and request modes.
3. **Preloading:** The code manages preloaded resources, including speculative and link preloads. It tracks them and issues warnings if they are unused.
4. **Request Handling:** It interacts with `URLLoader` to make network requests. It also handles setting request headers for revalidation.
5. **Timing and Metrics:** The code records performance timing information for resources.
6. **Error Handling:**  It handles canceled requests.
7. **Context and Dependencies:** The `ResourceFetcher` interacts with a `FetchContext`, `MemoryCache`, `URLLoaderFactory`, and a console logger.
8. **Concurrency:**  The code uses task runners (`freezable_task_runner_`, `unfreezable_task_runner_`) indicating asynchronous operations.

Now, let's map these functionalities to the specific requirements of the prompt:

* **Functionality List:** This will be a direct enumeration of the identified actions.
* **Relation to JS/HTML/CSS:**
    * **JavaScript:**  Fetching scripts, preloading scripts, the impact of `fetch()` API on resource loading.
    * **HTML:**  Loading images referenced by `<img>` tags, CSS files referenced by `<link>` tags, preloads defined by `<link rel="preload">`.
    * **CSS:**  Fetching stylesheets, preloading stylesheets.
* **Logical Reasoning (Input/Output):**  Pick a function like `DetermineRevalidationPolicy` and illustrate its behavior with sample inputs (request parameters, existing resource state) and the expected output (revalidation policy).
* **Common Usage Errors:** Think about scenarios where developers might misuse preloading or caching, leading to unexpected behavior.
* **Summary:** Condense the identified functionalities into a concise overview of the code's role.
```cpp
void ResourceFetcher::WarnUnusedPreloads(
    base::OnceCallback<void(Vector<KURL> unused_preloads)> callback) {
  int unused_resource_count = 0;
  Vector<KURL> unused_preloads;
  for (const auto& pair : preloads_) {
    Resource* resource = pair.value;
    if (!resource || !resource->IsUnusedPreload()) {
      continue;
    }

    ++unused_resource_count;
    unused_preloads.push_back(resource->Url());
    if (resource->IsLinkPreload()) {
      String message =
          "The resource " + resource->Url().GetString() + " was preloaded " +
          "using link preload but not used within a few seconds from the " +
          "window's load event. Please make sure it has an appropriate `as` " +
          "value and it is preloaded intentionally.";
      console_logger_->AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kWarning, message);
      TRACE_EVENT1("blink,blink.resource",
                   "ResourceFetcher::WarnUnusedPreloads", "data",
                   CreateTracedValueForUnusedPreload(
                       resource->Url(), Resource::MatchStatus::kOk,
                       resource->GetResourceRequest().GetDevToolsId()));

      base::UmaHistogramCounts100("Renderer.Preload.UnusedResource",
                                  static_cast<int>(resource->GetType()));
    }
    base::UmaHistogramEnumeration("Renderer.Preload.UnusedResource2",
                                  resource->GetType());
    base::UmaHistogramEnumeration(
        base::StrCat({"Renderer.Preload.UnusedResource2.",
                      LinkPreloadStrForHistogram(resource->IsLinkPreload())}),
        resource->GetType());
  }
  base::UmaHistogramCounts100("Renderer.Preload.UnusedResourceCount",
                              unused_resource_count);
  // Record the total count of deferred preloads based on the LCPP signal.
  base::UmaHistogramCounts100(
      base::StrCat(
          {kLCPPDeferUnusedPreloadHistogramPrefix, "DeferredResourceCount"}),
      deferred_preloads_.size());

  for (auto& pair : unused_early_hints_preloaded_resources_) {
    if (pair.value.state == EarlyHintsPreloadEntry::State::kWarnedUnused) {
      continue;
    }

    // TODO(https://crbug.com/1317936): Consider not showing the following
    // warning message when an Early Hints response requested preloading the
    // resource but the HTTP cache already had the response and no network
    // request was made for the resource. In such a situation not using the
    // resource wouldn't be harmful. We need to plumb information from the
    // browser process to check whether the resource was already in the HTTP
    // cache.
    String message = "The resource " + pair.key.GetString() +
                     " was preloaded using link preload in Early Hints but not "
                     "used within a few seconds from the window's load event.";
    console_logger_->AddConsoleMessage(
        mojom::blink::ConsoleMessageSource::kJavaScript,
        mojom::blink::ConsoleMessageLevel::kWarning, message);
    TRACE_EVENT1("blink,blink.resource",
                 "ResourceFetcher::WarnUnusedEarlyHintsPreloads", "data",
                 CreateTracedValueForUnusedEarlyHintsPreload(pair.key));
    pair.value.state = EarlyHintsPreloadEntry::
```

### ResourceFetcher.cc 的功能归纳 (第 3 部分)

这部分代码主要关注以下 `ResourceFetcher` 的功能：

1. **警告未使用的预加载资源:**
   - 实现了 `WarnUnusedPreloads` 函数，用于在一段时间后检查预加载的资源是否被使用。
   - 如果预加载的资源（通过 `<link rel="preload">` 或 Early Hints 预加载）在页面加载完成后的短时间内未被使用，则会在控制台输出警告信息。
   - 警告信息会提示开发者检查 `as` 属性是否正确设置，并确认该预加载是预期的行为。
   - 使用了 UMA (User Metrics Analysis) 来记录未使用的预加载资源的数量和类型，用于性能分析和优化。

2. **管理和清理预加载资源:**
   - `ClearPreloads` 函数用于清除预加载的资源。可以根据策略清除所有预加载或仅清除非 link preload 的资源。
   - `ScheduleWarnUnusedPreloads` 函数设置一个定时器，用于延迟执行 `WarnUnusedPreloads` 函数。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**  这段代码直接关系到 HTML 的预加载功能，特别是 `<link rel="preload">` 标签。`WarnUnusedPreloads` 的警告信息会建议开发者检查 HTML 中 `<link>` 标签的 `as` 属性。
    * **举例:** 如果 HTML 中有 `<link rel="preload" href="style.css" as="style">`，但 `style.css` 由于某种原因没有被页面实际使用（例如，拼写错误或条件加载未满足），`WarnUnusedPreloads` 就会发出警告。
* **JavaScript:** 控制台的警告信息会标记来源为 "JavaScript" (`mojom::blink::ConsoleMessageSource::kJavaScript`)，因为预加载通常是由浏览器在解析 HTML 时触发的，但警告是针对开发者的，以便他们了解潜在的性能问题。
* **CSS:**  预加载的 CSS 文件是 `WarnUnusedPreloads` 监控的对象之一。如果一个 CSS 文件被预加载但没有被渲染使用，就会触发警告。

**逻辑推理 (假设输入与输出):**

假设输入:

1. `preloads_` 包含一个 `Resource*` 指向一个 URL 为 "image.png" 的图片资源，该资源是通过 `<link rel="preload" href="image.png" as="image">` 预加载的。
2. 页面加载完成后 5 秒，`WarnUnusedPreloads` 函数被调用。
3. 在这 5 秒内，页面上没有任何 `<img>` 标签或其他方式引用 "image.png"。

输出:

1. 控制台会输出类似以下的警告信息: "The resource image.png was preloaded using link preload but not used within a few seconds from the window's load event. Please make sure it has an appropriate `as` value and it is preloaded intentionally."
2. UMA 指标 `Renderer.Preload.UnusedResource` 的值会增加 1 (如果这是第一个未使用的预加载资源)。
3. UMA 指标 `Renderer.Preload.UnusedResource2` 的值会根据资源类型（例如，ResourceType::kImage）增加。
4. UMA 指标 `Renderer.Preload.UnusedResource2.LinkPreload` 的值也会根据资源类型增加。

**用户或编程常见的使用错误:**

1. **错误的 `as` 属性:**  在 `<link rel="preload">` 中指定了错误的 `as` 属性，导致浏览器无法正确地将预加载的资源与后续的请求匹配起来。
   * **举例:**  `<link rel="preload" href="script.js" as="style">`  预加载了一个 JavaScript 文件，但错误地将其声明为样式表。这会导致浏览器预加载了资源，但在需要执行脚本时，可能仍然会发起一个新的请求，并且预加载的资源会被标记为未使用。

2. **过度预加载:**  预加载了过多的资源，但其中一些资源在页面加载后并没有被实际使用。这会浪费用户的带宽，并可能导致性能下降，因为浏览器需要处理和存储这些未使用的资源。 `WarnUnusedPreloads` 可以帮助开发者识别这类问题。

3. **条件加载的资源预加载不当:**  预加载的资源仅在特定条件下才会被使用，但预加载的触发时机早于条件判断。如果条件未满足，预加载的资源就会被标记为未使用。
   * **举例:**  预加载了一个只在用户点击某个按钮后才显示的图片，但在页面加载完成后的几秒内，用户没有点击该按钮，导致 `WarnUnusedPreloads` 发出警告。开发者需要更精细地控制预加载的时机或考虑使用其他技术。

**总结:**

这部分 `ResourceFetcher.cc` 的代码主要负责监控和管理预加载的资源，并在发现未使用的预加载时向开发者发出警告。这有助于开发者优化页面的加载性能，避免不必要的资源下载，并确保预加载功能被正确使用。通过 UMA 指标的收集，Chromium 团队也能更好地了解预加载功能的使用情况和潜在的改进方向。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_fetcher.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
inishAsError(ResourceError::CancelledError(params.Url()),
                              freezable_task_runner_.get());
    }
  }

  if (defer_policy == DeferPolicy::kDeferAndSchedule) {
    // If |resource| is potentially unused preload based on the LCPP hint,
    // schedule the loading instead of calling `StartLoad()`.
    ScheduleLoadingPotentiallyUnusedPreload(resource);
  }

  if (policy != RevalidationPolicy::kUse) {
    InsertAsPreloadIfNecessary(resource, params, resource_type);
  }

  if (resource->InspectorId() != identifier ||
      (!resource->StillNeedsLoad() && !resource->IsLoading())) {
    TRACE_EVENT_NESTABLE_ASYNC_END1(
        TRACE_DISABLED_BY_DEFAULT("network"), "ResourceLoad",
        TRACE_ID_WITH_SCOPE("BlinkResourceID", TRACE_ID_LOCAL(identifier)),
        "outcome", "Fail");
  }
  return resource;
}

void ResourceFetcher::RemoveResourceStrongReference(Resource* resource) {
  if (resource && document_resource_strong_refs_.Contains(resource)) {
    const size_t resource_size =
        static_cast<size_t>(resource->GetResponse().DecodedBodyLength());
    document_resource_strong_refs_.erase(resource);
    CHECK_GE(document_resource_strong_refs_total_size_, resource_size);
    document_resource_strong_refs_total_size_ -= resource_size;
  }
}

bool ResourceFetcher::HasStrongReferenceForTesting(Resource* resource) {
  return document_resource_strong_refs_.Contains(resource);
}

void ResourceFetcher::ResourceTimingReportTimerFired(TimerBase* timer) {
  DCHECK_EQ(timer, &resource_timing_report_timer_);
  Vector<ScheduledResourceTimingInfo> timing_reports;
  timing_reports.swap(scheduled_resource_timing_reports_);
  for (auto& scheduled_report : timing_reports) {
    Context().AddResourceTiming(std::move(scheduled_report.info),
                                scheduled_report.initiator_type);
  }
}

void ResourceFetcher::InitializeRevalidation(
    ResourceRequest& revalidating_request,
    Resource* resource) {
  DCHECK(resource);
  DCHECK(MemoryCache::Get()->Contains(resource));
  DCHECK(resource->IsLoaded());
  DCHECK(resource->CanUseCacheValidator());
  DCHECK(!resource->IsCacheValidator());
  DCHECK_EQ(properties_->GetControllerServiceWorkerMode(),
            mojom::ControllerServiceWorkerMode::kNoController);
  // RawResource doesn't support revalidation.
  CHECK(!IsRawResource(*resource));

  revalidating_request.SetIsRevalidating(true);

  const AtomicString& last_modified =
      resource->GetResponse().HttpHeaderField(http_names::kLastModified);
  const AtomicString& e_tag =
      resource->GetResponse().HttpHeaderField(http_names::kETag);
  if (!last_modified.empty() || !e_tag.empty()) {
    DCHECK_NE(mojom::blink::FetchCacheMode::kBypassCache,
              revalidating_request.GetCacheMode());
    if (revalidating_request.GetCacheMode() ==
        mojom::blink::FetchCacheMode::kValidateCache) {
      revalidating_request.SetHttpHeaderField(http_names::kCacheControl,
                                              AtomicString("max-age=0"));
    }
  }
  if (!last_modified.empty()) {
    revalidating_request.SetHttpHeaderField(http_names::kIfModifiedSince,
                                            last_modified);
  }
  if (!e_tag.empty()) {
    revalidating_request.SetHttpHeaderField(http_names::kIfNoneMatch, e_tag);
  }

  resource->SetRevalidatingRequest(revalidating_request);
}

namespace {

bool UseRenderBlockingTaskPriority(
    const mojom::blink::RequestContextType request_context,
    const RenderBlockingBehavior render_blocking_behavior) {
  switch (request_context) {
    case mojom::blink::RequestContextType::IMAGE:
      // Always boost the priority of images (see: https://crbug.com/1416030).
      return true;
    case mojom::blink::RequestContextType::IMAGE_SET:
      return base::FeatureList::IsEnabled(
          features::kBoostImageSetLoadingTaskPriority);
    case mojom::blink::RequestContextType::FONT:
      return base::FeatureList::IsEnabled(
          features::kBoostFontLoadingTaskPriority);
    case mojom::blink::RequestContextType::VIDEO:
      return base::FeatureList::IsEnabled(
          features::kBoostVideoLoadingTaskPriority);
    case mojom::blink::RequestContextType::STYLE:
      if (render_blocking_behavior == RenderBlockingBehavior::kBlocking) {
        return base::FeatureList::IsEnabled(
            features::kBoostRenderBlockingStyleLoadingTaskPriority);
      }
      return base::FeatureList::IsEnabled(
          features::kBoostNonRenderBlockingStyleLoadingTaskPriority);
    default:
      return false;
  }
}

}  // namespace

std::unique_ptr<URLLoader> ResourceFetcher::CreateURLLoader(
    const network::ResourceRequest& network_request,
    const ResourceLoaderOptions& options,
    const mojom::blink::RequestContextType request_context,
    const RenderBlockingBehavior render_blocking_behavior,
    const std::optional<base::UnguessableToken>&
        service_worker_race_network_request_token,
    bool is_from_origin_dirty_style_sheet) {
  DCHECK(!GetProperties().IsDetached());
  // TODO(http://crbug.com/1252983): Revert this to DCHECK.
  CHECK(loader_factory_);

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      unfreezable_task_runner_;
  if (network_request.keepalive &&
      (!base::FeatureList::IsEnabled(
           blink::features::kKeepAliveInBrowserMigration) ||
       (network_request.attribution_reporting_eligibility !=
            network::mojom::AttributionReportingEligibility::kUnset &&
        !base::FeatureList::IsEnabled(
            features::kAttributionReportingInBrowserMigration)))) {
    // Set the `task_runner` to the `AgentGroupScheduler`'s task-runner for
    // keepalive fetches because we want it to keep running even after the
    // frame is detached. It's pretty fragile to do that with the
    // `unfreezable_task_runner_` that's saved in the ResourceFetcher, because
    // that task runner is frame-associated.
    if (auto* frame_or_worker_scheduler = GetFrameOrWorkerScheduler()) {
      if (auto* frame_scheduler =
              frame_or_worker_scheduler->ToFrameScheduler()) {
        task_runner =
            frame_scheduler->GetAgentGroupScheduler()->DefaultTaskRunner();
      }
    }
  } else if (UseRenderBlockingTaskPriority(request_context,
                                           render_blocking_behavior)) {
    if (auto* frame_or_worker_scheduler = GetFrameOrWorkerScheduler()) {
      if (auto* frame_scheduler =
              frame_or_worker_scheduler->ToFrameScheduler()) {
        task_runner = frame_scheduler->GetTaskRunner(
            TaskType::kNetworkingUnfreezableRenderBlockingLoading);
      }
    }
  }
  return loader_factory_->CreateURLLoader(
      network_request, options, freezable_task_runner_, task_runner,
      back_forward_cache_loader_helper_,
      service_worker_race_network_request_token,
      is_from_origin_dirty_style_sheet);
}

CodeCacheHost* ResourceFetcher::GetCodeCacheHost() {
  DCHECK(!GetProperties().IsDetached());
  // TODO(http://crbug.com/1252983): Revert this to DCHECK.
  CHECK(loader_factory_);
  return loader_factory_->GetCodeCacheHost();
}

void ResourceFetcher::AddToMemoryCacheIfNeeded(const FetchParameters& params,
                                               Resource* resource) {
  if (!ShouldResourceBeAddedToMemoryCache(params, resource)) {
    return;
  }

  MemoryCache::Get()->Add(resource);
}

Resource* ResourceFetcher::CreateResourceForLoading(
    const FetchParameters& params,
    const ResourceFactory& factory) {
  const String cache_identifier =
      GetCacheIdentifier(params.GetResourceRequest().Url(),
                         params.GetResourceRequest().GetSkipServiceWorker());
  DCHECK(!IsMainThread() || params.IsStaleRevalidation() ||
         !MemoryCache::Get()->ResourceForURL(params.GetResourceRequest().Url(),
                                             cache_identifier));

  RESOURCE_LOADING_DVLOG(1) << "Loading Resource for "
                            << params.GetResourceRequest().Url().ElidedString();

  Resource* resource = factory.Create(
      params.GetResourceRequest(), params.Options(), params.DecoderOptions());
  resource->SetLinkPreload(params.IsLinkPreload());
  resource->SetCacheIdentifier(cache_identifier);

  AddToMemoryCacheIfNeeded(params, resource);
  return resource;
}

void ResourceFetcher::StorePerformanceTimingInitiatorInformation(
    Resource* resource,
    RenderBlockingBehavior render_blocking_behavior) {
  const AtomicString& fetch_initiator = resource->Options().initiator_info.name;
  if (fetch_initiator == fetch_initiator_type_names::kInternal) {
    return;
  }

  resource_timing_info_map_.insert(
      resource,
      PendingResourceTimingInfo{base::TimeTicks::Now(), fetch_initiator,
                                render_blocking_behavior});
}

void ResourceFetcher::RecordResourceTimingOnRedirect(
    Resource* resource,
    const ResourceResponse& redirect_response,
    const KURL& new_url) {
  PendingResourceTimingInfoMap::iterator it =
      resource_timing_info_map_.find(resource);
  if (it != resource_timing_info_map_.end()) {
    if (ResourceLoadTiming* load_timing =
            redirect_response.GetResourceLoadTiming()) {
      it->value.redirect_end_time = load_timing->ReceiveHeadersEnd();
    }
  }
}

static bool IsDownloadOrStreamRequest(const ResourceRequest& request) {
  // Never use cache entries for DownloadToBlob / UseStreamOnResponse requests.
  // The data will be delivered through other paths.
  return request.DownloadToBlob() || request.UseStreamOnResponse();
}

Resource* ResourceFetcher::MatchPreload(const FetchParameters& params,
                                        ResourceType type) {
  // TODO(crbug.com/1099975): PreloadKey should be modified to also take into
  // account the DOMWrapperWorld corresponding to the resource. This is because
  // we probably don't want to share preloaded resources across different
  // DOMWrapperWorlds to ensure predicatable behavior for preloads.
  auto it = preloads_.find(PreloadKey(params.Url(), type));
  if (it == preloads_.end()) {
    return nullptr;
  }

  Resource* resource = it->value;

  if (resource->MustRefetchDueToIntegrityMetadata(params)) {
    if (!params.IsSpeculativePreload() && !params.IsLinkPreload()) {
      PrintPreloadMismatch(resource, Resource::MatchStatus::kIntegrityMismatch);
    }
    return nullptr;
  }

  if (params.IsSpeculativePreload()) {
    return resource;
  }
  if (params.IsLinkPreload()) {
    resource->SetLinkPreload(true);
    return resource;
  }

  const ResourceRequest& request = params.GetResourceRequest();
  if (request.DownloadToBlob()) {
    PrintPreloadMismatch(resource, Resource::MatchStatus::kBlobRequest);
    return nullptr;
  }

  if (IsImageResourceDisallowedToBeReused(*resource)) {
    PrintPreloadMismatch(resource,
                         Resource::MatchStatus::kImageLoadingDisabled);
    return nullptr;
  }

  const Resource::MatchStatus match_status = resource->CanReuse(params);
  if (match_status != Resource::MatchStatus::kOk) {
    PrintPreloadMismatch(resource, match_status);
    return nullptr;
  }

  resource->MatchPreload(params);
  preloads_.erase(it);
  matched_preloads_.push_back(resource);
  return resource;
}

void ResourceFetcher::PrintPreloadMismatch(Resource* resource,
                                           Resource::MatchStatus status) {
  if (!resource->IsLinkPreload()) {
    return;
  }

  StringBuilder builder;
  builder.Append("A preload for '");
  builder.Append(resource->Url().GetString());
  builder.Append("' is found, but is not used ");

  switch (status) {
    case Resource::MatchStatus::kOk:
      NOTREACHED();
    case Resource::MatchStatus::kUnknownFailure:
      builder.Append("due to an unknown reason.");
      break;
    case Resource::MatchStatus::kIntegrityMismatch:
      builder.Append("due to an integrity mismatch.");
      break;
    case Resource::MatchStatus::kBlobRequest:
      builder.Append("because the new request loads the content as a blob.");
      break;
    case Resource::MatchStatus::kImageLoadingDisabled:
      builder.Append("because image loading is disabled.");
      break;
    case Resource::MatchStatus::kSynchronousFlagDoesNotMatch:
      builder.Append("because the new request is synchronous.");
      break;
    case Resource::MatchStatus::kRequestModeDoesNotMatch:
      builder.Append("because the request mode does not match. ");
      builder.Append("Consider taking a look at crossorigin attribute.");
      break;
    case Resource::MatchStatus::kRequestCredentialsModeDoesNotMatch:
      builder.Append("because the request credentials mode does not match. ");
      builder.Append("Consider taking a look at crossorigin attribute.");
      break;
    case Resource::MatchStatus::kKeepaliveSet:
      builder.Append("because the keepalive flag is set.");
      break;
    case Resource::MatchStatus::kRequestMethodDoesNotMatch:
      builder.Append("because the request HTTP method does not match.");
      break;
    case Resource::MatchStatus::kScriptTypeDoesNotMatch:
      builder.Append("because the script type does not match.");
      break;
  }
  console_logger_->AddConsoleMessage(mojom::ConsoleMessageSource::kOther,
                                     mojom::ConsoleMessageLevel::kWarning,
                                     builder.ToString());

  TRACE_EVENT1("blink,blink.resource", "ResourceFetcher::PrintPreloadMismatch",
               "data",
               CreateTracedValueForUnusedPreload(
                   resource->Url(), status,
                   resource->GetResourceRequest().GetDevToolsId()));
}

void ResourceFetcher::InsertAsPreloadIfNecessary(Resource* resource,
                                                 const FetchParameters& params,
                                                 ResourceType type) {
  if (!params.IsSpeculativePreload() && !params.IsLinkPreload()) {
    return;
  }
  DCHECK(!params.IsStaleRevalidation());
  // CSP web tests verify that preloads are subject to access checks by
  // seeing if they are in the `preload started` list. Therefore do not add
  // them to the list if the load is immediately denied.
  if (resource->LoadFailedOrCanceled() &&
      resource->GetResourceError().IsAccessCheck()) {
    return;
  }
  PreloadKey key(params.Url(), type);
  if (base::Contains(preloads_, key)) {
    return;
  }

  preloads_.insert(key, resource);
  resource->MarkAsPreload();
  if (preloaded_urls_for_test_) {
    preloaded_urls_for_test_->insert(resource->Url().GetString());
  }
}

bool ResourceFetcher::IsImageResourceDisallowedToBeReused(
    const Resource& existing_resource) const {
  // When images are disabled, don't ever load images, even if the image is
  // cached or it is a data: url. In this case:
  // - remove the image from the memory cache, and
  // - create a new resource but defer loading (this is done by
  //   ResourceNeedsLoad()).
  //
  // This condition must be placed before the condition on |is_static_data| to
  // prevent loading a data: URL.
  //
  // TODO(japhet): Can we get rid of one of these settings?

  if (existing_resource.GetType() != ResourceType::kImage) {
    return false;
  }

  return !Context().AllowImage();
}

ResourceFetcher::RevalidationPolicy
ResourceFetcher::DetermineRevalidationPolicy(
    ResourceType type,
    const FetchParameters& fetch_params,
    const Resource& existing_resource,
    bool is_static_data) const {
  RevalidationPolicy policy;
  const char* reason;
  std::tie(policy, reason) = DetermineRevalidationPolicyInternal(
      type, fetch_params, existing_resource, is_static_data);
  DCHECK(reason);

  RESOURCE_LOADING_DVLOG(1)
      << "ResourceFetcher::DetermineRevalidationPolicy "
      << "url = " << fetch_params.Url() << ", policy = " << GetNameFor(policy)
      << ", reason = \"" << reason << "\"";

  TRACE_EVENT_INSTANT2("blink", "ResourceFetcher::DetermineRevalidationPolicy",
                       TRACE_EVENT_SCOPE_THREAD, "policy", GetNameFor(policy),
                       "reason", reason);
  return policy;
}

const char* ResourceFetcher::GetNameFor(RevalidationPolicy policy) {
  switch (policy) {
    case RevalidationPolicy::kUse:
      return "use";
    case RevalidationPolicy::kRevalidate:
      return "revalidate";
    case RevalidationPolicy::kReload:
      return "reload";
    case RevalidationPolicy::kLoad:
      return "load";
  }
  NOTREACHED();
}

std::pair<ResourceFetcher::RevalidationPolicy, const char*>
ResourceFetcher::DetermineRevalidationPolicyInternal(
    ResourceType type,
    const FetchParameters& fetch_params,
    const Resource& existing_resource,
    bool is_static_data) const {
  const ResourceRequest& request = fetch_params.GetResourceRequest();

  Resource* cached_resource_in_fetcher = CachedResource(request.Url());

  if (IsDownloadOrStreamRequest(request)) {
    return {RevalidationPolicy::kReload,
            "It is for download or for streaming."};
  }

  if (IsImageResourceDisallowedToBeReused(existing_resource)) {
    return {RevalidationPolicy::kReload,
            "Reload due to 'allow image' settings."};
  }

  // If the existing resource is loading and the associated fetcher is not equal
  // to |this|, we must not use the resource. Otherwise, CSP violation may
  // happen in redirect handling.
  if (existing_resource.Loader() &&
      existing_resource.Loader()->Fetcher() != this) {
    return {RevalidationPolicy::kReload,
            "The existing resource is loading in a foreign fetcher."};
  }

  // It's hard to share a not-yet-referenced preloads via MemoryCache correctly.
  // A not-yet-matched preloads made by a foreign ResourceFetcher and stored in
  // the memory cache could be used without this block.
  if ((fetch_params.IsLinkPreload() || fetch_params.IsSpeculativePreload()) &&
      existing_resource.IsUnusedPreload()) {
    return {RevalidationPolicy::kReload,
            "The existing resource is an unused preload made "
            "from a foreign fetcher."};
  }

  // Checks if the resource has an explicit policy about integrity metadata.
  //
  // This is necessary because ScriptResource and CSSStyleSheetResource objects
  // do not keep the raw data around after the source is accessed once, so if
  // the resource is accessed from the MemoryCache for a second time, there is
  // no way to redo an integrity check.
  //
  // Thus, Blink implements a scheme where it caches the integrity information
  // for those resources after the first time it is checked, and if there is
  // another request for that resource, with the same integrity metadata, Blink
  // skips the integrity calculation. However, if the integrity metadata is a
  // mismatch, the MemoryCache must be skipped here, and a new request for the
  // resource must be made to get the raw data. This is expected to be an
  // uncommon case, however, as it implies two same-origin requests to the same
  // resource, but with different integrity metadata.
  if (existing_resource.MustRefetchDueToIntegrityMetadata(fetch_params)) {
    return {RevalidationPolicy::kReload, "Reload due to resource integrity."};
  }

  // If the same URL has been loaded as a different type, we need to reload.
  if (existing_resource.GetType() != type) {
    // FIXME: If existingResource is a Preload and the new type is LinkPrefetch
    // We really should discard the new prefetch since the preload has more
    // specific type information! crbug.com/379893
    // fast/dom/HTMLLinkElement/link-and-subresource-test hits this case.
    return {RevalidationPolicy::kReload, "Reload due to type mismatch."};
  }

  // If resource was populated from archive or data: url, use it.
  // This doesn't necessarily mean that |resource| was just created by using
  // CreateResourceForStaticData().
  if (is_static_data) {
    return {RevalidationPolicy::kUse, "Use the existing static resource."};
  }

  if (existing_resource.CanReuse(fetch_params) != Resource::MatchStatus::kOk) {
    return {RevalidationPolicy::kReload, "Reload due to Resource::CanReuse."};
  }

  // Don't reload resources while pasting.
  if (allow_stale_resources_) {
    return {RevalidationPolicy::kUse,
            "Use the existing resource due to |allow_stale_resources_|."};
  }

  // FORCE_CACHE uses the cache no matter what.
  if (request.GetCacheMode() == mojom::blink::FetchCacheMode::kForceCache) {
    return {RevalidationPolicy::kUse,
            "Use the existing resource due to cache-mode: 'force-cache'."};
  }

  // Don't reuse resources with Cache-control: no-store.
  if (existing_resource.HasCacheControlNoStoreHeader()) {
    return {RevalidationPolicy::kReload,
            "Reload due to cache-control: no-store."};
  }

  // During the initial load, avoid loading the same resource multiple times for
  // a single document, even if the cache policies would tell us to. We also
  // group loads of the same resource together. Raw resources are exempted, as
  // XHRs fall into this category and may have user-set Cache-Control: headers
  // or other factors that require separate requests.
  if (type != ResourceType::kRaw) {
    if (!properties_->IsLoadComplete() &&
        cached_resources_map_.Contains(
            MemoryCache::RemoveFragmentIdentifierIfNeeded(
                existing_resource.Url()))) {
      return {RevalidationPolicy::kUse,
              "Avoid making multiple requests for the same URL "
              "during the initial load."};
    }
    if (existing_resource.IsLoading()) {
      return {RevalidationPolicy::kUse,
              "Use the existing resource because it's being loaded."};
    }
  }

  // RELOAD always reloads
  if (request.GetCacheMode() == mojom::blink::FetchCacheMode::kBypassCache) {
    return {RevalidationPolicy::kReload, "Reload due to cache-mode: 'reload'."};
  }

  // We'll try to reload the resource if it failed last time.
  if (existing_resource.ErrorOccurred()) {
    return {RevalidationPolicy::kReload,
            "Reload because the existing resource has failed loading."};
  }

  // List of available images logic allows images to be re-used without cache
  // validation. We restrict this only to images from memory cache which are the
  // same as the version in the current document.
  if (type == ResourceType::kImage &&
      &existing_resource == cached_resource_in_fetcher) {
    return {RevalidationPolicy::kUse,
            "Images can be reused without cache validation."};
  }

  if (existing_resource.MustReloadDueToVaryHeader(request)) {
    return {RevalidationPolicy::kReload, "Reload due to vary header."};
  }

  // If any of the redirects in the chain to loading the resource were not
  // cacheable, we cannot reuse our cached resource.
  if (!existing_resource.CanReuseRedirectChain(*use_counter_)) {
    return {RevalidationPolicy::kReload,
            "Reload due to an uncacheable redirect."};
  }

  // Check if the cache headers requires us to revalidate (cache expiration for
  // example).
  if (request.GetCacheMode() == mojom::blink::FetchCacheMode::kValidateCache ||
      existing_resource.MustRevalidateDueToCacheHeaders(
          request.AllowsStaleResponse(), *use_counter_) ||
      request.CacheControlContainsNoCache()) {
    // Revalidation is harmful for non-matched preloads because it may lead to
    // sharing one preloaded resource among multiple ResourceFetchers.
    if (existing_resource.IsUnusedPreload()) {
      return {RevalidationPolicy::kReload,
              "Revalidation is harmful for non-matched preloads."};
    }

    // See if the resource has usable ETag or Last-modified headers. If the page
    // is controlled by the ServiceWorker, we choose the Reload policy because
    // the revalidation headers should not be exposed to the
    // ServiceWorker.(crbug.com/429570)
    //
    // TODO(falken): If the controller has no fetch event handler, we probably
    // can treat it as not being controlled in the S13nSW case. In the
    // non-S13nSW, we don't know what controller the request will ultimately go
    // to (due to skipWaiting) so be conservative.
    if (existing_resource.CanUseCacheValidator() &&
        properties_->GetControllerServiceWorkerMode() ==
            mojom::ControllerServiceWorkerMode::kNoController) {
      // If the resource is already a cache validator but not started yet, the
      // |Use| policy should be applied to subsequent requests.
      if (existing_resource.IsCacheValidator()) {
        DCHECK(existing_resource.StillNeedsLoad());
        return {RevalidationPolicy::kUse,
                "Merged to the revalidate request which has not yet started."};
      }
      return {RevalidationPolicy::kRevalidate, ""};
    }

    // No, must reload.
    return {RevalidationPolicy::kReload,
            "Reload due to missing cache validators."};
  }

  return {RevalidationPolicy::kUse,
          "Use the existing resource because there is no reason not to do so."};
}

void ResourceFetcher::SetAutoLoadImages(bool enable) {
  if (enable == auto_load_images_) {
    return;
  }

  auto_load_images_ = enable;

  if (!auto_load_images_) {
    return;
  }

  ReloadImagesIfNotDeferred();
}

bool ResourceFetcher::ShouldDeferImageLoad(const KURL& url) const {
  return !Context().AllowImage() ||
         (!auto_load_images_ && !url.ProtocolIsData());
}

void ResourceFetcher::ReloadImagesIfNotDeferred() {
  for (Resource* resource : not_loaded_image_resources_) {
    DCHECK_EQ(resource->GetType(), ResourceType::kImage);
    if (resource->StillNeedsLoad() && !ShouldDeferImageLoad(resource->Url())) {
      StartLoad(resource);
    }
  }
}

FetchContext& ResourceFetcher::Context() const {
  return *context_;
}

void ResourceFetcher::ClearContext() {
  scheduler_->Shutdown();
  ClearPreloads(ResourceFetcher::kClearAllPreloads);

  {
    // This block used to be
    //  context_ = Context().Detach();
    // While we are splitting FetchContext to multiple classes we need to call
    // "detach" for multiple objects in a coordinated manner. See
    // https://crbug.com/914739 for the progress.
    // TODO(yhirano): Remove the cross-class dependency.
    context_ = Context().Detach();
    properties_->Detach();
  }

  resource_load_observer_ = nullptr;
  use_counter_->Detach();
  console_logger_->Detach();
  if (back_forward_cache_loader_helper_) {
    back_forward_cache_loader_helper_->Detach();
  }
  loader_factory_ = nullptr;

  unused_preloads_timer_.Cancel();

  // Make sure the only requests still going are keepalive requests.
  // Callers of ClearContext() should be calling StopFetching() prior
  // to this, but it's possible for additional requests to start during
  // StopFetching() (e.g., fallback fonts that only trigger when the
  // first choice font failed to load).
  StopFetching();

  if (!loaders_.empty() || !non_blocking_loaders_.empty()) {
    CHECK(!base::FeatureList::IsEnabled(
              blink::features::kKeepAliveInBrowserMigration) ||
          !base::FeatureList::IsEnabled(
              blink::features::kAttributionReportingInBrowserMigration));
    // There are some keepalive requests.

    // The use of WrapPersistent creates a reference cycle intentionally,
    // to keep the ResourceFetcher and ResourceLoaders alive until the requests
    // complete or the timer fires.
    keepalive_loaders_task_handle_ = PostDelayedCancellableTask(
        *freezable_task_runner_, FROM_HERE,
        WTF::BindOnce(&ResourceFetcher::StopFetchingIncludingKeepaliveLoaders,
                      WrapPersistent(this)),
        kKeepaliveLoadersTimeout);
  }
}

int ResourceFetcher::BlockingRequestCount() const {
  return loaders_.size();
}

int ResourceFetcher::NonblockingRequestCount() const {
  return non_blocking_loaders_.size();
}

int ResourceFetcher::ActiveRequestCount() const {
  return loaders_.size() + non_blocking_loaders_.size();
}

void ResourceFetcher::EnableIsPreloadedForTest() {
  if (preloaded_urls_for_test_) {
    return;
  }
  preloaded_urls_for_test_ = std::make_unique<HashSet<String>>();

  for (const auto& pair : preloads_) {
    Resource* resource = pair.value;
    preloaded_urls_for_test_->insert(resource->Url().GetString());
  }
}

bool ResourceFetcher::IsPreloadedForTest(const KURL& url) const {
  DCHECK(preloaded_urls_for_test_);
  return preloaded_urls_for_test_->Contains(url.GetString());
}

void ResourceFetcher::ClearPreloads(ClearPreloadsPolicy policy) {
  Vector<PreloadKey> keys_to_be_removed;
  for (const auto& pair : preloads_) {
    Resource* resource = pair.value;
    if (policy == kClearAllPreloads || !resource->IsLinkPreload()) {
      MemoryCache::Get()->Remove(resource);
      keys_to_be_removed.push_back(pair.key);
    }
  }
  preloads_.RemoveAll(keys_to_be_removed);

  matched_preloads_.clear();
}

void ResourceFetcher::ScheduleWarnUnusedPreloads(
    base::OnceCallback<void(Vector<KURL> unused_preloads)> callback) {
  // If preloads_ is not empty here, it's full of link
  // preloads, as speculative preloads should have already been cleared when
  // parsing finished.
  if (preloads_.empty() && unused_early_hints_preloaded_resources_.empty()) {
    return;
  }
  unused_preloads_timer_ = PostDelayedCancellableTask(
      *freezable_task_runner_, FROM_HERE,
      WTF::BindOnce(&ResourceFetcher::WarnUnusedPreloads,
                    WrapWeakPersistent(this), std::move(callback)),
      kUnusedPreloadTimeout);
}

void ResourceFetcher::WarnUnusedPreloads(
    base::OnceCallback<void(Vector<KURL> unused_preloads)> callback) {
  int unused_resource_count = 0;
  Vector<KURL> unused_preloads;
  for (const auto& pair : preloads_) {
    Resource* resource = pair.value;
    if (!resource || !resource->IsUnusedPreload()) {
      continue;
    }

    ++unused_resource_count;
    unused_preloads.push_back(resource->Url());
    if (resource->IsLinkPreload()) {
      String message =
          "The resource " + resource->Url().GetString() + " was preloaded " +
          "using link preload but not used within a few seconds from the " +
          "window's load event. Please make sure it has an appropriate `as` " +
          "value and it is preloaded intentionally.";
      console_logger_->AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kWarning, message);
      TRACE_EVENT1("blink,blink.resource",
                   "ResourceFetcher::WarnUnusedPreloads", "data",
                   CreateTracedValueForUnusedPreload(
                       resource->Url(), Resource::MatchStatus::kOk,
                       resource->GetResourceRequest().GetDevToolsId()));

      base::UmaHistogramCounts100("Renderer.Preload.UnusedResource",
                                  static_cast<int>(resource->GetType()));
    }
    base::UmaHistogramEnumeration("Renderer.Preload.UnusedResource2",
                                  resource->GetType());
    base::UmaHistogramEnumeration(
        base::StrCat({"Renderer.Preload.UnusedResource2.",
                      LinkPreloadStrForHistogram(resource->IsLinkPreload())}),
        resource->GetType());
  }
  base::UmaHistogramCounts100("Renderer.Preload.UnusedResourceCount",
                              unused_resource_count);
  // Record the total count of deferred preloads based on the LCPP signal.
  base::UmaHistogramCounts100(
      base::StrCat(
          {kLCPPDeferUnusedPreloadHistogramPrefix, "DeferredResourceCount"}),
      deferred_preloads_.size());

  for (auto& pair : unused_early_hints_preloaded_resources_) {
    if (pair.value.state == EarlyHintsPreloadEntry::State::kWarnedUnused) {
      continue;
    }

    // TODO(https://crbug.com/1317936): Consider not showing the following
    // warning message when an Early Hints response requested preloading the
    // resource but the HTTP cache already had the response and no network
    // request was made for the resource. In such a situation not using the
    // resource wouldn't be harmful. We need to plumb information from the
    // browser process to check whether the resource was already in the HTTP
    // cache.
    String message = "The resource " + pair.key.GetString() +
                     " was preloaded using link preload in Early Hints but not "
                     "used within a few seconds from the window's load event.";
    console_logger_->AddConsoleMessage(
        mojom::blink::ConsoleMessageSource::kJavaScript,
        mojom::blink::ConsoleMessageLevel::kWarning, message);
    TRACE_EVENT1("blink,blink.resource",
                 "ResourceFetcher::WarnUnusedEarlyHintsPreloads", "data",
                 CreateTracedValueForUnusedEarlyHintsPreload(pair.key));
    pair.value.state = EarlyHintsPreloadEntry::
```