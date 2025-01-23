Response:
The user wants a summary of the functionality of the provided C++ code snippet from `resource_loader.cc`. This is part 2 of 3, implying there's context in other parts.

To achieve this, I will:

1. **Identify key methods and their purpose** within the given snippet.
2. **Relate these methods to the overall loading process** of resources in a web browser.
3. **Look for connections to JavaScript, HTML, and CSS**, explaining how this code might impact those technologies.
4. **Examine the code for conditional logic** to infer possible input/output scenarios.
5. **Identify potential user or programming errors** that could arise from or interact with this code.
This代码片段主要负责处理接收到资源响应 (response) 后的逻辑，包括处理响应头、接收数据、以及处理加载完成或失败的情况。它在资源加载过程中扮演着至关重要的角色，直接影响着如何解析和使用从网络获取的资源。

**功能归纳:**

1. **处理 HTTP 响应头:**
   - `DidReceiveResponse`:  这是处理接收到完整 HTTP 响应头的入口点。它会解析 `WebURLResponse` 对象，提取诸如状态码、MIME 类型、Content-Encoding 等信息。
   - `DidReceiveResponseInternal`:  执行更深层次的响应处理，例如检查 `nosniff` 头部以避免 MIME 类型混淆攻击，以及处理 CORS (跨域资源共享) 策略。
   -  它会检查响应头中的 `Content-Encoding`，特别是 `zstd`，并记录相关的 WebFeature 使用情况。
   -  它会检查是否使用了共享字典压缩 (`dcb`, `dcz`)，并记录相应的 WebFeature 使用情况。
   -  它会检查 preflight 结果中的通配符授权，并记录相关的废弃使用。
   -  它会处理自动升级请求 (例如 HTTP 升级到 HTTPS) 的指标记录。
   -  它会根据响应头中的 `X-Content-Type-Options` 进行 `nosniff` 检查，防止将某些类型的文件误认为可执行文件。
   -  它会处理 `Cross-Origin-Embedder-Policy` (COEP) 头部，以确保跨域隔离。
   -  如果响应是通过 Service Worker 获取的，会进行额外的 CSP (内容安全策略) 检查。
   -  如果启用了子资源过滤器 DNS 别名检查，会进行相应的检查。
   -  它会检查响应是否在没有 Range 请求的情况下返回了部分内容 (HTTP 状态码 206)。
   -  它会通知 `ResourceLoadObserver` 接收到响应。
   -  它会将接收到的响应信息存储到 `resource_` 对象中。
   -  如果 fetch 上下文已分离，会取消请求。
   -  它会设置缓存的元数据（如果存在且不是成功 revalidation 的情况）。
   -  它会根据响应头中的 `Cache-Control` 指令 (`no-cache`, `no-store`) 注册粘性特性，影响浏览器的缓存行为。
   -  如果 HTTP 状态码大于等于 400 且不应忽略 HTTP 状态码错误，则会触发错误处理。

2. **处理 HTTP 响应体 (Body):**
   - `DidReceiveResponse` 会根据响应体的数据类型 ( `mojo::ScopedDataPipeConsumerHandle` 或 `SegmentedBuffer`) 选择不同的处理方式。
   - 如果是成功 revalidation (HTTP 304)，则假定响应体为空。
   - `DidReceiveDataImpl`:  处理接收到的响应体数据块。它会将数据追加到 `resource_` 对象中，并通知 `ResourceLoadObserver`。
   - 如果请求需要将响应体下载到 Blob，则会使用 `BlobRegistry` 创建 Blob。
   - 如果响应体是通过数据管道 (Data Pipe) 传输的，则会创建 `DataPipeBytesConsumer` 来处理数据流。

3. **处理加载完成和失败:**
   - `DidFinishLoading`:  处理资源加载成功的场景。它会记录加载完成的时间、编码和解码后的数据长度，并通知 `ResourceFetcher` 加载完成。如果响应体还在加载，会延迟完成操作。
   - `DidFail`:  处理资源加载失败的场景。它会记录错误信息，并通知 `ResourceFetcher` 加载失败。
   - `HandleError`:  集中处理错误情况，包括记录错误信息、中止数据加载、释放资源等。它还会处理因缓存未命中而重新加载的情况。对于 CORS 错误，它会向控制台输出错误信息。

4. **同步和异步请求处理:**
   - `RequestSynchronously`:  处理同步请求的情况，直接调用 `URLLoader` 的同步加载方法。
   - `RequestAsynchronously`:  处理异步请求的情况，调用 `URLLoader` 的异步加载方法。对于 data URL，它会在单独的任务中处理。

5. **其他辅助功能:**
   - `DidSendData`: 记录已发送的数据量。
   - `Context`:  获取 `FetchContext` 对象。
   - `DidReceiveTransferSizeUpdate`: 记录传输大小的更新。
   - `DidFinishLoadingFirstPartInMultipart`: 处理 multipart 文档的第一部分加载完成。
   - `CountFeature`: 记录 WebFeature 的使用情况。
   - `Dispose`:  释放资源。
   - `ShouldBeKeptAliveWhenDetached`:  判断在 Fetch 上下文分离时是否应该保持活动状态（主要用于 keepalive 连接）。
   - `AbortResponseBodyLoading`: 中止响应体的加载。
   - `GetLoadingTaskRunner`: 获取加载任务的 TaskRunner。
   - `OnProgress`: 处理下载到 Blob 的进度更新。
   - `FinishedCreatingBlob`: 处理 Blob 创建完成。
   - `CheckResponseNosniff`: 检查响应是否允许嗅探 MIME 类型。
   - `HandleDataUrl`:  处理 data URL 的加载。
   - `ShouldBlockRequestBasedOnSubresourceFilterDnsAliasCheck`: 根据子资源过滤器 DNS 别名检查是否阻止请求 (代码片段不完整)。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * 当 JavaScript 发起 `fetch()` 请求或通过 `XMLHttpRequest` 请求资源时，`ResourceLoader` 会处理服务器返回的响应。例如，如果 JavaScript 代码尝试获取一个 JSON 文件，`DidReceiveResponse` 会解析响应头，确保 `Content-Type` 是 `application/json` 或者允许的类型，然后 `DidReceiveDataImpl` 会接收 JSON 数据，最终 JavaScript 可以解析这些数据。
    * 如果 JavaScript 代码尝试加载一个跨域的脚本，`ResourceLoader` 中的 CORS 检查逻辑会判断响应头是否满足 CORS 策略，如果策略不允许，`HandleError` 会被调用，导致 JavaScript 无法访问该脚本，并在控制台中输出 CORS 错误。
* **HTML:**
    * 当浏览器解析 HTML 遇到 `<img>` 标签、`<link>` 标签（用于 CSS）或 `<script>` 标签时，`ResourceLoader` 负责加载这些资源。例如，当加载 `<link rel="stylesheet" href="style.css">` 时，`DidReceiveResponse` 会检查响应头的 `Content-Type` 是否是 CSS 允许的 MIME 类型（例如 `text/css`），如果不是，`CheckResponseNosniff` 可能会阻止加载。
    * 如果 HTML 中使用了 Service Worker，并且 Service Worker 拦截了资源请求，`DidReceiveResponse` 中的 CSP 检查会针对 Service Worker 返回的响应进行。
* **CSS:**
    * 当加载 CSS 文件时，`DidReceiveResponse` 会检查 `Content-Type`，确保是 CSS MIME 类型。如果服务器返回了错误的 `Content-Type`，`CheckResponseNosniff` 会阻止 CSS 的应用，并在控制台中输出错误信息。
    * 如果 CSS 文件使用了 `@import` 规则引入了其他资源，会触发新的资源加载流程，同样由 `ResourceLoader` 处理。

**逻辑推理的假设输入与输出:**

**假设输入:**

* **情景 1 (成功加载图片):**
    * 请求 URL: `https://example.com/image.png`
    * 响应头: `HTTP/1.1 200 OK`, `Content-Type: image/png`, `Content-Length: 1024`
    * 响应体: 1024 字节的 PNG 图片数据
* **情景 2 (CORS 错误):**
    * 请求 URL: `https://api.otherdomain.com/data` (从 `https://example.com` 发起)
    * 响应头: `HTTP/1.1 200 OK`, `Content-Type: application/json` (缺少 `Access-Control-Allow-Origin` 头)
    * 响应体:  JSON 数据

**输出:**

* **情景 1:**
    * `DidReceiveResponse` 会成功解析响应头。
    * `DidReceiveResponseInternal` 会通过 `nosniff` 检查。
    * `DidReceiveDataImpl` 会接收 PNG 数据并添加到 `resource_` 对象中。
    * `DidFinishLoading` 会被调用，表示图片加载成功。
* **情景 2:**
    * `DidReceiveResponse` 会接收到响应头。
    * `DidReceiveResponseInternal` 中的 CORS 检查会失败，因为缺少 `Access-Control-Allow-Origin` 头。
    * `HandleError` 会被调用，生成一个 CORS 错误。
    * 控制台会输出 CORS 错误信息。

**用户或编程常见的使用错误举例:**

1. **服务器配置错误导致 MIME 类型不正确:**  如果服务器错误地将 CSS 文件设置为 `text/plain` 的 `Content-Type`，`CheckResponseNosniff` 会阻止加载，导致网页样式失效。开发者需要在服务器端正确配置 MIME 类型。
2. **CORS 配置错误:** 前端 JavaScript 尝试访问跨域 API，但后端服务器没有设置正确的 CORS 响应头 (例如 `Access-Control-Allow-Origin`)，会导致 `ResourceLoader` 阻止请求，并在浏览器控制台中显示 CORS 错误。开发者需要在后端服务器上配置允许跨域访问的策略。
3. **在需要 HTTPS 的页面中加载 HTTP 资源 (混合内容):**  如果一个 HTTPS 页面尝试加载 HTTP 的脚本或样式表，`ResourceLoader` 可能会阻止这些不安全的资源，以防止中间人攻击。开发者应该确保在 HTTPS 页面中加载的资源也是通过 HTTPS 提供的。
4. **使用错误的 data URL 格式:**  如果 JavaScript 或 HTML 中使用了格式错误的 data URL，`HandleDataUrl` 中的解析可能会失败，导致资源加载错误。开发者需要仔细检查 data URL 的格式是否正确。
5. **Service Worker 返回不符合 CSP 的响应:** 如果 Service Worker 拦截了请求并返回了一个违反页面 CSP 策略的响应，`DidReceiveResponse` 中的 CSP 检查会阻止该响应的使用。开发者需要确保 Service Worker 返回的响应符合页面的安全策略。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
uint64_t total_bytes_to_be_sent) {
  resource_->DidSendData(bytes_sent, total_bytes_to_be_sent);
}

FetchContext& ResourceLoader::Context() const {
  return fetcher_->Context();
}

void ResourceLoader::DidReceiveResponse(
    const WebURLResponse& response,
    absl::variant<mojo::ScopedDataPipeConsumerHandle, SegmentedBuffer> body,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  DCHECK(!response.IsNull());

  if (resource_->GetResourceRequest().GetKeepalive()) {
    // Logs when a keepalive request succeeds. It does not matter whether the
    // response is a multipart resource or not.
    FetchUtils::LogFetchKeepAliveRequestMetric(
        resource_->GetResourceRequest().GetRequestContext(),
        FetchUtils::FetchKeepAliveRequestState::kSucceeded,
        fetcher_->GetProperties().IsDetached());
  }

  DidReceiveResponseInternal(response.ToResourceResponse(),
                             std::move(cached_metadata));
  if (!IsLoading()) {
    return;
  }
  if (resource_->HasSuccessfulRevalidation()) {
    // When we succeeded the revalidation, the response is a 304 Not Modified.
    // The body of the 304 Not Modified response must be empty.
    //   RFC9110: https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.1-8
    //     All 1xx (Informational), 204 (No Content), and 304 (Not Modified)
    //     responses do not include content.
    // net::HttpStreamParser::CalculateResponseBodySize() is skipping loading
    // the body of 304 Not Modified response. And Blink don't fetch the
    // revalidating request when the page is controlled by a service worker.
    // So, We don't need to handle the body for 304 Not Modified responses.
    if (absl::holds_alternative<SegmentedBuffer>(body)) {
      CHECK(absl::get<SegmentedBuffer>(body).empty());
    } else {
      CHECK(absl::holds_alternative<mojo::ScopedDataPipeConsumerHandle>(body));
      // If the `body` is released here, the network service will treat the
      // disconnection of the `body` handle as if the request was cancelled. So
      // we keeps the `body` handle.
      empty_body_handle_for_revalidation_ =
          std::move(absl::get<mojo::ScopedDataPipeConsumerHandle>(body));
    }
    return;
  }
  if (absl::holds_alternative<SegmentedBuffer>(body)) {
    DidReceiveDataImpl(std::move(absl::get<SegmentedBuffer>(body)));
    return;
  }
  mojo::ScopedDataPipeConsumerHandle body_handle =
      std::move(absl::get<mojo::ScopedDataPipeConsumerHandle>(body));
  if (!body_handle) {
    return;
  }
  if (resource_->GetResourceRequest().DownloadToBlob()) {
    DCHECK(!blob_response_started_);
    blob_response_started_ = true;

    AtomicString mime_type = response.MimeType();

    // Callback is bound to a WeakPersistent, as ResourceLoader is kept alive by
    // ResourceFetcher as long as we still care about the result of the load.
    fetcher_->GetBlobRegistry()->RegisterFromStream(
        mime_type.IsNull() ? g_empty_string : mime_type.LowerASCII(), "",
        std::max(static_cast<int64_t>(0), response.ExpectedContentLength()),
        std::move(body_handle),
        progress_receiver_.BindNewEndpointAndPassRemote(GetLoadingTaskRunner()),
        WTF::BindOnce(&ResourceLoader::FinishedCreatingBlob,
                      WrapWeakPersistent(this)));
    return;
  }

  DataPipeBytesConsumer::CompletionNotifier* completion_notifier = nullptr;
  DidStartLoadingResponseBodyInternal(
      *MakeGarbageCollected<DataPipeBytesConsumer>(task_runner_for_body_loader_,
                                                   std::move(body_handle),
                                                   &completion_notifier));
  data_pipe_completion_notifier_ = completion_notifier;
}

void ResourceLoader::DidReceiveDataForTesting(base::span<const char> data) {
  DidReceiveDataImpl(data);
}

void ResourceLoader::DidReceiveResponseInternal(
    const ResourceResponse& response,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  const ResourceRequestHead& request = resource_->GetResourceRequest();

  AtomicString content_encoding =
      response.HttpHeaderField(http_names::kContentEncoding);
  bool used_zstd = false;
  if (EqualIgnoringASCIICase(content_encoding, "zstd")) {
    fetcher_->GetUseCounter().CountUse(WebFeature::kZstdContentEncoding);
    fetcher_->GetUseCounter().CountUse(
        WebFeature::kZstdContentEncodingForSubresource);
    used_zstd = true;
  }

  // Sample the UKM recorded events. Also, a current default task runner is
  // needed to obtain a UKM recorder, so if there is not one, do not record
  // UKMs.
  if ((base::RandDouble() <= kUkmSamplingRate) &&
      base::SequencedTaskRunner::HasCurrentDefault()) {
    ukm::builders::SubresourceLoad_ZstdContentEncoding builder(
        request.GetUkmSourceId());
    builder.SetUsedZstd(used_zstd);
    builder.Record(fetcher_->UkmRecorder());
  }

  if (response.DidUseSharedDictionary()) {
    fetcher_->GetUseCounter().CountUse(WebFeature::kSharedDictionaryUsed);
    fetcher_->GetUseCounter().CountUse(
        WebFeature::kSharedDictionaryUsedForSubresource);
    if (EqualIgnoringASCIICase(content_encoding, "dcb")) {
      fetcher_->GetUseCounter().CountUse(
          WebFeature::kSharedDictionaryUsedWithSharedBrotli);
    } else if (EqualIgnoringASCIICase(content_encoding, "dcz")) {
      fetcher_->GetUseCounter().CountUse(
          WebFeature::kSharedDictionaryUsedWithSharedZstd);
    }
  }

  if (response.HasAuthorizationCoveredByWildcardOnPreflight()) {
    fetcher_->GetUseCounter().CountDeprecation(
        mojom::WebFeature::kAuthorizationCoveredByWildcard);
  }

  CountPrivateNetworkAccessPreflightResult(
      response.PrivateNetworkAccessPreflightResult());

  if (request.IsAutomaticUpgrade()) {
    LogMixedAutoupgradeMetrics(MixedContentAutoupgradeStatus::kResponseReceived,
                               response.HttpStatusCode(),
                               request.GetUkmSourceId(),
                               fetcher_->UkmRecorder(), resource_);
  }

  ResourceType resource_type = resource_->GetType();

  const ResourceRequestHead& initial_request = resource_->GetResourceRequest();
  // The following parameters never change during the lifetime of a request.
  mojom::blink::RequestContextType request_context =
      initial_request.GetRequestContext();
  network::mojom::RequestDestination request_destination =
      initial_request.GetRequestDestination();

  const ResourceLoaderOptions& options = resource_->Options();

  // Perform 'nosniff' checks against the original response instead of the 304
  // response for a successful revalidation.
  const ResourceResponse& nosniffed_response =
      (resource_->IsCacheValidator() && response.HttpStatusCode() == 304)
          ? resource_->GetResponse()
          : response;

  if (std::optional<ResourceRequestBlockedReason> blocked_reason =
          CheckResponseNosniff(request_context, nosniffed_response)) {
    HandleError(ResourceError::CancelledDueToAccessCheckError(
        response.CurrentRequestUrl(), blocked_reason.value()));
    return;
  }

  // https://wicg.github.io/cross-origin-embedder-policy/#integration-html
  // TODO(crbug.com/1064920): Remove this once PlzDedicatedWorker ships.
  if (options.reject_coep_unsafe_none &&
      !network::CompatibleWithCrossOriginIsolated(
          response.GetCrossOriginEmbedderPolicy()) &&
      !response.CurrentRequestUrl().ProtocolIsData() &&
      !response.CurrentRequestUrl().ProtocolIs("blob")) {
    DCHECK(!base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
    HandleError(ResourceError::BlockedByResponse(
        response.CurrentRequestUrl(), network::mojom::BlockedByResponseReason::
                                          kCoepFrameResourceNeedsCoepHeader));
    return;
  }

  // Redirect information for possible post-request checks below.
  const std::optional<ResourceRequest::RedirectInfo>& previous_redirect_info =
      request.GetRedirectInfo();
  const KURL& original_url = previous_redirect_info
                                 ? previous_redirect_info->original_url
                                 : request.Url();
  const ResourceRequest::RedirectInfo redirect_info(original_url,
                                                    request.Url());

  if (response.WasFetchedViaServiceWorker()) {
    // Run post-request CSP checks. This is the "Should response to request be
    // blocked by Content Security Policy?" algorithm in the CSP specification:
    // https://w3c.github.io/webappsec-csp/#should-block-response
    //
    // In particular, the connect-src directive's post-request check:
    // https://w3c.github.io/webappsec-csp/#connect-src-post-request)
    //
    // We only run post-request checks when the response was fetched via service
    // worker, because that is the only case where the response URL can differ
    // from the current request URL, allowing the result of the check to differ
    // from the pre-request check. The pre-request check is implemented in
    // ResourceFetcher::PrepareRequest() and
    // ResourceFetcher::WillFollowRedirect().
    //
    // TODO(falken): To align with the CSP specification, implement post-request
    // checks as a first-class concept instead of just reusing the functions for
    // pre-request checks, and consider running the checks regardless of service
    // worker interception.
    //
    // CanRequest() below only checks enforced policies: check report-only
    // here to ensure violations are sent.
    const KURL& response_url = response.ResponseUrl();
    Context().CheckCSPForRequest(
        request_context, request_destination, response_url, options,
        ReportingDisposition::kReport, original_url,
        ResourceRequest::RedirectStatus::kFollowedRedirect);

    std::optional<ResourceRequestBlockedReason> blocked_reason =
        Context().CanRequest(resource_type, ResourceRequest(initial_request),
                             response_url, options,
                             ReportingDisposition::kReport, redirect_info);
    if (blocked_reason) {
      HandleError(ResourceError::CancelledDueToAccessCheckError(
          response_url, blocked_reason.value()));
      return;
    }
  }

  if (base::FeatureList::IsEnabled(
          features::kSendCnameAliasesToSubresourceFilterFromRenderer)) {
    bool should_block = ShouldBlockRequestBasedOnSubresourceFilterDnsAliasCheck(
        response.DnsAliases(), request.Url(), original_url, resource_type,
        initial_request, options, redirect_info);

    if (should_block) {
      return;
    }
  }

  // A response should not serve partial content if it was not requested via a
  // Range header: https://fetch.spec.whatwg.org/#main-fetch
  if (response.GetType() == network::mojom::FetchResponseType::kOpaque &&
      response.HttpStatusCode() == 206 && response.HasRangeRequested() &&
      !initial_request.HttpHeaderFields().Contains(http_names::kRange)) {
    HandleError(ResourceError::CancelledDueToAccessCheckError(
        response.CurrentRequestUrl(), ResourceRequestBlockedReason::kOther));
    return;
  }

  fetcher_->MarkEarlyHintConsumedIfNeeded(resource_->InspectorId(), resource_,
                                          response);
  // FrameType never changes during the lifetime of a request.
  if (auto* observer = fetcher_->GetResourceLoadObserver()) {
    ResourceRequest request_for_obserber(initial_request);
    // TODO(yoichio): Have DidReceiveResponse take a ResourceResponseHead, not
    // ResourceRequest.
    observer->DidReceiveResponse(
        resource_->InspectorId(), request_for_obserber, response, resource_,
        ResourceLoadObserver::ResponseSource::kNotFromMemoryCache);
  }

  resource_->ResponseReceived(response);

  if (resource_->Loader() && fetcher_->GetProperties().IsDetached()) {
    // If the fetch context is already detached, we don't need further signals,
    // so let's cancel the request.
    HandleError(ResourceError::CancelledError(response.CurrentRequestUrl()));
    return;
  }

  if (!resource_->Loader()) {
    return;
  }

  // Not SetSerializedCachedMetadata in a successful revalidation
  // because resource content would not expect to be changed.
  if (!resource_->HasSuccessfulRevalidation() && cached_metadata &&
      cached_metadata->size()) {
    resource_->SetSerializedCachedMetadata(std::move(*cached_metadata));
  }

  if (auto* frame_or_worker_scheduler = fetcher_->GetFrameOrWorkerScheduler()) {
    if (response.CacheControlContainsNoCache()) {
      frame_or_worker_scheduler->RegisterStickyFeature(
          SchedulingPolicy::Feature::kSubresourceHasCacheControlNoCache,
          {SchedulingPolicy::DisableBackForwardCache()});
    }
    if (response.CacheControlContainsNoStore()) {
      frame_or_worker_scheduler->RegisterStickyFeature(
          SchedulingPolicy::Feature::kSubresourceHasCacheControlNoStore,
          {SchedulingPolicy::DisableBackForwardCache()});
    }
  }

  if (!resource_->Loader()) {
    return;
  }

  if (response.HttpStatusCode() >= 400 &&
      !resource_->ShouldIgnoreHTTPStatusCodeErrors()) {
    HandleError(ResourceError::HttpError(response.CurrentRequestUrl()));
    return;
  }
}

void ResourceLoader::DidReceiveData(base::span<const char> data) {
  DidReceiveDataImpl(data);
}

void ResourceLoader::DidReceiveDataImpl(
    absl::variant<SegmentedBuffer, base::span<const char>> data) {
  size_t data_size = 0;
  // If a BackgroundResponseProcessor consumed the body data on the background
  // thread, this method is called with a SegmentedBuffer data. Otherwise, it is
  // called with a span<const char> data several times.
  if (absl::holds_alternative<SegmentedBuffer>(data)) {
    data_size = absl::get<SegmentedBuffer>(data).size();
    if (auto* observer = fetcher_->GetResourceLoadObserver()) {
      for (const auto& span : absl::get<SegmentedBuffer>(data)) {
        observer->DidReceiveData(resource_->InspectorId(),
                                 base::SpanOrSize(span));
      }
    }
  } else {
    CHECK(absl::holds_alternative<base::span<const char>>(data));
    base::span<const char> span = absl::get<base::span<const char>>(data);
    data_size = span.size();
    if (auto* observer = fetcher_->GetResourceLoadObserver()) {
      observer->DidReceiveData(resource_->InspectorId(),
                               base::SpanOrSize(span));
    }
  }
  resource_->AppendData(std::move(data));

  // This value should not be exposed for opaque responses.
  if (resource_->response_.WasFetchedViaServiceWorker() &&
      resource_->response_.GetType() !=
          network::mojom::FetchResponseType::kOpaque) {
    // `received_body_length_from_service_worker_` needs to fit into both a
    // uint64_t and an int64_t so must be >= 0 and also <=
    // std::numeric_limits<int64_t>::max(); Since `length` is guaranteed never
    // to be negative, the value must always increase, giving assurance that it
    // will always be >= 0, but the CheckAdd is used to enforce the second
    // constraint.
    received_body_length_from_service_worker_ =
        base::CheckAdd(received_body_length_from_service_worker_, data_size)
            .ValueOrDie<int64_t>();
  }
}

void ResourceLoader::DidReceiveTransferSizeUpdate(int transfer_size_diff) {
  if (auto* observer = fetcher_->GetResourceLoadObserver()) {
    observer->DidReceiveTransferSizeUpdate(resource_->InspectorId(),
                                           transfer_size_diff);
  }
}

void ResourceLoader::DidFinishLoadingFirstPartInMultipart() {
  TRACE_EVENT_NESTABLE_ASYNC_END1(
      TRACE_DISABLED_BY_DEFAULT("network"), "ResourceLoad",
      TRACE_ID_WITH_SCOPE("BlinkResourceID",
                          TRACE_ID_LOCAL(resource_->InspectorId())),
      "outcome", RequestOutcomeToString(RequestOutcome::kSuccess));

  fetcher_->HandleLoaderFinish(resource_.Get(), base::TimeTicks(),
                               ResourceFetcher::kDidFinishFirstPartInMultipart,
                               0);
}

void ResourceLoader::DidFinishLoading(base::TimeTicks response_end_time,
                                      int64_t encoded_data_length,
                                      uint64_t encoded_body_length,
                                      int64_t decoded_body_length) {
  if (resource_->response_.WasFetchedViaServiceWorker()) {
    encoded_body_length = received_body_length_from_service_worker_;
    decoded_body_length = received_body_length_from_service_worker_;
  }

  resource_->SetEncodedDataLength(encoded_data_length);
  resource_->SetEncodedBodyLength(encoded_body_length);
  resource_->SetDecodedBodyLength(decoded_body_length);

  response_end_time_for_error_cases_ = response_end_time;

  if ((response_body_loader_ && !has_seen_end_of_body_ &&
       !response_body_loader_->IsAborted()) ||
      (resource_->GetResourceRequest().DownloadToBlob() && !blob_finished_ &&
       blob_response_started_)) {
    // If the body is still being loaded, we defer the completion until all the
    // body is received.
    deferred_finish_loading_info_ =
        DeferredFinishLoadingInfo{response_end_time};

    if (data_pipe_completion_notifier_) {
      data_pipe_completion_notifier_->SignalComplete();
    }
    return;
  }

  Release(ResourceLoadScheduler::ReleaseOption::kReleaseAndSchedule,
          ResourceLoadScheduler::TrafficReportHints(encoded_data_length,
                                                    decoded_body_length));
  loader_.reset();
  response_body_loader_ = nullptr;
  has_seen_end_of_body_ = false;
  deferred_finish_loading_info_ = std::nullopt;
  finished_ = true;

  TRACE_EVENT_NESTABLE_ASYNC_END1(
      TRACE_DISABLED_BY_DEFAULT("network"), "ResourceLoad",
      TRACE_ID_WITH_SCOPE("BlinkResourceID",
                          TRACE_ID_LOCAL(resource_->InspectorId())),
      "outcome", RequestOutcomeToString(RequestOutcome::kSuccess));

  fetcher_->HandleLoaderFinish(resource_.Get(), response_end_time,
                               ResourceFetcher::kDidFinishLoading,
                               inflight_keepalive_bytes_);
}

void ResourceLoader::DidFail(const WebURLError& error,
                             base::TimeTicks response_end_time,
                             int64_t encoded_data_length,
                             uint64_t encoded_body_length,
                             int64_t decoded_body_length) {
  const ResourceRequestHead& request = resource_->GetResourceRequest();
  response_end_time_for_error_cases_ = response_end_time;

  if (request.IsAutomaticUpgrade()) {
    LogMixedAutoupgradeMetrics(MixedContentAutoupgradeStatus::kFailed,
                               error.reason(), request.GetUkmSourceId(),
                               fetcher_->UkmRecorder(), resource_);
  }

  CountPrivateNetworkAccessPreflightResult(
      error.private_network_access_preflight_result());

  resource_->SetEncodedDataLength(encoded_data_length);
  resource_->SetEncodedBodyLength(encoded_body_length);
  resource_->SetDecodedBodyLength(decoded_body_length);
  HandleError(ResourceError(error));
}

void ResourceLoader::CountFeature(blink::mojom::WebFeature feature) {
  fetcher_->GetUseCounter().CountUse(feature);
}

void ResourceLoader::HandleError(const ResourceError& error) {
  if (resource_->GetResourceRequest().GetKeepalive()) {
    FetchUtils::LogFetchKeepAliveRequestMetric(
        resource_->GetResourceRequest().GetRequestContext(),
        FetchUtils::FetchKeepAliveRequestState::kFailed);
  }

  if (error.CorsErrorStatus() &&
      error.CorsErrorStatus()
          ->has_authorization_covered_by_wildcard_on_preflight) {
    fetcher_->GetUseCounter().CountUse(
        mojom::WebFeature::kAuthorizationCoveredByWildcard);
  }

  if (response_body_loader_) {
    response_body_loader_->Abort();
  }

  if (data_pipe_completion_notifier_) {
    data_pipe_completion_notifier_->SignalError(BytesConsumer::Error());
  }

  if (is_cache_aware_loading_activated_ && error.IsCacheMiss() &&
      !fetcher_->GetProperties().ShouldBlockLoadingSubResource()) {
    resource_->WillReloadAfterDiskCacheMiss();
    is_cache_aware_loading_activated_ = false;
    Restart();
    return;
  }
  if (error.CorsErrorStatus()) {
    // CORS issues are reported via network service instrumentation.
    const AtomicString& initiator_name =
        resource_->Options().initiator_info.name;
    if (initiator_name != fetch_initiator_type_names::kFetch ||
        !base::FeatureList::IsEnabled(
            features::kDevToolsImprovedNetworkError)) {
      fetcher_->GetConsoleLogger().AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kError,
          cors::GetErrorStringForConsoleMessage(
              *error.CorsErrorStatus(), resource_->GetResourceRequest().Url(),
              resource_->LastResourceRequest().Url(), *resource_->GetOrigin(),
              resource_->GetType(), initiator_name),
          false /* discard_duplicates */,
          mojom::blink::ConsoleMessageCategory::Cors);
    }
  }

  Release(ResourceLoadScheduler::ReleaseOption::kReleaseAndSchedule,
          ResourceLoadScheduler::TrafficReportHints::InvalidInstance());
  loader_.reset();
  response_body_loader_ = nullptr;
  has_seen_end_of_body_ = false;
  deferred_finish_loading_info_ = std::nullopt;
  finished_ = true;

  TRACE_EVENT_NESTABLE_ASYNC_END1(
      TRACE_DISABLED_BY_DEFAULT("network"), "ResourceLoad",
      TRACE_ID_WITH_SCOPE("BlinkResourceID",
                          TRACE_ID_LOCAL(resource_->InspectorId())),
      "outcome", RequestOutcomeToString(RequestOutcome::kFail));

  // Set Now() as the response time, in case a more accurate one wasn't set in
  // DidFinishLoading or DidFail. This is important for error cases that don't
  // go through those methods.
  if (response_end_time_for_error_cases_.is_null()) {
    response_end_time_for_error_cases_ = base::TimeTicks::Now();
  }
  fetcher_->HandleLoaderError(resource_.Get(),
                              response_end_time_for_error_cases_, error,
                              inflight_keepalive_bytes_);
}

void ResourceLoader::RequestSynchronously() {
  DCHECK(IsLoading());
  DCHECK_EQ(resource_->GetResourceRequest().Priority(),
            ResourceLoadPriority::kHighest);

  WebURLResponse response_out;
  std::optional<WebURLError> error_out;
  scoped_refptr<SharedBuffer> data_out;
  int64_t encoded_data_length = URLLoaderClient::kUnknownEncodedDataLength;
  uint64_t encoded_body_length = 0;
  scoped_refptr<BlobDataHandle> downloaded_blob;
  const ResourceRequestHead& request = resource_->GetResourceRequest();

  if (resource_->Url().ProtocolIsData()) {
    CHECK(!network_resource_request_);
    CHECK(!loader_);
    // We don't have to verify mime type again since it's allowed to handle
    // the data url with invalid mime type in some cases.
    // CanHandleDataURLRequestLocally() has already checked if the data url can
    // be handled here.
    auto [result, response, data] = network_utils::ParseDataURL(
        resource_->Url(), request.HttpMethod(), request.GetUkmSourceId(),
        fetcher_->UkmRecorder());
    if (result != net::OK) {
      error_out = WebURLError(result, resource_->Url());
    } else {
      response_out = WrappedResourceResponse(response);
      data_out = std::move(data);
    }
  } else {
    CHECK(network_resource_request_);
    CHECK(loader_);
    // Don't do mime sniffing for fetch (crbug.com/2016)
    bool no_mime_sniffing = request.GetRequestContext() ==
                            blink::mojom::blink::RequestContextType::FETCH;
    loader_->LoadSynchronously(
        std::move(network_resource_request_), Context().GetTopFrameOrigin(),
        request.DownloadToBlob(), no_mime_sniffing, request.TimeoutInterval(),
        this, response_out, error_out, data_out, encoded_data_length,
        encoded_body_length, downloaded_blob,
        Context().CreateResourceLoadInfoNotifierWrapper());
  }
  // A message dispatched while synchronously fetching the resource
  // can bring about the cancellation of this load.
  if (!IsLoading()) {
    return;
  }
  int64_t decoded_body_length = data_out ? data_out->size() : 0;
  if (error_out) {
    DidFail(*error_out, base::TimeTicks::Now(), encoded_data_length,
            encoded_body_length, decoded_body_length);
    return;
  }

  DidReceiveResponseInternal(response_out.ToResourceResponse(),
                             /*cached_metadata=*/std::nullopt);
  if (!IsLoading()) {
    return;
  }
  DCHECK_GE(response_out.ToResourceResponse().EncodedBodyLength(), 0);

  // Follow the async case convention of not calling DidReceiveData or
  // appending data to m_resource if the response body is empty. Copying the
  // empty buffer is a noop in most cases, but is destructive in the case of
  // a 304, where it will overwrite the cached data we should be reusing.
  if (data_out && data_out->size()) {
    for (const auto& span : *data_out) {
      DidReceiveData(span);
    }
  }

  if (request.DownloadToBlob()) {
    if (downloaded_blob) {
      OnProgress(downloaded_blob->size());
    }
    FinishedCreatingBlob(std::move(downloaded_blob));
  }
  DidFinishLoading(base::TimeTicks::Now(), encoded_data_length,
                   encoded_body_length, decoded_body_length);
}

void ResourceLoader::RequestAsynchronously() {
  if (resource_->Url().ProtocolIsData()) {
    CHECK(!network_resource_request_);
    CHECK(!loader_);
    // Handle DataURL in another task instead of using |loader_|.
    GetLoadingTaskRunner()->PostTask(
        FROM_HERE, WTF::BindOnce(&ResourceLoader::HandleDataUrl,
                                 WrapWeakPersistent(this)));
    return;
  }
  CHECK(loader_);
  CHECK(network_resource_request_);

  // When `loader_` is a BackgroundURLLoader and
  // kBackgroundResponseProcessorBackground feature param is enabled, creates a
  // BackgroundResponseProcessor for the `resource_`, and set it to the
  // `loader_`.
  if (loader_->CanHandleResponseOnBackground()) {
    if (auto factory =
            resource_->MaybeCreateBackgroundResponseProcessorFactory()) {
      loader_->SetBackgroundResponseProcessorFactory(std::move(factory));
    }
  }

  // Don't do mime sniffing for fetch (crbug.com/2016)
  bool no_mime_sniffing = resource_->GetResourceRequest().GetRequestContext() ==
                          blink::mojom::blink::RequestContextType::FETCH;

  // Don't pass a CodeCacheHost when DownloadToBlob is true. The detailed
  // decision logic for whether or not to fetch code cache from the isolated
  // code cache is implemented in ResourceRequestSender::CodeCacheFetcher. We
  // only check the DownloadToBlob flag here, which ResourceRequestSender cannot
  // know.
  loader_->LoadAsynchronously(std::move(network_resource_request_),
                              Context().GetTopFrameOrigin(), no_mime_sniffing,
                              Context().CreateResourceLoadInfoNotifierWrapper(),
                              !resource_->GetResourceRequest().DownloadToBlob()
                                  ? fetcher_->GetCodeCacheHost()
                                  : nullptr,
                              this);
}

void ResourceLoader::Dispose() {
  loader_ = nullptr;
  progress_receiver_.reset();

  // Release() should be called to release |scheduler_client_id_| beforehand in
  // DidFinishLoading() or DidFail(), but when a timer to call Cancel() is
  // ignored due to GC, this case happens. We just release here because we can
  // not schedule another request safely. See crbug.com/675947.
  if (scheduler_client_id_ != ResourceLoadScheduler::kInvalidClientId) {
    Release(ResourceLoadScheduler::ReleaseOption::kReleaseOnly,
            ResourceLoadScheduler::TrafficReportHints::InvalidInstance());
  }
}

bool ResourceLoader::ShouldBeKeptAliveWhenDetached() const {
  if (base::FeatureList::IsEnabled(
          blink::features::kKeepAliveInBrowserMigration) &&
      resource_->GetResourceRequest().GetKeepalive()) {
    if (resource_->GetResourceRequest().GetAttributionReportingEligibility() ==
        network::mojom::AttributionReportingEligibility::kUnset) {
      // When enabled, non-attribution reporting Fetch keepalive requests should
      // not be kept alive by renderer.
      return false;
    }
    if (base::FeatureList::IsEnabled(
            blink::features::kAttributionReportingInBrowserMigration)) {
      // Attribution reporting keepalive requests with its owned migration
      // enabled should not be kept alive by renderer.
      return false;
    }
  }

  return resource_->GetResourceRequest().GetKeepalive() &&
         resource_->GetResponse().IsNull();
}

void ResourceLoader::AbortResponseBodyLoading() {
  if (response_body_loader_) {
    response_body_loader_->Abort();
  }
}

scoped_refptr<base::SingleThreadTaskRunner>
ResourceLoader::GetLoadingTaskRunner() {
  return fetcher_->GetTaskRunner();
}

void ResourceLoader::OnProgress(uint64_t delta) {
  DCHECK(!blob_finished_);

  if (scheduler_client_id_ == ResourceLoadScheduler::kInvalidClientId) {
    return;
  }

  if (auto* observer = fetcher_->GetResourceLoadObserver()) {
    observer->DidReceiveData(
        resource_->InspectorId(),
        base::SpanOrSize<const char>(base::checked_cast<size_t>(delta)));
  }
  resource_->DidDownloadData(delta);
}

void ResourceLoader::FinishedCreatingBlob(
    const scoped_refptr<BlobDataHandle>& blob) {
  DCHECK(!blob_finished_);

  if (scheduler_client_id_ == ResourceLoadScheduler::kInvalidClientId) {
    return;
  }

  if (auto* observer = fetcher_->GetResourceLoadObserver()) {
    observer->DidDownloadToBlob(resource_->InspectorId(), blob.get());
  }
  resource_->DidDownloadToBlob(blob);

  blob_finished_ = true;
  if (deferred_finish_loading_info_) {
    const ResourceResponse& response = resource_->GetResponse();
    DidFinishLoading(deferred_finish_loading_info_->response_end_time,
                     response.EncodedDataLength(), response.EncodedBodyLength(),
                     response.DecodedBodyLength());
  }
}

std::optional<ResourceRequestBlockedReason>
ResourceLoader::CheckResponseNosniff(
    mojom::blink::RequestContextType request_context,
    const ResourceResponse& response) {
  bool sniffing_allowed =
      ParseContentTypeOptionsHeader(response.HttpHeaderField(
          http_names::kXContentTypeOptions)) != kContentTypeOptionsNosniff;
  if (sniffing_allowed) {
    return std::nullopt;
  }

  String mime_type = response.HttpContentType();
  if (request_context == mojom::blink::RequestContextType::STYLE &&
      !MIMETypeRegistry::IsSupportedStyleSheetMIMEType(mime_type)) {
    fetcher_->GetConsoleLogger().AddConsoleMessage(
        mojom::ConsoleMessageSource::kSecurity,
        mojom::ConsoleMessageLevel::kError,
        "Refused to apply style from '" +
            response.CurrentRequestUrl().ElidedString() +
            "' because its MIME type ('" + mime_type + "') " +
            "is not a supported stylesheet MIME type, and strict MIME checking "
            "is enabled.");
    return ResourceRequestBlockedReason::kContentType;
  }
  // TODO(mkwst): Move the 'nosniff' bit of 'AllowedByNosniff::MimeTypeAsScript'
  // here alongside the style checks, and put its use counters somewhere else.

  return std::nullopt;
}

void ResourceLoader::HandleDataUrl() {
  if (!IsLoading()) {
    return;
  }
  if (freeze_mode_ != LoaderFreezeMode::kNone) {
    defers_handling_data_url_ = true;
    return;
  }

  // Extract a ResourceResponse from the data url.
  // We don't have to verify mime type again since it's allowed to handle the
  // data url with invalid mime type in some cases.
  // CanHandleDataURLRequestLocally() has already checked if the data url can be
  // handled here.
  auto [result, response, data] = network_utils::ParseDataURL(
      resource_->Url(), resource_->GetResourceRequest().HttpMethod(),
      resource_->GetResourceRequest().GetUkmSourceId(),
      fetcher_->UkmRecorder());
  if (result != net::OK) {
    HandleError(ResourceError(result, resource_->Url(), std::nullopt));
    return;
  }
  DCHECK(data);
  const size_t data_size = data->size();

  DidReceiveResponseInternal(response, /*cached_metadata=*/std::nullopt);
  if (!IsLoading()) {
    return;
  }

  auto* bytes_consumer =
      MakeGarbageCollected<SharedBufferBytesConsumer>(std::move(data));
  DidStartLoadingResponseBodyInternal(*bytes_consumer);
  if (!IsLoading()) {
    return;
  }

  // DidFinishLoading() may deferred until the response body loader reaches to
  // end.
  DidFinishLoading(base::TimeTicks::Now(), data_size, data_size, data_size);
}

bool ResourceLoader::ShouldBlockRequestBasedOnSubresourceFilterDnsAliasCheck(
    const Vector<String>&
```