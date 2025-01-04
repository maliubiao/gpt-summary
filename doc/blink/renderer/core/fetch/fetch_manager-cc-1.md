Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/fetch/fetch_manager.cc`.

Here's a breakdown of the code and its functions:

1. **`FetchManager::Loader::DidReceiveResponse`**: Handles the initial response from the network. Sets up integrity checking (SRI) if needed.
2. **`FetchManager::Loader::DidReceiveCachedMetadata`**: Handles cached metadata.
3. **`FetchManager::Loader::DidStartLoadingResponseBody`**:  Starts processing the response body, potentially adding buffering for caching.
4. **`FetchManager::Loader::DidFinishLoading`**:  Handles successful completion of loading, notifying about success and cleaning up.
5. **`FetchManager::Loader::DidFail`**: Handles failures during loading, including Trust Token errors and CORS errors. Reports errors to DevTools.
6. **`FetchManager::Loader::DidFailRedirectCheck`**: Handles failures in redirect checks.
7. **`FetchLoaderBase::Start`**:  Initiates the fetching process. Performs checks like HSTS, referrer, mixed content, and CSP. Decides whether to perform a scheme fetch or an HTTP fetch based on the request's properties (origin, mode, scheme).
8. **`FetchManager::Loader::Dispose`**: Cleans up resources, cancels the loader.
9. **`FetchManager::Loader::Abort`**: Aborts the fetch, rejecting the promise and canceling the underlying loader.
10. **`FetchLoaderBase::PerformSchemeFetch`**: Handles fetching based on the URL scheme (HTTP, data).
11. **`FetchLoaderBase::FileIssueAndPerformNetworkError`**: Reports CORS-related network errors.
12. **`FetchLoaderBase::PerformNetworkError`**:  Handles general network errors.
13. **`FetchLoaderBase::PerformHTTPFetch`**:  Performs an HTTP fetch by creating a `ResourceRequest` and a `ThreadableLoader`.
14. **`FetchLoaderBase::PerformDataFetch`**: Performs a fetch for `data:` URLs.
15. **`FetchManager::Loader::CreateLoader`**: Creates a `ThreadableLoader` to handle the actual network request.
16. **`FetchLoaderBase::AddConsoleMessage`**: Adds console messages, typically for errors.
17. **`FetchManager::Loader::Failed`**: Handles failures, rejects the promise, and notifies completion.
18. **`FetchManager::Loader::NotifyFinished`**: Notifies the `FetchManager` that the loader has finished.
19. **`FetchManager::Loader::IsDeferred`**: Indicates if the fetch is deferred (for FetchLater API).
20. **`FetchManager::Loader::LogIfKeepalive`**: Logs metrics for keep-alive requests.
21. **`FetchLaterManager::DeferredLoader`**: A specialized loader for the FetchLater API, which delays the actual network request.
22. **`FetchLaterManager::DeferredLoader::Process`**:  Activates a deferred fetch.
23. **`FetchLaterManager::DeferredLoader::GetDeferredBytesForUrlOrigin`**:  Gets the body size of a deferred request if it's same-origin.
24. **`FetchLaterManager::DeferredLoader::Abort`**: Aborts a deferred fetch.
25. **`FetchLaterManager::DeferredLoader::CreateLoader`**: Creates a `FetchLaterLoader` in the browser process for deferred fetches.
26. **`FetchLaterManager::DeferredLoader::Failed`**: Handles failures for deferred fetches.
27. **`FetchLaterManager::DeferredLoader::NotifyFinished`**: Notifies the `FetchLaterManager` about the completion of a deferred loader.
28. **`FetchLaterManager::DeferredLoader::TimerFired`**:  Triggers the activation of a deferred fetch after a timeout.
29. **`FetchManager::Fetch`**:  The main entry point for initiating a fetch request. Creates a `Loader` and returns a promise.
30. **`FetchLaterManager::FetchLater`**: The main entry point for the FetchLater API.

The code manages the lifecycle of fetching resources, handling different scenarios like success, failure, caching, CORS, and the FetchLater API.
这是 blink 引擎中 `FetchManager` 的一部分，主要负责管理和执行资源获取（fetch）操作。`FetchManager::Loader` 是一个内部类，负责处理单个 fetch 请求的生命周期。

**功能归纳:**

这部分代码主要定义了 `FetchManager::Loader` 和 `FetchLaterManager::DeferredLoader` 两个类，它们负责执行具体的 fetch 操作。

*   **`FetchManager::Loader`**:  处理常规的 fetch 请求，包括接收响应头、处理缓存元数据、接收响应体、处理加载完成和加载失败等事件。它还负责处理与安全相关的检查，例如 SRI (Subresource Integrity)。
*   **`FetchLaterManager::DeferredLoader`**: 处理 "延迟获取" (FetchLater) API 的请求。这种请求不会立即发送，而是会在稍后的某个时间点或满足特定条件时发送。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript `fetch()` API:** 当 JavaScript 代码调用 `fetch()` 函数时，最终会触发 `FetchManager::Fetch` 方法来创建一个 `FetchManager::Loader` 实例，并执行相应的网络请求。
    *   **假设输入:** JavaScript 代码 `fetch('https://example.com/data.json')`
    *   **输出:**  `FetchManager::Fetch` 创建一个 `Loader` 对象，并开始向 `https://example.com/data.json` 发起请求。
*   **HTML `<link>` 标签和 CSS:** 当浏览器解析 HTML 并遇到 `<link>` 标签加载 CSS 文件时，或者 CSS 中使用 `@import` 规则时，也会触发 fetch 操作。虽然不一定直接使用 `FetchManager::Loader`，但 `FetchManager` 整体负责管理这些资源加载。
*   **Service Workers:** Service Workers 可以拦截 `fetch` 请求，并使用 `FetchEvent.respondWith()` 返回自定义的 `Response`。`FetchManager::Loader` 的逻辑会处理 Service Worker 返回的响应。

**逻辑推理的假设输入与输出:**

*   **假设输入:** 一个 fetch 请求，响应头中包含 `Content-Type: application/json` 和有效的 SRI 校验值。
*   **输出:** `FetchManager::Loader::DidReceiveResponse` 会创建一个 `SRIVerifier` 对象，并在接收响应体时进行完整性校验。如果校验成功，`DidFinishLoading` 会被调用。如果校验失败，`DidFail` 会被调用。

**用户或编程常见的使用错误举例:**

*   **CORS 问题:**  如果 JavaScript 代码从一个域名的网页向另一个域名的 API 发起 fetch 请求，而目标 API 没有正确设置 CORS 头信息，`FetchLoaderBase::Start` 中的 CORS 检查会阻止请求，并在 `FileIssueAndPerformNetworkError` 中报告错误。
    *   **用户操作:** 在 `https://user.example.com` 的页面上运行 JavaScript 代码 `fetch('https://api.example.net/data')`，如果 `api.example.net` 没有设置 `Access-Control-Allow-Origin: *` 或 `Access-Control-Allow-Origin: https://user.example.com`。
    *   **结果:** 控制台会显示类似 "Fetch API cannot load https://api.example.net/data. No 'Access-Control-Allow-Origin' header is present on the requested resource." 的错误信息。
*   **SRI 校验失败:**  如果 HTML `<script>` 或 `<link>` 标签中指定了 `integrity` 属性，但实际加载的资源内容与 `integrity` 属性的值不匹配，`FetchManager::Loader::DidReceiveResponse` 创建的 `SRIVerifier` 会检测到错误，并调用 `DidFail`。
    *   **用户操作:** 在 HTML 中使用 `<script src="https://cdn.example.com/script.js" integrity="sha384-xxxxxxxxxxxxx">`，但 `cdn.example.com/script.js` 的内容被修改过。
    *   **结果:** 浏览器会阻止脚本的执行，并在控制台显示 SRI 校验失败的错误信息。
*   **FetchLater API 使用不当:**  开发者可能错误地设置 `activate_after` 参数，导致请求在不合适的时间发送，或者忘记处理 `FetchLaterResult` 的状态。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个网页。**
2. **网页加载 HTML、CSS 和 JavaScript 资源。**
3. **JavaScript 代码执行，调用了 `fetch()` API 或者使用了其他触发资源加载的功能 (例如动态插入带有 `src` 属性的标签)。**
4. **`blink::mojom::FetchAPI::Fetch` (或类似接口) 被调用，最终进入 `FetchManager::Fetch`。**
5. **`FetchManager::Fetch` 创建一个 `FetchManager::Loader` 实例，并传递请求数据。**
6. **`FetchManager::Loader::Start` 方法开始执行，进行各种安全检查和策略判断。**
7. **`ThreadableLoader` 被创建，并向网络层发起请求。**
8. **网络层返回响应，`FetchManager::Loader` 的各种 `DidReceive...` 方法被调用，处理响应的各个阶段。**
9. **如果发生错误，例如 CORS 失败或 SRI 校验失败，`FetchManager::Loader::DidFail` 会被调用。**
10. **对于 FetchLater API，步骤类似，但会创建 `FetchLaterManager::DeferredLoader`，并且请求不会立即发送，而是会等待 `activate_after` 时间到达或被显式激活。**

在调试过程中，可以通过以下方式来追踪到 `FetchManager::Loader` 的执行：

*   **设置断点:** 在 `FetchManager::Loader` 和 `FetchLoaderBase` 的关键方法 (例如 `Start`, `DidReceiveResponse`, `DidFail`) 设置断点。
*   **查看网络请求日志:**  浏览器的开发者工具中的 "Network" 标签可以查看发出的网络请求和响应头信息，这有助于理解请求的流程和可能发生的错误。
*   **查看控制台日志:** 错误信息和警告信息通常会输出到控制台，这些信息可能指示了 fetch 过程中出现的问题。
*   **使用 Chromium 的 tracing 工具:**  通过 Chromium 的 tracing 功能 (chrome://tracing)，可以记录更详细的内部事件，包括 fetch 相关的操作。

总而言之，这段代码是 Chromium Blink 引擎中处理网络资源获取的核心部分，它与 JavaScript `fetch()` API、HTML 资源加载以及各种网络安全策略紧密相关。理解这段代码的功能对于调试网络请求问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/fetch/fetch_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
 response_resolver_.Clear();
  } else {
    DCHECK(!integrity_verifier_);
    // We have another place holder body for SRI.
    PlaceHolderBytesConsumer* verified = place_holder_body_;
    place_holder_body_ = MakeGarbageCollected<PlaceHolderBytesConsumer>();
    BytesConsumer* underlying = place_holder_body_;

    integrity_verifier_ = MakeGarbageCollected<SRIVerifier>(
        underlying, verified, r, this, GetFetchRequestData()->Integrity(),
        response.CurrentRequestUrl(), r->GetResponse()->GetType());
  }
}

void FetchManager::Loader::DidReceiveCachedMetadata(mojo_base::BigBuffer data) {
  if (cached_metadata_handler_) {
    cached_metadata_handler_->SetSerializedCachedMetadata(std::move(data));
  }
}

void FetchManager::Loader::DidStartLoadingResponseBody(BytesConsumer& body) {
  if (GetFetchRequestData()->Integrity().empty() &&
      !response_has_no_store_header_) {
    // BufferingBytesConsumer reads chunks from |bytes_consumer| as soon as
    // they get available to relieve backpressure.  Buffering starts after
    // a short delay, however, to allow the Response to be drained; e.g.
    // when the Response is passed to FetchEvent.respondWith(), etc.
    //
    // https://fetch.spec.whatwg.org/#fetching
    // The user agent should ignore the suspension request if the ongoing
    // fetch is updating the response in the HTTP cache for the request.
    place_holder_body_->Update(BufferingBytesConsumer::CreateWithDelay(
        &body, GetExecutionContext()->GetTaskRunner(TaskType::kNetworking)));
  } else {
    place_holder_body_->Update(&body);
  }
  place_holder_body_ = nullptr;
}

void FetchManager::Loader::DidFinishLoading(uint64_t) {
  DCHECK(!place_holder_body_);
  DCHECK(!failed_);

  finished_ = true;

  auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext());
  if (window && window->GetFrame() &&
      network::IsSuccessfulStatus(response_http_status_code_)) {
    window->GetFrame()->GetPage()->GetChromeClient().AjaxSucceeded(
        window->GetFrame());
  }
  NotifyFinished();
}

void FetchManager::Loader::DidFail(uint64_t identifier,
                                   const ResourceError& error) {
  if (GetFetchRequestData() && GetFetchRequestData()->TrustTokenParams()) {
    HistogramNetErrorForTrustTokensOperation(
        GetFetchRequestData()->TrustTokenParams()->operation,
        error.ErrorCode());
  }

  if (error.TrustTokenOperationError() !=
      network::mojom::blink::TrustTokenOperationStatus::kOk) {
    Failed(String(),
           TrustTokenErrorToDOMException(error.TrustTokenOperationError()),
           IdentifiersFactory::SubresourceRequestId(identifier));
    return;
  }

  std::optional<base::UnguessableToken> issue_id;
  std::optional<String> issue_summary;
  if (const auto& cors_error_status = error.CorsErrorStatus()) {
    issue_id = cors_error_status->issue_id;
    if (base::FeatureList::IsEnabled(features::kDevToolsImprovedNetworkError)) {
      issue_summary = cors::GetErrorStringForIssueSummary(
          *cors_error_status, fetch_initiator_type_names::kFetch);
    }
  }
  Failed(String(), nullptr,
         IdentifiersFactory::SubresourceRequestId(identifier), issue_id,
         issue_summary);
}

void FetchManager::Loader::DidFailRedirectCheck(uint64_t identifier) {
  Failed(String(), nullptr,
         IdentifiersFactory::SubresourceRequestId(identifier));
}

void FetchLoaderBase::Start(ExceptionState& exception_state) {
  // "1. If |request|'s url contains a Known HSTS Host, modify it per the
  // requirements of the 'URI [sic] Loading and Port Mapping' chapter of HTTP
  // Strict Transport Security."
  // FIXME: Implement this.

  // "2. If |request|'s referrer is not none, set |request|'s referrer to the
  // result of invoking determine |request|'s referrer."
  // We set the referrer using workerGlobalScope's URL in
  // WorkerThreadableLoader.

  // "3. If |request|'s synchronous flag is unset and fetch is not invoked
  // recursively, run the remaining steps asynchronously."
  // We don't support synchronous flag.

  // "4. Let response be the value corresponding to the first matching
  // statement:"

  // "- should fetching |request| be blocked as mixed content returns blocked"
  // We do mixed content checking in ResourceFetcher.

  // "- should fetching |request| be blocked as content security returns
  //    blocked"
  CHECK(execution_context_);
  if (!execution_context_->GetContentSecurityPolicyForWorld(world_.Get())
           ->AllowConnectToSource(fetch_request_data_->Url(),
                                  fetch_request_data_->Url(),
                                  RedirectStatus::kNoRedirect)) {
    // "A network error."
    PerformNetworkError(
        "Refused to connect to '" + fetch_request_data_->Url().ElidedString() +
        "' because it violates the document's Content Security Policy.");
    return;
  }

  const KURL& url = fetch_request_data_->Url();
  // "- |request|'s url's origin is same origin with |request|'s origin,
  //    |request|'s tainted origin flag is unset, and the CORS flag is unset"
  // Note tainted origin flag is always unset here.
  // Note we don't support to call this method with |CORS flag|
  // "- |request|'s current URL's scheme is |data|"
  // "- |request|'s mode is |navigate| or |websocket|".
  if (fetch_request_data_->Origin()->CanReadContent(url) ||
      (fetch_request_data_->IsolatedWorldOrigin() &&
       fetch_request_data_->IsolatedWorldOrigin()->CanReadContent(url)) ||
      fetch_request_data_->Mode() == network::mojom::RequestMode::kNavigate) {
    // "The result of performing a scheme fetch using request."
    PerformSchemeFetch(exception_state);
    return;
  }

  // "- |request|'s mode is |same-origin|"
  if (fetch_request_data_->Mode() == RequestMode::kSameOrigin) {
    // This error is so early that there isn't an identifier yet, generate one.
    FileIssueAndPerformNetworkError(RendererCorsIssueCode::kDisallowedByMode,
                                    CreateUniqueIdentifier());
    return;
  }

  // "- |request|'s mode is |no CORS|"
  if (fetch_request_data_->Mode() == RequestMode::kNoCors) {
    // "If |request|'s redirect mode is not |follow|, then return a network
    // error.
    if (fetch_request_data_->Redirect() != RedirectMode::kFollow) {
      // This error is so early that there isn't an identifier yet, generate
      // one.
      FileIssueAndPerformNetworkError(
          RendererCorsIssueCode::kNoCorsRedirectModeNotFollow,
          CreateUniqueIdentifier());
      return;
    }

    // "Set |request|'s response tainting to |opaque|."
    // Response tainting is calculated in the CORS module in the network
    // service.
    //
    // "The result of performing a scheme fetch using |request|."
    PerformSchemeFetch(exception_state);
    return;
  }

  // "- |request|'s url's scheme is not one of 'http' and 'https'"
  // This may include other HTTP-like schemes if the embedder has added them
  // to SchemeRegistry::registerURLSchemeAsSupportingFetchAPI.
  if (!SchemeRegistry::ShouldTreatURLSchemeAsSupportingFetchAPI(
          fetch_request_data_->Url().Protocol())) {
    // This error is so early that there isn't an identifier yet, generate one.
    FileIssueAndPerformNetworkError(RendererCorsIssueCode::kCorsDisabledScheme,
                                    CreateUniqueIdentifier());
    return;
  }

  // "Set |request|'s response tainting to |CORS|."
  // Response tainting is calculated in the CORS module in the network
  // service.

  // "The result of performing an HTTP fetch using |request| with the
  // |CORS flag| set."
  PerformHTTPFetch(exception_state);
}

void FetchManager::Loader::Dispose() {
  // Prevent notification
  fetch_manager_ = nullptr;
  if (threadable_loader_) {
    if (GetFetchRequestData()->Keepalive()) {
      threadable_loader_->Detach();
    } else {
      threadable_loader_->Cancel();
    }
    threadable_loader_ = nullptr;
  }
  if (integrity_verifier_)
    integrity_verifier_->Cancel();
  SetExecutionContext(nullptr);
}

// https://fetch.spec.whatwg.org/#abort-fetch
// To abort a fetch() call with a promise, request, responseObject, and an
// error:
void FetchManager::Loader::Abort() {
  ScriptState* script_state = GetScriptState();
  v8::Local<v8::Value> error = Signal()->reason(script_state).V8Value();
  // 1. Reject promise with error.
  if (response_resolver_) {
    response_resolver_->Reject(error);
    response_resolver_.Clear();
  }
  if (threadable_loader_) {
    // Prevent re-entrancy.
    auto loader = threadable_loader_;
    threadable_loader_ = nullptr;
    loader->Cancel();
  }

  // 2. If request’s body is non-null and is readable, then cancel request’s
  //  body with error.
  if (FetchRequestData* fetch_request_data = GetFetchRequestData()) {
    if (BodyStreamBuffer* body_stream_buffer = fetch_request_data->Buffer()) {
      if (ReadableStream* readable_stream = body_stream_buffer->Stream()) {
        ReadableStream::Cancel(script_state, readable_stream, error);
      }
    }
  }
  NotifyFinished();
}

void FetchLoaderBase::PerformSchemeFetch(ExceptionState& exception_state) {
  // "To perform a scheme fetch using |request|, switch on |request|'s url's
  // scheme, and run the associated steps:"
  if (SchemeRegistry::ShouldTreatURLSchemeAsSupportingFetchAPI(
          fetch_request_data_->Url().Protocol()) ||
      fetch_request_data_->Url().ProtocolIs("blob")) {
    // "Return the result of performing an HTTP fetch using |request|."
    PerformHTTPFetch(exception_state);
  } else if (fetch_request_data_->Url().ProtocolIsData()) {
    PerformDataFetch();
  } else {
    // FIXME: implement other protocols.
    // This error is so early that there isn't an identifier yet, generate one.
    FileIssueAndPerformNetworkError(RendererCorsIssueCode::kCorsDisabledScheme,
                                    CreateUniqueIdentifier());
  }
}

void FetchLoaderBase::FileIssueAndPerformNetworkError(
    RendererCorsIssueCode network_error,
    int64_t identifier) {
  auto issue_id = base::UnguessableToken::Create();
  switch (network_error) {
    case RendererCorsIssueCode::kCorsDisabledScheme: {
      AuditsIssue::ReportCorsIssue(
          execution_context_, identifier, network_error,
          fetch_request_data_->Url().GetString(),
          fetch_request_data_->Origin()->ToString(),
          fetch_request_data_->Url().Protocol(), issue_id);
      PerformNetworkError(
          "Fetch API cannot load " + fetch_request_data_->Url().GetString() +
              ". URL scheme \"" + fetch_request_data_->Url().Protocol() +
              "\" is not supported.",
          issue_id);
      break;
    }
    case RendererCorsIssueCode::kDisallowedByMode: {
      AuditsIssue::ReportCorsIssue(execution_context_, identifier,
                                   network_error,
                                   fetch_request_data_->Url().GetString(),
                                   fetch_request_data_->Origin()->ToString(),
                                   WTF::g_empty_string, issue_id);
      PerformNetworkError(
          "Fetch API cannot load " + fetch_request_data_->Url().GetString() +
              ". Request mode is \"same-origin\" but the URL\'s "
              "origin is not same as the request origin " +
              fetch_request_data_->Origin()->ToString() + ".",
          issue_id);

      break;
    }
    case RendererCorsIssueCode::kNoCorsRedirectModeNotFollow: {
      AuditsIssue::ReportCorsIssue(execution_context_, identifier,
                                   network_error,
                                   fetch_request_data_->Url().GetString(),
                                   fetch_request_data_->Origin()->ToString(),
                                   WTF::g_empty_string, issue_id);
      PerformNetworkError(
          "Fetch API cannot load " + fetch_request_data_->Url().GetString() +
              ". Request mode is \"no-cors\" but the redirect mode "
              "is not \"follow\".",
          issue_id);
      break;
    }
  }
}

void FetchLoaderBase::PerformNetworkError(
    const String& message,
    std::optional<base::UnguessableToken> issue_id) {
  Failed(message, nullptr, std::nullopt, issue_id);
}

void FetchLoaderBase::PerformHTTPFetch(ExceptionState& exception_state) {
  // CORS preflight fetch procedure is implemented inside ThreadableLoader.

  // "1. Let |HTTPRequest| be a copy of |request|, except that |HTTPRequest|'s
  //  body is a tee of |request|'s body."
  // We use ResourceRequest class for HTTPRequest.
  // FIXME: Support body.
  ResourceRequest request(fetch_request_data_->Url());
  request.SetRequestorOrigin(fetch_request_data_->Origin());
  request.SetNavigationRedirectChain(
      fetch_request_data_->NavigationRedirectChain());
  request.SetIsolatedWorldOrigin(fetch_request_data_->IsolatedWorldOrigin());
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  request.SetRequestDestination(fetch_request_data_->Destination());
  request.SetFetchLikeAPI(true);
  request.SetHttpMethod(fetch_request_data_->Method());
  request.SetFetchWindowId(fetch_request_data_->WindowId());
  request.SetTrustTokenParams(fetch_request_data_->TrustTokenParams());
  request.SetMode(fetch_request_data_->Mode());
  request.SetTargetAddressSpace(fetch_request_data_->TargetAddressSpace());

  request.SetCredentialsMode(fetch_request_data_->Credentials());
  for (const auto& header : fetch_request_data_->HeaderList()->List()) {
    request.AddHttpHeaderField(AtomicString(header.first),
                               AtomicString(header.second));
  }

  if (fetch_request_data_->Method() != http_names::kGET &&
      fetch_request_data_->Method() != http_names::kHEAD) {
    if (fetch_request_data_->Buffer()) {
      scoped_refptr<EncodedFormData> form_data =
          fetch_request_data_->Buffer()->DrainAsFormData(exception_state);
      if (form_data) {
        request.SetHttpBody(form_data);
      } else if (RuntimeEnabledFeatures::FetchUploadStreamingEnabled(
                     execution_context_)) {
        UseCounter::Count(execution_context_,
                          WebFeature::kFetchUploadStreaming);
        DCHECK(!fetch_request_data_->Buffer()->IsStreamLocked());
        mojo::PendingRemote<network::mojom::blink::ChunkedDataPipeGetter>
            pending_remote;
        fetch_request_data_->Buffer()->DrainAsChunkedDataPipeGetter(
            script_state_, pending_remote.InitWithNewPipeAndPassReceiver(),
            /*client=*/nullptr);
        request.MutableBody().SetStreamBody(std::move(pending_remote));
      }
    }
  }
  request.SetCacheMode(fetch_request_data_->CacheMode());
  request.SetRedirectMode(fetch_request_data_->Redirect());
  request.SetFetchPriorityHint(fetch_request_data_->FetchPriorityHint());
  request.SetPriority(fetch_request_data_->Priority());
  request.SetUseStreamOnResponse(true);
  request.SetReferrerString(fetch_request_data_->ReferrerString());
  request.SetReferrerPolicy(fetch_request_data_->GetReferrerPolicy());

  if (IsDeferred()) {
    // https://whatpr.org/fetch/1647/9ca4bda...9994c1d.html#request-a-deferred-fetch
    // "Deferred fetching"
    // 4. Set request’s service-workers mode to "none".
    request.SetSkipServiceWorker(true);
  } else {
    request.SetSkipServiceWorker(world_->IsIsolatedWorld());
  }

  if (fetch_request_data_->Keepalive()) {
    request.SetKeepalive(true);
    UseCounter::Count(execution_context_, mojom::WebFeature::kFetchKeepalive);
  }

  request.SetBrowsingTopics(fetch_request_data_->BrowsingTopics());
  request.SetAdAuctionHeaders(fetch_request_data_->AdAuctionHeaders());
  request.SetAttributionReportingEligibility(
      fetch_request_data_->AttributionReportingEligibility());
  request.SetAttributionReportingSupport(
      fetch_request_data_->AttributionSupport());
  request.SetSharedStorageWritableOptedIn(
      fetch_request_data_->SharedStorageWritable());

  request.SetOriginalDestination(fetch_request_data_->OriginalDestination());

  request.SetServiceWorkerRaceNetworkRequestToken(
      fetch_request_data_->ServiceWorkerRaceNetworkRequestToken());

  request.SetFetchLaterAPI(IsDeferred());

  if (execution_context_->IsSharedWorkerGlobalScope() &&
      DynamicTo<SharedWorkerGlobalScope>(*execution_context_)
          ->DoesRequireCrossSiteRequestForCookies()) {
    request.SetSiteForCookies(net::SiteForCookies());
  }

  // "3. Append `Host`, ..."
  // FIXME: Implement this when the spec is fixed.

  // "4.If |HTTPRequest|'s force Origin header flag is set, append `Origin`/
  // |HTTPRequest|'s origin, serialized and utf-8 encoded, to |HTTPRequest|'s
  // header list."
  // We set Origin header in updateRequestForAccessControl() called from
  // ThreadableLoader::makeCrossOriginAccessRequest

  // "5. Let |credentials flag| be set if either |HTTPRequest|'s credentials
  // mode is |include|, or |HTTPRequest|'s credentials mode is |same-origin|
  // and the |CORS flag| is unset, and unset otherwise."

  ResourceLoaderOptions resource_loader_options(world_);
  resource_loader_options.initiator_info.name =
      fetch_initiator_type_names::kFetch;
  resource_loader_options.data_buffering_policy = kDoNotBufferData;
  if (fetch_request_data_->URLLoaderFactory()) {
    mojo::PendingRemote<network::mojom::blink::URLLoaderFactory> factory_clone;
    fetch_request_data_->URLLoaderFactory()->Clone(
        factory_clone.InitWithNewPipeAndPassReceiver());
    resource_loader_options.url_loader_factory =
        base::MakeRefCounted<base::RefCountedData<
            mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>>>(
            std::move(factory_clone));
  }

  if (fetch_request_data_->Keepalive() && !request.IsFetchLaterAPI()) {
    FetchUtils::LogFetchKeepAliveRequestMetric(
        request.GetRequestContext(),
        FetchUtils::FetchKeepAliveRequestState::kTotal);
  }
  CreateLoader(std::move(request), resource_loader_options);
}

// performDataFetch() is almost the same as performHTTPFetch(), except for:
// - We set AllowCrossOriginRequests to allow requests to data: URLs in
//   'same-origin' mode.
// - We reject non-GET method.
void FetchLoaderBase::PerformDataFetch() {
  DCHECK(fetch_request_data_->Url().ProtocolIsData());

  ResourceRequest request(fetch_request_data_->Url());
  request.SetRequestorOrigin(fetch_request_data_->Origin());
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  request.SetRequestDestination(fetch_request_data_->Destination());
  request.SetFetchLikeAPI(true);
  request.SetUseStreamOnResponse(true);
  request.SetHttpMethod(fetch_request_data_->Method());
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);
  request.SetRedirectMode(RedirectMode::kError);
  request.SetFetchPriorityHint(fetch_request_data_->FetchPriorityHint());
  request.SetPriority(fetch_request_data_->Priority());
  // We intentionally skip 'setExternalRequestStateFromRequestorAddressSpace',
  // as 'data:' can never be external.

  ResourceLoaderOptions resource_loader_options(world_);
  resource_loader_options.data_buffering_policy = kDoNotBufferData;

  CreateLoader(std::move(request), resource_loader_options);
}

void FetchManager::Loader::CreateLoader(
    ResourceRequest request,
    const ResourceLoaderOptions& resource_loader_options) {
  threadable_loader_ = MakeGarbageCollected<ThreadableLoader>(
      *GetExecutionContext(), this, resource_loader_options);
  threadable_loader_->Start(std::move(request));
}

bool FetchLoaderBase::AddConsoleMessage(
    const String& message,
    std::optional<base::UnguessableToken> issue_id) {
  if (execution_context_->IsContextDestroyed())
    return false;
  if (!message.empty()) {
    // CORS issues are reported via network service instrumentation, with the
    // exception of early errors reported in FileIssueAndPerformNetworkError.
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kJavaScript,
        mojom::blink::ConsoleMessageLevel::kError, message);
    if (issue_id) {
      console_message->SetCategory(mojom::blink::ConsoleMessageCategory::Cors);
    }
    execution_context_->AddConsoleMessage(console_message);
  }
  return true;
}

void FetchManager::Loader::Failed(
    const String& message,
    DOMException* dom_exception,
    std::optional<String> devtools_request_id,
    std::optional<base::UnguessableToken> issue_id,
    std::optional<String> issue_summary) {
  if (failed_ || finished_) {
    return;
  }
  failed_ = true;
  if (!AddConsoleMessage(message, issue_id)) {
    return;
  }
  if (response_resolver_) {
    ScriptState::Scope scope(GetScriptState());
    if (dom_exception) {
      response_resolver_->Reject(dom_exception);
    } else {
      response_resolver_->RejectBecauseFailed(
          std::move(devtools_request_id), issue_id, std::move(issue_summary));
      LogIfKeepalive("Failed");
    }
    response_resolver_.Clear();
  }
  NotifyFinished();
}

void FetchManager::Loader::NotifyFinished() {
  if (fetch_manager_)
    fetch_manager_->OnLoaderFinished(this);
}

bool FetchManager::Loader::IsDeferred() const {
  return false;
}

void FetchManager::Loader::LogIfKeepalive(
    std::string_view request_state) const {
  return;
  CHECK(request_state == "Succeeded" || request_state == "Failed");
  if (!GetFetchRequestData()->Keepalive()) {
    return;
  }

  base::TimeDelta duration = base::TimeTicks::Now() - request_started_time_;
  base::UmaHistogramMediumTimes("FetchKeepAlive.RequestDuration", duration);
  base::UmaHistogramMediumTimes(
      base::StrCat({"FetchKeepAlive.RequestDuration.", request_state}),
      duration);
}

// A subtype of FetchLoader to handle the deferred fetching algorithm [1].
//
// This loader and FetchManager::Loader are similar that they both runs the
// fetching algorithm provided by the base class. However, this loader does not
// go down ThreadableLoader and ResourceFetcher. Rather, it creates requests via
// a similar mojo FetchLaterLoaderFactory. Other differences include:
//   - `IsDeferred()` is true, which helps the base generate different requests.
//   - Expect no response after `Start()` is called.
//   - Support activateAfter from [2] to allow sending at specified time.
//   - Support FetchLaterResult from [2].
//
// Underlying, this loader intends to create a "deferred" fetch request,
// i.e. `ResourceRequest.is_fetch_later_api` is true, when `Start()` is called.
// The request will not be sent by network service (handled via browser)
// immediately until ExecutionContext of the FetchLaterManager is destroyed.
//
// Note that this loader does not use the "defer" mechanism as described in
// `ResourcFetcher::RequestResource()` or `ResourceFetcher::StartLoad()`, as
// the latter method can only be called when ResourcFetcher is not detached.
// Plus, the browser companion must be notified when the context is still alive.
//
// [1]:
// https://whatpr.org/fetch/1647/9ca4bda...9994c1d.html#request-a-deferred-fetch
// [2]:
// https://whatpr.org/fetch/1647/9ca4bda...9994c1d.html#dom-global-fetch-later
class FetchLaterManager::DeferredLoader final
    : public GarbageCollected<FetchLaterManager::DeferredLoader>,
      public FetchLoaderBase {
 public:
  DeferredLoader(ExecutionContext* ec,
                 FetchLaterManager* fetch_later_manager,
                 FetchRequestData* fetch_request_data,
                 ScriptState* script_state,
                 AbortSignal* signal,
                 const std::optional<base::TimeDelta>& activate_after)
      : FetchLoaderBase(ec, fetch_request_data, script_state, signal),
        fetch_later_manager_(fetch_later_manager),
        fetch_later_result_(MakeGarbageCollected<FetchLaterResult>()),
        activate_after_(activate_after),
        timer_(ec->GetTaskRunner(FetchLaterManager::kTaskType),
               this,
               &DeferredLoader::TimerFired),
        loader_(ec) {
    base::UmaHistogramBoolean("FetchLater.Renderer.Total", true);
    // `timer_` is started in `CreateLoader()` so that it won't end before a
    // request is created.
  }

  FetchLaterResult* fetch_later_result() { return fetch_later_result_.Get(); }

  // FetchLoaderBase overrides:
  void Dispose() override {
    // Prevent notification
    fetch_later_manager_ = nullptr;
    SetExecutionContext(nullptr);

    timer_.Stop();
    // The browser companion will take care of the actual request sending when
    // discoverying the URL loading connections from here are gone.
  }

  void Process(const FetchLaterRendererMetricType& metric_type) {
    // https://whatpr.org/fetch/1647/9ca4bda...9994c1d.html#process-a-deferred-fetch
    // To process a deferred fetch deferredRecord:
    // 1. If deferredRecord’s invoke state is not "deferred", then return.
    if (invoke_state_ != InvokeState::DEFERRED) {
      return;
    }
    // 2. Set deferredRecord’s invoke state to "activated".
    SetInvokeState(InvokeState::ACTIVATED);
    // 3. Fetch deferredRecord’s request.
    if (loader_) {
      LogFetchLaterMetric(metric_type);
      loader_->SendNow();
    }
  }

  // Returns this loader's request body length if the followings are all true:
  // - this loader's request has a non-null body.
  // - `url` is "same origin" with this loader's request URL.
  uint64_t GetDeferredBytesForUrlOrigin(const KURL& url) const {
    return GetFetchRequestData()->Buffer() &&
                   SecurityOrigin::AreSameOrigin(GetFetchRequestData()->Url(),
                                                 url)
               ? GetFetchRequestData()->BufferByteLength()
               : 0;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(fetch_later_manager_);
    visitor->Trace(fetch_later_result_);
    visitor->Trace(timer_);
    visitor->Trace(loader_);
    FetchLoaderBase::Trace(visitor);
  }

  // For testing only:
  void RecreateTimerForTesting(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      const base::TickClock* tick_clock) {
    timer_.Stop();
    timer_.SetTaskRunnerForTesting(std::move(task_runner), tick_clock);
    if (activate_after_.has_value()) {
      timer_.StartOneShot(*activate_after_, FROM_HERE);
    }
  }

 private:
  enum class InvokeState {
    DEFERRED,
    ABORTED,
    ACTIVATED
  };
  void SetInvokeState(InvokeState state) {
    switch (state) {
      case InvokeState::DEFERRED:
        UseCounter::Count(GetExecutionContext(),
                          WebFeature::kFetchLaterInvokeStateDeferred);
        break;
      case InvokeState::ABORTED:
        UseCounter::Count(GetExecutionContext(),
                          WebFeature::kFetchLaterInvokeStateAborted);
        break;
      case InvokeState::ACTIVATED:
        UseCounter::Count(GetExecutionContext(),
                          WebFeature::kFetchLaterInvokeStateActivated);
        break;
      default:
        NOTREACHED();
    };
    invoke_state_ = state;
    fetch_later_result_->SetActivated(state == InvokeState::ACTIVATED);
  }

  // FetchLoaderBase overrides:
  bool IsDeferred() const override { return true; }
  void Abort() override {
    // https://whatpr.org/fetch/1647/9ca4bda...9994c1d.html#dom-global-fetch-later
    // 10. Add the following abort steps to requestObject’s signal:
    // 10-1. Set deferredRecord’s invoke state to "aborted".
    SetInvokeState(InvokeState::ABORTED);
    // 10-2. Remove deferredRecord from request’s client’s fetch group’s
    // deferred fetch records.
    if (loader_) {
      LogFetchLaterMetric(FetchLaterRendererMetricType::kAbortedByUser);
      loader_->Cancel();
    }
    NotifyFinished();
  }
  // Triggered after `Start()`.
  void CreateLoader(
      ResourceRequest request,
      const ResourceLoaderOptions& resource_loader_options) override {
    auto* factory = fetch_later_manager_->GetFactory();
    if (!factory) {
      Failed(/*message=*/String(), /*dom_exception=*/nullptr);
      return;
    }
    std::unique_ptr<network::ResourceRequest> network_request =
        fetch_later_manager_->PrepareNetworkRequest(std::move(request),
                                                    resource_loader_options);
    if (!network_request) {
      Failed(/*message=*/String(), /*dom_exception=*/nullptr);
      return;
    }

    // Don't do mime sniffing for fetch (crbug.com/2016)
    uint32_t url_loader_options = network::mojom::blink::kURLLoadOptionNone;
    // Computes a unique request_id for this renderer process.
    int request_id = GenerateRequestId();
    factory->CreateFetchLaterLoader(
        loader_.BindNewEndpointAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(FetchLaterManager::kTaskType)),
        request_id, url_loader_options, *network_request,
        net::MutableNetworkTrafficAnnotationTag(
            kFetchLaterTrafficAnnotationTag));
    CHECK(loader_.is_bound());
    loader_.set_disconnect_handler(WTF::BindOnce(
        &DeferredLoader::NotifyFinished, WrapWeakPersistent(this)));

    // https://whatpr.org/fetch/1647.html#request-a-deferred-fetch
    // Continued with "request a deferred fetch"
    // 12. If `activate_after_` is not null, then run the following steps in
    // parallel:
    if (activate_after_.has_value()) {
      // 12-1. The user agent should wait until `activate_after_`
      // milliseconds have passed ...
      // Implementation followed by `TimerFired()`.
      timer_.StartOneShot(*activate_after_, FROM_HERE);
    }
  }
  void Failed(const String& message,
              DOMException* dom_exception,
              std::optional<String> devtools_request_id = std::nullopt,
              std::optional<base::UnguessableToken> issue_id = std::nullopt,
              std::optional<String> issue_summary = std::nullopt) override {
    AddConsoleMessage(message, issue_id);
    NotifyFinished();
  }

  // Notifies the owner to remove `this` from its container, after which
  // `Dispose()` will also be called.
  void NotifyFinished() {
    if (fetch_later_manager_) {
      fetch_later_manager_->OnDeferredLoaderFinished(this);
    }
  }

  // Triggered by `timer_`.
  void TimerFired(TimerBase*) {
    // https://whatpr.org/fetch/1647.html#request-a-deferred-fetch
    // Continued with "request a deferred fetch":
    // 12-3. Process a deferred fetch given deferredRecord.
    Process(FetchLaterRendererMetricType::kActivatedByTimeout);
    NotifyFinished();
  }

  // A deferred fetch record's "invoke state" field.
  InvokeState invoke_state_ = InvokeState::DEFERRED;

  // Owns this instance.
  Member<FetchLaterManager> fetch_later_manager_;

  // Retains strong reference to the returned V8 object of a FetchLater API call
  // that creates this loader.
  //
  // The object itself may be held by a script, and may easily outlive `this` if
  // the script keeps holding the object after the FetchLater request completes.
  //
  // This field should be updated whenever `invoke_state_` changes.
  Member<FetchLaterResult> fetch_later_result_;

  // The "activateAfter" to request a deferred fetch.
  // https://whatpr.org/fetch/1647.html#request-a-deferred-fetch
  const std::optional<base::TimeDelta> activate_after_;
  // A timer to handle `activate_after_`.
  HeapTaskRunnerTimer<DeferredLoader> timer_;

  // Connects to FetchLaterLoader in browser.
  HeapMojoAssociatedRemote<mojom::blink::FetchLaterLoader> loader_;
};

FetchManager::FetchManager(ExecutionContext* execution_context)
    : ExecutionContextLifecycleObserver(execution_context) {}

ScriptPromise<Response> FetchManager::Fetch(ScriptState* script_state,
                                            FetchRequestData* request,
                                            AbortSignal* signal,
                                            ExceptionState& exception_state) {
  DCHECK(signal);
  if (signal->aborted()) {
    return ScriptPromise<Response>::Reject(script_state,
                                           signal->reason(script_state));
  }

  request->SetDestination(network::mojom::RequestDestination::kEmpty);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<Response>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  auto* loader = MakeGarbageCollected<Loader>(
      GetExecutionContext(), this, resolver, request, script_state, signal);
  loaders_.insert(loader);
  // TODO(ricea): Reject the Response body with AbortError, not TypeError.
  loader->Start(exception_state);
  return promise;
}

FetchLaterResult* FetchLaterManager::FetchLater(
    ScriptState* script_state,
    FetchRequestData* request,
    AbortSignal* signal,
    std::optional<DOMHighResTimeStamp> activate_after_ms,
    ExceptionState& exception_s
"""


```