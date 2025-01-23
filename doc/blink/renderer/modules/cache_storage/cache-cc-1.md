Response:
The user wants a summary of the functionalities implemented in the provided C++ code snippet from `blink/renderer/modules/cache_storage/cache.cc`. This is the second part of the file, and the user wants a consolidated understanding of its capabilities.

I need to analyze each function within the snippet and describe its purpose. I should also identify any connections to JavaScript, HTML, and CSS, providing examples where applicable. Furthermore, I need to consider potential user errors and how they might lead to the execution of this code. Finally, I should perform logical reasoning to infer input-output scenarios for the functions.

Here's a breakdown of the functions and my initial thoughts:

- **`Trace(Visitor* visitor)`**: This is likely a standard Chromium tracing mechanism for debugging and performance analysis. It doesn't directly relate to web technologies.
- **`CreateAbortController(ScriptState* script_state)`**: This function creates an `AbortController`, which is a JavaScript API. It's used to cancel asynchronous operations, like fetch requests.
- **`MatchImpl(...)`**: This function seems to implement the `Cache.match()` JavaScript API, allowing retrieval of a cached response matching a given request. It interacts heavily with `Request` and `Response` objects, and has options for controlling the matching behavior.
- **`MatchAllImpl(...)`**:  Similar to `MatchImpl`, this likely implements the `Cache.matchAll()` JavaScript API, returning all matching cached responses.
- **`AddAllImpl(...)`**: This appears to implement the `Cache.addAll()` JavaScript API, which adds multiple resources to the cache. It involves fetching resources and storing them.
- **`DeleteImpl(...)`**: This function likely implements the `Cache.delete()` JavaScript API, removing a cached entry based on a request.
- **`PutImpl(...)`**: This function seems to be the core logic for adding or updating a cache entry using the `Cache.put()` JavaScript API. It handles both `Request` and `Response` objects.
- **`KeysImpl(...)`**: This likely implements the `Cache.keys()` JavaScript API, retrieving a list of `Request` objects representing the keys in the cache.

Now, I need to elaborate on the relationships with web technologies, provide examples, and consider error scenarios and debugging.
这是`blink/renderer/modules/cache_storage/cache.cc`文件的第二部分，该文件主要负责实现浏览器缓存API中的`Cache`接口。  总结来说，这部分代码实现了 `Cache` 对象上用于查询、添加、删除缓存条目的核心功能。

**核心功能归纳:**

这部分代码主要实现了以下 `Cache` 对象的方法，这些方法允许 JavaScript 代码与特定的命名缓存进行交互：

1. **`Trace(Visitor* visitor)`**:
   - **功能**:  这是一个用于 Chromium 内部 tracing 机制的方法。它允许在代码执行过程中记录信息，用于调试和性能分析。
   - **与 Web 技术的关系**:  虽然不直接与 JavaScript, HTML 或 CSS 交互，但它是浏览器底层实现的一部分，确保了缓存功能的稳定性和可调试性。

2. **`CreateAbortController(ScriptState* script_state)`**:
   - **功能**: 创建一个新的 `AbortController` 对象。`AbortController` 用于取消一个或多个 Web API 操作，例如 `fetch`。
   - **与 Web 技术的关系**:  直接关联 JavaScript 的 `AbortController` API。
   - **举例**:  JavaScript 代码可以使用此方法创建的 `AbortController` 的信号来取消 `Cache.match` 或 `Cache.addAll` 等操作。

3. **`MatchImpl(ScriptState* script_state, const Request* request, const CacheQueryOptions* options, ExceptionState& exception_state)`**:
   - **功能**:  实现 `Cache.match()` 方法的核心逻辑。它尝试在缓存中查找与给定 `Request` 对象匹配的 `Response`。
   - **与 Web 技术的关系**:  直接对应 JavaScript 的 `Cache.match()` API。
   - **假设输入与输出**:
     - **假设输入**:  一个 `Request` 对象，例如 `new Request('/api/data')`，以及可选的 `CacheQueryOptions` 对象，例如 `{ ignoreSearch: true }`。
     - **预期输出**:  一个 Promise，resolve 时会返回匹配的 `Response` 对象，如果没有找到匹配项则 resolve 为 `undefined`。如果发生错误，Promise 会 reject。
   - **用户或编程常见的使用错误**:
     - 错误地假设 `Cache.match()` 会匹配 `POST` 请求，除非设置了 `ignoreMethod: true`。
   - **用户操作如何到达这里 (调试线索)**:  当 Service Worker 或网页中的 JavaScript 代码调用 `caches.open('my-cache').then(cache => cache.match(request))` 时，并且 `request` 参数是一个 `Request` 对象，就会执行此代码。

4. **`MatchAllImpl(ScriptState* script_state, const Request* request, const CacheQueryOptions* options, ExceptionState& exception_state)`**:
   - **功能**: 实现 `Cache.matchAll()` 方法的核心逻辑。它在缓存中查找所有与给定 `Request` 对象匹配的 `Response` 对象。
   - **与 Web 技术的关系**: 直接对应 JavaScript 的 `Cache.matchAll()` API。
   - **假设输入与输出**:
     - **假设输入**: 一个可选的 `Request` 对象（如果为 null，则匹配所有缓存条目），以及可选的 `CacheQueryOptions` 对象。
     - **预期输出**: 一个 Promise，resolve 时会返回一个包含所有匹配 `Response` 对象的数组。如果发生错误，Promise 会 reject。
   - **用户或编程常见的使用错误**:
     - 期望使用 `matchAll()` 匹配 `POST` 请求，但忘记设置 `ignoreMethod: true`。
   - **用户操作如何到达这里 (调试线索)**:  当 JavaScript 代码调用 `caches.open('my-cache').then(cache => cache.matchAll(request))` 时，就会执行此代码。

5. **`AddAllImpl(ScriptState* script_state, const String& method_name, const HeapVector<Member<Request>>& request_list, ExceptionState& exception_state)`**:
   - **功能**: 实现 `Cache.addAll()` 方法的核心逻辑。它接收一个 `Request` 对象数组，并尝试将这些请求对应的响应添加到缓存中。这通常涉及发起网络请求。
   - **与 Web 技术的关系**: 直接对应 JavaScript 的 `Cache.addAll()` API。
   - **假设输入与输出**:
     - **假设输入**: 一个包含多个 `Request` 对象的数组，例如 `[new Request('/image1.png'), new Request('/image2.png')]`。
     - **预期输出**: 一个 Promise，resolve 时表示所有请求都已成功添加到缓存。如果任何一个请求失败，Promise 会 reject。
   - **用户或编程常见的使用错误**:
     - 提供的 `Request` 对象指向的资源返回非 2xx 状态码，导致 `addAll()` 操作失败。
     - `Request` 对象的 `signal` 属性关联的 `AbortSignal` 被触发，导致请求被取消。
   - **用户操作如何到达这里 (调试线索)**:  当 JavaScript 代码调用 `caches.open('my-cache').then(cache => cache.addAll([request1, request2]))` 时，就会执行此代码。

6. **`DeleteImpl(ScriptState* script_state, const Request* request, const CacheQueryOptions* options, ExceptionState& exception_state)`**:
   - **功能**: 实现 `Cache.delete()` 方法的核心逻辑。它尝试从缓存中删除与给定 `Request` 对象匹配的条目。
   - **与 Web 技术的关系**: 直接对应 JavaScript 的 `Cache.delete()` API。
   - **假设输入与输出**:
     - **假设输入**: 一个 `Request` 对象，例如 `new Request('/old-data')`，以及可选的 `CacheQueryOptions` 对象。
     - **预期输出**: 一个 Promise，resolve 时返回 `true` 如果至少有一个匹配的条目被删除，返回 `false` 如果没有找到匹配项。如果发生错误，Promise 会 reject。
   - **用户或编程常见的使用错误**:
     - 期望删除 `POST` 请求的缓存条目，但忘记设置 `ignoreMethod: true`。
   - **用户操作如何到达这里 (调试线索)**: 当 JavaScript 代码调用 `caches.open('my-cache').then(cache => cache.delete(request))` 时，就会执行此代码。

7. **`PutImpl(ScriptPromiseResolver<IDLUndefined>* resolver, const String& method_name, const HeapVector<Member<Request>>& requests, const HeapVector<Member<Response>>& responses, const WTF::Vector<scoped_refptr<BlobDataHandle>>& blob_list, ExceptionState& exception_state, int64_t trace_id)`**:
   - **功能**: 实现 `Cache.put()` 方法的核心逻辑，或者 `Cache.addAll()` 内部用于添加单个条目的逻辑。它将给定的 `Request` 和 `Response` 对象添加到缓存中。
   - **与 Web 技术的关系**:  直接对应 JavaScript 的 `Cache.put()` API，以及 `Cache.addAll()` 的内部实现。
   - **假设输入与输出**:
     - **假设输入**: 一个 `Request` 对象和一个 `Response` 对象。
     - **预期输出**: 一个 Promise，resolve 时表示 `Request`/`Response` 对已成功添加到缓存。如果发生错误，Promise 会 reject。
   - **用户或编程常见的使用错误**:
     - 尝试缓存不合法的 `Response` 对象。
   - **用户操作如何到达这里 (调试线索)**: 当 JavaScript 代码调用 `caches.open('my-cache').then(cache => cache.put(request, response))` 时，或者当 `addAll` 内部循环处理每个请求时，就会执行此代码。

8. **`KeysImpl(ScriptState* script_state, const Request* request, const CacheQueryOptions* options, ExceptionState& exception_state)`**:
   - **功能**: 实现 `Cache.keys()` 方法的核心逻辑。它返回缓存中所有键（即 `Request` 对象）的列表。
   - **与 Web 技术的关系**: 直接对应 JavaScript 的 `Cache.keys()` API。
   - **假设输入与输出**:
     - **假设输入**: 一个可选的 `Request` 对象作为匹配模式，以及可选的 `CacheQueryOptions` 对象。
     - **预期输出**: 一个 Promise，resolve 时返回一个包含缓存中所有匹配 `Request` 对象的数组。如果发生错误，Promise 会 reject。
   - **用户或编程常见的使用错误**:
     - 期望使用 `keys()` 匹配 `POST` 请求，但忘记设置 `ignoreMethod: true`。
   - **用户操作如何到达这里 (调试线索)**: 当 JavaScript 代码调用 `caches.open('my-cache').then(cache => cache.keys(request))` 时，就会执行此代码。

**总结**:

这部分 `cache.cc` 代码主要负责实现 `Cache` 接口提供的各种操作，允许 JavaScript 代码通过 Service Workers 或网页中的脚本来管理浏览器的缓存。它处理了查找、添加和删除缓存条目的核心逻辑，并与底层的存储机制进行交互。 这些功能是构建离线 Web 应用和优化网络性能的关键组成部分。

### 提示词
```
这是目录为blink/renderer/modules/cache_storage/cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
>Trace(cache_remote_);
  ScriptWrappable::Trace(visitor);
}

AbortController* Cache::CreateAbortController(ScriptState* script_state) {
  return AbortController::Create(script_state);
}

ScriptPromise<V8UnionResponseOrUndefined> Cache::MatchImpl(
    ScriptState* script_state,
    const Request* request,
    const CacheQueryOptions* options,
    ExceptionState& exception_state) {
  mojom::blink::FetchAPIRequestPtr mojo_request =
      request->CreateFetchAPIRequest();
  mojom::blink::CacheQueryOptionsPtr mojo_options =
      mojom::blink::CacheQueryOptions::From(options);

  int64_t trace_id = blink::cache_storage::CreateTraceId();
  TRACE_EVENT_WITH_FLOW2("CacheStorage", "Cache::MatchImpl",
                         TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_OUT,
                         "request", CacheStorageTracedValue(mojo_request),
                         "options", CacheStorageTracedValue(mojo_options));

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8UnionResponseOrUndefined>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  if (request->method() != http_names::kGET && !options->ignoreMethod()) {
    resolver->Resolve();
    return promise;
  }

  bool in_related_fetch_event = false;
  bool in_range_fetch_event = false;
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (auto* global_scope = DynamicTo<ServiceWorkerGlobalScope>(context)) {
    in_related_fetch_event = global_scope->HasRelatedFetchEvent(request->url());
    in_range_fetch_event = global_scope->HasRangeFetchEvent(request->url());
  }

  // Make sure to bind the Cache object to keep the mojo remote alive during
  // the operation. Otherwise GC might prevent the callback from ever being
  // executed.
  cache_remote_->Match(
      std::move(mojo_request), std::move(mojo_options), in_related_fetch_event,
      in_range_fetch_event, trace_id,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          [](base::TimeTicks start_time, const CacheQueryOptions* options,
             int64_t trace_id, Cache* self,
             ScriptPromiseResolver<V8UnionResponseOrUndefined>* resolver,
             mojom::blink::MatchResultPtr result) {
            base::TimeDelta elapsed = base::TimeTicks::Now() - start_time;
            UMA_HISTOGRAM_LONG_TIMES("ServiceWorkerCache.Cache.Renderer.Match",
                                     elapsed);
            if (options->hasIgnoreSearch() && options->ignoreSearch()) {
              UMA_HISTOGRAM_LONG_TIMES(
                  "ServiceWorkerCache.Cache.Renderer.Match.IgnoreSearch",
                  elapsed);
            }
            if (result->is_status()) {
              TRACE_EVENT_WITH_FLOW1(
                  "CacheStorage", "Cache::MatchImpl::Callback",
                  TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_IN, "status",
                  CacheStorageTracedValue(result->get_status()));
              switch (result->get_status()) {
                case mojom::CacheStorageError::kErrorNotFound:
                  UMA_HISTOGRAM_LONG_TIMES(
                      "ServiceWorkerCache.Cache.Renderer.Match.Miss", elapsed);
                  resolver->Resolve();
                  break;
                default:
                  RejectCacheStorageWithError(resolver, result->get_status());
                  break;
              }
            } else {
              UMA_HISTOGRAM_LONG_TIMES(
                  "ServiceWorkerCache.Cache.Renderer.Match.Hit", elapsed);
              ScriptState::Scope scope(resolver->GetScriptState());
              if (result->is_eager_response()) {
                TRACE_EVENT_WITH_FLOW1(
                    "CacheStorage", "Cache::MatchImpl::Callback",
                    TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_IN,
                    "eager_response",
                    CacheStorageTracedValue(
                        result->get_eager_response()->response));
                resolver->Resolve(
                    CreateEagerResponse(resolver->GetScriptState(),
                                        std::move(result->get_eager_response()),
                                        self->blob_client_list_));
              } else {
                TRACE_EVENT_WITH_FLOW1(
                    "CacheStorage", "Cache::MatchImpl::Callback",
                    TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_IN,
                    "response",
                    CacheStorageTracedValue(result->get_response()));
                resolver->Resolve(Response::Create(resolver->GetScriptState(),
                                                   *result->get_response()));
              }
            }
          },
          base::TimeTicks::Now(), WrapPersistent(options), trace_id,
          WrapPersistent(this))));

  return promise;
}

ScriptPromise<IDLSequence<Response>> Cache::MatchAllImpl(
    ScriptState* script_state,
    const Request* request,
    const CacheQueryOptions* options,
    ExceptionState& exception_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Response>>>(
          script_state, exception_state.GetContext());
  const auto promise = resolver->Promise();

  mojom::blink::CacheQueryOptionsPtr mojo_options =
      mojom::blink::CacheQueryOptions::From(options);
  mojom::blink::FetchAPIRequestPtr fetch_api_request;
  if (request) {
    fetch_api_request = request->CreateFetchAPIRequest();
  }

  int64_t trace_id = blink::cache_storage::CreateTraceId();
  TRACE_EVENT_WITH_FLOW2("CacheStorage", "Cache::MatchAllImpl",
                         TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_OUT,
                         "request", CacheStorageTracedValue(fetch_api_request),
                         "options", CacheStorageTracedValue(mojo_options));

  if (request && request->method() != http_names::kGET &&
      !options->ignoreMethod()) {
    resolver->Resolve(HeapVector<Member<Response>>());
    return promise;
  }

  // Make sure to bind the Cache object to keep the mojo remote alive during
  // the operation. Otherwise GC might prevent the callback from ever being
  // executed.
  cache_remote_->MatchAll(
      std::move(fetch_api_request), std::move(mojo_options), trace_id,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          [](base::TimeTicks start_time, const CacheQueryOptions* options,
             int64_t trace_id, Cache* _,
             ScriptPromiseResolver<IDLSequence<Response>>* resolver,
             mojom::blink::MatchAllResultPtr result) {
            UMA_HISTOGRAM_LONG_TIMES(
                "ServiceWorkerCache.Cache.Renderer.MatchAll",
                base::TimeTicks::Now() - start_time);
            if (result->is_status()) {
              TRACE_EVENT_WITH_FLOW1(
                  "CacheStorage", "Cache::MatchAllImpl::Callback",
                  TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_IN, "status",
                  CacheStorageTracedValue(result->get_status()));
              RejectCacheStorageWithError(resolver, result->get_status());
            } else {
              TRACE_EVENT_WITH_FLOW1(
                  "CacheStorage", "Cache::MatchAllImpl::Callback",
                  TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_IN,
                  "response_list",
                  CacheStorageTracedValue(result->get_responses()));
              ScriptState::Scope scope(resolver->GetScriptState());
              HeapVector<Member<Response>> responses;
              responses.ReserveInitialCapacity(result->get_responses().size());
              for (auto& response : result->get_responses()) {
                responses.push_back(
                    Response::Create(resolver->GetScriptState(), *response));
              }
              resolver->Resolve(responses);
            }
          },
          base::TimeTicks::Now(), WrapPersistent(options), trace_id,
          WrapPersistent(this))));
  return promise;
}

ScriptPromise<IDLUndefined> Cache::AddAllImpl(
    ScriptState* script_state,
    const String& method_name,
    const HeapVector<Member<Request>>& request_list,
    ExceptionState& exception_state) {
  int64_t trace_id = blink::cache_storage::CreateTraceId();
  TRACE_EVENT_WITH_FLOW0("CacheStorage", "Cache::AddAllImpl",
                         TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_OUT);

  if (request_list.empty())
    return ToResolvedUndefinedPromise(script_state);

  // Validate all requests before starting to load or store any of them.
  for (wtf_size_t i = 0; i < request_list.size(); ++i) {
    ValidateRequestForPut(request_list[i], exception_state);
    if (exception_state.HadException())
      return EmptyPromise();
  }

  auto* barrier_callback = MakeGarbageCollected<BarrierCallbackForPutResponse>(
      script_state, this, method_name, request_list,
      exception_state.GetContext(), trace_id);

  // We must get the promise before any rejections can happen during loading.
  auto promise = barrier_callback->Promise();

  // Begin loading each of the requests.
  for (wtf_size_t i = 0; i < request_list.size(); ++i) {
    auto* init = RequestInit::Create();
    if (barrier_callback->Signal()) {
      HeapVector<Member<AbortSignal>> signals;
      signals.push_back(barrier_callback->Signal());
      signals.push_back(request_list[i]->signal());
      init->setSignal(MakeGarbageCollected<AbortSignal>(script_state, signals));
    }

    V8RequestInfo* info = MakeGarbageCollected<V8RequestInfo>(request_list[i]);

    auto* response_loader = MakeGarbageCollected<ResponseBodyLoader>(
        script_state, barrier_callback, i, /*require_ok_response=*/true,
        trace_id);
    auto* on_resolve =
        MakeGarbageCollected<FetchResolveHandler>(response_loader);
    // The |response_loader=nullptr| makes this handler a reject handler
    // internally.
    auto* on_reject =
        MakeGarbageCollected<FetchRejectHandler>(barrier_callback);
    scoped_fetcher_->Fetch(script_state, info, init, exception_state)
        .Then(script_state, on_resolve, on_reject);
  }

  return promise;
}

ScriptPromise<IDLBoolean> Cache::DeleteImpl(ScriptState* script_state,
                                            const Request* request,
                                            const CacheQueryOptions* options,
                                            ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  const auto promise = resolver->Promise();

  Vector<mojom::blink::BatchOperationPtr> batch_operations;
  batch_operations.push_back(mojom::blink::BatchOperation::New());
  auto& operation = batch_operations.back();
  operation->operation_type = mojom::blink::OperationType::kDelete;
  operation->request = request->CreateFetchAPIRequest();
  operation->match_options = mojom::blink::CacheQueryOptions::From(options);

  int64_t trace_id = blink::cache_storage::CreateTraceId();
  TRACE_EVENT_WITH_FLOW2("CacheStorage", "Cache::DeleteImpl",
                         TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_OUT,
                         "request", CacheStorageTracedValue(operation->request),
                         "options",
                         CacheStorageTracedValue(operation->match_options));

  if (request->method() != http_names::kGET && !options->ignoreMethod()) {
    resolver->Resolve(false);
    return promise;
  }

  // Make sure to bind the Cache object to keep the mojo remote alive during
  // the operation. Otherwise GC might prevent the callback from ever being
  // executed.
  cache_remote_->Batch(
      std::move(batch_operations), trace_id,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          [](base::TimeTicks start_time, const CacheQueryOptions* options,
             int64_t trace_id, Cache* _,
             ScriptPromiseResolver<IDLBoolean>* resolver,
             mojom::blink::CacheStorageVerboseErrorPtr error) {
            UMA_HISTOGRAM_LONG_TIMES(
                "ServiceWorkerCache.Cache.Renderer.DeleteOne",
                base::TimeTicks::Now() - start_time);
            TRACE_EVENT_WITH_FLOW1(
                "CacheStorage", "Cache::DeleteImpl::Callback",
                TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_IN, "status",
                CacheStorageTracedValue(error->value));
            if (error->value != mojom::blink::CacheStorageError::kSuccess) {
              switch (error->value) {
                case mojom::blink::CacheStorageError::kErrorNotFound:
                  resolver->Resolve(false);
                  break;
                default:
                  StringBuilder message;
                  if (error->message) {
                    message.Append("Cache.delete(): ");
                    message.Append(error->message);
                  }
                  RejectCacheStorageWithError(resolver, error->value,
                                              message.ToString());
                  break;
              }
            } else {
              resolver->Resolve(true);
            }
          },
          base::TimeTicks::Now(), WrapPersistent(options), trace_id,
          WrapPersistent(this))));
  return promise;
}

void Cache::PutImpl(ScriptPromiseResolver<IDLUndefined>* resolver,
                    const String& method_name,
                    const HeapVector<Member<Request>>& requests,
                    const HeapVector<Member<Response>>& responses,
                    const WTF::Vector<scoped_refptr<BlobDataHandle>>& blob_list,
                    ExceptionState& exception_state,
                    int64_t trace_id) {
  DCHECK_EQ(requests.size(), responses.size());
  DCHECK_EQ(requests.size(), blob_list.size());

  TRACE_EVENT_WITH_FLOW0("CacheStorage", "Cache::PutImpl",
                         TRACE_ID_GLOBAL(trace_id),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  ScriptState* script_state = resolver->GetScriptState();
  ScriptState::Scope scope(script_state);
  ExecutionContext* context = ExecutionContext::From(script_state);

  BarrierCallbackForPutComplete* barrier_callback =
      MakeGarbageCollected<BarrierCallbackForPutComplete>(
          requests.size(), this, method_name, resolver, trace_id);

  for (wtf_size_t i = 0; i < requests.size(); ++i) {
    if (!blob_list[i] ||
        !ShouldGenerateV8CodeCache(script_state, responses[i])) {
      mojom::blink::BatchOperationPtr batch_operation =
          mojom::blink::BatchOperation::New();
      batch_operation->operation_type = mojom::blink::OperationType::kPut;
      batch_operation->request = requests[i]->CreateFetchAPIRequest();
      batch_operation->response =
          responses[i]->PopulateFetchAPIResponse(requests[i]->url());
      batch_operation->response->blob = std::move(blob_list[i]);
      barrier_callback->OnSuccess(i, std::move(batch_operation));
      continue;
    }

    BytesConsumer* consumer =
        MakeGarbageCollected<BlobBytesConsumer>(context, blob_list[i]);
    BodyStreamBuffer* buffer =
        BodyStreamBuffer::Create(script_state, consumer, /*signal=*/nullptr,
                                 /*cached_metadata_handler=*/nullptr);
    FetchDataLoader* loader = FetchDataLoader::CreateLoaderAsArrayBuffer();
    buffer->StartLoading(loader,
                         MakeGarbageCollected<CodeCacheHandleCallbackForPut>(
                             script_state, i, barrier_callback, requests[i],
                             responses[i], std::move(blob_list[i]), trace_id),
                         exception_state);
    if (exception_state.HadException()) {
      barrier_callback->OnError("Could not inspect response body state");
      return;
    }
  }
}

ScriptPromise<IDLSequence<Request>> Cache::KeysImpl(
    ScriptState* script_state,
    const Request* request,
    const CacheQueryOptions* options,
    ExceptionState& exception_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Request>>>(
          script_state, exception_state.GetContext());
  const auto promise = resolver->Promise();

  mojom::blink::CacheQueryOptionsPtr mojo_options =
      mojom::blink::CacheQueryOptions::From(options);
  mojom::blink::FetchAPIRequestPtr fetch_api_request;
  if (request) {
    fetch_api_request = request->CreateFetchAPIRequest();
  }

  int64_t trace_id = blink::cache_storage::CreateTraceId();
  TRACE_EVENT_WITH_FLOW2("CacheStorage", "Cache::DeleteImpl",
                         TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_OUT,
                         "request", CacheStorageTracedValue(fetch_api_request),
                         "options", CacheStorageTracedValue(mojo_options));

  if (request && request->method() != http_names::kGET &&
      !options->ignoreMethod()) {
    resolver->Resolve(HeapVector<Member<Request>>());
    return promise;
  }

  // Make sure to bind the Cache object to keep the mojo remote alive during
  // the operation. Otherwise GC might prevent the callback from ever being
  // executed.
  cache_remote_->Keys(
      std::move(fetch_api_request), std::move(mojo_options), trace_id,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          [](base::TimeTicks start_time, const CacheQueryOptions* options,
             int64_t trace_id, Cache* _,
             ScriptPromiseResolver<IDLSequence<Request>>* resolver,
             mojom::blink::CacheKeysResultPtr result) {
            UMA_HISTOGRAM_LONG_TIMES("ServiceWorkerCache.Cache.Renderer.Keys",
                                     base::TimeTicks::Now() - start_time);
            if (result->is_status()) {
              TRACE_EVENT_WITH_FLOW1(
                  "CacheStorage", "Cache::KeysImpl::Callback",
                  TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_IN, "status",
                  CacheStorageTracedValue(result->get_status()));
              RejectCacheStorageWithError(resolver, result->get_status());
            } else {
              TRACE_EVENT_WITH_FLOW1(
                  "CacheStorage", "Cache::KeysImpl::Callback",
                  TRACE_ID_GLOBAL(trace_id), TRACE_EVENT_FLAG_FLOW_IN, "status",
                  CacheStorageTracedValue(result->get_keys()));
              ScriptState::Scope scope(resolver->GetScriptState());
              HeapVector<Member<Request>> requests;
              requests.ReserveInitialCapacity(result->get_keys().size());
              for (auto& request : result->get_keys()) {
                requests.push_back(Request::Create(
                    resolver->GetScriptState(), std::move(request),
                    Request::ForServiceWorkerFetchEvent::kFalse));
              }
              resolver->Resolve(requests);
            }
          },
          base::TimeTicks::Now(), WrapPersistent(options), trace_id,
          WrapPersistent(this))));
  return promise;
}

}  // namespace blink
```