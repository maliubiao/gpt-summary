Response:
The user is asking for a summary of the functionality of the `fetch_manager.cc` file in the Chromium Blink engine, specifically focusing on the `FetchLaterManager` class.

To answer this, I need to analyze the code and identify the key operations and responsibilities of `FetchLaterManager`. I should also look for connections to JavaScript, HTML, and CSS, as well as common user errors and how to reach this code during debugging.

Here's a breakdown of the thought process:

1. **Identify the Core Class:** The main focus is the `FetchLaterManager` class. The other class, `FetchManager`, seems related to general fetch operations but the prompt specifically asks about `fetch_manager.cc` in the context of "part 3", suggesting the focus is on the "later" functionality.

2. **Analyze `FetchLaterManager`'s Methods:**  Go through each method and understand its purpose:
    * **Constructor:**  Initialization, including permission checks for `background-sync`.
    * **`fetchLater()`:**  The core method for scheduling deferred fetches. This is where most of the logic resides. Pay attention to the checks it performs (HTTPS, trustworthy URL, permissions policy, body length).
    * **`ContextDestroyed()`:**  Handles the termination of the execution context and processes any remaining deferred fetches.
    * **`ContextEnteredBackForwardCache()`:**  Deals with how deferred fetches are handled when the page enters the back/forward cache, considering background sync permission.
    * **`OnDeferredLoaderFinished()`:**  Cleans up after a deferred fetch is completed.
    * **`IsBackgroundSyncGranted()`:**  Checks the status of the background sync permission.
    * **`OnPermissionStatusChange()`:**  Updates the cached background sync permission status.
    * **`NumLoadersForTesting()`, `RecreateTimerForTesting()`, `ComputeLoadPriorityForTesting()`:** Utility methods primarily used for testing.
    * **`PrepareNetworkRequest()`:**  Constructs the `network::ResourceRequest` for a deferred fetch.
    * **`Trace()`:**  For debugging and memory management.

3. **Identify Key Functionalities:** Based on the method analysis, the main functionalities of `FetchLaterManager` are:
    * **Scheduling Deferred Fetches:**  Allowing web pages to schedule requests that will be executed later, even after the page is closed (if background sync is available).
    * **Quota Management:** Enforcing limits on the size and number of deferred fetches to prevent abuse.
    * **Security and Privacy:** Ensuring deferred fetches adhere to security requirements (HTTPS, trustworthy URLs, permissions policy).
    * **Lifecycle Management:** Handling deferred fetches when the execution context is destroyed or enters the back/forward cache.
    * **Integration with Permissions:** Utilizing the background sync permission to control behavior in background scenarios.

4. **Relate to Web Technologies:**
    * **JavaScript:** The `fetchLater()` method is directly callable from JavaScript. It takes `Request` and `AbortSignal` objects as arguments, which are standard web APIs.
    * **HTML:**  The `fetchLater()` API is triggered within the context of a Document, which is part of the HTML DOM.
    * **CSS:**  Less direct relationship, but if a deferred fetch loads a resource that affects styling (e.g., an image), there's an indirect connection.

5. **Consider Logic and Examples:**  Focus on the `fetchLater()` method's input and output, including potential errors.
    * **Input:** `Request` object (URL, headers, body), optional `activate_after_ms`, `AbortSignal`.
    * **Output:** A `Promise` that resolves when the deferred fetch is scheduled (or rejects if there's an error).
    * **Error Examples:** Negative `activate_after`, non-HTTPS URL, exceeding quota, calling from a non-active document.

6. **Think About User/Programming Errors:** Identify common mistakes developers might make when using `fetchLater()`. These often correspond to the checks within the `fetchLater()` method.

7. **Trace User Actions:**  Consider the steps a user would take to trigger `fetchLater()`. This helps in understanding the debugging context.

8. **Synthesize and Summarize:** Combine the findings into a concise description of the file's purpose and the `FetchLaterManager`'s role.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on the general `FetchManager` class. The prompt's context ("part 3") and the code provided clearly indicate the focus should be on `FetchLaterManager`.
* I need to be specific about how `fetchLater()` relates to JavaScript APIs like `fetch`, `Request`, and `AbortSignal`.
*  The explanation of the quota mechanism needs to be clear and highlight the potential for `QuotaExceededError`.
* I should emphasize the role of background sync permission in enabling truly background fetches.

By following these steps, I can create a comprehensive and accurate summary of the `fetch_manager.cc` file and the `FetchLaterManager` class.
这是 `blink/renderer/core/fetch/fetch_manager.cc` 文件的第三部分，主要关注的是 `FetchLaterManager` 类，它负责处理延迟发起的 Fetch API 请求 (fetchLater)。以下是对 `FetchLaterManager` 功能的归纳：

**`FetchLaterManager` 的主要功能:**

1. **延迟发起 Fetch 请求 (fetchLater):**  `FetchLaterManager` 的核心功能是实现 `fetchLater()` JavaScript API。这个 API 允许网页在当前页面卸载或关闭后，延迟发起 HTTP 请求。这对于执行一些非关键性的后台任务非常有用。

2. **请求参数验证和预处理:** 在真正发起请求之前，`FetchLaterManager` 会对 `fetchLater()` 接收到的请求参数进行一系列的验证，以确保请求的合法性和安全性：
    * **检查 HTTPS:** 强制 `fetchLater` 只能在 HTTPS 上使用，确保数据传输的安全性。
    * **检查 URL 的可信度:** 确保请求的 URL 是潜在可信的，防止向不安全的地址发送请求。
    * **检查 Document 的状态:** 确保 `fetchLater` 是从一个完全激活的 Document 中调用的，避免在页面状态不明确时发起请求。
    * **检查请求体大小:**  限制延迟请求的整体大小，包括 URL 和头部信息，以及请求体的大小，防止资源滥用。
    * **检查请求体长度:** 不允许发送请求体长度未知的延迟请求 (例如，来自 live ReadableStream 的请求体)。
    * **检查权限策略 (Permissions Policy):**  如果启用了相关特性，会检查是否允许当前文档的来源使用 `deferred-fetch` 权限策略。

3. **管理延迟请求的生命周期:**  `FetchLaterManager` 负责管理已调度的延迟请求的生命周期：
    * **存储延迟请求:** 将延迟请求的信息存储在 `deferred_loaders_` 列表中。
    * **处理上下文销毁:** 当关联的执行上下文（例如，Document）被销毁时，`FetchLaterManager` 会负责处理这些延迟请求，根据情况立即执行或者留给浏览器稍后处理 (例如，利用 Background Sync API)。
    * **处理进入 Back/Forward Cache:** 当页面进入 Back/Forward Cache 时，`FetchLaterManager` 会根据 Background Sync 权限的状态，决定是立即执行还是稍后执行延迟请求。
    * **请求完成后的清理:**  当延迟请求完成后，会从 `deferred_loaders_` 中移除并释放相关资源。

4. **集成 Background Sync API (可选):**  如果启用了 `IsFetchLaterUseBackgroundSyncPermissionEnabled()`，`FetchLaterManager` 会观察 Background Sync 的权限状态。如果权限被授予，延迟请求可能会在页面关闭后通过 Background Sync API 执行。

5. **配额管理:**  `FetchLaterManager` 会限制每个来源可以调度的延迟请求的总大小，防止滥用。它会跟踪当前已调度的延迟请求的大小，并在添加新的请求时进行检查，如果超出配额则会抛出 `QuotaExceededError`。

6. **准备网络请求:**  `PrepareNetworkRequest` 方法负责根据延迟请求的参数创建一个 `network::ResourceRequest` 对象，用于发起实际的网络请求。它会设置请求的一些特殊属性，例如 `keepalive: true` 和特定的内容类型。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  `FetchLaterManager` 直接实现了 `globalThis.fetchLater()` JavaScript API 的后端逻辑。
    * **示例:** 在 JavaScript 中调用 `fetchLater('/api/background-task', { method: 'POST', body: JSON.stringify({ data: 'some data' }) })` 会最终触发 `FetchLaterManager::fetchLater()` 方法。

* **HTML:** `fetchLater()` 是在 HTML 文档的上下文中调用的。
    * **示例:**  一个按钮的点击事件处理函数中调用 `fetchLater()`，或者在页面卸载时通过 `window.addEventListener('beforeunload', ...)` 调用 `fetchLater()`。

* **CSS:**  与 CSS 的关系相对间接。如果延迟请求是为了获取某些资源（例如，字体、图片），这些资源可能会影响页面的样式。
    * **示例:**  一个延迟请求用于预加载下一页可能需要的 CSS 文件。虽然 `FetchLaterManager` 不直接处理 CSS，但它负责发起加载 CSS 文件的请求。

**逻辑推理、假设输入与输出:**

**假设输入:**

```javascript
// JavaScript 代码
const controller = new AbortController();
fetchLater('/api/data', {
  method: 'GET',
  signal: controller.signal,
  activateAfter: 5000 // 5 秒后激活
}).then(result => {
  console.log('FetchLater scheduled:', result);
}).catch(error => {
  console.error('FetchLater error:', error);
});
```

**`FetchLaterManager::fetchLater()` 的处理流程 (简化):**

1. **输入:**  `request` 对象包含 `/api/data` 的 GET 请求，`activate_after_ms` 为 5000，`signal` 是 `AbortController` 的信号。
2. **检查信号:** 检查 `signal` 是否已中止。
3. **检查 `activate_after`:** 确保 `activate_after` 不是负数。
4. **检查 Document 状态:** 确保调用时 Document 处于激活状态。
5. **检查 URL 安全性:** 确保 `/api/data` 是 HTTPS 且 URL 可信。
6. **检查权限策略:** 如果启用，检查是否允许 `deferred-fetch`。
7. **计算请求大小:** 计算请求 URL 和头部的大小。
8. **检查请求体:**  由于是 GET 请求，没有请求体，跳过相关检查。
9. **检查配额:** 检查当前已调度的延迟请求大小加上当前请求的大小是否超过配额。
10. **创建 `DeferredLoader`:** 创建一个 `DeferredLoader` 对象来管理这个延迟请求。
11. **添加到列表:** 将 `DeferredLoader` 添加到 `deferred_loaders_` 列表。
12. **启动 `DeferredLoader`:** 启动 `DeferredLoader`，它会安排在 5 秒后发起请求。
13. **输出:** 返回一个表示延迟请求结果的 Promise。

**用户或编程常见的使用错误:**

1. **在非 HTTPS 页面上调用 `fetchLater()`:**
   * **错误:** `TypeError: fetchLater is only supported over HTTPS.`
   * **用户操作:** 用户在非 HTTPS 页面上运行包含 `fetchLater()` 调用的 JavaScript 代码。

2. **传递不安全的 URL 给 `fetchLater()`:**
   * **错误:** `SecurityError: fetchLater was passed an insecure URL.`
   * **用户操作:** 用户尝试将一个 HTTP 或其他非受信协议的 URL 传递给 `fetchLater()`。

3. **在页面进入 Back/Forward Cache 后期望 `fetchLater()` 立即执行，但没有 Background Sync 权限:**
   * **预期:** 请求应该在页面进入 BFCache 后立即发出 (如果没有配置 `activateAfter`)。
   * **实际:** 如果没有 Background Sync 权限，请求可能会延迟到页面真正被销毁时才发出，或者根本不发出。
   * **调试线索:** 检查 `ContextEnteredBackForwardCache()` 方法的逻辑，以及 Background Sync 权限的状态。

4. **`activateAfter` 设置为负数:**
   * **错误:** `RangeError: fetchLater's activateAfter cannot be negative.`
   * **用户操作:**  JavaScript 代码中将 `activateAfter` 设置为一个负值。

5. **尝试发送带有未知长度请求体的延迟请求:**
   * **错误:** `TypeError: fetchLater doesn't support body with unknown length.`
   * **用户操作:**  尝试将一个来自 ReadableStream 的请求体传递给 `fetchLater()`，因为 ReadableStream 的 `Content-Length` 通常是未知的。

6. **超出延迟请求的配额限制:**
   * **错误:** `DOMException: QuotaExceededError: fetchLater exceeds its quota for the origin.`
   * **用户操作:** 页面尝试调度过多的或总大小过大的延迟请求。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问一个包含 `fetchLater()` 调用的网页。**
2. **JavaScript 代码执行，调用 `globalThis.fetchLater()`。**
3. **Blink 引擎接收到 `fetchLater()` 的调用，并将其路由到 `FetchLaterManager::fetchLater()` 方法。**
4. **在 `FetchLaterManager::fetchLater()` 中，会进行各种检查 (如 HTTPS, URL 可信度, 配额等)。**
5. **如果所有检查都通过，则会创建一个 `DeferredLoader` 对象来管理这个延迟请求。**
6. **当页面卸载或进入 Back/Forward Cache 时，`FetchLaterManager::ContextDestroyed()` 或 `FetchLaterManager::ContextEnteredBackForwardCache()` 方法会被调用。**
7. **这些方法会遍历 `deferred_loaders_` 列表，并根据情况处理这些延迟请求 (例如，立即发起请求或等待稍后通过 Background Sync 执行)。**
8. **当延迟请求被实际执行时，`DeferredLoader` 会创建 `network::ResourceRequest` 并使用 `FetchLaterManager::PrepareNetworkRequest()` 进行准备。**
9. **网络请求完成后，`DeferredLoader` 会通知 `FetchLaterManager`，最终调用 `FetchLaterManager::OnDeferredLoaderFinished()` 进行清理。**

在调试时，你可以设置断点在 `FetchLaterManager::fetchLater()`, `FetchLaterManager::ContextDestroyed()`, `FetchLaterManager::ContextEnteredBackForwardCache()`, 和 `DeferredLoader` 的相关方法中，来跟踪延迟请求的生命周期和状态。 观察 `deferred_loaders_` 列表可以帮助了解当前有哪些待处理的延迟请求。

### 提示词
```
这是目录为blink/renderer/core/fetch/fetch_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
tate) {
  // https://whatpr.org/fetch/1647.html#dom-global-fetch-later
  // Continuing the fetchLater(input, init) method steps:
  CHECK(signal);
  // 2. If request’s signal is aborted, then throw signal’s abort reason.
  if (signal->aborted()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kAbortError,
                                      "The user aborted a fetchLater request.");
    return nullptr;
  }

  std::optional<base::TimeDelta> activate_after = std::nullopt;
  if (activate_after_ms.has_value()) {
    activate_after = base::Milliseconds(*activate_after_ms);
    // 6. If `activate_after` is less than 0 then throw a RangeError.
    if (activate_after->is_negative()) {
      exception_state.ThrowRangeError(
          "fetchLater's activateAfter cannot be negative.");
      return nullptr;
    }
  }

  // 7. Let deferredRecord be the result of calling "request a deferred fetch"
  // given `request` and `activate_after`. This may throw an exception.
  //
  // "request a deferred fetch":
  // https://whatpr.org/fetch/1647.html#request-a-deferred-fetch

  // 1. If request’s client is not a fully active Document, then throw an
  // "InvalidStateError" DOMException.
  if (!DomWindow() || GetExecutionContext()->is_in_back_forward_cache()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "fetchLater can only be called from a fully active Document.");
    return nullptr;
  }

  // 2. If request’s URL’s scheme is not an HTTPS scheme, then throw a
  // TypeError.
  if (!request->Url().ProtocolIs(WTF::g_https_atom)) {
    exception_state.ThrowTypeError("fetchLater is only supported over HTTPS.");
    return nullptr;
  }
  // 3. If request’s URL is not a potentially trustworthy url, then throw a
  // "SecurityError" DOMException.
  if (!network::IsUrlPotentiallyTrustworthy(GURL(request->Url()))) {
    exception_state.ThrowSecurityError(
        "fetchLater was passed an insecure URL.");
    return nullptr;
  }

  // TODO(crbug.com/40276121): Remove this after implementing Step 7.
  if (IsFetchLaterUsePermissionsPolicyEnabled() &&
      !GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kDeferredFetch,
          ReportOptions::kReportOnFailure)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Access to fetchLater requires the permissions policy "
        "\"deferred-fetch\" be enabled for the origin of this document.");
    return nullptr;
  }

  // 4. Let `total_request_length` be the length of request’s URL, serialized
  // with exclude fragment set to true.
  uint64_t total_request_length = GetUrlLengthWithoutFragment(request->Url());

  // 5. For each (name, value) in header list, increment `total_request_length`
  // by name’s length + value’s length.
  for (const auto& header : request->HeaderList()->List()) {
    total_request_length += header.first.length() + header.second.length();
  }

  // 6. If request’s body is not null then:
  if (request->Buffer()) {
    // 6-1. If request’s body’s length is null, then throw a TypeError.
    if (request->BufferByteLength() == 0) {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kFetchLaterErrorUnknownBodyLength);
      exception_state.ThrowTypeError(
          "fetchLater doesn't support body with unknown length.");
      return nullptr;
    }
    // 6-2. If request’s body’s source is null, then throw a TypeError.
    // This disallows sending deferred fetches with a live ReadableStream.
    // NOTE: Equivalent to Step 6-1 above, as implementation does not set
    // BufferByteLength() for ReadableStream.

    // 6-3 Increment totalRequestLength by request’s body’s length.
    total_request_length += request->BufferByteLength();
  }

  // TODO(crbug.com/40276121): Update the following steps.
  // Run Step 9 below for potential early termination. It also caps
  // `bytes_per_origin`.
  if (total_request_length > kMaxScheduledDeferredBytesPerOrigin) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kFetchLaterErrorQuotaExceeded);
    exception_state.ThrowDOMException(
        DOMExceptionCode::kQuotaExceededError,
        "fetchLater exceeds its quota for the origin.");
    return nullptr;
  }

  // 8. For each deferredRecord in request’s client’s fetch group’s deferred
  // fetch records: if deferredRecord’s request’s body is not null and
  // deferredRecord’s request’s URL’s origin is same origin with request’s
  // URL’s origin, then increment `bytes_for_origin` by deferredRecord’s
  // request’s body’s length.
  for (const auto& deferred_loader : deferred_loaders_) {
    // `bytes_for_orign` is capped below the max (64 kilobytes), and the value
    // returned by every deferred_loader has run through the same cap. Hence,
    // the sum here is guaranteed to be <= 128 kilobytes.
    total_request_length +=
        deferred_loader->GetDeferredBytesForUrlOrigin(request->Url());
    // 9. If `bytes_for_origin` is greater than 64 kilobytes, then throw a
    // QuotaExceededError.
    if (total_request_length > kMaxScheduledDeferredBytesPerOrigin) {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kFetchLaterErrorQuotaExceeded);
      exception_state.ThrowDOMException(
          DOMExceptionCode::kQuotaExceededError,
          "fetchLater exceeds its quota for the origin.");
      return nullptr;
    }
  }

  // 8. Set request’s service-workers mode to "none".
  // NOTE: Done in `FetchLoaderBase::PerformHTTPFetch()`.

  request->SetDestination(network::mojom::RequestDestination::kEmpty);
  // 9. Set request’s keepalive to true.
  request->SetKeepalive(true);

  // 10. Let deferredRecord be a new deferred fetch record whose request is
  // `request`.
  auto* deferred_loader = MakeGarbageCollected<DeferredLoader>(
      GetExecutionContext(), this, request, script_state, signal,
      activate_after);
  // 11. Append deferredRecord to request’s client’s fetch group’s deferred
  // fetch records.
  deferred_loaders_.insert(deferred_loader);

  deferred_loader->Start(exception_state);
  return deferred_loader->fetch_later_result();
}

void FetchManager::ContextDestroyed() {
  // https://whatpr.org/fetch/1647/9ca4bda...7bff4de.html#concept-defer=fetch-record
  // When a fetch group fetchGroup is terminated:
  // 1. For each fetch record of fetchGroup's fetch records, if record's
  // controller is non-null and record’s done flag is unset and keepalive is
  // false, terminate the fetch record’s controller .
  for (auto& loader : loaders_) {
    loader->Dispose();
  }
}

void FetchManager::OnLoaderFinished(Loader* loader) {
  loaders_.erase(loader);
  loader->Dispose();
}

void FetchManager::Trace(Visitor* visitor) const {
  visitor->Trace(loaders_);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

FetchLaterManager::FetchLaterManager(ExecutionContext* ec)
    : ExecutionContextLifecycleObserver(ec),
      permission_observer_receiver_(this, ec) {
  // TODO(crbug.com/1356128): FetchLater API is only supported in Document.
  // Supporting it in workers is blocked by keepalive in browser migration.
  CHECK(ec->IsWindow());

  if (IsFetchLaterUseBackgroundSyncPermissionEnabled()) {
    auto* permission_service =
        DomWindow()->document()->GetPermissionService(ec);
    CHECK(permission_service);

    mojo::PendingRemote<mojom::blink::PermissionObserver> observer;
    permission_observer_receiver_.Bind(
        observer.InitWithNewPipeAndPassReceiver(),
        // Same as `permission_service`'s task type.
        ec->GetTaskRunner(TaskType::kPermission));
    CHECK(permission_observer_receiver_.is_bound());
    // Registers an observer for BackgroundSync permission.
    // Cannot use `HasPermission()` as it's asynchronous. At the time the
    // permission status is needed, e.g. on entering BackForwardCache, it may
    // not have enough time to wait for response.
    auto descriptor = mojom::blink::PermissionDescriptor::New();
    descriptor->name = mojom::blink::PermissionName::BACKGROUND_SYNC;
    permission_service->AddPermissionObserver(std::move(descriptor),
                                              background_sync_permission_,
                                              std::move(observer));
  }
}

blink::ChildURLLoaderFactoryBundle* FetchLaterManager::GetFactory() {
  // Do nothing if context is detached.
  if (!DomWindow()) {
    return nullptr;
  }
  return DomWindow()->GetFrame()->Client()->GetLoaderFactoryBundle();
}

void FetchLaterManager::ContextDestroyed() {
  // https://whatpr.org/fetch/1647/9ca4bda...7bff4de.html#concept-defer=fetch-record
  // When a fetch group fetchGroup is terminated:
  // 2. process deferred fetches for fetchGroup.
  // https://whatpr.org/fetch/1647/9ca4bda...9994c1d.html#process-deferred-fetches
  // To process deferred fetches given a fetch group fetchGroup:
  for (auto& deferred_loader : deferred_loaders_) {
    // 3. For each deferred fetch record deferredRecord, process a deferred
    // fetch given deferredRecord.
    deferred_loader->Process(FetchLaterRendererMetricType::kContextDestroyed);
    deferred_loader->Dispose();
  }
  // Unlike regular Fetch loaders, FetchLater loaders should be cleared
  // immediately when the context is gone, as there is no work left here.
  deferred_loaders_.clear();
}

void FetchLaterManager::ContextEnteredBackForwardCache() {
  // TODO(crbug.com/1465781): Replace with spec once it's finalized.
  // https://github.com/WICG/pending-beacon/issues/3#issuecomment-1286397825
  // Sending any requests "after" the context goes into BackForwardCache
  // requires BackgroundSync permission. If not granted, we should force sending
  // all of them now instead of waiting until `ContextDestroyed()`.
  if (IsFetchLaterSendOnEnterBackForwardCacheEnabled() ||
      (IsFetchLaterUseBackgroundSyncPermissionEnabled() &&
       !IsBackgroundSyncGranted())) {
    for (auto& deferred_loader : deferred_loaders_) {
      deferred_loader->Process(
          FetchLaterRendererMetricType::kActivatedOnEnteredBackForwardCache);
      deferred_loader->Dispose();
    }
    deferred_loaders_.clear();
  }
}

void FetchLaterManager::OnDeferredLoaderFinished(
    DeferredLoader* deferred_loader) {
  deferred_loaders_.erase(deferred_loader);
  deferred_loader->Dispose();
}

bool FetchLaterManager::IsBackgroundSyncGranted() const {
  return background_sync_permission_ == mojom::blink::PermissionStatus::GRANTED;
}

void FetchLaterManager::OnPermissionStatusChange(
    mojom::blink::PermissionStatus status) {
  background_sync_permission_ = status;
}

size_t FetchLaterManager::NumLoadersForTesting() const {
  return deferred_loaders_.size();
}

void FetchLaterManager::RecreateTimerForTesting(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const base::TickClock* tick_clock) {
  for (auto& deferred_loader : deferred_loaders_) {
    deferred_loader->RecreateTimerForTesting(task_runner, tick_clock);
  }
}

// static
ResourceLoadPriority FetchLaterManager::ComputeLoadPriorityForTesting(
    const FetchParameters& params) {
  return ComputeFetchLaterLoadPriority(params);
}

std::unique_ptr<network::ResourceRequest>
FetchLaterManager::PrepareNetworkRequest(
    ResourceRequest request,
    const ResourceLoaderOptions& options) const {
  if (!GetExecutionContext()) {
    // No requests if the context is destroyed.
    return nullptr;
  }
  CHECK(DomWindow());
  ResourceFetcher* fetcher = DomWindow()->Fetcher();
  CHECK(fetcher);

  FetchParameters params(std::move(request), options);
  WebScopedVirtualTimePauser unused_virtual_time_pauser;
  params.OverrideContentType(kFetchLaterContentType);
  const FetchClientSettingsObject& fetch_client_settings_object =
      fetcher->GetProperties().GetFetchClientSettingsObject();

  FetchManagerResourceRequestContext resource_request_context;
  if (!RuntimeEnabledFeatures::
          MinimimalResourceRequestPrepBeforeCacheLookupEnabled()) {
    if (PrepareResourceRequest(
            kFetchLaterResourceType, fetch_client_settings_object, params,
            fetcher->Context(), unused_virtual_time_pauser,
            resource_request_context, KURL()) != std::nullopt) {
      return nullptr;
    }
  } else {
    if (PrepareResourceRequestForCacheAccess(
            kFetchLaterResourceType, fetch_client_settings_object, KURL(),
            resource_request_context, fetcher->Context(),
            params) != std::nullopt) {
      return nullptr;
    }
    UpgradeResourceRequestForLoaderNew(
        kFetchLaterResourceType, params, fetcher->Context(),
        resource_request_context, unused_virtual_time_pauser);
  }

  // From `ResourceFetcher::StartLoad()`:
  ScriptForbiddenScope script_forbidden_scope;
  auto network_resource_request = std::make_unique<network::ResourceRequest>();
  PopulateResourceRequest(
      params.GetResourceRequest(),
      std::move(params.MutableResourceRequest().MutableBody()),
      network_resource_request.get());
  return network_resource_request;
}

void FetchLaterManager::Trace(Visitor* visitor) const {
  visitor->Trace(deferred_loaders_);
  visitor->Trace(permission_observer_receiver_);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink
```