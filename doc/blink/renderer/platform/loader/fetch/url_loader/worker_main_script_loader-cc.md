Response:
Let's break down the thought process for analyzing the `WorkerMainScriptLoader.cc` file.

1. **Understand the Context:** The file name `worker_main_script_loader.cc` and its location within the Blink rendering engine (`blink/renderer/platform/loader/fetch/url_loader/`) immediately suggest its core responsibility: loading the main script for a Web Worker. The "url_loader" part indicates it uses the network stack (via `URLLoader`) for fetching. Knowing it's for workers implies dealing with JavaScript execution in a separate thread/context.

2. **Identify Key Classes and Data Structures:**  Scan the `#include` directives and the class definition itself (`WorkerMainScriptLoader`). This reveals the main players and the types of data they handle:

    * **Networking:** `network::mojom::URLResponseHeadPtr`, `network::URLLoaderCompletionStatus`, `net::RedirectInfo`, `mojo::ScopedDataPipeConsumerHandle`, `network::mojom::EarlyHintsPtr`. These point to the interaction with Chromium's network service.
    * **Blink Loading:** `FetchParameters`, `WorkerMainScriptLoadParameters`, `FetchContext`, `ResourceLoadObserver`, `WorkerMainScriptLoaderClient`, `ResourceRequest`, `ResourceResponse`, `CachedMetadataHandler`, `ScriptCachedMetadataHandler`. These are Blink's internal abstractions for handling resource loading.
    * **JavaScript & Web Workers:**  The very purpose of loading the "main script" connects it to JavaScript execution within a worker. While not explicitly mentioning JavaScript objects, the loading process is fundamentally about fetching and preparing that script.
    * **Mojo:**  `mojo::SimpleWatcher`, `mojo::ScopedDataPipeConsumerHandle`. This indicates asynchronous communication using Mojo pipes.
    * **Utility/Core:** `base::TimeTicks`, `GURL`, `WebURL`, `WebURLResponse`, `WTF::TextEncoding`, `base::span`. These are fundamental types used throughout Chromium and Blink.

3. **Analyze the `Start()` Method (Core Functionality):**  This is the entry point. Deconstruct its steps:

    * **Initialization:**  Setting up member variables, including the crucial `client_`.
    * **Resource Load Initiation Notification:** `resource_load_info_notifier_wrapper_->NotifyResourceLoadInitiated(...)`. This highlights the connection to resource tracking and performance monitoring.
    * **Handling Redirects:** `HandleRedirections(...)`. Important for understanding how the loader deals with server-side redirects.
    * **Response Processing:** Creating a `ResourceResponse` and notifying the `resource_load_observer_`.
    * **Error Handling:** Checking for HTTP error status codes and failing early.
    * **Encoding Detection:** Determining the script encoding.
    * **Binding to URLLoader:** Establishing the communication channel with the network service via Mojo.
    * **Starting Body Loading:** Calling `StartLoadingBody()`.

4. **Analyze `StartLoadingBody()` and `OnReadable()` (Data Handling):** These methods manage the asynchronous reading of the script content from the `data_pipe_`.

    * **`StartLoadingBody()`:** Sets up a `mojo::SimpleWatcher` to be notified when data is available.
    * **`OnReadable()`:** Reads data from the pipe, passes it to the `client_` (`DidReceiveDataWorkerMainScript`), and notifies the `resource_load_observer_`. Crucially, it handles the end-of-data condition.

5. **Analyze `OnComplete()` (Completion Handling):**  This method is called when the network fetch is complete.

    * **Error Check:**  Determines if the load was successful.
    * **Resource Timing:**  Captures timing information for performance analysis.
    * **Notification:** Calls `NotifyCompletionIfAppropriate()`.

6. **Analyze `NotifyCompletionIfAppropriate()` (Finalization):**  This method handles the final steps after data reception is complete.

    * **Ensuring both completion and end-of-data:**  A safety check.
    * **Resource Load Completion Notification:** `resource_load_info_notifier_wrapper_->NotifyResourceLoadCompleted(...)`.
    * **Client Notification:** Calling `OnFinishedLoadingWorkerMainScript()` or `OnFailedLoadingWorkerMainScript()` on the `client_`.

7. **Identify Relationships to JavaScript, HTML, CSS:**

    * **JavaScript:** This loader is *specifically* for the main script of a worker, which is JavaScript code. The loaded script will be executed in the worker's context.
    * **HTML:**  Workers are typically initiated from an HTML page using the `new Worker()` constructor. The loader fetches the script specified in that constructor.
    * **CSS:** While this loader directly fetches JavaScript, workers can, in some scenarios, interact with the document or fetch CSS resources (though not the primary purpose of *this* loader).

8. **Look for Logic and Assumptions:**

    * **Redirections:** The code explicitly handles HTTP redirects. The assumption is that the underlying `URLLoader` provides redirect information.
    * **Error Handling:**  The code checks for network errors and HTTP status code errors.
    * **Asynchronous Loading:**  The use of Mojo pipes and watchers clearly demonstrates asynchronous data fetching.

9. **Consider User/Programming Errors:**

    * **Incorrect Script URL:** If the URL passed to the `Worker` constructor is invalid, the load will fail.
    * **Network Issues:**  General network problems (DNS resolution, connectivity issues) will lead to errors.
    * **Server-Side Errors:** HTTP status codes like 404 (Not Found) will cause the load to fail.
    * **CORS Issues:**  While not explicitly implemented *in this specific file* (the comment about CSP suggests related checks might be elsewhere), CORS restrictions could prevent loading scripts from different origins.

10. **Structure the Explanation:** Organize the findings into logical categories like "Functionality," "Relationship to Web Technologies," "Logic and Assumptions," and "Potential Errors."  Use clear and concise language, providing examples where appropriate.

By following these steps, one can systematically analyze the provided code and extract the key information needed to answer the prompt effectively. The process involves understanding the context, identifying the core components, tracing the execution flow, and connecting the functionality to broader web development concepts.
好的，让我们来分析一下 `blink/renderer/platform/loader/fetch/url_loader/worker_main_script_loader.cc` 这个文件的功能。

**主要功能:**

`WorkerMainScriptLoader` 类的主要功能是**负责加载 Web Worker 的主脚本文件**。它使用 Chromium 的网络堆栈 (通过 `URLLoader`) 来获取脚本内容，并管理加载过程中的各种事件和状态。

**具体功能点:**

1. **发起和管理网络请求:**
   - 接收 `FetchParameters` 包含的请求信息，例如 URL、HTTP 方法、请求头等。
   - 使用 `URLLoader` (通过 `url_loader_remote_`) 与网络服务进行通信。
   - 处理 HTTP 重定向 (通过 `HandleRedirections`)。

2. **处理 HTTP 响应:**
   - 接收并解析 HTTP 响应头 (`URLResponseHeadPtr`)。
   - 检查 HTTP 状态码，如果是非成功的状态码，则会通知客户端加载失败。
   - 获取响应的文本编码。

3. **接收脚本内容:**
   - 通过 Mojo 的数据管道 (`data_pipe_`) 异步接收脚本内容。
   - 使用 `mojo::SimpleWatcher` 监听数据管道的可读事件。
   - 将接收到的数据传递给 `WorkerMainScriptLoaderClient` 进行处理。

4. **提供加载进度通知:**
   - 通过 `ResourceLoadObserver` 通知资源加载的各个阶段，例如接收到响应、接收到数据、加载完成或失败。

5. **处理缓存元数据:**
   - 创建 `ScriptCachedMetadataHandler` 来处理脚本的缓存元数据，用于提高后续加载速度。

6. **处理加载完成和失败:**
   - 当脚本内容接收完毕或发生错误时，会通知 `WorkerMainScriptLoaderClient` 加载完成或失败。
   - 记录资源加载的完成状态和时间信息。

7. **处理连接关闭:**
   - 如果与网络服务的连接意外关闭，会通知加载失败。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`WorkerMainScriptLoader` 与 JavaScript 有着直接的关系，因为它加载的就是 Web Worker 的 **主 JavaScript 文件**。与 HTML 和 CSS 的关系是间接的，因为 Web Worker 通常是由 HTML 页面中的 JavaScript 代码创建的。

* **JavaScript:**
    - **功能关系:** `WorkerMainScriptLoader` 负责获取并传递 Web Worker 执行所需的 JavaScript 代码。
    - **举例:** 在 HTML 中，你可以使用以下 JavaScript 代码创建一个 Web Worker：
      ```javascript
      const worker = new Worker('my-worker.js');
      ```
      当执行这段代码时，Blink 引擎会创建 `WorkerMainScriptLoader` 来加载 `my-worker.js` 这个脚本。

* **HTML:**
    - **功能关系:** HTML 页面通过 `<script>` 标签或者 JavaScript 代码 (如 `new Worker()`) 触发脚本的加载。
    - **举例:** 上面的 JavaScript 代码示例中，`new Worker('my-worker.js')` 这行代码位于 HTML 页面引用的 JavaScript 文件中，间接地触发了 `WorkerMainScriptLoader` 对 `my-worker.js` 的加载。

* **CSS:**
    - **功能关系:**  `WorkerMainScriptLoader` 主要负责 JavaScript 文件的加载，与 CSS 文件的直接加载关系不大。然而，Web Worker 中的 JavaScript 代码可能会请求或操作 CSS 资源（例如，通过 `fetch` API 加载 CSS 文件）。
    - **举例:**  在 `my-worker.js` 中，你可能会有如下代码：
      ```javascript
      fetch('styles.css')
        .then(response => response.text())
        .then(cssText => {
          // 处理 CSS 内容
        });
      ```
      虽然 `WorkerMainScriptLoader` 不直接加载 `styles.css`，但它加载的 `my-worker.js` 中的 JavaScript 代码会发起对 `styles.css` 的请求，这个请求会由其他的加载器处理。

**逻辑推理 (假设输入与输出):**

假设输入：

* **`fetch_params`:** 包含以下信息：
    * `resource_request.url()`: `https://example.com/my-worker.js`
    * `options.credentials()`: `kInclude` (携带凭据)
* **`worker_main_script_load_params`:** 包含网络响应头信息、数据管道等。
    * `response_head->http_status_code`: 200
    * `response_head->mime_type`: `application/javascript`
    * `response_body`:  包含 `console.log("Hello from worker!");` 的数据管道。

输出：

1. **成功加载:** `WorkerMainScriptLoaderClient::OnFinishedLoadingWorkerMainScript()` 会被调用。
2. **脚本内容传递:** `WorkerMainScriptLoaderClient::DidReceiveDataWorkerMainScript()` 会被调用，并将 "console.log("Hello from worker!");" 作为数据传递给客户端。
3. **资源加载观察者通知:** `ResourceLoadObserver` 会收到一系列事件通知，包括接收到响应、接收到数据、加载完成等。
4. **资源定时信息:** 如果是 HTTP(S) 请求，会创建并添加资源定时信息。

假设输入 (错误情况):

* **`fetch_params`:**
    * `resource_request.url()`: `https://example.com/my-worker.js`
* **`worker_main_script_load_params`:**
    * `response_head->http_status_code`: 404

输出：

1. **加载失败:** `WorkerMainScriptLoaderClient::OnFailedLoadingWorkerMainScript()` 会被调用。
2. **资源加载观察者通知:** `ResourceLoadObserver` 会收到加载失败的通知，包含错误码 (例如 `net::ERR_FAILED`) 和 URL。

**用户或编程常见的使用错误:**

1. **错误的 Worker 脚本 URL:**
   - **错误:** 在 JavaScript 中创建 Worker 时，指定了一个不存在或者无法访问的脚本 URL。
   - **后果:** `WorkerMainScriptLoader` 会尝试加载该 URL，但由于服务器返回 404 或其他错误，加载会失败，Worker 无法启动。

2. **CORS 问题:**
   - **错误:**  Worker 脚本的 URL 与创建 Worker 的页面的来源不同源，且服务器没有设置正确的 CORS 头信息允许跨域访问。
   - **后果:**  `WorkerMainScriptLoader` 会阻止加载脚本，浏览器会抛出 CORS 相关的错误。

3. **网络连接问题:**
   - **错误:**  用户的网络连接中断或者不稳定。
   - **后果:** `WorkerMainScriptLoader` 在加载过程中可能会遇到网络错误，导致加载失败。

4. **服务器错误:**
   - **错误:**  托管 Worker 脚本的服务器出现内部错误 (例如 500 Internal Server Error)。
   - **后果:** `WorkerMainScriptLoader` 会接收到非 200 的 HTTP 状态码，从而判断加载失败。

5. **MIME 类型错误:**
   - **错误:**  服务器返回的 Worker 脚本的 MIME 类型不是 JavaScript 相关的类型 (例如 `text/plain`)。
   - **后果:**  虽然 `WorkerMainScriptLoader` 可能会成功下载脚本，但后续的脚本解析和执行可能会失败，或者浏览器会拒绝执行该脚本。

总而言之，`WorkerMainScriptLoader` 在 Blink 引擎中扮演着关键的角色，它负责将 Web Worker 的蓝图 (JavaScript 代码) 从网络世界带到浏览器中，为 Web 应用提供强大的后台处理能力。理解它的功能有助于我们更好地理解 Web Worker 的加载流程以及可能遇到的问题。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/worker_main_script_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/worker_main_script_loader.h"

#include "base/containers/span.h"
#include "services/network/public/cpp/header_util.h"
#include "services/network/public/cpp/record_ontransfersizeupdate_utils.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/url_conversion.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_context.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/worker_main_script_loader_client.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

WorkerMainScriptLoader::WorkerMainScriptLoader() = default;

WorkerMainScriptLoader::~WorkerMainScriptLoader() = default;

void WorkerMainScriptLoader::Start(
    const FetchParameters& fetch_params,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    FetchContext* fetch_context,
    ResourceLoadObserver* resource_load_observer,
    WorkerMainScriptLoaderClient* client) {
  DCHECK(resource_load_observer);
  DCHECK(client);
  request_id_ = worker_main_script_load_params->request_id;
  start_time_ = base::TimeTicks::Now();
  initial_request_ = fetch_params.GetResourceRequest();
  resource_loader_options_ = fetch_params.Options();
  initial_request_url_ = fetch_params.GetResourceRequest().Url();
  last_request_url_ = initial_request_url_;
  resource_load_observer_ = resource_load_observer;
  fetch_context_ = fetch_context;
  client_ = client;
  resource_load_info_notifier_wrapper_ =
      fetch_context->CreateResourceLoadInfoNotifierWrapper();

  // TODO(crbug.com/929370): Support CSP check to post violation reports for
  // worker top-level scripts, if off-the-main-thread fetch is enabled.

  // Currently we don't support ad resource check for the worker scripts.
  resource_load_info_notifier_wrapper_->NotifyResourceLoadInitiated(
      request_id_, GURL(initial_request_url_),
      initial_request_.HttpMethod().Latin1(),
      WebStringToGURL(WebString(initial_request_.ReferrerString())),
      initial_request_.GetRequestDestination(), net::HIGHEST,
      /*is_ad_resource=*/false);

  if (!worker_main_script_load_params->redirect_responses.empty()) {
    HandleRedirections(worker_main_script_load_params->redirect_infos,
                       worker_main_script_load_params->redirect_responses);
  }

  auto response_head = std::move(worker_main_script_load_params->response_head);
  WebURLResponse response =
      WebURLResponse::Create(WebURL(last_request_url_), *response_head,
                             response_head->ssl_info.has_value(), request_id_);
  resource_response_ = response.ToResourceResponse();
  resource_load_info_notifier_wrapper_->NotifyResourceResponseReceived(
      std::move(response_head));

  ResourceRequest resource_request(initial_request_);
  resource_load_observer_->DidReceiveResponse(
      initial_request_.InspectorId(), resource_request, resource_response_,
      /*resource=*/nullptr,
      ResourceLoadObserver::ResponseSource::kNotFromMemoryCache);

  if (resource_response_.IsHTTP() &&
      !network::IsSuccessfulStatus(resource_response_.HttpStatusCode())) {
    client_->OnFailedLoadingWorkerMainScript();
    resource_load_observer_->DidFailLoading(
        initial_request_.Url(), initial_request_.InspectorId(),
        ResourceError(net::ERR_FAILED, last_request_url_, std::nullopt),
        resource_response_.EncodedDataLength(),
        ResourceLoadObserver::IsInternalRequest(
            resource_loader_options_.initiator_info.name ==
            fetch_initiator_type_names::kInternal));
    return;
  }

  script_encoding_ =
      resource_response_.TextEncodingName().empty()
          ? UTF8Encoding()
          : WTF::TextEncoding(resource_response_.TextEncodingName());

  url_loader_remote_.Bind(std::move(
      worker_main_script_load_params->url_loader_client_endpoints->url_loader));
  receiver_.Bind(
      std::move(worker_main_script_load_params->url_loader_client_endpoints
                    ->url_loader_client));
  receiver_.set_disconnect_handler(WTF::BindOnce(
      &WorkerMainScriptLoader::OnConnectionClosed, WrapWeakPersistent(this)));
  data_pipe_ = std::move(worker_main_script_load_params->response_body);

  client_->OnStartLoadingBodyWorkerMainScript(resource_response_);
  StartLoadingBody();
}

void WorkerMainScriptLoader::Cancel() {
  if (has_cancelled_)
    return;
  has_cancelled_ = true;
  if (watcher_ && watcher_->IsWatching())
    watcher_->Cancel();

  receiver_.reset();
  url_loader_remote_.reset();
}

void WorkerMainScriptLoader::OnReceiveEarlyHints(
    network::mojom::EarlyHintsPtr early_hints) {
  // This has already happened in the browser process.
  NOTREACHED();
}

void WorkerMainScriptLoader::OnReceiveResponse(
    network::mojom::URLResponseHeadPtr response_head,
    mojo::ScopedDataPipeConsumerHandle handle,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  // This has already happened in the browser process.
  NOTREACHED();
}

void WorkerMainScriptLoader::OnReceiveRedirect(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr response_head) {
  // This has already happened in the browser process.
  NOTREACHED();
}

void WorkerMainScriptLoader::OnUploadProgress(
    int64_t current_position,
    int64_t total_size,
    OnUploadProgressCallback callback) {
  // This has already happened in the browser process.
  NOTREACHED();
}

void WorkerMainScriptLoader::OnTransferSizeUpdated(int32_t transfer_size_diff) {
  network::RecordOnTransferSizeUpdatedUMA(
      network::OnTransferSizeUpdatedFrom::kWorkerMainScriptLoader);
}

void WorkerMainScriptLoader::OnComplete(
    const network::URLLoaderCompletionStatus& status) {
  if (status.error_code != net::OK)
    has_seen_end_of_data_ = true;

  // Reports resource timing info for the worker main script.
  resource_response_.SetEncodedBodyLength(status.encoded_body_length);
  resource_response_.SetDecodedBodyLength(status.decoded_body_length);
  resource_response_.SetCurrentRequestUrl(last_request_url_);

  // https://fetch.spec.whatwg.org/#fetch-finale
  // Step 3.3.1. If fetchParams's request's URL's scheme is not an HTTP(S)
  // scheme, then return.
  //
  // i.e. call `AddResourceTiming()` only if the URL's scheme is HTTP(S).
  if (initial_request_url_.ProtocolIsInHTTPFamily()) {
    mojom::blink::ResourceTimingInfoPtr timing_info = CreateResourceTimingInfo(
        start_time_, initial_request_url_, &resource_response_);
    timing_info->response_end = status.completion_time;
    fetch_context_->AddResourceTiming(std::move(timing_info),
                                      fetch_initiator_type_names::kOther);
  }

  has_received_completion_ = true;
  status_ = status;
  NotifyCompletionIfAppropriate();
}

CachedMetadataHandler* WorkerMainScriptLoader::CreateCachedMetadataHandler() {
  // Currently we support the metadata caching only for HTTP family.
  if (!initial_request_url_.ProtocolIsInHTTPFamily() ||
      !resource_response_.CurrentRequestUrl().ProtocolIsInHTTPFamily()) {
    return nullptr;
  }

  std::unique_ptr<CachedMetadataSender> cached_metadata_sender =
      CachedMetadataSender::Create(
          resource_response_, mojom::blink::CodeCacheType::kJavascript,
          SecurityOrigin::Create(initial_request_url_));
  return MakeGarbageCollected<ScriptCachedMetadataHandler>(
      script_encoding_, std::move(cached_metadata_sender));
}

void WorkerMainScriptLoader::Trace(Visitor* visitor) const {
  visitor->Trace(fetch_context_);
  visitor->Trace(resource_load_observer_);
  visitor->Trace(client_);
  visitor->Trace(resource_loader_options_);
}

void WorkerMainScriptLoader::StartLoadingBody() {
  // Loading body may be cancelled before starting by calling |Cancel()|.
  if (has_cancelled_)
    return;

  watcher_ = std::make_unique<mojo::SimpleWatcher>(
      FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL);
  MojoResult rv =
      watcher_->Watch(data_pipe_.get(), MOJO_HANDLE_SIGNAL_READABLE,
                      WTF::BindRepeating(&WorkerMainScriptLoader::OnReadable,
                                         WrapWeakPersistent(this)));
  DCHECK_EQ(MOJO_RESULT_OK, rv);
  watcher_->ArmOrNotify();
}

void WorkerMainScriptLoader::OnReadable(MojoResult) {
  // It isn't necessary to handle MojoResult here since BeginReadDataRaw()
  // returns an equivalent error.
  base::span<const uint8_t> buffer;
  MojoResult rv = data_pipe_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, buffer);
  switch (rv) {
    case MOJO_RESULT_BUSY:
    case MOJO_RESULT_INVALID_ARGUMENT:
      NOTREACHED();
    case MOJO_RESULT_FAILED_PRECONDITION:
      has_seen_end_of_data_ = true;
      NotifyCompletionIfAppropriate();
      return;
    case MOJO_RESULT_SHOULD_WAIT:
      watcher_->ArmOrNotify();
      return;
    case MOJO_RESULT_OK:
      break;
    default:
      OnComplete(network::URLLoaderCompletionStatus(net::ERR_FAILED));
      return;
  }

  if (!buffer.empty()) {
    base::span<const char> chars = base::as_chars(buffer);
    client_->DidReceiveDataWorkerMainScript(chars);
    resource_load_observer_->DidReceiveData(initial_request_.InspectorId(),
                                            base::SpanOrSize(chars));
  }

  rv = data_pipe_->EndReadData(buffer.size());
  DCHECK_EQ(rv, MOJO_RESULT_OK);
  watcher_->ArmOrNotify();
}

void WorkerMainScriptLoader::NotifyCompletionIfAppropriate() {
  if (!has_received_completion_ || !has_seen_end_of_data_)
    return;

  data_pipe_.reset();
  watcher_->Cancel();
  resource_load_info_notifier_wrapper_->NotifyResourceLoadCompleted(status_);

  if (!client_)
    return;
  WorkerMainScriptLoaderClient* client = client_.Get();
  client_.Clear();

  if (status_.error_code == net::OK) {
    client->OnFinishedLoadingWorkerMainScript();
    resource_load_observer_->DidFinishLoading(
        initial_request_.InspectorId(), base::TimeTicks::Now(),
        resource_response_.EncodedDataLength(),
        resource_response_.DecodedBodyLength());
  } else {
    client->OnFailedLoadingWorkerMainScript();
    resource_load_observer_->DidFailLoading(
        last_request_url_, initial_request_.InspectorId(),
        ResourceError(status_.error_code, last_request_url_, std::nullopt),
        resource_response_.EncodedDataLength(),
        ResourceLoadObserver::IsInternalRequest(
            ResourceLoadObserver::IsInternalRequest(
                resource_loader_options_.initiator_info.name ==
                fetch_initiator_type_names::kInternal)));
  }
}

void WorkerMainScriptLoader::OnConnectionClosed() {
  if (!has_received_completion_) {
    OnComplete(network::URLLoaderCompletionStatus(net::ERR_ABORTED));
    return;
  }
}

void WorkerMainScriptLoader::HandleRedirections(
    std::vector<net::RedirectInfo>& redirect_infos,
    std::vector<network::mojom::URLResponseHeadPtr>& redirect_responses) {
  DCHECK_EQ(redirect_infos.size(), redirect_responses.size());
  for (size_t i = 0; i < redirect_infos.size(); ++i) {
    auto& redirect_info = redirect_infos[i];
    auto& redirect_response = redirect_responses[i];
    last_request_url_ = KURL(redirect_info.new_url);
    resource_load_info_notifier_wrapper_->NotifyResourceRedirectReceived(
        redirect_info, std::move(redirect_response));
  }
}

}  // namespace blink
```