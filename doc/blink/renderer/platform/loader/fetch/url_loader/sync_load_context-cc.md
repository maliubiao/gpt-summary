Response:
Let's break down the thought process for analyzing the `SyncLoadContext.cc` file.

1. **Understand the Goal:** The request is to analyze the provided C++ source code file (`SyncLoadContext.cc`) and identify its functionality, its relation to web technologies (JavaScript, HTML, CSS), provide examples, explain logical reasoning with input/output, and highlight potential usage errors.

2. **Initial Skim and High-Level Understanding:**  A quick read-through reveals keywords like "SyncLoadContext," "URLLoader," "ResourceRequest," "Redirect," "Response," "Blob," "DataPipe," "WaitableEvent," and "Timeout."  This immediately suggests the file is about handling synchronous network requests within the Blink rendering engine. The "sync" aspect is crucial and distinguishes it from asynchronous loading.

3. **Identify Core Functionality by Class and Method Analysis:**  Focus on the `SyncLoadContext` class and its methods.

    * **Constructor/Destructor:**  `SyncLoadContext` takes parameters related to the request, URL loader factory, and response. The destructor is simple, suggesting resource cleanup is handled elsewhere (likely by the `resource_request_sender_`).

    * **`StartAsyncWithWaitableEvent`:** This static method is the entry point for initiating a synchronous load. The name "Async" is a bit misleading because it ultimately blocks, but it internally uses asynchronous mechanisms. The `WaitableEvent` parameters are the key to the synchronous behavior. It's responsible for creating the `SyncLoadContext` instance and initiating the network request via `resource_request_sender_`.

    * **`OnUploadProgress`:**  A simple callback for upload progress, likely irrelevant for *synchronous* loading where the request is typically sent before waiting for the response.

    * **`OnReceivedRedirect`:** Handles server redirects. Crucially, it stores the redirect information and signals the `redirect_or_response_event_`, allowing the calling thread to inspect the redirect and potentially follow it.

    * **`FollowRedirect`:**  Resumes the loading process after a redirect, sending the follow-up request. It includes checks to prevent issues after an abort or timeout.

    * **`CancelRedirect`:**  Stops the redirect process.

    * **`OnReceivedResponse`:**  Handles the initial response headers and body. It distinguishes between downloading the body as a Blob and reading it through a data pipe.

    * **`OnTransferSizeUpdated`:**  Another likely irrelevant callback for synchronous loading.

    * **`OnCompletedRequest`:**  Called when the network request finishes (successfully or with an error). It stores the completion status but might wait for blob download to finish.

    * **`OnFinishCreatingBlob`:**  Handles the completion of a Blob download.

    * **`OnBodyReadable`:**  Manages reading data from the data pipe. It handles partial reads and completion.

    * **`OnAbort`:**  Handles external abortion of the request.

    * **`OnTimeout`:** Handles the request timeout.

    * **`CompleteRequest`:** Signals the completion of the request and triggers cleanup.

    * **`Completed`:**  A simple check to see if the request is finished.

4. **Identify the `SignalHelper` Class:** This inner class manages the synchronization primitives (`WaitableEvent` and `OneShotTimer`). Its purpose is to simplify starting, stopping, and restarting the waiting mechanisms, especially during redirects.

5. **Relate to Web Technologies:** Now, connect the functionality to web concepts.

    * **JavaScript:**  Synchronous XHR (`XMLHttpRequest` with `async = false`) is the primary user-facing feature that would trigger this code path. Loading synchronous scripts also falls into this category.

    * **HTML:**  Synchronous script tags (`<script src="..." async="false">`) rely on synchronous loading.

    * **CSS:**  While CSS loading is generally asynchronous, there might be edge cases or internal mechanisms where synchronous loading is used (less common).

6. **Provide Examples:**  Concrete examples solidify understanding. The synchronous XHR example is the most straightforward. Mentioning synchronous script loading is also important.

7. **Explain Logical Reasoning (Input/Output):**  Focus on the core synchronous behavior. The input is the initial request, and the output is the final response (or an error). Explain how redirects are handled as intermediate steps. The waitable events are the central mechanism for blocking and signaling.

8. **Identify Potential Usage Errors:** Think about how developers might misuse synchronous loading.

    * **Main Thread Blocking:**  The most critical error. Explain the performance implications.
    * **Timeouts:**  Illustrate how setting an appropriate timeout is important.
    * **Aborting:**  Show how to correctly abort a synchronous request if needed.

9. **Review and Refine:**  Read through the analysis. Ensure the explanations are clear, concise, and accurate. Check for any missing details or areas that could be explained better. For instance, explicitly mentioning the role of the `WaitableEvent` in blocking the calling thread is key. Also, clarify the misleading "Async" in `StartAsyncWithWaitableEvent`. Emphasize the *blocking* nature of the synchronous load from the caller's perspective.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps focus too much on the individual network request details.
* **Correction:** Shift focus to the *synchronous* nature of the context and how it achieves blocking.
* **Initial thought:** Not enough emphasis on the `WaitableEvent`.
* **Correction:** Highlight its role as the primary synchronization mechanism.
* **Initial thought:** The name `StartAsyncWithWaitableEvent` is confusing.
* **Correction:**  Acknowledge the confusing name and explain that while it uses asynchronous *internals*, the *external* behavior is synchronous and blocking.
* **Initial thought:**  Not enough emphasis on the negative consequences of synchronous loading.
* **Correction:**  Clearly explain the main thread blocking issue and its impact on user experience.

By following this systematic approach, combining code analysis with a high-level understanding of web technologies and potential usage scenarios, a comprehensive and accurate explanation of `SyncLoadContext.cc` can be generated.
好的，让我们来分析一下 `blink/renderer/platform/loader/fetch/url_loader/sync_load_context.cc` 文件的功能。

**核心功能：**

这个文件的核心功能是**在 Blink 渲染引擎中实现同步的网络资源加载机制**。  它提供了一个 `SyncLoadContext` 类，用于管理一个同步的 URL 加载请求的生命周期。  这意味着当发起一个同步加载请求时，调用线程会**阻塞**，直到请求完成（成功或失败）或超时。

**主要组成部分和功能分解：**

1. **`SyncLoadContext` 类:**
   - **管理同步加载的状态:**  跟踪加载的各个阶段，例如是否已接收重定向、响应头、响应体、是否已完成等。
   - **处理网络事件:**  作为网络加载过程中的事件接收器，响应诸如接收到重定向、响应头、响应体数据以及请求完成等事件。
   - **同步机制:**  使用 `base::WaitableEvent` 来阻塞调用线程，直到特定的事件发生（例如，接收到响应或发生重定向）。
   - **超时处理:**  使用 `base::OneShotTimer` 实现超时机制，防止同步加载无限期阻塞。
   - **Blob 下载支持:**  可以处理将响应体下载为 Blob 的情况。
   - **错误处理:**  记录和处理网络请求过程中发生的错误。
   - **资源管理:**  管理网络请求相关的资源，例如 `mojo::ScopedDataPipeConsumerHandle` 用于接收响应体数据。

2. **`SignalHelper` 内部类:**
   - **简化信号管理:**  封装了 `base::WaitableEvent` 和 `base::OneShotTimer` 的管理，用于处理重定向、响应和超时信号。
   - **统一启动和停止:**  提供统一的方法来启动和停止等待事件和超时定时器。
   - **支持重定向后重启:**  在重定向发生后，能够重新启动等待事件和超时定时器。

3. **`StartAsyncWithWaitableEvent` 静态方法:**
   - **启动同步加载:**  作为启动同步加载请求的入口点。
   - **创建 `SyncLoadContext` 实例:**  负责创建 `SyncLoadContext` 对象并初始化相关参数。
   - **发起网络请求:**  使用 `ResourceRequestSender` 发起实际的网络请求。
   - **传递回调:**  接收用于通知加载结果的回调函数和事件。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`SyncLoadContext` 的主要应用场景是支持浏览器中的**同步操作**，这些操作可能会由 JavaScript 或浏览器内部机制触发。

* **JavaScript:**
    * **同步 XMLHttpRequest (XHR):** 当 JavaScript 代码中使用 `XMLHttpRequest` 对象并设置 `async = false` 时，会触发同步加载。`SyncLoadContext` 就用于处理这类同步请求。

      ```javascript
      var xhr = new XMLHttpRequest();
      xhr.open('GET', 'https://example.com/data.json', false); // 第三个参数 false 表示同步
      xhr.send();
      if (xhr.status === 200) {
        console.log(xhr.responseText); // 代码会阻塞在这里，直到请求完成
      }
      ```

* **HTML:**
    * **同步脚本加载:**  虽然不推荐，但可以使用 `<script>` 标签的 `async="false"` 或不设置 `async` 属性（在某些情况下）来强制脚本同步加载。浏览器内部会使用同步加载机制，`SyncLoadContext` 可能会参与其中。

      ```html
      <script src="script.js"></script> <!-- 默认或 async="false"，可能触发同步加载 -->
      ```

* **CSS:**
    * **CSS 资源加载（某些特定情况）：**  虽然 CSS 通常是异步加载的，但在某些特定的渲染阻塞场景下，或者浏览器内部的某些优化策略中，可能会涉及到同步加载 CSS 资源。 `SyncLoadContext` 可能在这些不太常见的场景中被使用。  更常见的是，CSS 加载会影响渲染树的构建，从而间接影响 JavaScript 的执行时机。

**逻辑推理 (假设输入与输出):**

假设输入：

1. **请求 URL:** `https://example.com/api/data`
2. **请求方法:** `GET`
3. **同步标志:**  设置为同步加载
4. **超时时间:** 5 秒
5. **服务器响应：**
   - 状态码：200 OK
   - Content-Type: `application/json`
   - 响应体：`{"key": "value"}`

输出：

- `SyncLoadResponse` 对象会被填充以下信息：
    - `url`: `https://example.com/api/data`
    - `head`: 包含响应头信息，例如状态码、Content-Type 等。
    - `data`: 一个 `SharedBuffer`，包含响应体数据 `{"key": "value"}`。
    - `error_code`: `net::OK` (表示成功)。

假设输入（重定向场景）：

1. **请求 URL:** `https://old.example.com/data`
2. **请求方法:** `GET`
3. **同步标志:** 设置为同步加载
4. **超时时间:** 5 秒
5. **服务器响应 (第一次请求):**
   - 状态码：302 Found
   - Location: `https://new.example.com/data`
6. **服务器响应 (第二次请求):**
   - 状态码：200 OK
   - Content-Type: `text/plain`
   - 响应体：`Hello, world!`

输出：

- `SyncLoadResponse` 对象会被填充以下信息：
    - `url`: `https://new.example.com/data` (最终的 URL)
    - `head`: 包含第二次请求的响应头信息。
    - `data`: 包含第二次请求的响应体数据 `Hello, world!`。
    - `redirect_info`:  包含重定向的相关信息。
    - `error_code`: `net::OK`.

**涉及用户或编程常见的使用错误：**

1. **在主线程进行同步加载:**  这是最常见的也是最严重的使用错误。由于同步加载会阻塞调用线程，如果在浏览器的主线程（UI 线程）进行同步加载，会导致页面**卡顿**，用户界面无响应，严重影响用户体验，甚至可能导致浏览器无响应。

   ```javascript
   // 在主线程执行，会导致页面卡死
   var xhr = new XMLHttpRequest();
   xhr.open('GET', 'https://slow.example.com/data', false);
   xhr.send();
   ```

2. **设置过长的超时时间:**  如果超时时间设置得过长，当网络请求真的出现问题时，用户需要等待很长时间才能得到反馈，同样会影响用户体验。 应该根据实际情况设置合理的超时时间。

3. **没有处理错误情况:**  同步加载可能会失败（例如，网络错误、服务器错误）。  如果没有适当的错误处理机制，可能会导致程序行为不确定。

   ```javascript
   var xhr = new XMLHttpRequest();
   xhr.open('GET', 'https://nonexistent.example.com/data', false);
   try {
     xhr.send();
     if (xhr.status === 200) {
       console.log(xhr.responseText);
     } else {
       console.error("请求失败，状态码:", xhr.status);
     }
   } catch (error) {
     console.error("请求过程中发生错误:", error);
   }
   ```

4. **在不必要的情况下使用同步加载:**  大多数情况下，异步加载是更好的选择，因为它不会阻塞主线程，提供更好的用户体验。  只有在明确需要同步行为的特定场景下才应该使用同步加载。

5. **忘记处理重定向:**  同步加载可能会遇到 HTTP 重定向。开发者需要理解如何处理重定向，例如检查 `xhr.responseURL` 或 `xhr.status` 来判断是否发生了重定向。  `SyncLoadContext` 内部会处理重定向，但调用者需要理解其行为。

**总结:**

`SyncLoadContext.cc` 文件实现了 Blink 引擎中处理同步网络加载的核心逻辑。它通过阻塞调用线程的方式来保证请求的顺序执行，主要用于支持同步的 JavaScript 操作和浏览器内部的特定同步加载需求。虽然同步加载在某些场景下是必要的，但开发者需要谨慎使用，尤其要避免在主线程进行同步操作，并妥善处理错误和超时情况，以避免影响用户体验。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/sync_load_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/sync_load_context.h"

#include <optional>
#include <string>

#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "net/http/http_request_headers.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/client_hints/client_hints.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/url_loader_throttle.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/sync_load_response.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "url/origin.h"

namespace blink {

// An inner helper class to manage the SyncLoadContext's events and timeouts,
// so that we can stop or resumse all of them at once.
class SyncLoadContext::SignalHelper final {
 public:
  SignalHelper(SyncLoadContext* context,
               base::WaitableEvent* redirect_or_response_event,
               base::WaitableEvent* abort_event,
               base::TimeDelta timeout)
      : context_(context),
        redirect_or_response_event_(redirect_or_response_event),
        abort_event_(abort_event) {
    // base::TimeDelta::Max() means no timeout.
    if (timeout != base::TimeDelta::Max()) {
      // Instantiate a base::OneShotTimer instance.
      timeout_timer_.emplace();
    }
    Start(timeout);
  }

  void SignalRedirectOrResponseComplete() {
    abort_watcher_.StopWatching();
    if (timeout_timer_)
      timeout_timer_->Stop();
    redirect_or_response_event_->Signal();
  }

  bool RestartAfterRedirect() {
    if (abort_event_ && abort_event_->IsSignaled())
      return false;

    base::TimeDelta timeout_remainder = base::TimeDelta::Max();
    if (timeout_timer_) {
      timeout_remainder =
          timeout_timer_->desired_run_time() - base::TimeTicks::Now();
      if (timeout_remainder <= base::TimeDelta())
        return false;
    }
    Start(timeout_remainder);
    return true;
  }

 private:
  void Start(base::TimeDelta timeout) {
    DCHECK(!redirect_or_response_event_->IsSignaled());
    if (abort_event_) {
      abort_watcher_.StartWatching(
          abort_event_,
          base::BindOnce(&SyncLoadContext::OnAbort, base::Unretained(context_)),
          context_->task_runner_);
    }
    if (timeout_timer_) {
      DCHECK_NE(base::TimeDelta::Max(), timeout);
      timeout_timer_->Start(FROM_HERE, timeout, context_.get(),
                            &SyncLoadContext::OnTimeout);
    }
  }

  raw_ptr<SyncLoadContext> context_;
  raw_ptr<base::WaitableEvent> redirect_or_response_event_;
  raw_ptr<base::WaitableEvent> abort_event_;
  base::WaitableEventWatcher abort_watcher_;
  std::optional<base::OneShotTimer> timeout_timer_;
};

// static
void SyncLoadContext::StartAsyncWithWaitableEvent(
    std::unique_ptr<network::ResourceRequest> request,
    scoped_refptr<base::SingleThreadTaskRunner> loading_task_runner,
    const net::NetworkTrafficAnnotationTag& traffic_annotation,
    uint32_t loader_options,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_url_loader_factory,
    WebVector<std::unique_ptr<URLLoaderThrottle>> throttles,
    SyncLoadResponse* response,
    SyncLoadContext** context_for_redirect,
    base::WaitableEvent* redirect_or_response_event,
    base::WaitableEvent* abort_event,
    base::TimeDelta timeout,
    mojo::PendingRemote<mojom::blink::BlobRegistry> download_to_blob_registry,
    const Vector<String>& cors_exempt_header_list,
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper) {
  scoped_refptr<SyncLoadContext> context(base::AdoptRef(new SyncLoadContext(
      request.get(), std::move(pending_url_loader_factory), response,
      context_for_redirect, redirect_or_response_event, abort_event, timeout,
      std::move(download_to_blob_registry), loading_task_runner)));
  context->resource_request_sender_->SendAsync(
      std::move(request), std::move(loading_task_runner), traffic_annotation,
      loader_options, cors_exempt_header_list, context,
      context->url_loader_factory_, std::move(throttles),
      std::move(resource_load_info_notifier_wrapper),
      /*code_cache_host=*/nullptr,
      /*evict_from_bfcache_callback=*/
      base::OnceCallback<void(mojom::blink::RendererEvictionReason)>(),
      /*did_buffer_load_while_in_bfcache_callback=*/
      base::RepeatingCallback<void(size_t)>());
}

SyncLoadContext::SyncLoadContext(
    network::ResourceRequest* request,
    std::unique_ptr<network::PendingSharedURLLoaderFactory> url_loader_factory,
    SyncLoadResponse* response,
    SyncLoadContext** context_for_redirect,
    base::WaitableEvent* redirect_or_response_event,
    base::WaitableEvent* abort_event,
    base::TimeDelta timeout,
    mojo::PendingRemote<mojom::blink::BlobRegistry> download_to_blob_registry,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : response_(response),
      context_for_redirect_(context_for_redirect),
      body_watcher_(FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL),
      download_to_blob_registry_(std::move(download_to_blob_registry)),
      task_runner_(std::move(task_runner)),
      signals_(std::make_unique<SignalHelper>(this,
                                              redirect_or_response_event,
                                              abort_event,
                                              timeout)) {
  if (download_to_blob_registry_)
    mode_ = Mode::kBlob;

  url_loader_factory_ =
      network::SharedURLLoaderFactory::Create(std::move(url_loader_factory));

  // Constructs a new ResourceRequestSender specifically for this request.
  resource_request_sender_ = std::make_unique<ResourceRequestSender>();

  // Initialize the final URL with the original request URL. It will be
  // overwritten on redirects.
  response_->url = request->url;

  has_authorization_header_ =
      request->headers.HasHeader(net::HttpRequestHeaders::kAuthorization);
}

SyncLoadContext::~SyncLoadContext() {}

void SyncLoadContext::OnUploadProgress(uint64_t position, uint64_t size) {}

void SyncLoadContext::OnReceivedRedirect(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr head,
    FollowRedirectCallback follow_redirect_callback) {
  DCHECK(!Completed());

  if (has_authorization_header_ &&
      !url::IsSameOriginWith(response_->url, redirect_info.new_url)) {
    response_->has_authorization_header_between_cross_origin_redirect_ = true;
  }

  response_->url = redirect_info.new_url;
  response_->head = std::move(head);
  response_->redirect_info = redirect_info;
  *context_for_redirect_ = this;

  follow_redirect_callback_ = std::move(follow_redirect_callback);
  signals_->SignalRedirectOrResponseComplete();
}

void SyncLoadContext::FollowRedirect(std::vector<std::string> removed_headers,
                                     net::HttpRequestHeaders modified_headers) {
  CHECK(follow_redirect_callback_);
  if (!signals_->RestartAfterRedirect()) {
    CancelRedirect();
    return;
  }

  response_->redirect_info = net::RedirectInfo();
  *context_for_redirect_ = nullptr;
  std::move(follow_redirect_callback_)
      .Run(std::move(removed_headers), std::move(modified_headers));
}

void SyncLoadContext::CancelRedirect() {
  response_->redirect_info = net::RedirectInfo();
  *context_for_redirect_ = nullptr;

  response_->error_code = net::ERR_ABORTED;
  CompleteRequest();
}

void SyncLoadContext::OnReceivedResponse(
    network::mojom::URLResponseHeadPtr head,
    mojo::ScopedDataPipeConsumerHandle body,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  DCHECK(!Completed());
  response_->head = std::move(head);

  if (!body) {
    return;
  }

  if (mode_ == Mode::kBlob) {
    DCHECK(download_to_blob_registry_);
    DCHECK(!blob_response_started_);

    blob_response_started_ = true;

    download_to_blob_registry_->RegisterFromStream(
        String(response_->head->mime_type), "",
        std::max<int64_t>(0, response_->head->content_length), std::move(body),
        mojo::NullAssociatedRemote(),
        base::BindOnce(&SyncLoadContext::OnFinishCreatingBlob,
                       base::Unretained(this)));
    return;
  }
  DCHECK_EQ(Mode::kInitial, mode_);
  mode_ = Mode::kDataPipe;
  // setup datapipe to read.
  body_handle_ = std::move(body);
  body_watcher_.Watch(
      body_handle_.get(),
      MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
      base::BindRepeating(&SyncLoadContext::OnBodyReadable,
                          base::Unretained(this)));
  body_watcher_.ArmOrNotify();
}

void SyncLoadContext::OnTransferSizeUpdated(int transfer_size_diff) {}

void SyncLoadContext::OnCompletedRequest(
    const network::URLLoaderCompletionStatus& status) {
  if (Completed()) {
    // It means the response has been aborted due to an error before finishing
    // the response.
    return;
  }
  request_completed_ = true;
  response_->error_code = status.error_code;
  response_->extended_error_code = status.extended_error_code;
  response_->resolve_error_info = status.resolve_error_info;
  response_->should_collapse_initiator = status.should_collapse_initiator;
  response_->cors_error = status.cors_error_status;
  response_->head->encoded_data_length = status.encoded_data_length;
  DCHECK_GE(status.encoded_body_length, 0);
  response_->head->encoded_body_length =
      network::mojom::EncodedBodyLength::New(status.encoded_body_length);
  if ((blob_response_started_ && !blob_finished_) || body_handle_.is_valid()) {
    // The body is still begin downloaded as a Blob, or being read through the
    // handle. Wait until it's completed.
    return;
  }
  CompleteRequest();
}

void SyncLoadContext::OnFinishCreatingBlob(
    const scoped_refptr<BlobDataHandle>& blob) {
  DCHECK(!Completed());
  blob_finished_ = true;
  response_->downloaded_blob = blob;
  if (request_completed_)
    CompleteRequest();
}

void SyncLoadContext::OnBodyReadable(MojoResult,
                                     const mojo::HandleSignalsState&) {
  DCHECK_EQ(Mode::kDataPipe, mode_);
  DCHECK(body_handle_.is_valid());
  base::span<const uint8_t> buffer;
  MojoResult result =
      body_handle_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, buffer);
  if (result == MOJO_RESULT_SHOULD_WAIT) {
    body_watcher_.ArmOrNotify();
    return;
  }
  if (result == MOJO_RESULT_FAILED_PRECONDITION) {
    // Whole body has been read.
    body_handle_.reset();
    body_watcher_.Cancel();
    if (request_completed_)
      CompleteRequest();
    return;
  }
  if (result != MOJO_RESULT_OK) {
    // Something went wrong.
    body_handle_.reset();
    body_watcher_.Cancel();
    response_->error_code = net::ERR_FAILED;
    CompleteRequest();
    return;
  }

  base::span<const char> chars = base::as_chars(buffer);
  if (!response_->data) {
    response_->data = SharedBuffer::Create(chars.data(), chars.size());
  } else {
    response_->data->Append(chars.data(), chars.size());
  }
  body_handle_->EndReadData(chars.size());
  body_watcher_.ArmOrNotify();
}

void SyncLoadContext::OnAbort(base::WaitableEvent* event) {
  DCHECK(!Completed());
  body_handle_.reset();
  body_watcher_.Cancel();
  response_->error_code = net::ERR_ABORTED;
  CompleteRequest();
}

void SyncLoadContext::OnTimeout() {
  // OnTimeout() must not be called after CompleteRequest() was called, because
  // the OneShotTimer must have been stopped.
  DCHECK(!Completed());
  body_handle_.reset();
  body_watcher_.Cancel();
  response_->error_code = net::ERR_TIMED_OUT;
  CompleteRequest();
}

void SyncLoadContext::CompleteRequest() {
  DCHECK(blob_finished_ || (mode_ != Mode::kBlob));
  DCHECK(!body_handle_.is_valid());
  body_watcher_.Cancel();
  signals_->SignalRedirectOrResponseComplete();
  signals_ = nullptr;
  response_ = nullptr;

  // This will indirectly cause this object to be deleted.
  resource_request_sender_->DeletePendingRequest(task_runner_);
}

bool SyncLoadContext::Completed() const {
  DCHECK_EQ(!signals_, !response_);
  return !response_;
}

}  // namespace blink
```