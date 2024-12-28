Response:
The user wants to understand the functionality of the `background_url_loader.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose** of this class. Based on the name, it likely handles URL loading in the background.
2. **Examine the included headers** to get clues about its dependencies and interactions with other parts of the engine (e.g., networking, caching, threading).
3. **Analyze the methods and members** of the `BackgroundURLLoader` and its internal `Context` class to understand its workflow.
4. **Determine its relationship with JavaScript, HTML, and CSS.** Background loading often relates to prefetching or caching resources used by these technologies.
5. **Infer logical reasoning** based on the code structure, like how requests are initiated, handled, and how responses are processed.
6. **Identify potential user/programming errors** by considering how the loader is used and what could go wrong.
7. **Summarize the functionality** based on the analysis.

**High-level observation:** The code defines a `BackgroundURLLoader` class, which uses an internal `Context` class to manage the actual loading process. The `Context` appears to handle communication between the main thread and a background thread for performing network requests. It also seems to integrate with caching mechanisms and handles redirects and errors.

**Relationship with web technologies:**  Background loading is crucial for optimizing the loading of web page resources (JavaScript, CSS, images, etc.) to improve performance.

**Logical reasoning:** When a request is made, it's likely passed to the `Context`, which then sends the request on a background thread. The response is then processed and sent back to the main thread.

**Potential errors:** Incorrect configuration of request parameters, issues with background thread management, or conflicts with caching policies could lead to errors.
这是 `blink/renderer/platform/loader/fetch/url_loader/background_url_loader.cc` 文件的第一部分，主要定义了 `BackgroundURLLoader` 类及其内部的 `Context` 类。

**功能归纳:**

`BackgroundURLLoader` 的主要功能是**在后台执行网络请求**。它被设计用来加载资源，而不会阻塞主线程，这对于提高用户体验至关重要，尤其是在加载可能耗时的资源时。

**详细功能点:**

1. **异步请求处理:**  `BackgroundURLLoader` 允许在后台线程发起和处理网络请求，使得主线程可以继续执行其他任务，例如渲染页面和响应用户交互。这通过内部的 `Context` 类来实现，该类负责将任务调度到后台线程执行。
2. **支持 GET 请求:**  目前代码明确指出只支持 HTTP GET 方法的请求。
3. **支持 HTTP(S) 和 Blob URL:**  支持加载 `http://`, `https://` 和 `blob:` 协议的 URL。
4. **不支持 Keep-Alive 请求:**  明确指出不支持 `keepalive` 连接，这可能是为了简化后台线程中的生命周期管理。
5. **不支持预渲染的文档:**  `prerender::NoStatePrefetchHelper` 在后台线程尚不支持。
6. **集成 URLLoaderThrottle:**  可以使用 `URLLoaderThrottle` 来修改请求或响应，例如实现 MIME 类型嗅探 (`MimeSniffingThrottle`) 和应用实验性功能 (`VariationsThrottles`)。
7. **集成 Back-Forward Cache (BFCache):**  与 BFCache 集成，允许在页面从 BFCache 恢复时加载资源，并能在资源加载过程中管理 BFCache 的缓存大小和执行驱逐。
8. **支持 CORS Exempt Headers:**  允许指定一些请求头可以不受 CORS 限制。
9. **处理重定向:**  能够处理服务器返回的 HTTP 重定向。
10. **处理响应:**  接收和处理来自服务器的响应头和响应体。
11. **错误处理:**  能够处理网络请求过程中发生的错误。
12. **优先级管理:**  可以设置和修改请求的优先级。
13. **冻结/解冻请求:**  支持在特定状态下冻结和解冻请求，这可能与页面生命周期管理有关。
14. **与 `BackgroundResponseProcessor` 协同:**  可以与 `BackgroundResponseProcessor` 协同工作，对响应体进行后台处理。
15. **指标收集:**  使用 UMA 宏记录后台资源获取的支持状态。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`BackgroundURLLoader` 的功能直接关系到 JavaScript, HTML 和 CSS 的加载和使用：

* **JavaScript:** 当 JavaScript 代码发起一个网络请求 (例如使用 `fetch()` 或 `XMLHttpRequest`) 来获取数据或脚本时，`BackgroundURLLoader` 可以在后台处理这些请求，避免阻塞用户界面的交互。例如，一个网页可以使用 JavaScript 在后台加载新的数据，然后在不刷新页面的情况下更新页面内容。
* **HTML:** HTML 中的 `<img>` 标签、`<link>` 标签 (用于加载 CSS) 和 `<script>` 标签都可能触发网络请求。`BackgroundURLLoader` 可以用于预加载这些资源，提高页面加载速度。例如，当用户访问一个包含大量图片的网页时，浏览器可以在后台并行加载这些图片，使得用户可以更快地看到网页内容。
* **CSS:**  与 HTML 的 `<link>` 标签类似，CSS 文件本身也需要通过网络加载。`BackgroundURLLoader` 可以确保 CSS 文件在后台被高效加载，以便浏览器能够快速渲染页面的样式。

**逻辑推理及假设输入与输出:**

假设输入一个 `network::ResourceRequest` 对象，请求一个 CSS 文件：

* **假设输入:**
    * `request->url`:  `https://example.com/style.css`
    * `request->method`: `GET`
    * `options.synchronous_policy`:  非 `kRequestSynchronously`
    * `request.keepalive`: `false`
* **逻辑推理:**
    1. `CanHandleRequestInternal` 会检查请求是否满足后台加载的条件（GET 方法，HTTP(S) 协议等）。
    2. 如果满足条件，`BackgroundURLLoader` 会创建一个 `Context` 对象来处理这个请求。
    3. `Context::StartOnBackground` 会在后台线程发起网络请求。
    4. 当接收到响应时，`Context` 会通过 `ResourceRequestClient` 的回调方法接收响应头和响应体。
    5. 最终，`URLLoaderClient` 的回调方法 (例如 `DidReceiveResponse`, `DidFinishLoading`) 会在主线程被调用，将响应数据传递给调用者。
* **假设输出:**
    * `URLLoaderClient::DidReceiveResponse` 被调用，参数包含 CSS 文件的响应头。
    * `URLLoaderClient::DidFinishLoading` 被调用，表示 CSS 文件加载完成。

**用户或编程常见的使用错误及举例说明:**

1. **尝试同步加载:** 用户可能错误地设置了 `ResourceLoaderOptions::synchronous_policy` 为 `kRequestSynchronously`，导致 `CanHandleRequest` 返回 `false`，因为 `BackgroundURLLoader` 不支持同步请求。
   ```c++
   ResourceLoaderOptions options;
   options.synchronous_policy = kRequestSynchronously;
   // ... 使用 BackgroundURLLoader 发起请求，将会失败或使用其他 Loader
   ```
2. **发起非 GET 请求:**  如果尝试使用 `BackgroundURLLoader` 发起 `POST` 或其他非 `GET` 方法的请求，`CanHandleRequestInternal` 会返回 `kUnsupportedNonGetRequest`。
   ```c++
   network::ResourceRequest request;
   request.method = net::HttpRequestHeaders::kPostMethod;
   // ... 使用 BackgroundURLLoader 发起请求，将会失败或使用其他 Loader
   ```
3. **使用不支持的协议:**  如果请求的 URL 使用了非 HTTP(S) 或 Blob 协议（例如 `ftp://`），`CanHandleRequestInternal` 会返回 `kUnsupportedNonHttpUrlRequest`。
   ```c++
   network::ResourceRequest request;
   request.url = GURL("ftp://example.com/file.txt");
   // ... 使用 BackgroundURLLoader 发起请求，将会失败或使用其他 Loader
   ```
4. **没有正确处理回调:**  用户需要在 `URLLoaderClient` 中实现相应的回调方法来处理请求的响应、错误和进度，如果未正确实现或处理这些回调，可能会导致程序行为异常或数据丢失。

总结来说，`BackgroundURLLoader` 是 Chromium Blink 引擎中一个重要的组件，负责在后台异步加载网络资源，从而提高 Web 页面的加载速度和用户体验。它与 JavaScript, HTML 和 CSS 的资源加载密切相关，并在引擎内部与多种机制（如缓存、节流器）集成。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/background_url_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/background_url_loader.h"

#include <atomic>
#include <cstdint>
#include <memory>

#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/checked_math.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/common/loader/background_resource_fetch_histograms.h"
#include "third_party/blink/public/common/loader/mime_sniffing_throttle.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/navigation/renderer_eviction_reason.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/web_background_resource_fetch_assets.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/platform/back_forward_cache_buffer_limit_tracker.h"
#include "third_party/blink/renderer/platform/loader/fetch/back_forward_cache_loader_helper.h"
#include "third_party/blink/renderer/platform/loader/fetch/background_code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/background_response_processor.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace {

using FollowRedirectCallback =
    base::OnceCallback<void(std::vector<std::string> removed_headers,
                            net::HttpRequestHeaders modified_headers)>;

using BodyVariant = blink::BackgroundResponseProcessor::BodyVariant;

}  // namespace

namespace WTF {

template <>
struct CrossThreadCopier<FollowRedirectCallback> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = FollowRedirectCallback;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<url::Origin> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = url::Origin;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<network::mojom::URLResponseHeadPtr> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = network::mojom::URLResponseHeadPtr;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<network::URLLoaderCompletionStatus>
    : public CrossThreadCopierByValuePassThrough<
          network::URLLoaderCompletionStatus> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<net::RedirectInfo>
    : public CrossThreadCopierByValuePassThrough<net::RedirectInfo> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<std::vector<std::string>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = std::vector<std::string>;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<
    std::vector<std::unique_ptr<blink::URLLoaderThrottle>>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = std::vector<std::unique_ptr<blink::URLLoaderThrottle>>;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<std::optional<mojo_base::BigBuffer>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = std::optional<mojo_base::BigBuffer>;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<net::HttpRequestHeaders> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = net::HttpRequestHeaders;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<BodyVariant> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = BodyVariant;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<std::optional<network::URLLoaderCompletionStatus>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = std::optional<network::URLLoaderCompletionStatus>;
  static Type Copy(Type&& value) { return std::move(value); }
};

}  // namespace WTF

namespace blink {

namespace {

BackgroundResourceFetchSupportStatus CanHandleRequestInternal(
    const network::ResourceRequest& request,
    const ResourceLoaderOptions& options,
    bool is_prefech_only_document) {
  if (options.synchronous_policy == kRequestSynchronously) {
    return BackgroundResourceFetchSupportStatus::kUnsupportedSyncRequest;
  }
  // Currently, BackgroundURLLoader only supports GET requests.
  if (request.method != net::HttpRequestHeaders::kGetMethod) {
    return BackgroundResourceFetchSupportStatus::kUnsupportedNonGetRequest;
  }

  // Currently, only supports HTTP family and blob URL because:
  // - PDF plugin is using the mechanism of subresource overrides with
  //   "chrome-extension://" urls. But ChildURLLoaderFactoryBundle::Clone()
  //   can't clone `subresource_overrides_`. So BackgroundURLLoader can't handle
  //   requests from the PDF plugin.
  if (!request.url.SchemeIsHTTPOrHTTPS() && !request.url.SchemeIsBlob()) {
    return BackgroundResourceFetchSupportStatus::kUnsupportedNonHttpUrlRequest;
  }

  // Don't support keepalive request which must be handled aligning with the
  // page lifecycle states. It is difficult to handle in the background thread.
  if (request.keepalive) {
    return BackgroundResourceFetchSupportStatus::kUnsupportedKeepAliveRequest;
  }

  // Currently prerender::NoStatePrefetchHelper doesn't work on the background
  // thread.
  if (is_prefech_only_document) {
    return BackgroundResourceFetchSupportStatus::
        kUnsupportedPrefetchOnlyDocument;
  }

  // TODO(crbug.com/1379780): Determine the range of supported requests.
  return BackgroundResourceFetchSupportStatus::kSupported;
}

}  // namespace

class BackgroundURLLoader::Context
    : public WTF::ThreadSafeRefCounted<BackgroundURLLoader::Context> {
 public:
  Context(scoped_refptr<WebBackgroundResourceFetchAssets>
              background_resource_fetch_context,
          const Vector<String>& cors_exempt_header_list,
          scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
          BackForwardCacheLoaderHelper* back_forward_cache_loader_helper,
          scoped_refptr<BackgroundCodeCacheHost> background_code_cache_host)
      : background_resource_fetch_context_(
            std::move(background_resource_fetch_context)),
        cors_exempt_header_list_(cors_exempt_header_list),
        unfreezable_task_runner_(std::move(unfreezable_task_runner)),
        background_task_runner_(
            background_resource_fetch_context_->GetTaskRunner()),
        back_forward_cache_loader_helper_(
            std::make_unique<WeakPersistent<BackForwardCacheLoaderHelper>>(
                back_forward_cache_loader_helper)),
        background_code_cache_host_(std::move(background_code_cache_host)) {
    DETACH_FROM_SEQUENCE(background_sequence_checker_);
  }

  ~Context() {
    // WeakPersistent must be destructed in the original thread.
    unfreezable_task_runner_->DeleteSoon(
        FROM_HERE, std::move(back_forward_cache_loader_helper_));
  }
  scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner() const {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    return unfreezable_task_runner_;
  }

  void Cancel() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    canceled_ = true;
    client_ = nullptr;
    PostCrossThreadTask(
        *background_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&Context::CancelOnBackground, scoped_refptr(this)));
    {
      base::AutoLock locker(tasks_lock_);
      tasks_.clear();
    }
  }

  void Freeze(LoaderFreezeMode mode) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    if (freeze_mode_ == mode) {
      return;
    }
    freeze_mode_ = mode;
    PostCrossThreadTask(*background_task_runner_, FROM_HERE,
                        CrossThreadBindOnce(&Context::FreezeOnBackground,
                                            scoped_refptr(this), mode));

    if (freeze_mode_ == LoaderFreezeMode::kNone) {
      PostCrossThreadTask(*unfreezable_task_runner_, FROM_HERE,
                          CrossThreadBindOnce(&Context::RunTasksOnMainThread,
                                              scoped_refptr(this)));
    }
  }

  void DidChangePriority(WebURLRequest::Priority new_priority,
                         int intra_priority_value) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    PostCrossThreadTask(
        *background_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&Context::DidChangePriorityOnBackground,
                            scoped_refptr(this), new_priority,
                            intra_priority_value));
  }

  void SetBackgroundResponseProcessorFactory(
      std::unique_ptr<BackgroundResponseProcessorFactory>
          background_response_processor_factory) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    background_response_processor_factory_ =
        std::move(background_response_processor_factory);
  }

  void Start(std::unique_ptr<network::ResourceRequest> request,
             scoped_refptr<const SecurityOrigin> top_frame_origin,
             bool no_mime_sniffing,
             std::unique_ptr<ResourceLoadInfoNotifierWrapper>
                 resource_load_info_notifier_wrapper,
             bool should_use_code_cache_host,
             URLLoaderClient* client) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    url_ = KURL(request->url);
    has_devtools_request_id_ = request->devtools_request_id.has_value();
    client_ = client;

    PostCrossThreadTask(
        *background_task_runner_, FROM_HERE,
        CrossThreadBindOnce(
            &Context::StartOnBackground, scoped_refptr(this),
            std::move(background_resource_fetch_context_), std::move(request),
            top_frame_origin ? top_frame_origin->ToUrlOrigin() : url::Origin(),
            no_mime_sniffing, cors_exempt_header_list_,
            std::move(resource_load_info_notifier_wrapper),
            should_use_code_cache_host,
            std::move(background_response_processor_factory_)));
  }

 private:
  class RequestClient : public ResourceRequestClient,
                        public BackgroundResponseProcessor::Client {
   public:
    explicit RequestClient(
        scoped_refptr<Context> context,
        scoped_refptr<base::SequencedTaskRunner> background_task_runner,
        std::unique_ptr<BackgroundResponseProcessor>
            background_response_processor)
        : context_(std::move(context)),
          background_task_runner_(std::move(background_task_runner)),
          background_response_processor_(
              std::move(background_response_processor)) {
      CHECK(background_task_runner_->RunsTasksInCurrentSequence());
    }
    ~RequestClient() override = default;

    // ResourceRequestClient overrides:
    void OnUploadProgress(uint64_t position, uint64_t size) override {
      // We don't support sending body.
      NOTREACHED();
    }
    void OnReceivedRedirect(
        const net::RedirectInfo& redirect_info,
        network::mojom::URLResponseHeadPtr head,
        FollowRedirectCallback follow_redirect_callback) override {
      CHECK(background_task_runner_->RunsTasksInCurrentSequence());
      // Wrapping `follow_redirect_callback` with base::OnTaskRunnerDeleter to
      // make sure that `follow_redirect_callback` will be destructed in the
      // background thread when `client_->WillFollowRedirect()` returns false
      // in Context::OnReceivedRedirect() or the request is canceled before
      // Context::OnReceivedRedirect() is called in the main thread.
      context_->PostTaskToMainThread(CrossThreadBindOnce(
          &Context::OnReceivedRedirect, context_, redirect_info,
          std::move(head),
          std::unique_ptr<FollowRedirectCallback, base::OnTaskRunnerDeleter>(
              new FollowRedirectCallback(std::move(follow_redirect_callback)),
              base::OnTaskRunnerDeleter(context_->background_task_runner_))));
    }
    void OnReceivedResponse(
        network::mojom::URLResponseHeadPtr head,
        mojo::ScopedDataPipeConsumerHandle body,
        std::optional<mojo_base::BigBuffer> cached_metadata) override {
      CHECK(background_task_runner_->RunsTasksInCurrentSequence());
      if (background_response_processor_) {
        if (background_response_processor_->MaybeStartProcessingResponse(
                head, body, cached_metadata, background_task_runner_, this)) {
          waiting_for_background_response_processor_ = true;
          return;
        }
        background_response_processor_.reset();
      }
      context_->PostTaskToMainThread(CrossThreadBindOnce(
          &Context::OnReceivedResponse, context_, std::move(head),
          std::move(body), std::move(cached_metadata)));
    }
    void OnTransferSizeUpdated(int transfer_size_diff) override {
      CHECK(background_task_runner_->RunsTasksInCurrentSequence());
      if (waiting_for_background_response_processor_) {
        deferred_transfer_size_diff_ =
            base::CheckAdd(deferred_transfer_size_diff_, transfer_size_diff)
                .ValueOrDie();
        return;
      }
      context_->PostTaskToMainThread(CrossThreadBindOnce(
          &Context::OnTransferSizeUpdated, context_, transfer_size_diff));
    }
    void OnCompletedRequest(
        const network::URLLoaderCompletionStatus& status) override {
      CHECK(background_task_runner_->RunsTasksInCurrentSequence());
      if (waiting_for_background_response_processor_) {
        deferred_status_ = status;
        return;
      }
      context_->PostTaskToMainThread(
          CrossThreadBindOnce(&Context::OnCompletedRequest, context_, status));
    }

    // BackgroundResponseProcessor::Client overrides:
    void DidFinishBackgroundResponseProcessor(
        network::mojom::URLResponseHeadPtr head,
        BodyVariant body,
        std::optional<mojo_base::BigBuffer> cached_metadata) override {
      CHECK(background_task_runner_->RunsTasksInCurrentSequence());
      background_response_processor_.reset();
      waiting_for_background_response_processor_ = false;
      if (absl::holds_alternative<SegmentedBuffer>(body)) {
        context_->DidReadDataByBackgroundResponseProcessorOnBackground(
            absl::get<SegmentedBuffer>(body).size());
      }
      context_->PostTaskToMainThread(CrossThreadBindOnce(
          &Context::DidFinishBackgroundResponseProcessor, context_,
          std::move(head), std::move(body), std::move(cached_metadata),
          deferred_transfer_size_diff_, std::move(deferred_status_)));
    }
    void PostTaskToMainThread(CrossThreadOnceClosure task) override {
      context_->PostTaskToMainThread(std::move(task));
    }

   private:
    scoped_refptr<Context> context_;
    const scoped_refptr<base::SequencedTaskRunner> background_task_runner_;
    std::unique_ptr<BackgroundResponseProcessor> background_response_processor_;

    int deferred_transfer_size_diff_ = 0;
    std::optional<network::URLLoaderCompletionStatus> deferred_status_;
    bool waiting_for_background_response_processor_ = false;
    base::WeakPtrFactory<RequestClient> weak_factory_{this};
  };

  void StartOnBackground(scoped_refptr<WebBackgroundResourceFetchAssets>
                             background_resource_fetch_context,
                         std::unique_ptr<network::ResourceRequest> request,
                         const url::Origin& top_frame_origin,
                         bool no_mime_sniffing,
                         const Vector<String>& cors_exempt_header_list,
                         std::unique_ptr<ResourceLoadInfoNotifierWrapper>
                             resource_load_info_notifier_wrapper,
                         bool should_use_code_cache_host,
                         std::unique_ptr<BackgroundResponseProcessorFactory>
                             background_response_processor_factory) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    if (canceled_) {
      // This happens when the request was canceled (eg: window.stop())
      // quickly after starting the request.
      return;
    }

    std::vector<std::unique_ptr<blink::URLLoaderThrottle>> throttles;
    URLLoaderThrottleProvider* throttle_provider =
        background_resource_fetch_context->GetThrottleProvider();
    if (throttle_provider) {
      WebVector<std::unique_ptr<blink::URLLoaderThrottle>> web_throttles =
          throttle_provider->CreateThrottles(
              background_resource_fetch_context->GetLocalFrameToken(),
              *request);
      throttles.reserve(base::checked_cast<wtf_size_t>(web_throttles.size()));
      for (auto& throttle : web_throttles) {
        throttles.push_back(std::move(throttle));
      }
    }

    resource_request_sender_ = std::make_unique<ResourceRequestSender>();
    net::NetworkTrafficAnnotationTag tag =
        FetchUtils::GetTrafficAnnotationTag(*request);
    Platform::Current()->AppendVariationsThrottles(top_frame_origin,
                                                   &throttles);

    uint32_t loader_options = network::mojom::kURLLoadOptionNone;
    if (!no_mime_sniffing) {
      loader_options |= network::mojom::kURLLoadOptionSniffMimeType;
      throttles.push_back(
          std::make_unique<MimeSniffingThrottle>(background_task_runner_));
    }
    request_id_ = resource_request_sender_->SendAsync(
        std::move(request), background_task_runner_, tag, loader_options,
        cors_exempt_header_list,
        base::MakeRefCounted<RequestClient>(
            this, background_task_runner_,
            background_response_processor_factory
                ? std::move(*background_response_processor_factory).Create()
                : nullptr),
        background_resource_fetch_context->GetLoaderFactory(),
        std::move(throttles), std::move(resource_load_info_notifier_wrapper),
        should_use_code_cache_host && background_code_cache_host_
            ? &background_code_cache_host_->GetCodeCacheHost(
                  background_task_runner_)
            : nullptr,
        base::BindOnce(&Context::EvictFromBackForwardCacheOnBackground, this),
        base::BindRepeating(
            &Context::DidBufferLoadWhileInBackForwardCacheOnBackground, this));
  }

  void CancelOnBackground() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    if (request_id_ != -1) {
      resource_request_sender_->Cancel(background_task_runner_);
      resource_request_sender_.reset();
      request_id_ = -1;
    }
  }

  void FreezeOnBackground(LoaderFreezeMode mode) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    if (request_id_ != -1) {
      resource_request_sender_->Freeze(mode);
    }
  }

  void DidChangePriorityOnBackground(WebURLRequest::Priority new_priority,
                                     int intra_priority_value) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    if (request_id_ != -1) {
      net::RequestPriority net_priority =
          WebURLRequest::ConvertToNetPriority(new_priority);
      resource_request_sender_->DidChangePriority(net_priority,
                                                  intra_priority_value);
    }
  }

  void PostTaskToMainThread(CrossThreadOnceClosure task) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    {
      base::AutoLock locker(tasks_lock_);
      tasks_.push_back(std::move(task));
    }
    PostCrossThreadTask(*unfreezable_task_runner_, FROM_HERE,
                        CrossThreadBindOnce(&Context::RunTasksOnMainThread,
                                            scoped_refptr(this)));
  }

  void PostTaskToMainThread(CrossThreadOnceFunction<void(int)> task) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    PostTaskToMainThread(CrossThreadBindOnce(std::move(task), request_id_));
  }

  void RunTasksOnMainThread() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    if (!client_) {
      // The request was canceled.
      base::AutoLock locker(tasks_lock_);
      tasks_.clear();
      return;
    }

    while (freeze_mode_ == LoaderFreezeMode::kNone) {
      CrossThreadOnceFunction<void(void)> task;
      {
        base::AutoLock locker(tasks_lock_);
        if (tasks_.empty()) {
          return;
        }
        if (!client_) {
          tasks_.clear();
          return;
        }
        task = tasks_.TakeFirst();
      }
      std::move(task).Run();
    }
  }

  void OnReceivedRedirect(
      const net::RedirectInfo& redirect_info,
      network::mojom::URLResponseHeadPtr head,
      std::unique_ptr<FollowRedirectCallback, base::OnTaskRunnerDeleter>
          follow_redirect_callback,
      int request_id) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    WebURLResponse response = WebURLResponse::Create(
        url_, *head, has_devtools_request_id_, request_id);
    url_ = KURL(redirect_info.new_url);
    std::vector<std::string> removed_headers;
    net::HttpRequestHeaders modified_headers;
    if (client_->WillFollowRedirect(
            url_, redirect_info.new_site_for_cookies,
            WebString::FromUTF8(redirect_info.new_referrer),
            ReferrerUtils::NetToMojoReferrerPolicy(
                redirect_info.new_referrer_policy),
            WebString::FromUTF8(redirect_info.new_method), response,
            has_devtools_request_id_, &removed_headers, modified_headers,
            redirect_info.insecure_scheme_was_upgraded)) {
      PostCrossThreadTask(
          *background_task_runner_, FROM_HERE,
          CrossThreadBindOnce(std::move(*follow_redirect_callback),
                              std::move(removed_headers),
                              std::move(modified_headers)));
    }
  }
  void OnReceivedResponse(network::mojom::URLResponseHeadPtr head,
                          BodyVariant body,
                          std::optional<mojo_base::BigBuffer> cached_metadata,
                          int request_id) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    WebURLResponse response = WebURLResponse::Create(
        url_, *head, has_devtools_request_id_, request_id);
    client_->DidReceiveResponse(response, std::move(body),
                                std::move(cached_metadata));
  }
  void DidFinishBackgroundResponseProcessor(
      network::mojom::URLResponseHeadPtr head,
      BodyVariant body,
      std::optional<mojo_base::BigBuffer> cached_metadata,
      int deferred_transfer_size_diff,
      std::optional<network::URLLoaderCompletionStatus> deferred_status,
      int request_id) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);

    OnReceivedResponse(std::move(head), std::move(body),
                       std::move(cached_metadata), request_id);
    if (client_ && deferred_transfer_size_diff > 0) {
      OnTransferSizeUpdated(deferred_transfer_size_diff);
    }
    if (client_ && deferred_status) {
      OnCompletedRequest(*deferred_status);
    }
  }
  void OnTransferSizeUpdated(int transfer_size_diff) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    client_->DidReceiveTransferSizeUpdate(transfer_size_diff);
  }
  void OnCompletedRequest(const network::URLLoaderCompletionStatus& status) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    int64_t total_transfer_size = status.encoded_data_length;
    int64_t encoded_body_size = status.encoded_body_length;
    if (status.error_code != net::OK) {
      client_->DidFail(WebURLError::Create(status, url_),
                       status.completion_time, total_transfer_size,
                       encoded_body_size, status.decoded_body_length);
    } else {
      client_->DidFinishLoading(status.completion_time, total_transfer_size,
                                encoded_body_size, status.decoded_body_length);
    }
  }

  void EvictFromBackForwardCacheOnBackground(
      mojom::blink::RendererEvictionReason reason) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    PostCrossThreadTask(*unfreezable_task_runner_, FROM_HERE,
                        CrossThreadBindOnce(&Context::EvictFromBackForwardCache,
                                            scoped_refptr(this), reason));
  }
  void EvictFromBackForwardCache(mojom::blink::RendererEvictionReason reason) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    if (back_forward_cache_loader_helper_ &&
        *back_forward_cache_loader_helper_) {
      (*back_forward_cache_loader_helper_)->EvictFromBackForwardCache(reason);
    }
  }
  void DidBufferLoadWhileInBackForwardCacheOnBackground(size_t num_bytes) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    // Need to update the process wide count in the background thread.
    BackForwardCacheBufferLimitTracker::Get().DidBufferBytes(num_bytes);
    PostCrossThreadTask(
        *unfreezable_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&Context::DidBufferLoadWhileInBackForwardCache,
                            scoped_refptr(this), num_bytes));
  }
  void DidBufferLoadWhileInBackForwardCache(size_t num_bytes) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    if (freeze_mode_ != LoaderFreezeMode::kBufferIncoming) {
      // This happens when the page was restored from BFCache, and
      // Context::Freeze(LoaderFreezeMode::kNone) was called in the main thread,
      // but Context::FreezeOnBackground(LoaderFreezeMode::kNone) was not called
      // in the background thread when MojoURLLoaderClient::BodyBuffer received
      // the data. In that case, we need to decrease the process-wide total
      // byte count tracked by BackForwardCacheBufferLimitTracker because we
      // have updated it in DidBufferLoadWhileInBackForwardCacheOnBackground().
      BackForwardCacheBufferLimitTracker::Get()
          .DidRemoveFrameOrWorkerFromBackForwardCache(num_bytes);
      return;
    }
    if (back_forward_cache_loader_helper_ &&
        *back_forward_cache_loader_helper_) {
      // We updated the process wide count in the background thread, so setting
      // `update_process_wide_count` to false.
      (*back_forward_cache_loader_helper_)
          ->DidBufferLoadWhileInBackForwardCache(
              /*update_process_wide_count=*/false, num_bytes);
    }
  }

  void DidReadDataByBackgroundResponseProcessorOnBackground(
      size_t total_read_size) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(background_sequence_checker_);
    PostCrossThreadTask(
        *unfreezable_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&Context::DidReadDataByBackgroundResponseProcessor,
                            scoped_refptr(this), total_read_size));
  }

  void DidReadDataByBackgroundResponseProcessor(size_t total_read_size) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
    if (freeze_mode_ != LoaderFreezeMode::kBufferIncoming ||
        !back_forward_cache_loader_helper_ ||
        !*back_forward_cache_loader_helper_) {
      return;
    }
    (*back_forward_cache_loader_helper_)
        ->DidBufferLoadWhileInBackForwardCache(
            /*update_process_wide_count=*/true, total_read_size);
    if (!BackForwardCacheBufferLimitTracker::Get()
             .IsUnderPerProcessBufferLimit()) {
      (*back_forward_cache_loader_helper_)
          ->EvictFromBackForwardCache(
              mojom::blink::RendererEvictionReason::kNetworkExceedsBufferLimit);
    }
  }

  scoped_refptr<WebBackgroundResourceFetchAssets>
      background_resource_fetch_context_
          GUARDED_BY_CONTEXT(main_thread_sequence_checker_);

  const Vector<String> cors_exempt_header_list_
      GUARDED_BY_CONTEXT(main_thread_sequence_checker_);

  const scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner_;
  const scoped_refptr<base::SequencedTaskRunner> background_task_runner_;

  std::unique_ptr<WeakPersistent<BackForwardCacheLoaderHelper>>
      back_forward_cache_loader_helper_
          GUARDED_BY_CONTEXT(main_thread_sequence_checker_);

  scoped_refptr<BackgroundCodeCacheHost> background_code_cache_host_
      GUARDED_BY_CONTEXT(background_sequence_checker_);

  Deque<CrossThreadOnceFunction<void(void)>> tasks_ GUARDED_BY(tasks_lock_);
  base::Lock tasks_lock_;

  raw_ptr<URLLoaderClient> client_
      GUARDED_BY_CONTEXT(main_thread_sequence_checker_) = nullptr;
  KURL url_ GUARDED_BY_CONTEXT(main_thread_sequence_checker_);
  bool has_devtools_request_id_
      GUARDED_BY_CONTEXT(main_thread_sequence_checker_) = false;
  LoaderFreezeMode freeze_mode_ GUARDED_BY_CONTEXT(
      main_thread_sequence_checker_) = LoaderFreezeMode::kNone;

  std::unique_ptr<BackgroundResponseProcessorFactory>
      background_response_processor_factory_
          GUARDED_BY_CONTEXT(main_thread_sequence_checker_);

  std::unique_ptr<ResourceRequestSender> resource_request_sender_
      GUARDED_BY_CONTEXT(background_sequence_checker_);
  int request_id_ GUARDED_BY_CONTEXT(background_sequence_checker_) = -1;

  std::atomic<bool> canceled_ = false;
  SEQUENCE_CHECKER(main_thread_sequence_checker_);
  SEQUENCE_CHECKER(background_sequence_checker_);
};

// static
bool BackgroundURLLoader::CanHandleRequest(
    const network::ResourceRequest& request,
    const ResourceLoaderOptions& options,
    bool is_prefech_only_document) {
  CHECK(IsMainThread());
  auto result =
      CanHandleRequestInternal(request, options, is_prefech_only_document);
  base::UmaHistogramEnumeration(
      kBackgroundResourceFetchSupportStatusHistogramName, result);
  return result == BackgroundResourceFetchSupportStatus::kSupported;
}

BackgroundURLLoader::BackgroundURLLoader(
    scoped_refptr<WebBackgroundResourceFetchAssets>
        background_resource_fetch_context,
    const Vector<String>& cors_exempt_header_list,
    scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
    BackForwardCacheLoaderHelper* back_forward_cache_loader_helper,
    scoped_refptr<BackgroundCodeCacheHost> background_code_cache_host)
    : context_(base::MakeRefCounted<Context>(
          std::move(background_resource_fetch_context),
          cors_exempt_header_list,
          std::move(unfreezable_task_runner),
          back_forward_cache_loader_helper,
          std::move(background_code_cache_host))) {
  CHECK(IsMainThread());
}

BackgroundURLLoader::~BackgroundURLLoader() {
  CHECK(IsMainThread());
  context_->Cancel();
}

void BackgroundURLLoader::LoadSynchronously(
    std::unique_ptr<network::ResourceRequest> request,
    scoped_refptr<const SecurityOrigin> top_frame_origin,
    bool download_to_blob,
    bool no_mime_sniffing,
    base::TimeDelta timeout_interval,
    URLLoaderClient* client,
    WebURLResponse& response,
    std::optional<WebURLError>& error,
    scoped_refptr<SharedBuffer>& data,
    int64_t& encoded_data_length,
    uint64_t& encoded_body_length,
    scoped_refptr<BlobDataHandle>& downloaded_blob,
    std::unique_ptr<ResourceLoadInfoNotifierWrap
"""


```