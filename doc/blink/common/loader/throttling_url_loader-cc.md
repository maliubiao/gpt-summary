Response: Let's break down the request and the thought process to generate the comprehensive explanation of `throttling_url_loader.cc`.

**1. Understanding the Core Request:**

The request asks for an explanation of the `ThrottlingURLLoader` class in Chromium's Blink engine, focusing on its functionality and its relationship with web technologies (JavaScript, HTML, CSS). It also asks for examples of logical reasoning (input/output) and common usage errors.

**2. Initial Analysis of the Code:**

The first step is to skim the code and identify key components and patterns. Here's a mental checklist and initial observations:

* **Includes:** Lots of Chromium/Blink specific headers (`third_party/blink`, `base`, `net`, `services/network`). This signals it's a low-level networking component within the browser.
* **`ThrottlingURLLoader` Class:** This is the central element.
* **`URLLoaderThrottle`:**  The name suggests this class *modifies* or *controls* the loading process. The `throttles_` vector confirms this.
* **Delegation:**  The `ForwardingThrottleDelegate` class strongly indicates a delegation pattern, where the `ThrottlingURLLoader` acts as a mediator.
* **Start/Redirect/Response/Complete:** These are common stages in a network request lifecycle, and methods like `Start`, `OnReceiveRedirect`, `OnReceiveResponse`, `OnComplete` suggest the class manages this lifecycle.
* **Deferred Operations:**  The `deferred_stage_` and `deferring_throttles_` members indicate the ability to pause or delay the loading process.
* **Header Manipulation:** Methods like `UpdateRequestHeaders`, `MergeRemovedHeaders`, and the presence of `modified_headers_` and `modified_cors_exempt_headers_` suggest the ability to modify HTTP headers.
* **Metrics/Histograms:** The inclusion of `base/metrics/histogram_functions.h` and usage of `base::UmaHistogramTimes` indicate performance tracking.
* **CORS:** The involvement of `services/network/public/cpp/cors/cors.h` and the handling of CORS-exempt headers point to interaction with Cross-Origin Resource Sharing.
* **"Throttling"**: The name itself implies the primary function is to regulate or control the rate/flow of URL loading.

**3. Deconstructing Functionality:**

Based on the initial analysis, I would start categorizing the functionalities:

* **Core URL Loading Management:** The class orchestrates the creation and management of a `network::mojom::URLLoader`.
* **Throttle Integration:** The primary purpose seems to be the execution and management of `URLLoaderThrottle` instances. These throttles can inspect and modify the request and response at various stages.
* **Request Modification:**  Throttles can modify request headers (both regular and CORS-exempt), and even the URL itself (for redirects).
* **Response Interception:** Throttles can intercept the response and potentially provide an alternative loader.
* **Deferred Execution:** The class supports deferring the request at different stages, allowing throttles to perform asynchronous operations.
* **Metrics and Logging:** The class records various performance metrics related to throttling.
* **Error Handling:** The class provides mechanisms for canceling requests with specific error codes.
* **Redirect Handling:** The class manages HTTP redirects, including those initiated by throttles.
* **Priority Setting:** The class allows setting the priority of the network request.

**4. Relating to Web Technologies (HTML, CSS, JavaScript):**

This requires thinking about how these technologies interact with network requests:

* **HTML:**  Fetching HTML documents is a core use case. Throttles might be used to optimize HTML loading (e.g., prioritize certain resources).
* **CSS:**  Loading stylesheets is another common network request. Throttles can be used to implement CSS optimizations or security policies.
* **JavaScript:** `fetch()` API calls and `XMLHttpRequest` initiate network requests that pass through this loader. Throttles can be used for custom logic related to these requests (e.g., adding authentication headers).

**5. Generating Examples and Scenarios:**

* **Logical Reasoning (Input/Output):** This requires constructing simple scenarios. A throttle adding a header is a good example. The input is the initial request, and the output is the modified request.
* **User/Programming Errors:**  Thinking about common mistakes when working with network requests and how throttles might be misused is key here. Forgetting to resume a deferred request or adding conflicting headers are good examples.

**6. Structuring the Output:**

Organizing the information logically is crucial for clarity. I decided to structure the explanation as follows:

* **Core Function:** Start with a high-level summary of what the class does.
* **Key Functionalities (Detailed):** Break down the core features into more granular points with explanations and code references where appropriate.
* **Relationship with Web Technologies:**  Provide concrete examples of how the loader interacts with HTML, CSS, and JavaScript.
* **Logical Reasoning Example:**  Demonstrate a simple input/output scenario with a header modification.
* **Common Usage Errors:** Highlight potential pitfalls for developers.

**7. Refining and Adding Detail:**

After the initial draft, I reviewed the code again to ensure accuracy and completeness. I added more specific details, like mentioning the different deferred stages, the role of `ForwardingThrottleDelegate`, and the purpose of various member variables. I also tried to use the same terminology as the code itself.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus on individual methods.
* **Correction:** Realized it's better to group by functionality for better understanding.
* **Initial thought:** Just list the functionalities.
* **Correction:** Added detailed explanations and examples to make it more useful.
* **Initial thought:** The examples could be very complex.
* **Correction:** Simplified the examples to illustrate the core concepts clearly.

By following this structured approach, combining code analysis with an understanding of web technologies and common development practices, I was able to generate a comprehensive and informative explanation of the `ThrottlingURLLoader` class.
`throttling_url_loader.cc` 文件是 Chromium Blink 引擎中 `ThrottlingURLLoader` 类的实现，这个类的主要功能是**在实际执行网络请求之前和之后，通过一系列的 "throttles" (节流器) 来检查和修改请求和响应**。 它的核心作用是在 `network::mojom::URLLoader` 和其客户端之间插入一个中间层，允许在请求的不同阶段执行自定义的逻辑。

**核心功能:**

1. **请求和响应的拦截和修改:** `ThrottlingURLLoader` 允许注册多个 `URLLoaderThrottle` 对象。在请求发起、重定向、接收响应和完成等各个阶段，它会依次调用这些 throttle 的方法，允许它们：
    * 修改请求的 URL、方法、Headers 等。
    * 延迟请求的执行。
    * 取消请求。
    * 修改响应头。
    * 拦截响应并提供自定义的 `URLLoader` 和 `URLLoaderClient`。

2. **管理 Throttle 的生命周期:** `ThrottlingURLLoader` 负责创建和管理 `URLLoaderThrottle` 实例，并确保在合适的时机调用它们的方法。

3. **处理请求的不同阶段:** 它实现了 `network::mojom::URLLoaderClient` 接口，接收来自底层网络栈的事件（例如重定向、接收到响应、上传进度、传输大小更新、完成等），并在这些事件发生时通知相关的 throttle。

4. **支持请求的延迟和恢复:**  Throttle 可以选择延迟请求的继续执行。`ThrottlingURLLoader` 维护一个延迟的 throttle 列表，并在所有延迟的 throttle 都指示可以继续时，再恢复请求。

5. **支持请求的取消:**  Throttle 可以选择取消请求，并提供错误代码和自定义原因。

6. **记录性能指标:**  代码中使用了 `base::UmaHistogramTimes` 等函数，用于记录各个阶段的耗时，例如 throttle 的执行时间、延迟时间等，用于性能分析。

7. **处理 CORS 豁免头:**  代码中涉及到 `cors_exempt_header_list` 和 `modified_cors_exempt_headers_`，说明 `ThrottlingURLLoader` 能够处理 CORS 相关的逻辑，允许 throttle 添加或修改被浏览器认为是 CORS 豁免的头。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ThrottlingURLLoader` 本身并不直接解析 JavaScript, HTML 或 CSS 代码。 然而，它在加载这些资源的过程中起着关键的作用，因为它控制着网络请求的生命周期。

* **JavaScript:**
    * **示例:** 当 JavaScript 代码使用 `fetch()` API 发起网络请求时，这个请求会经过 `ThrottlingURLLoader`。 一个 throttle 可以用来添加身份验证头（例如 `Authorization`），或者根据某些条件阻止特定的 JavaScript 文件被加载。
        * **假设输入:** JavaScript 代码执行 `fetch('/api/data')`。
        * **Throttle 的逻辑:** 检查请求的 URL 是否以 `/api/` 开头。如果是，则添加 `Authorization: Bearer <token>` 头。
        * **输出:** 实际发送的网络请求包含 `Authorization` 头。
    * **用户/编程常见的使用错误:**  如果一个 throttle 错误地阻止了所有 JavaScript 文件的加载，会导致网页功能完全失效。例如，一个开发者可能写了一个 throttle，本意是阻止某些第三方脚本，但不小心匹配了所有的 `.js` 文件。

* **HTML:**
    * **示例:** 当浏览器加载 HTML 文件时，`ThrottlingURLLoader` 会处理对 HTML 文件的请求。一个 throttle 可以用来注入一些元数据到 HTML 响应头中，或者根据用户代理阻止某些 HTML 文件被加载。
        * **假设输入:** 浏览器请求 `index.html`。
        * **Throttle 的逻辑:** 检查响应头，如果响应状态码是 200 OK，则添加一个自定义的响应头 `X-Custom-Header: processed-by-throttle`。
        * **输出:** 浏览器接收到的响应头包含 `X-Custom-Header: processed-by-throttle`。
    * **用户/编程常见的使用错误:**  如果一个 throttle 修改了 HTML 文件的内容（虽然这个类本身不直接修改内容，但 throttle 可以拦截并替换），可能会破坏页面的结构或功能。 例如，一个 throttle 尝试移除所有的 `<script>` 标签，但这会导致页面上的 JavaScript 代码无法执行。

* **CSS:**
    * **示例:** 当浏览器加载 CSS 文件时，`ThrottlingURLLoader` 同样会参与。一个 throttle 可以用来修改 CSS 文件的缓存策略，或者根据来源阻止某些 CSS 文件被加载，以增强安全性。
        * **假设输入:** 浏览器请求 `styles.css`。
        * **Throttle 的逻辑:**  检查请求的来源，如果是来自一个特定的域名，则设置 `Cache-Control: max-age=3600` 响应头。
        * **输出:**  如果满足条件，服务器返回的响应头会包含 `Cache-Control: max-age=3600`。
    * **用户/编程常见的使用错误:** 如果一个 throttle 错误地阻止了所有 CSS 文件的加载，会导致网页样式丢失，变得难以阅读。 例如，一个开发者编写了一个 throttle 来阻止某些广告相关的 CSS 文件，但不小心匹配了所有 `.css` 文件。

**逻辑推理的假设输入与输出:**

以下是一个关于请求头修改的逻辑推理示例：

**假设输入:**

1. **初始请求头:**
   ```
   GET /resource HTTP/1.1
   User-Agent: Chrome
   Accept-Language: en-US,en;q=0.9
   ```

2. **Throttle 的逻辑:** 有一个 throttle 被配置为移除 `Accept-Language` 头，并添加一个自定义头 `X-Custom-Version: 1.0`。

**输出:**

实际发送的网络请求头将会是：

```
GET /resource HTTP/1.1
User-Agent: Chrome
X-Custom-Version: 1.0
```

**用户或编程常见的使用错误举例说明:**

1. **忘记调用 `Resume()` 导致请求被无限期延迟:**  如果一个 throttle 在 `WillStartRequest` 或其他阶段调用了 delegate 的 `Defer()` 方法来延迟请求，但忘记在稍后调用 `Resume()`，会导致请求一直处于挂起状态，页面无法加载。

2. **在多个 throttle 中修改相同的请求头导致冲突:** 如果多个 throttle 尝试修改同一个请求头，可能会导致意想不到的结果。例如，一个 throttle 设置了 `Authorization` 头，而另一个 throttle 又尝试覆盖它，最终生效的头取决于 throttle 的执行顺序。

3. **在不应该修改请求头的时候修改:**  某些请求头是被浏览器控制的，throttle 不应该尝试修改它们。例如，修改 `Host` 头可能会导致安全问题。

4. **错误地判断是否需要延迟请求:**  Throttle 的逻辑如果过于复杂或者存在错误，可能会导致不必要的延迟，影响页面加载性能。

5. **在重定向过程中修改了不应该修改的头:**  某些头在重定向过程中有特殊的含义，不恰当的修改可能会导致重定向失败。

总而言之，`throttling_url_loader.cc` 中实现的 `ThrottlingURLLoader` 提供了一个强大的机制来在网络请求的不同阶段插入自定义的逻辑，这对于实现各种功能（例如安全策略、性能优化、实验性特性等）非常有用。然而，不当的使用 throttle 也可能导致各种问题，因此需要谨慎地设计和实现 throttle 的逻辑。

### 提示词
```
这是目录为blink/common/loader/throttling_url_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/loader/throttling_url_loader.h"

#include <string_view>
#include <vector>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/strings/strcat.h"
#include "base/strings/stringprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/timer/elapsed_timer.h"
#include "base/trace_event/trace_event.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/redirect_util.h"
#include "services/network/public/cpp/cors/cors.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/record_ontransfersizeupdate_utils.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"

namespace blink {

namespace {

void RemoveModifiedHeadersBeforeMerge(
    net::HttpRequestHeaders* modified_headers) {
  DCHECK(modified_headers);
  modified_headers->RemoveHeader(net::HttpRequestHeaders::kAcceptLanguage);
}

// Merges |removed_headers_B| into |removed_headers_A|.
void MergeRemovedHeaders(std::vector<std::string>* removed_headers_A,
                         const std::vector<std::string>& removed_headers_B) {
  for (auto& header : removed_headers_B) {
    if (!base::Contains(*removed_headers_A, header))
      removed_headers_A->emplace_back(std::move(header));
  }
}

#if DCHECK_IS_ON()
void CheckThrottleWillNotCauseCorsPreflight(
    const std::set<std::string>& initial_headers,
    const std::set<std::string>& initial_cors_exempt_headers,
    const net::HttpRequestHeaders& headers,
    const net::HttpRequestHeaders& cors_exempt_headers,
    const std::vector<std::string> cors_exempt_header_list) {
  // There are many ways for the renderer to cache the list, e.g. for workers,
  // and it might have been cached before the renderer receives a message with
  // the list. This isn't guaranteed because the caching paths aren't triggered
  // by mojo calls that are associated with the method that receives the list.
  // Since the renderer just checks to help catch develper bugs, if the list
  // isn't received don't DCHECK. Most of the time it will which is all we need
  // on bots.
  if (cors_exempt_header_list.empty())
    return;

  base::flat_set<std::string> cors_exempt_header_flat_set(
      cors_exempt_header_list);
  for (auto& header : headers.GetHeaderVector()) {
    if (!base::Contains(initial_headers, header.key) &&
        !network::cors::IsCorsSafelistedHeader(header.key, header.value)) {
      bool is_cors_exempt = cors_exempt_header_flat_set.count(header.key);
      NOTREACHED()
          << "Throttle added cors unsafe header " << header.key
          << (is_cors_exempt
                  ? " . Header is cors exempt so should have "
                    "been added to RequestHeaders::cors_exempt_headers "
                    "instead of "
                    "of RequestHeaders::cors_exempt_headers."
                  : "");
    }
  }

  for (auto& header : cors_exempt_headers.GetHeaderVector()) {
    if (cors_exempt_header_flat_set.count(header.key) == 0 &&
        !base::Contains(initial_cors_exempt_headers, header.key)) {
      NOTREACHED()
          << "Throttle added cors exempt header " << header.key
          << " but it wasn't configured as cors exempt by the browser. See "
             "content::StoragePartitionImpl::InitNetworkContext() and "
             "content::ContentBrowserClient::ConfigureNetworkContextParams().";
    }
  }
}
#endif

void RecordHistogram(const std::string& stage,
                     base::Time start,
                     const std::string& metric_type) {
  base::TimeDelta delta = base::Time::Now() - start;
  base::UmaHistogramTimes(
      base::StrCat({"Net.URLLoaderThrottle", metric_type, ".", stage}), delta);
}

void RecordDeferTimeHistogram(const std::string& stage,
                              base::Time start,
                              const char* throttle_name) {
  constexpr char kMetricType[] = "DeferTime";
  RecordHistogram(stage, start, kMetricType);
  if (throttle_name != nullptr) {
    RecordHistogram(base::StrCat({stage, ".", throttle_name}), start,
                    kMetricType);
  }
}

void RecordExecutionTimeHistogram(const std::string& stage, base::Time start) {
  RecordHistogram(stage, start, "ExecutionTime");
}

}  // namespace

const char ThrottlingURLLoader::kFollowRedirectReason[] = "FollowRedirect";

class ThrottlingURLLoader::ForwardingThrottleDelegate
    : public URLLoaderThrottle::Delegate {
 public:
  ForwardingThrottleDelegate(ThrottlingURLLoader* loader,
                             URLLoaderThrottle* throttle)
      : loader_(loader), throttle_(throttle) {}
  ForwardingThrottleDelegate(const ForwardingThrottleDelegate&) = delete;
  ForwardingThrottleDelegate& operator=(const ForwardingThrottleDelegate&) =
      delete;
  ~ForwardingThrottleDelegate() override = default;

  // URLLoaderThrottle::Delegate:
  void CancelWithError(int error_code,
                       std::string_view custom_reason) override {
    CancelWithExtendedError(error_code, 0, custom_reason);
  }

  void CancelWithExtendedError(int error_code,
                               int extended_reason_code,
                               std::string_view custom_reason) override {
    if (!loader_)
      return;

    ScopedDelegateCall scoped_delegate_call(this);
    loader_->CancelWithExtendedError(error_code, extended_reason_code,
                                     custom_reason);
  }

  void Resume() override {
    if (!loader_)
      return;

    ScopedDelegateCall scoped_delegate_call(this);
    loader_->StopDeferringForThrottle(throttle_);
  }

  void UpdateDeferredResponseHead(
      network::mojom::URLResponseHeadPtr new_response_head,
      mojo::ScopedDataPipeConsumerHandle body) override {
    if (!loader_)
      return;
    ScopedDelegateCall scoped_delegate_call(this);
    loader_->UpdateDeferredResponseHead(std::move(new_response_head),
                                        std::move(body));
  }

  void InterceptResponse(
      mojo::PendingRemote<network::mojom::URLLoader> new_loader,
      mojo::PendingReceiver<network::mojom::URLLoaderClient>
          new_client_receiver,
      mojo::PendingRemote<network::mojom::URLLoader>* original_loader,
      mojo::PendingReceiver<network::mojom::URLLoaderClient>*
          original_client_receiver,
      mojo::ScopedDataPipeConsumerHandle* body) override {
    if (!loader_)
      return;

    ScopedDelegateCall scoped_delegate_call(this);
    loader_->InterceptResponse(std::move(new_loader),
                               std::move(new_client_receiver), original_loader,
                               original_client_receiver, body);
  }

  void Detach() { loader_ = nullptr; }

  void DidRestartForCriticalClientHint() override {
    loader_->DidRestartForCriticalClientHint();
  }

 private:
  // This class helps ThrottlingURLLoader to keep track of whether it is being
  // called by its throttles.
  // If ThrottlingURLLoader is destoyed while any of the throttles is calling
  // into it, it delays destruction of the throttles. That way throttles don't
  // need to worry about any delegate calls may destory them synchronously.
  class ScopedDelegateCall {
   public:
    explicit ScopedDelegateCall(ForwardingThrottleDelegate* owner)
        : owner_(owner) {
      DCHECK(owner_->loader_);

      owner_->loader_->inside_delegate_calls_++;
    }

    ScopedDelegateCall(const ScopedDelegateCall&) = delete;
    ScopedDelegateCall& operator=(const ScopedDelegateCall&) = delete;

    ~ScopedDelegateCall() {
      // The loader may have been detached and destroyed.
      if (owner_->loader_)
        owner_->loader_->inside_delegate_calls_--;
    }

   private:
    const raw_ptr<ForwardingThrottleDelegate> owner_;
  };

  raw_ptr<ThrottlingURLLoader, DanglingUntriaged> loader_;
  const raw_ptr<URLLoaderThrottle> throttle_;
};

ThrottlingURLLoader::StartInfo::StartInfo(
    scoped_refptr<network::SharedURLLoaderFactory> in_url_loader_factory,
    int32_t in_request_id,
    uint32_t in_options,
    network::ResourceRequest* in_url_request,
    scoped_refptr<base::SequencedTaskRunner> in_task_runner,
    std::optional<std::vector<std::string>> in_cors_exempt_header_list)
    : url_loader_factory(std::move(in_url_loader_factory)),
      request_id(in_request_id),
      options(in_options),
      url_request(*in_url_request),
      task_runner(std::move(in_task_runner)) {
  cors_exempt_header_list = std::move(in_cors_exempt_header_list);
}

ThrottlingURLLoader::StartInfo::~StartInfo() = default;

ThrottlingURLLoader::ResponseInfo::ResponseInfo(
    network::mojom::URLResponseHeadPtr in_response_head)
    : response_head(std::move(in_response_head)) {}

ThrottlingURLLoader::ResponseInfo::~ResponseInfo() = default;

ThrottlingURLLoader::RedirectInfo::RedirectInfo(
    const net::RedirectInfo& in_redirect_info,
    network::mojom::URLResponseHeadPtr in_response_head)
    : redirect_info(in_redirect_info),
      response_head(std::move(in_response_head)) {}

ThrottlingURLLoader::RedirectInfo::~RedirectInfo() = default;

ThrottlingURLLoader::PriorityInfo::PriorityInfo(
    net::RequestPriority in_priority,
    int32_t in_intra_priority_value)
    : priority(in_priority), intra_priority_value(in_intra_priority_value) {}

// static
std::unique_ptr<ThrottlingURLLoader> ThrottlingURLLoader::CreateLoaderAndStart(
    scoped_refptr<network::SharedURLLoaderFactory> factory,
    std::vector<std::unique_ptr<URLLoaderThrottle>> throttles,
    int32_t request_id,
    uint32_t options,
    network::ResourceRequest* url_request,
    network::mojom::URLLoaderClient* client,
    const net::NetworkTrafficAnnotationTag& traffic_annotation,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    std::optional<std::vector<std::string>> cors_exempt_header_list,
    ClientReceiverDelegate* client_receiver_delegate) {
  DCHECK(url_request);
  std::unique_ptr<ThrottlingURLLoader> loader(
      new ThrottlingURLLoader(std::move(throttles), client, traffic_annotation,
                              client_receiver_delegate));
  loader->Start(std::move(factory), request_id, options, url_request,
                std::move(task_runner), std::move(cors_exempt_header_list));
  return loader;
}

ThrottlingURLLoader::~ThrottlingURLLoader() {
  TRACE_EVENT_WITH_FLOW0("loading", "ThrottlingURLLoader::~ThrottlingURLLoader",
                         TRACE_ID_LOCAL(this), TRACE_EVENT_FLAG_FLOW_IN);
  if (inside_delegate_calls_ > 0) {
    // A throttle is calling into this object. In this case, delay destruction
    // of the throttles, so that throttles don't need to worry about any
    // delegate calls may destroy them synchronously.
    for (auto& entry : throttles_)
      entry.delegate->Detach();

    auto throttles =
        std::make_unique<std::vector<ThrottleEntry>>(std::move(throttles_));
    base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(
        FROM_HERE, std::move(throttles));
  }
}

void ThrottlingURLLoader::FollowRedirectForcingRestart() {
  url_loader_.ResetWithReason(
      network::mojom::URLLoader::kClientDisconnectReason,
      kFollowRedirectReason);
  client_receiver_.reset();
  CHECK(throttle_will_redirect_redirect_url_.is_empty());

  UpdateRequestHeaders(start_info_->url_request);

  removed_headers_.clear();
  modified_headers_.Clear();
  modified_cors_exempt_headers_.Clear();

  StartNow();
}

void ThrottlingURLLoader::ResetForFollowRedirect(
    network::ResourceRequest& resource_request,
    const std::vector<std::string>& removed_headers,
    const net::HttpRequestHeaders& modified_headers,
    const net::HttpRequestHeaders& modified_cors_exempt_headers) {
  MergeRemovedHeaders(&removed_headers_, removed_headers);
  RemoveModifiedHeadersBeforeMerge(&modified_headers_);
  modified_headers_.MergeFrom(modified_headers);
  modified_cors_exempt_headers_.MergeFrom(modified_cors_exempt_headers);
  // Call UpdateRequestHeaders() after headers are merged.
  UpdateRequestHeaders(resource_request);

  url_loader_.ResetWithReason(
      network::mojom::URLLoader::kClientDisconnectReason,
      kFollowRedirectReason);
}

void ThrottlingURLLoader::RestartWithFactory(
    scoped_refptr<network::SharedURLLoaderFactory> factory,
    uint32_t url_loader_options) {
  DCHECK_EQ(DEFERRED_NONE, deferred_stage_);
  DCHECK(!loader_completed_);
  url_loader_.reset();
  client_receiver_.reset();
  start_info_->url_loader_factory = std::move(factory);
  start_info_->options = url_loader_options;
  body_.reset();
  cached_metadata_.reset();
  StartNow();
}

void ThrottlingURLLoader::FollowRedirect(
    const std::vector<std::string>& removed_headers,
    const net::HttpRequestHeaders& modified_headers,
    const net::HttpRequestHeaders& modified_cors_exempt_headers) {
  MergeRemovedHeaders(&removed_headers_, removed_headers);
  RemoveModifiedHeadersBeforeMerge(&modified_headers_);
  modified_headers_.MergeFrom(modified_headers);
  modified_cors_exempt_headers_.MergeFrom(modified_cors_exempt_headers);

  if (!throttle_will_start_redirect_url_.is_empty()) {
    throttle_will_start_redirect_url_ = GURL();
    // This is a synthesized redirect, so no need to tell the URLLoader.
    UpdateRequestHeaders(start_info_->url_request);
    StartNow();
    return;
  }

  if (url_loader_) {
    std::optional<GURL> new_url;
    if (!throttle_will_redirect_redirect_url_.is_empty())
      new_url = throttle_will_redirect_redirect_url_;
    url_loader_->FollowRedirect(removed_headers_, modified_headers_,
                                modified_cors_exempt_headers_, new_url);
    throttle_will_redirect_redirect_url_ = GURL();
  }

  removed_headers_.clear();
  modified_headers_.Clear();
  modified_cors_exempt_headers_.Clear();
}

void ThrottlingURLLoader::SetPriority(net::RequestPriority priority,
                                      int32_t intra_priority_value) {
  if (!url_loader_) {
    if (!loader_completed_) {
      // Only check |deferred_stage_| if this resource has not been redirected
      // by a throttle.
      if (throttle_will_start_redirect_url_.is_empty() &&
          throttle_will_redirect_redirect_url_.is_empty()) {
        DCHECK_EQ(DEFERRED_START, deferred_stage_);
      }

      priority_info_ =
          std::make_unique<PriorityInfo>(priority, intra_priority_value);
    }
    return;
  }

  url_loader_->SetPriority(priority, intra_priority_value);
}

network::mojom::URLLoaderClientEndpointsPtr ThrottlingURLLoader::Unbind() {
  return network::mojom::URLLoaderClientEndpoints::New(
      url_loader_.Unbind(), client_receiver_.Unbind());
}

ThrottlingURLLoader::ThrottlingURLLoader(
    std::vector<std::unique_ptr<URLLoaderThrottle>> throttles,
    network::mojom::URLLoaderClient* client,
    const net::NetworkTrafficAnnotationTag& traffic_annotation,
    ClientReceiverDelegate* client_receiver_delegate)
    : forwarding_client_(client),
      client_receiver_delegate_(std::move(client_receiver_delegate)),
      traffic_annotation_(traffic_annotation) {
  TRACE_EVENT_WITH_FLOW0("loading", "ThrottlingURLLoader::ThrottlingURLLoader",
                         TRACE_ID_LOCAL(this), TRACE_EVENT_FLAG_FLOW_OUT);
  throttles_.reserve(throttles.size());
  for (auto& throttle : throttles)
    throttles_.emplace_back(this, std::move(throttle));
}

void ThrottlingURLLoader::Start(
    scoped_refptr<network::SharedURLLoaderFactory> factory,
    int32_t request_id,
    uint32_t options,
    network::ResourceRequest* url_request,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    std::optional<std::vector<std::string>> cors_exempt_header_list) {
  TRACE_EVENT_WITH_FLOW0("loading", "ThrottlingURLLoader::Start",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK_EQ(DEFERRED_NONE, deferred_stage_);
  DCHECK(!loader_completed_);

  bool deferred = false;
  DCHECK(deferring_throttles_.empty());
  if (!throttles_.empty()) {
    original_url_ = url_request->url;
    for (auto& entry : throttles_) {
      auto* throttle = entry.throttle.get();
      bool throttle_deferred = false;

#if DCHECK_IS_ON()
      std::set<std::string> initial_headers, initial_cors_exempt_headers;
      if (cors_exempt_header_list) {
        for (auto& header : url_request->headers.GetHeaderVector())
          initial_headers.insert(header.key);

        for (auto& header : url_request->cors_exempt_headers.GetHeaderVector())
          initial_cors_exempt_headers.insert(header.key);
      }
#endif

      base::Time start = base::Time::Now();
      throttle->WillStartRequest(url_request, &throttle_deferred);
      RecordExecutionTimeHistogram(GetStageNameForHistogram(DEFERRED_START),
                                   start);

#if DCHECK_IS_ON()
      if (cors_exempt_header_list) {
        CheckThrottleWillNotCauseCorsPreflight(
            initial_headers, initial_cors_exempt_headers, url_request->headers,
            url_request->cors_exempt_headers, *cors_exempt_header_list);
      }
#endif

      if (original_url_ != url_request->url) {
        DCHECK(throttle_will_start_redirect_url_.is_empty())
            << "ThrottlingURLLoader doesn't support multiple throttles "
               "changing the URL.";
        if (original_url_.SchemeIsHTTPOrHTTPS() &&
            !url_request->url.SchemeIsHTTPOrHTTPS()) {
          NOTREACHED() << "A URLLoaderThrottle can't redirect from http(s) to "
                       << "a non http(s) scheme.";
        } else {
          throttle_will_start_redirect_url_ = url_request->url;
        }
        // Restore the original URL so that all throttles see the same original
        // URL.
        url_request->url = original_url_;
      }
      if (!HandleThrottleResult(throttle, throttle_deferred, &deferred))
        return;
    }
  }

  start_info_ = std::make_unique<StartInfo>(factory, request_id, options,
                                            url_request, std::move(task_runner),
                                            std::move(cors_exempt_header_list));

  if (deferred)
    deferred_stage_ = DEFERRED_START;
  else
    StartNow();
}

void ThrottlingURLLoader::StartNow() {
  TRACE_EVENT_WITH_FLOW0("loading", "ThrottlingURLLoader::StartNow",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(start_info_);
  if (!throttle_will_start_redirect_url_.is_empty()) {
    auto first_party_url_policy =
        start_info_->url_request.update_first_party_url_on_redirect
            ? net::RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT
            : net::RedirectInfo::FirstPartyURLPolicy::NEVER_CHANGE_URL;

    net::RedirectInfo redirect_info = net::RedirectInfo::ComputeRedirectInfo(
        start_info_->url_request.method, start_info_->url_request.url,
        start_info_->url_request.site_for_cookies, first_party_url_policy,
        start_info_->url_request.referrer_policy,
        start_info_->url_request.referrer.spec(),
        // Use status code 307 to preserve the method, so POST requests work.
        net::HTTP_TEMPORARY_REDIRECT, throttle_will_start_redirect_url_,
        std::nullopt, false, false, false);

    // Set Critical-CH restart info and clear for next redirect.
    redirect_info.critical_ch_restart_time = critical_ch_restart_time_;
    critical_ch_restart_time_ = base::TimeTicks();

    bool should_clear_upload = false;
    net::RedirectUtil::UpdateHttpRequest(
        start_info_->url_request.url, start_info_->url_request.method,
        redirect_info, std::nullopt, std::nullopt,
        &start_info_->url_request.headers, &should_clear_upload);

    if (should_clear_upload) {
      start_info_->url_request.request_body = nullptr;
    }

    // Set the new URL in the ResourceRequest struct so that it is the URL
    // that's requested.
    start_info_->url_request.url = throttle_will_start_redirect_url_;

    auto response_head = network::mojom::URLResponseHead::New();
    std::string header_string = base::StringPrintf(
        "HTTP/1.1 %i Internal Redirect\n"
        "Location: %s",
        net::HTTP_TEMPORARY_REDIRECT,
        throttle_will_start_redirect_url_.spec().c_str());

    response_head->headers = base::MakeRefCounted<net::HttpResponseHeaders>(
        net::HttpUtil::AssembleRawHeaders(header_string));
    response_head->encoded_data_length = header_string.size();
    start_info_->task_runner->PostTask(
        FROM_HERE,
        base::BindOnce(&ThrottlingURLLoader::OnReceiveRedirect,
                       weak_factory_.GetWeakPtr(), std::move(redirect_info),
                       std::move(response_head)));
    return;
  }

  if (start_info_->url_request.keepalive) {
    base::UmaHistogramBoolean("FetchKeepAlive.Renderer.Total.Started", true);
  }
  DCHECK(start_info_->url_loader_factory);
  start_info_->url_loader_factory->CreateLoaderAndStart(
      url_loader_.BindNewPipeAndPassReceiver(start_info_->task_runner),
      start_info_->request_id, start_info_->options, start_info_->url_request,
      client_receiver_.BindNewPipeAndPassRemote(start_info_->task_runner),
      net::MutableNetworkTrafficAnnotationTag(traffic_annotation_));

  // TODO(https://crbug.com/919736): Remove this call.
  client_receiver_.internal_state()->EnableBatchDispatch();

  client_receiver_.set_disconnect_handler(base::BindOnce(
      &ThrottlingURLLoader::OnClientConnectionError, base::Unretained(this)));

  if (priority_info_) {
    auto priority_info = std::move(priority_info_);
    url_loader_->SetPriority(priority_info->priority,
                             priority_info->intra_priority_value);
  }

  // Initialize with the request URL, may be updated when on redirects
  response_url_ = start_info_->url_request.url;
}

void ThrottlingURLLoader::RestartWithURLResetNow() {
  url_loader_.reset();
  client_receiver_.reset();
  throttle_will_start_redirect_url_ = original_url_;
  StartNow();
}

bool ThrottlingURLLoader::HandleThrottleResult(URLLoaderThrottle* throttle,
                                               bool throttle_deferred,
                                               bool* should_defer) {
  DCHECK(!deferring_throttles_.count(throttle));
  if (loader_completed_)
    return false;
  if (throttle_deferred) {
    *should_defer = true;
    deferring_throttles_.insert({throttle, base::Time::Now()});
  }
  return true;
}

void ThrottlingURLLoader::StopDeferringForThrottle(
    URLLoaderThrottle* throttle) {
  auto iter = deferring_throttles_.find(throttle);
  if (iter == deferring_throttles_.end())
    return;

  if (deferred_stage_ != DEFERRED_NONE) {
    const char* name = nullptr;
    if (deferred_stage_ == DEFERRED_START) {
      name = throttle->NameForLoggingWillStartRequest();
    } else if (deferred_stage_ == DEFERRED_RESPONSE) {
      name = throttle->NameForLoggingWillProcessResponse();
    }
    RecordDeferTimeHistogram(GetStageNameForHistogram(deferred_stage_),
                             iter->second, name);
  }
  deferring_throttles_.erase(iter);
  if (deferring_throttles_.empty() && !loader_completed_)
    Resume();
}

void ThrottlingURLLoader::OnReceiveEarlyHints(
    network::mojom::EarlyHintsPtr early_hints) {
  DCHECK_EQ(DEFERRED_NONE, deferred_stage_);
  DCHECK(!loader_completed_);

  forwarding_client_->OnReceiveEarlyHints(std::move(early_hints));
}

void ThrottlingURLLoader::OnReceiveResponse(
    network::mojom::URLResponseHeadPtr response_head,
    mojo::ScopedDataPipeConsumerHandle body,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  DCHECK_EQ(DEFERRED_NONE, deferred_stage_);
  DCHECK(!loader_completed_);
  DCHECK(deferring_throttles_.empty());
  TRACE_EVENT_WITH_FLOW1("loading", "ThrottlingURLLoader::OnReceiveResponse",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "url", response_url_.possibly_invalid_spec());
  if (client_receiver_delegate_) {
    client_receiver_delegate_->OnReceiveResponse(
        std::move(response_head), std::move(body), std::move(cached_metadata));
    return;
  }

  if (start_info_ && start_info_->url_request.keepalive) {
    base::UmaHistogramBoolean("FetchKeepAlive.Renderer.Total.ReceivedResponse",
                              true);
  }
  base::ElapsedTimer timer;
  did_receive_response_ = true;
  body_ = std::move(body);
  cached_metadata_ = std::move(cached_metadata);

  // Dispatch BeforeWillProcessResponse().
  if (!throttles_.empty()) {
    URLLoaderThrottle::RestartWithURLReset has_pending_restart(false);
    for (auto& entry : throttles_) {
      auto* throttle = entry.throttle.get();
      base::Time start = base::Time::Now();
      auto weak_ptr = weak_factory_.GetWeakPtr();
      throttle->BeforeWillProcessResponse(response_url_, *response_head,
                                          &has_pending_restart);
      if (!weak_ptr) {
        return;
      }
      RecordExecutionTimeHistogram("BeforeWillProcessResponse", start);
      if (!HandleThrottleResult(throttle)) {
        return;
      }
    }

    if (has_pending_restart) {
      RestartWithURLResetNow();
      return;
    }
  }

  // Dispatch WillProcessResponse().
  if (!throttles_.empty()) {
    bool deferred = false;
    for (auto& entry : throttles_) {
      auto* throttle = entry.throttle.get();
      bool throttle_deferred = false;
      base::Time start = base::Time::Now();
      auto weak_ptr = weak_factory_.GetWeakPtr();
      throttle->WillProcessResponse(response_url_, response_head.get(),
                                    &throttle_deferred);
      if (!weak_ptr) {
        return;
      }
      RecordExecutionTimeHistogram(GetStageNameForHistogram(DEFERRED_RESPONSE),
                                   start);
      if (!HandleThrottleResult(throttle, throttle_deferred, &deferred))
        return;
    }

    if (deferred) {
      deferred_stage_ = DEFERRED_RESPONSE;
      response_info_ = std::make_unique<ResponseInfo>(std::move(response_head));
      client_receiver_.Pause();
      return;
    }
  }

  forwarding_client_->OnReceiveResponse(
      std::move(response_head), std::move(body_), std::move(cached_metadata_));
  base::UmaHistogramTimes("Net.URLLoaderThrottle.OnReceiveResponseTime",
                          timer.Elapsed());
}

void ThrottlingURLLoader::OnReceiveRedirect(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr response_head) {
  DCHECK_EQ(DEFERRED_NONE, deferred_stage_);
  DCHECK(!loader_completed_);
  DCHECK(deferring_throttles_.empty());
  if (start_info_ && start_info_->url_request.keepalive) {
    base::UmaHistogramBoolean("FetchKeepAlive.Renderer.Total.Redirected", true);
  }

  if (!throttles_.empty()) {
    URLLoaderThrottle::RestartWithURLReset has_pending_restart(false);
    for (auto& entry : throttles_) {
      auto* throttle = entry.throttle.get();
      auto weak_ptr = weak_factory_.GetWeakPtr();
      std::vector<std::string> removed_headers;
      net::HttpRequestHeaders modified_headers;
      net::HttpRequestHeaders modified_cors_exempt_headers;
      net::RedirectInfo redirect_info_copy = redirect_info;
      throttle->BeforeWillRedirectRequest(
          &redirect_info_copy, *response_head, &has_pending_restart,
          &removed_headers, &modified_headers, &modified_cors_exempt_headers);

      if (!weak_ptr)
        return;
    }

    if (has_pending_restart) {
      RestartWithURLResetNow();
      return;
    }

    bool deferred = false;
    for (auto& entry : throttles_) {
      auto* throttle = entry.throttle.get();
      bool throttle_deferred = false;
      auto weak_ptr = weak_factory_.GetWeakPtr();
      std::vector<std::string> removed_headers;
      net::HttpRequestHeaders modified_headers;
      net::HttpRequestHeaders modified_cors_exempt_headers;
      net::RedirectInfo redirect_info_copy = redirect_info;
      base::Time start = base::Time::Now();
      throttle->WillRedirectRequest(
          &redirect_info_copy, *response_head, &throttle_deferred,
          &removed_headers, &modified_headers, &modified_cors_exempt_headers);

      if (!weak_ptr)
        return;

      RecordExecutionTimeHistogram(GetStageNameForHistogram(DEFERRED_REDIRECT),
                                   start);
#if DCHECK_IS_ON()
      if (start_info_->cors_exempt_header_list) {
        CheckThrottleWillNotCauseCorsPreflight(
            std::set<std::string>(), std::set<std::string>(), modified_headers,
            modified_cors_exempt_headers,
            *start_info_->cors_exempt_header_list);
      }
#endif

      if (redirect_info_copy.new_url != redirect_info.new_url) {
        DCHECK(throttle_will_redirect_redirect_url_.is_empty())
            << "ThrottlingURLLoader doesn't support multiple throttles "
               "changing the URL.";
        throttle_will_redirect_redirect_url_ = redirect_info_copy.new_url;
      }

      if (!HandleThrottleResult(throttle, throttle_deferred, &deferred))
        return;

      MergeRemovedHeaders(&removed_headers_, removed_headers);
      RemoveModifiedHeadersBeforeMerge(&modified_headers_);
      modified_headers_.MergeFrom(modified_headers);
      modified_cors_exempt_headers_.MergeFrom(modified_cors_exempt_headers);
    }

    if (deferred) {
      deferred_stage_ = DEFERRED_REDIRECT;
      redirect_info_ = std::make_unique<RedirectInfo>(redirect_info,
                                                      std::move(response_head));
      // |client_receiver_| can be unbound if the redirect came from a
      // throttle.
      if (client_receiver_.is_bound())
        client_receiver_.Pause();
      return;
    }
  }

  // Update the request in case |FollowRedirectForcingRestart()| is called, and
  // needs to use the request updated for the redirect.
  network::ResourceRequest& request = start_info_->url_request;
  request.url = redirect_info.new_url;
  request.method = redirect_info.new_method;
  request.site_for_cookies = redirect_info.new_site_for_cookies;
  request.referrer = GURL(redirect_info.new_referrer);
  request.referrer_policy = redirect_info.new_referrer_policy;
  if (request.trusted_params) {
    request.trusted_params->isolation_info =
        request.trusted_params->isolation_info.CreateForRedirect(
            url::Origin::Create(request.url));
  }

  // TODO(dhausknecht) at this point we do not actually know if we commit to the
  // redirect or if it will be cancelled. FollowRedirect would be a more
  // suitable place to set this URL but there we do not have the data.
  response_url_ = redirect_info.new_url;
  if (client_receiver_delegate_) {
    client_receiver_delegate_->EndReceiveRedirect(redirect_info,
                                                  std::move(response_head));
    return;
  }
  forwarding_client_->OnReceiveRedirect(redirect_info,
                                        std::move(response_head));
}

void ThrottlingURLLoader::OnUploadProgress(
    int64_t current_position,
    int64_t total_size,
    OnUploadProgressCallback ack_callback) {
  DCHECK_EQ(DEFERRED_NONE, deferred_stage_);
  DCHECK(!loader_completed_);

  forwarding_client_->OnUploadProgress(current_position, total_size,
                                       std::move(ack_callback));
}

void ThrottlingURLLoader::OnTransferSizeUpdated(int32_t transfer_size_diff) {
  DCHECK_EQ(DEFERRED_NONE, deferred_stage_);
  DCHECK(!loader_completed_);
  network::RecordOnTransferSizeUpdatedUMA(
      network::OnTransferSizeUpdatedFrom::kThrottlingURLLoader);

  forwarding_client_->OnTransferSizeUpdated(transfer_size_diff);
}

void ThrottlingURLLoader::OnComplete(
    const network::URLLoaderCompletionStatus& status) {
  DCHECK_EQ(DEFERRED_NONE, deferred_stage_);
  DCHECK(!loader_completed_);
  if (client_receiver_delegate_) {
    client_receiver_delegate_->OnComplete(status);
    return;
  }

  // Only dispatch WillOnCompleteWithError() if status is not OK.
  if (!throttles_.empty() && status.error_code != net::OK) {
    for (auto& entry : throttles_) {
      auto* throttle = entry.throttle.get();
      base::Time start = base::Time::Now();
      auto weak_ptr = weak_factory_.GetWeakPtr();
      throttle->WillOnCompleteWithError(status);
      if (!weak_ptr) {
        return;
      }
      RecordExecutionTimeHistogram("WillOnCompleteWithError", start);
      if (!HandleThrottleResult(throttle)) {
        return;
      }
    }
  }

  // This is the last expected message. Pipe closure before this is an error
  // (see OnClientConnectionError). After this it is expected and should be
  // ignored. The owner of |this| is expected to destroy |this| when
  // OnComplete() and all data has been read. Destruction of |this| will
  // destroy |url_loader_| appropriately.
  loader_completed_ = true;
  forwarding_client_->OnComplete(status);
}

void ThrottlingURLLoader::OnClientConnectionError() {
  CancelWithError(net::ERR_ABORTED, "");
}

void ThrottlingURLLoader::CancelWithError(int error_code,
                                          std::string_view custom_reason) {
  CancelWithExtendedError(error_code, 0, custom_reason);
}

void ThrottlingURLLoader::CancelWithExtendedError(
    int error_code,
    int extended_reason_code,
    std::string_view custom_reason) {
  if (loader_completed_)
    return;

  network::URLLoaderCompletionStatus status;
  status.error_code = error_code;
  status.completion_time = base::TimeTicks::Now();
  status.extended_error_code = extended_reason_code;

  deferred_stage_ = DEFERRED_NONE;
  DisconnectClient(custom_reason);
  if (client_receiver_delegate_) {
    client_receiver_delegate_->CancelWithStatus(status);
    return;
  }
  forwarding_client_->OnComplete(status);
}

void ThrottlingURLLoader::Resume() {
  if (loader_completed_ || deferred_stage_ == DEFERRED_NONE)
    return;

  auto prev_deferred_stage = deferred_stage_;
  deferred_stage_ = DEFERRED_NONE;
  switch (prev_deferred_stage) {
    case DEFERRED_START: {
      StartNow();
      break;
    }
    case DEFERRED_REDIRECT: {
      // |client_receiver_| can be unbound if the redirect came from a
      // throttle.
      if (client_receiver_.is_bound())
        client_receiver_.Resume();
      // TODO(dhausknecht) at this point we do not actually know if we commit to
      // the redirect or if it will be cancelled. FollowRedirect would be a more
      // suitable place to set this URL but there we do not have the data.
      response_url_ = redirect_info_->redirect_info.new_url;
      forwarding_client_->OnReceiveRedirect(
          redirect_info_->redirect_info,
          std::move(redirect_info_->response_head));
      // Note: |this| may be deleted here.
      break;
    }
    case DEFERRED_RESPONSE: {
      client_receiver_.Resume();
      forwarding_client_->OnReceiveResponse(
          std::move(response_info_->response_head), std::move(body_),
          std::move(cached_metadata_));
      // Note: |this| may be deleted here.
      break;
    }
    case DEFERRED_NONE:
      NOTREACHED();
  }
}

void ThrottlingURLLoader::SetPriority(net::RequestPriority priority) {
  if (url_loader_)
    url_loader_->SetPriority(priority, -1);
}

void ThrottlingURLLoader::UpdateRequestHeaders(
    network::ResourceRequest& resource_request) {
  for (const std::string& header : removed_headers_) {
    resource_request.headers.RemoveHeader(header);
    resource_request.cors_exempt_headers.RemoveHeader(header);
  }
  resource_request.headers.MergeFrom(modified_headers_);
  resource_request.cors_exempt_headers.MergeFrom(modified_cors_exempt_headers_);
}

void ThrottlingURLLoader::UpdateDeferredResponseHead(
    network::mojom::URLResponseHeadPtr new_response_head,
    mojo::ScopedDataPipeConsumerHandle body) {
  DCHECK(response_info_);
  DCHECK(!body_);
  DCHECK_EQ(DEFERRED_RESPONSE, deferred_stage_);
  response_info_->response_head = std::move(new_response_head);
  body_ = std::move(body);
}

void ThrottlingURLLoader::PauseReadingBodyFromNet() {
  if (url_loader_) {
    url_loader_->PauseReadingBodyFromNet();
  }
}

void ThrottlingURLLoader::ResumeReadingBodyFromNet() {
  if (url_loader_) {
    url_loader_->ResumeReadingBodyFromNet();
  }
}

void ThrottlingURLLoader::InterceptResponse(
    mojo::PendingRemote<network::mojom::URLLoader> new_loader,
    mojo::PendingReceiver<network::mojom::URLLoaderClient> new_client_receiver,
    mojo::PendingRemote<network::mojom::URLLoader>* original_loader,
    mojo::PendingReceiver<network::mojom::URLLoaderClient>*
        original_client_receiver,
    mojo::ScopedDataPipeConsumerHandle* body) {
  response_intercepted_ = true;

  body->swap(body_);
  if (original_loader) {
    url_loader_->ResumeReadingBodyFromNet();
    *original_loader = url_loader_.Unbind();
  }
  url_loader_.Bind(std::move(new_loader));

  if (original_client_receiver)
    *original_client_receiver = client_receiver_.Unbind();
  client_receiver_.Bind(std::move(new_client_receiver),
                        start_info_->task_runner);
  client_receiver_.set_disconnect_handler(base::BindOnce(
      &ThrottlingURLLoader::OnClientConnectionError, base::Unretained(this)));
}

void ThrottlingURLLoader::DisconnectClient(std::string_view custom_reason) {
  client_receiver_.reset();

  if (!custom_reason.empty()) {
    url_loader_.ResetWithReason(
        network::mojom::URLLoader::kClientDisconnectReason,
        std::string(custom_reason));
  } else {
    url_loader_.reset();
  }

  loader_completed_ = true;
}

const char* ThrottlingURLLoader::GetStageNameForHistogram(DeferredStage stage) {
  switch (stage) {
    case DEFERRED_START:
      return "WillStartRequest";
    case DEFERRED_REDIRECT:
      return "WillRedirectRequest";
    case DEFERRED_RESPONSE:
      return "WillProcessResponse";
    case DEFERRED_NONE:
      NOTREACHED();
  }
}

ThrottlingURLLoader::ThrottleEntry::ThrottleEntry(
    ThrottlingURLLoader* loader,
    std::unique_ptr<URLLoaderThrottle> the_throttle)
    : throttle(std::move(the_throttle)),
      delegate(std::make_unique<ForwardingThrottleDelegate>(loader,
                                                            throttle.get())) {
  throttle->set_delegate(delegate.get());
}

ThrottlingURLLoader::ThrottleEntry::ThrottleEntry(ThrottleEntry&& other) =
    default;

ThrottlingURLLoader::ThrottleEntry::~ThrottleEntry() {
  // `delegate` is destroyed before `throttle`; clear the pointer so the
  // throttle cannot inadvertently use-after-free the delegate.
  throttle->set_delegate(nullptr);
}

ThrottlingURLLoader::ThrottleEntry& ThrottlingURLLoader::ThrottleEntry::
operator=(ThrottleEntry&& other) = default;

}  // namespace blink
```