Response:
Let's break down the request and the provided code to formulate the answer.

**1. Understanding the Core Request:**

The main goal is to understand the functionality of the `url_loader.cc` file within the Chromium Blink rendering engine. The request specifically asks to:

* List its functions.
* Explain its relationship to JavaScript, HTML, and CSS.
* Provide examples of logical reasoning with input/output scenarios.
* Identify common user or programming errors related to its use.

**2. Initial Code Analysis (Skimming and Keyword Spotting):**

A quick scan of the code reveals key elements:

* **Includes:** Mentions of network, mojo, blink public APIs, fetch, and platform. This immediately suggests it's involved in network requests within the rendering engine.
* **Classes:**  `URLLoader` and its inner class `Context`. This implies a main class responsible for URL loading and a helper class likely managing the lifecycle and details of individual requests.
* **Key Methods:** `Start`, `Cancel`, `Freeze`, `DidChangePriority`, `LoadSynchronously`, `LoadAsynchronously`. These point to core functionalities of initiating, controlling, and managing network requests.
* **Callbacks:** Methods like `OnUploadProgress`, `OnReceivedRedirect`, `OnReceivedResponse`, `OnCompletedRequest` clearly indicate it interacts with the network layer through callbacks.
* **Data Structures:** Use of `network::ResourceRequest`, `network::mojom::URLResponseHeadPtr`, `mojo::ScopedDataPipeConsumerHandle`, etc., reinforces its role in handling network data.
* **JavaScript/HTML/CSS Clues:**  The presence of `URLLoaderThrottle`, `MimeSniffingThrottle`, and mentions of `WebURLRequest`, `WebURLResponse` strongly link it to the process of fetching web resources, which includes JavaScript, HTML, and CSS.
* **Synchronization:** The existence of `LoadSynchronously` and `base::WaitableEvent` suggests support for synchronous network operations.

**3. Detailed Analysis and Function Categorization:**

Now, let's analyze the functionality more systematically:

* **Core Functionality (URLLoader & Context):**  The central purpose is clearly managing the process of fetching resources from the network. The `URLLoader` acts as the main interface, and the `Context` handles the details of a single request.
* **Request Initialization and Control (`Start`, `Cancel`, `Freeze`, `DidChangePriority`):** These methods manage the lifecycle of a network request. `Start` initiates it, `Cancel` stops it, `Freeze` pauses it (important for background tab behavior, for example), and `DidChangePriority` allows adjusting the request's importance.
* **Synchronous vs. Asynchronous Loading (`LoadSynchronously`, `LoadAsynchronously`):**  The code explicitly handles both modes of network requests. This is crucial for different loading scenarios. Synchronous loading might be used in specific contexts where the result is needed immediately (though generally discouraged on the main thread), while asynchronous loading is the norm for web pages.
* **Network Interaction (Callbacks):** The `ResourceRequestClient` interface and its methods (`OnUploadProgress`, etc.) are the bridge to the underlying network layer. These callbacks receive updates on the progress, redirects, responses, and completion status of the network request.
* **Throttling and Modification (`URLLoaderThrottle`):**  The code uses `URLLoaderThrottle` to intercept and potentially modify network requests. The `MimeSniffingThrottle` is a concrete example, demonstrating the ability to perform actions based on the content type.
* **Integration with Other Blink Components:**  The code interacts with `BackForwardCacheLoaderHelper` (for caching), `Platform` (for platform-specific functionalities), `SecurityOrigin` (for security checks), and likely others.
* **DevTools Integration:**  The `has_devtools_request_id_` flag indicates a connection to the browser's developer tools for network request tracking.

**4. Connecting to JavaScript, HTML, and CSS:**

The connection here is quite direct:

* **HTML:** When the browser parses an HTML document and encounters elements like `<script src="...">`, `<link rel="stylesheet" href="...">`, `<img> src="..."`, etc., the `URLLoader` is involved in fetching these external resources.
* **CSS:**  The loading of external CSS files (via `<link>`) relies on `URLLoader`.
* **JavaScript:**  Fetching external JavaScript files (via `<script src="...">`) is a primary use case for `URLLoader`. `fetch()` API calls in JavaScript also heavily utilize this mechanism internally.

**5. Logical Reasoning (Input/Output Examples):**

Here, I need to create plausible scenarios:

* **Successful Asynchronous Load:** Focus on the flow of callbacks and the final outcome.
* **Redirection:** Demonstrate how `OnReceivedRedirect` and `WillFollowRedirect` interact.
* **Error Scenario:** Show how network errors propagate through the callbacks.

**6. Identifying Common Errors:**

Think about common mistakes developers or the system might make:

* **Cancellation Issues:**  Canceling requests at the wrong time can lead to inconsistencies.
* **Incorrect Usage of Synchronous Loading:** Blocking the main thread.
* **Security-related Errors:** CORS issues are directly handled by this component.
* **Throttle Misconfiguration:** If custom throttles are used.

**7. Structuring the Answer:**

Finally, organize the information logically, starting with a high-level overview, then delving into specific functionalities, connections to web technologies, examples, and error scenarios. Use clear headings and bullet points for readability.

By following these steps, I can construct a comprehensive and accurate answer to the user's request. The process involves understanding the code, identifying its purpose, connecting it to relevant concepts, and providing concrete examples and error scenarios.
好的，让我们来详细分析一下 `blink/renderer/platform/loader/fetch/url_loader/url_loader.cc` 这个文件的功能。

**核心功能：管理和执行URL加载请求**

`URLLoader` 类是 Blink 渲染引擎中负责发起和管理网络请求的核心组件。 它的主要职责是：

1. **接收和处理URL加载请求:**  `URLLoader` 接收来自 Blink 渲染引擎其他部分的请求，这些请求通常是加载 HTML 文档、CSS 样式表、JavaScript 脚本、图片等资源。
2. **构建和配置网络请求:**  基于接收到的请求信息（例如 URL、请求方法、头部信息等），`URLLoader` 会构建一个底层的网络请求对象 (`network::ResourceRequest`)。
3. **应用请求拦截和修改 (Throttling):**  `URLLoader` 支持使用 `URLLoaderThrottle` 接口来拦截和修改网络请求。 这允许在请求发送到网络层之前执行各种操作，例如添加自定义头部、阻止请求、模拟网络条件等。
4. **将请求发送到网络层:**  `URLLoader` 将构建好的网络请求发送到 Chromium 的网络服务 (Network Service)。
5. **处理网络响应:**  当网络服务返回响应时，`URLLoader` 会接收响应头、响应体以及其他相关信息。
6. **处理重定向:**  如果服务器返回重定向响应，`URLLoader` 会根据策略处理重定向，并可能发起新的请求。
7. **MIME 类型嗅探:**  如果需要，`URLLoader` 可以执行 MIME 类型嗅探，以确定资源的内容类型。
8. **错误处理:**  `URLLoader` 负责处理网络请求过程中发生的错误，例如连接错误、超时、HTTP 错误等，并将错误信息传递给请求的发起方。
9. **同步和异步加载:**  `URLLoader` 支持同步和异步两种加载模式。同步加载会阻塞当前线程直到请求完成，而异步加载则不会阻塞。
10. **与 Back/Forward 缓存交互:**  `URLLoader` 与浏览器的 Back/Forward 缓存机制集成，以优化页面导航时的资源加载。
11. **提供加载进度信息:**  `URLLoader` 可以提供上传和下载的进度信息。
12. **支持 Keep-Alive 连接:**  通过 `KeepAliveHandle` 来管理 Keep-Alive 连接，提高网络效率。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`URLLoader` 是 Blink 引擎加载网页资源的关键部分，因此与 JavaScript, HTML, CSS 的功能紧密相关。

* **HTML:**
    * 当浏览器解析 HTML 文档时，遇到 `<img>`, `<link>`, `<script>`, `<iframe>`, `<audio>`, `<video>` 等标签时，如果这些标签引用了外部资源，Blink 引擎会使用 `URLLoader` 来加载这些资源。
    * **例子:**  当 HTML 中包含 `<img src="image.png">` 时，`URLLoader` 会发起一个 GET 请求来获取 `image.png`。
* **CSS:**
    * 当 HTML 文档中包含 `<link rel="stylesheet" href="style.css">` 时，`URLLoader` 会加载 `style.css` 文件，其中包含页面的样式信息。
    * **例子:**  `URLLoader` 会根据 `href` 属性的值，向服务器请求 `style.css` 文件。
* **JavaScript:**
    * 当 HTML 文档中包含 `<script src="script.js"></script>` 时，`URLLoader` 会下载并执行 `script.js` 文件，其中包含了网页的交互逻辑。
    * JavaScript 中的 `fetch()` API 和 `XMLHttpRequest` 对象底层也是使用类似的机制（可能经过不同的封装）来发起网络请求的，最终也可能与 `URLLoader` 或其类似的组件交互。
    * **例子:**  JavaScript 代码中执行 `fetch('data.json')` 会触发一个异步请求，该请求最终由 Blink 的网络加载机制处理，其中就包括了 `URLLoader` 的参与。

**逻辑推理与假设输入输出**

假设我们有一个简单的 HTML 文件 `index.html`:

```html
<!DOCTYPE html>
<html>
<head>
  <title>测试页面</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <img src="image.png">
  <script src="script.js"></script>
</body>
</html>
```

**假设输入:**  Blink 引擎开始加载 `index.html`。

**逻辑推理 (涉及 `URLLoader` 的部分):**

1. **解析 HTML:**  HTML 解析器会识别出 `link` 标签，需要加载 `style.css`。
2. **创建 URLLoader:**  Blink 会创建一个 `URLLoader` 实例来处理加载 `style.css` 的请求。
3. **构建请求:** `URLLoader` 会创建一个 `network::ResourceRequest` 对象，其中包含 `style.css` 的 URL，请求方法为 GET，以及可能的头部信息（如 User-Agent）。
4. **发送请求:** `URLLoader` 将请求发送到网络服务。
5. **接收响应:**  网络服务返回 `style.css` 的内容和响应头。
6. **回调:** `URLLoader` 通过回调 (`OnReceivedResponse`) 将响应数据传递给渲染引擎的其他部分，例如 CSS 解析器。

重复上述步骤，`URLLoader` 还会处理 `image.png` 和 `script.js` 的加载请求。

**假设输出 (针对 `style.css`):**

* **成功加载:**  CSS 解析器接收到 `style.css` 的内容，并将其应用于页面的渲染。
* **加载失败 (例如 404):** `URLLoader` 会通过回调 (`OnCompletedRequest`) 通知渲染引擎加载失败，并提供错误信息。  浏览器开发者工具的网络面板会显示 `style.css` 的请求状态为 404。

**用户或编程常见的使用错误举例**

虽然开发者通常不会直接与 `URLLoader` 交互，但与网络请求相关的常见错误会涉及到 `URLLoader` 的处理流程：

1. **CORS (跨域资源共享) 错误:**
   * **场景:**  JavaScript 代码尝试使用 `fetch` 或 `XMLHttpRequest` 请求一个来自不同域的资源，但服务器没有设置正确的 CORS 头部。
   * **`URLLoader` 的处理:** `URLLoader` 会检查响应头中的 CORS 相关信息，如果发现违规，会阻止 JavaScript 获取响应数据，并报告 CORS 错误。
   * **用户/编程错误:**  前端开发者没有意识到 CORS 限制，或者后端开发者没有正确配置 CORS 头部。
2. **混合内容 (Mixed Content) 错误:**
   * **场景:**  一个 HTTPS 页面尝试加载来自 HTTP 地址的资源（例如图片、脚本、样式表）。
   * **`URLLoader` 的处理:**  出于安全考虑，浏览器通常会阻止或警告加载混合内容。 `URLLoader` 会检测到这种情况并阻止请求（默认行为，可以配置）。
   * **用户/编程错误:**  开发者在 HTTPS 网站中引用了 HTTP 资源。
3. **请求被阻止 (例如通过 Content Security Policy - CSP):**
   * **场景:**  HTML 文档的 CSP 头部禁止加载来自特定来源的脚本。
   * **`URLLoader` 的处理:**  在发送请求之前或接收到响应后，`URLLoader` 会根据 CSP 策略检查请求是否允许。如果违反策略，请求会被阻止。
   * **用户/编程错误:**  开发者设置了过于严格的 CSP 策略，导致必要的资源无法加载。
4. **无限重定向:**
   * **场景:**  服务器配置错误，导致请求在多个 URL 之间无限循环重定向。
   * **`URLLoader` 的处理:**  `URLLoader` 通常会设置重定向次数限制，当达到限制时会停止重定向，并报告错误。
   * **用户/编程错误:**  后端服务器的重定向配置错误。
5. **请求取消 (例如用户导航离开页面):**
   * **场景:**  用户点击链接或关闭标签页，导致当前页面的资源加载被取消。
   * **`URLLoader` 的处理:**  当页面卸载或请求被取消时，`URLLoader` 会停止正在进行的网络请求。
   * **用户行为:** 用户主动取消加载。

总而言之，`blink/renderer/platform/loader/fetch/url_loader/url_loader.cc` 文件中的 `URLLoader` 类是 Blink 渲染引擎中至关重要的网络请求管理中心，它负责着网页上各种资源的加载工作，并与 JavaScript, HTML, CSS 的功能息息相关。 理解其工作原理有助于我们更好地理解浏览器如何获取和渲染网页内容。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/url_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader.h"

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/struct_ptr.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/encoded_body_length.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom-forward.h"
#include "services/network/public/mojom/url_response_head.mojom-forward.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/loader/mime_sniffing_throttle.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/common/loader/url_loader_throttle.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/web_loader_freeze_mode.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/loader/fetch/back_forward_cache_loader_helper.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/background_response_processor.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/sync_load_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

using base::Time;
using base::TimeTicks;

namespace blink {

// Utilities -------------------------------------------------------------------

// This inner class exists since the URLLoader may be deleted while inside a
// call to URLLoaderClient. Refcounting is to keep the context from being
// deleted if it may have work to do after calling into the client.
class URLLoader::Context : public ResourceRequestClient {
 public:
  Context(URLLoader* loader,
          const Vector<String>& cors_exempt_header_list,
          base::WaitableEvent* terminate_sync_load_event,
          scoped_refptr<base::SingleThreadTaskRunner> freezable_task_runner,
          scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
          scoped_refptr<network::SharedURLLoaderFactory> factory,
          mojo::PendingRemote<mojom::blink::KeepAliveHandle> keep_alive_handle,
          BackForwardCacheLoaderHelper* back_forward_cache_loader_helper,
          Vector<std::unique_ptr<URLLoaderThrottle>> throttles);

  int request_id() const { return request_id_; }
  URLLoaderClient* client() const { return client_; }
  void set_client(URLLoaderClient* client) { client_ = client; }

  // Returns a task runner that might be unfreezable.
  // TODO(https://crbug.com/1137682): Rename this to GetTaskRunner instead once
  // we migrate all usage of the freezable task runner to use the (maybe)
  // unfreezable task runner.
  scoped_refptr<base::SingleThreadTaskRunner> GetMaybeUnfreezableTaskRunner();

  void Cancel();
  void Freeze(LoaderFreezeMode mode);
  void DidChangePriority(WebURLRequest::Priority new_priority,
                         int intra_priority_value);
  void Start(std::unique_ptr<network::ResourceRequest> request,
             scoped_refptr<const SecurityOrigin> top_frame_origin,
             bool download_to_blob,
             bool no_mime_sniffing,
             base::TimeDelta timeout_interval,
             SyncLoadResponse* sync_load_response,
             std::unique_ptr<ResourceLoadInfoNotifierWrapper>
                 resource_load_info_notifier_wrapper,
             CodeCacheHost* code_cache_host);

  // ResourceRequestClient overrides:
  void OnUploadProgress(uint64_t position, uint64_t size) override;
  void OnReceivedRedirect(
      const net::RedirectInfo& redirect_info,
      network::mojom::URLResponseHeadPtr head,
      FollowRedirectCallback follow_redirect_callback) override;
  void OnReceivedResponse(
      network::mojom::URLResponseHeadPtr head,
      mojo::ScopedDataPipeConsumerHandle body,
      std::optional<mojo_base::BigBuffer> cached_metadata) override;
  void OnTransferSizeUpdated(int transfer_size_diff) override;
  void OnCompletedRequest(
      const network::URLLoaderCompletionStatus& status) override;

  void SetResourceRequestSenderForTesting(  // IN-TEST
      std::unique_ptr<ResourceRequestSender> resource_request_sender);

 private:
  ~Context() override;

  raw_ptr<URLLoader> loader_;

  KURL url_;
  // This is set in Start() and is used by SetSecurityStyleAndDetails() to
  // determine if security details should be added to the request for DevTools.
  //
  // Additionally, if there is a redirect, WillFollowRedirect() will update this
  // for the new request. InspectorNetworkAgent will have the chance to attach a
  // DevTools request id to that new request, and it will propagate here.
  bool has_devtools_request_id_;

  raw_ptr<URLLoaderClient> client_;
  // TODO(https://crbug.com/1137682): Remove |freezable_task_runner_|, migrating
  // the current usage to use |unfreezable_task_runner_| instead. Also, rename
  // |unfreezable_task_runner_| to |maybe_unfreezable_task_runner_| here and
  // elsewhere, because it's only unfreezable if the kLoadingTasksUnfreezable
  // flag is on, so the name might be misleading (or if we've removed the
  // |freezable_task_runner_|, just rename this to |task_runner_| and note that
  // the task runner might or might not be unfreezable, depending on flags).
  scoped_refptr<base::SingleThreadTaskRunner> freezable_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner_;
  mojo::PendingRemote<mojom::blink::KeepAliveHandle> keep_alive_handle_;
  LoaderFreezeMode freeze_mode_ = LoaderFreezeMode::kNone;
  const Vector<String> cors_exempt_header_list_;
  raw_ptr<base::WaitableEvent> terminate_sync_load_event_;

  int request_id_;

  std::unique_ptr<ResourceRequestSender> resource_request_sender_;

  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory_;

  WeakPersistent<BackForwardCacheLoaderHelper>
      back_forward_cache_loader_helper_;
  Vector<std::unique_ptr<URLLoaderThrottle>> throttles_;
};

// URLLoader::Context -------------------------------------------------------

URLLoader::Context::Context(
    URLLoader* loader,
    const Vector<String>& cors_exempt_header_list,
    base::WaitableEvent* terminate_sync_load_event,
    scoped_refptr<base::SingleThreadTaskRunner> freezable_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
    mojo::PendingRemote<mojom::blink::KeepAliveHandle> keep_alive_handle,
    BackForwardCacheLoaderHelper* back_forward_cache_loader_helper,
    Vector<std::unique_ptr<URLLoaderThrottle>> throttles)
    : loader_(loader),
      has_devtools_request_id_(false),
      client_(nullptr),
      freezable_task_runner_(std::move(freezable_task_runner)),
      unfreezable_task_runner_(std::move(unfreezable_task_runner)),
      keep_alive_handle_(std::move(keep_alive_handle)),
      cors_exempt_header_list_(cors_exempt_header_list),
      terminate_sync_load_event_(terminate_sync_load_event),
      request_id_(-1),
      resource_request_sender_(std::make_unique<ResourceRequestSender>()),
      url_loader_factory_(std::move(url_loader_factory)),
      back_forward_cache_loader_helper_(back_forward_cache_loader_helper),
      throttles_(std::move(throttles)) {
  DCHECK(url_loader_factory_);
}

scoped_refptr<base::SingleThreadTaskRunner>
URLLoader::Context::GetMaybeUnfreezableTaskRunner() {
  return unfreezable_task_runner_;
}

void URLLoader::Context::Cancel() {
  TRACE_EVENT_WITH_FLOW0("loading", "URLLoader::Context::Cancel", this,
                         TRACE_EVENT_FLAG_FLOW_IN);
  if (request_id_ != -1) {
    // TODO(https://crbug.com/1137682): Change this to use
    // |unfreezable_task_runner_| instead?
    resource_request_sender_->Cancel(freezable_task_runner_);
    request_id_ = -1;
  }

  // Do not make any further calls to the client.
  client_ = nullptr;
  loader_ = nullptr;
}

void URLLoader::Context::Freeze(LoaderFreezeMode mode) {
  if (request_id_ != -1) {
    resource_request_sender_->Freeze(mode);
  }
  freeze_mode_ = mode;
}

void URLLoader::Context::DidChangePriority(WebURLRequest::Priority new_priority,
                                           int intra_priority_value) {
  if (request_id_ != -1) {
    net::RequestPriority net_priority =
        WebURLRequest::ConvertToNetPriority(new_priority);
    resource_request_sender_->DidChangePriority(net_priority,
                                                intra_priority_value);
  }
}

void URLLoader::Context::Start(
    std::unique_ptr<network::ResourceRequest> request,
    scoped_refptr<const SecurityOrigin> top_frame_origin,
    bool download_to_blob,
    bool no_mime_sniffing,
    base::TimeDelta timeout_interval,
    SyncLoadResponse* sync_load_response,
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper,
    CodeCacheHost* code_cache_host) {
  DCHECK_EQ(request_id_, -1);

  url_ = KURL(request->url);
  has_devtools_request_id_ = request->devtools_request_id.has_value();

  std::vector<std::unique_ptr<blink::URLLoaderThrottle>> throttles;
  for (auto& throttle : throttles_) {
    throttles.push_back(std::move(throttle));
  }

  // The top frame origin of shared and service workers is null.
  Platform::Current()->AppendVariationsThrottles(
      top_frame_origin ? top_frame_origin->ToUrlOrigin() : url::Origin(),
      &throttles);

  uint32_t loader_options = network::mojom::kURLLoadOptionNone;
  if (!no_mime_sniffing) {
    loader_options |= network::mojom::kURLLoadOptionSniffMimeType;
    throttles.push_back(std::make_unique<MimeSniffingThrottle>(
        GetMaybeUnfreezableTaskRunner()));
  }

  if (sync_load_response) {
    DCHECK_EQ(freeze_mode_, LoaderFreezeMode::kNone);
    CHECK(!code_cache_host);

    loader_options |= network::mojom::kURLLoadOptionSynchronous;
    request->load_flags |= net::LOAD_IGNORE_LIMITS;

    mojo::PendingRemote<mojom::blink::BlobRegistry> download_to_blob_registry;
    if (download_to_blob) {
      Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
          download_to_blob_registry.InitWithNewPipeAndPassReceiver());
    }
    net::NetworkTrafficAnnotationTag tag =
        FetchUtils::GetTrafficAnnotationTag(*request);
    resource_request_sender_->SendSync(
        std::move(request), tag, loader_options, sync_load_response,
        url_loader_factory_, std::move(throttles), timeout_interval,
        cors_exempt_header_list_, terminate_sync_load_event_,
        std::move(download_to_blob_registry), base::WrapRefCounted(this),
        std::move(resource_load_info_notifier_wrapper));
    return;
  }

  TRACE_EVENT_WITH_FLOW0("loading", "URLLoader::Context::Start", this,
                         TRACE_EVENT_FLAG_FLOW_OUT);
  net::NetworkTrafficAnnotationTag tag =
      FetchUtils::GetTrafficAnnotationTag(*request);
  request_id_ = resource_request_sender_->SendAsync(
      std::move(request), GetMaybeUnfreezableTaskRunner(), tag, loader_options,
      cors_exempt_header_list_, base::WrapRefCounted(this), url_loader_factory_,
      std::move(throttles), std::move(resource_load_info_notifier_wrapper),
      code_cache_host,
      base::BindOnce(&BackForwardCacheLoaderHelper::EvictFromBackForwardCache,
                     back_forward_cache_loader_helper_),
      base::BindRepeating(
          &BackForwardCacheLoaderHelper::DidBufferLoadWhileInBackForwardCache,
          back_forward_cache_loader_helper_,
          /*update_process_wide_count=*/true));

  if (freeze_mode_ != LoaderFreezeMode::kNone) {
    resource_request_sender_->Freeze(LoaderFreezeMode::kStrict);
  }
}

void URLLoader::Context::OnUploadProgress(uint64_t position, uint64_t size) {
  if (client_) {
    client_->DidSendData(position, size);
  }
}

void URLLoader::Context::OnReceivedRedirect(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr head,
    FollowRedirectCallback follow_redirect_callback) {
  if (!client_) {
    return;
  }

  TRACE_EVENT_WITH_FLOW0("loading", "URLLoader::Context::OnReceivedRedirect",
                         this,
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  WebURLResponse response = WebURLResponse::Create(
      url_, *head, has_devtools_request_id_, request_id_);

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
    std::move(follow_redirect_callback)
        .Run(std::move(removed_headers), std::move(modified_headers));
  }
}

void URLLoader::Context::OnReceivedResponse(
    network::mojom::URLResponseHeadPtr head,
    mojo::ScopedDataPipeConsumerHandle body,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  if (!client_) {
    return;
  }

  TRACE_EVENT_WITH_FLOW0("loading", "URLLoader::Context::OnReceivedResponse",
                         this,
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  // These headers must be stripped off before entering into the renderer
  // (see also https://crbug.com/1019732).
  DCHECK(!head->headers || !head->headers->HasHeader("set-cookie"));
  DCHECK(!head->headers || !head->headers->HasHeader("set-cookie2"));
  DCHECK(!head->headers || !head->headers->HasHeader("clear-site-data"));

  WebURLResponse response = WebURLResponse::Create(
      url_, *head, has_devtools_request_id_, request_id_);
  client_->DidReceiveResponse(response, std::move(body),
                              std::move(cached_metadata));
}

void URLLoader::Context::OnTransferSizeUpdated(int transfer_size_diff) {
  client_->DidReceiveTransferSizeUpdate(transfer_size_diff);
}

void URLLoader::Context::OnCompletedRequest(
    const network::URLLoaderCompletionStatus& status) {
  int64_t total_transfer_size = status.encoded_data_length;
  int64_t encoded_body_size = status.encoded_body_length;

  if (client_) {
    TRACE_EVENT_WITH_FLOW0("loading", "URLLoader::Context::OnCompletedRequest",
                           this, TRACE_EVENT_FLAG_FLOW_IN);

    if (status.error_code != net::OK) {
      client_->DidFail(WebURLError::Create(status, url_),
                       status.completion_time, total_transfer_size,
                       encoded_body_size, status.decoded_body_length);
    } else {
      client_->DidFinishLoading(status.completion_time, total_transfer_size,
                                encoded_body_size, status.decoded_body_length);
    }
  }
}

URLLoader::Context::~Context() {
  // We must be already cancelled at this point.
  DCHECK_LT(request_id_, 0);
}

// URLLoader ----------------------------------------------------------------

URLLoader::URLLoader(
    const Vector<String>& cors_exempt_header_list,
    base::WaitableEvent* terminate_sync_load_event,
    scoped_refptr<base::SingleThreadTaskRunner> freezable_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
    mojo::PendingRemote<mojom::blink::KeepAliveHandle> keep_alive_handle,
    BackForwardCacheLoaderHelper* back_forward_cache_loader_helper,
    Vector<std::unique_ptr<URLLoaderThrottle>> throttles)
    : context_(base::MakeRefCounted<Context>(this,
                                             cors_exempt_header_list,
                                             terminate_sync_load_event,
                                             std::move(freezable_task_runner),
                                             std::move(unfreezable_task_runner),
                                             std::move(url_loader_factory),
                                             std::move(keep_alive_handle),
                                             back_forward_cache_loader_helper,
                                             std::move(throttles))) {}

URLLoader::URLLoader() = default;

URLLoader::~URLLoader() {
  Cancel();
}

void URLLoader::LoadSynchronously(
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
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper) {
  if (!context_) {
    return;
  }

  TRACE_EVENT0("loading", "URLLoader::loadSynchronously");
  SyncLoadResponse sync_load_response;

  DCHECK(!context_->client());
  context_->set_client(client);

  const bool has_devtools_request_id = request->devtools_request_id.has_value();
  context_->Start(std::move(request), std::move(top_frame_origin),
                  download_to_blob, no_mime_sniffing, timeout_interval,
                  &sync_load_response,
                  std::move(resource_load_info_notifier_wrapper),
                  /*code_cache_host=*/nullptr);

  const KURL final_url(sync_load_response.url);

  // TODO(tc): For file loads, we may want to include a more descriptive
  // status code or status text.
  const int error_code = sync_load_response.error_code;
  if (error_code != net::OK) {
    if (sync_load_response.cors_error) {
      error = WebURLError(*sync_load_response.cors_error,
                          WebURLError::HasCopyInCache::kFalse, final_url);
    } else {
      // SyncResourceHandler returns ERR_ABORTED for CORS redirect errors,
      // so we treat the error as a web security violation.
      const WebURLError::IsWebSecurityViolation is_web_security_violation =
          error_code == net::ERR_ABORTED
              ? WebURLError::IsWebSecurityViolation::kTrue
              : WebURLError::IsWebSecurityViolation::kFalse;
      error = WebURLError(error_code, sync_load_response.extended_error_code,
                          sync_load_response.resolve_error_info,
                          WebURLError::HasCopyInCache::kFalse,
                          is_web_security_violation, final_url,
                          sync_load_response.should_collapse_initiator
                              ? WebURLError::ShouldCollapseInitiator::kTrue
                              : WebURLError::ShouldCollapseInitiator::kFalse);
    }
    return;
  }

  if (sync_load_response
          .has_authorization_header_between_cross_origin_redirect_) {
    client->CountFeature(mojom::WebFeature::kAuthorizationCrossOrigin);
  }

  response =
      WebURLResponse::Create(final_url, *sync_load_response.head,
                             has_devtools_request_id, context_->request_id());
  encoded_data_length = sync_load_response.head->encoded_data_length;
  encoded_body_length =
      sync_load_response.head->encoded_body_length
          ? sync_load_response.head->encoded_body_length->value
          : 0;
  if (sync_load_response.downloaded_blob) {
    downloaded_blob = std::move(sync_load_response.downloaded_blob);
  }

  data = sync_load_response.data;
}

void URLLoader::LoadAsynchronously(
    std::unique_ptr<network::ResourceRequest> request,
    scoped_refptr<const SecurityOrigin> top_frame_origin,
    bool no_mime_sniffing,
    std::unique_ptr<ResourceLoadInfoNotifierWrapper>
        resource_load_info_notifier_wrapper,
    CodeCacheHost* code_cache_host,
    URLLoaderClient* client) {
  if (!context_) {
    return;
  }

  TRACE_EVENT_WITH_FLOW0("loading", "URLLoader::loadAsynchronously", this,
                         TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(!context_->client());

  context_->set_client(client);
  context_->Start(std::move(request), std::move(top_frame_origin),
                  /*download_to_blob=*/false, no_mime_sniffing,
                  base::TimeDelta(), /*sync_load_response=*/nullptr,
                  std::move(resource_load_info_notifier_wrapper),
                  code_cache_host);
}

void URLLoader::Cancel() {
  if (context_) {
    context_->Cancel();
  }
}

void URLLoader::Freeze(LoaderFreezeMode mode) {
  if (context_) {
    context_->Freeze(mode);
  }
}

void URLLoader::DidChangePriority(WebURLRequest::Priority new_priority,
                                  int intra_priority_value) {
  if (context_) {
    context_->DidChangePriority(new_priority, intra_priority_value);
  }
}

scoped_refptr<base::SingleThreadTaskRunner>
URLLoader::GetTaskRunnerForBodyLoader() {
  if (!context_) {
    return nullptr;
  }
  return context_->GetMaybeUnfreezableTaskRunner();
}

void URLLoader::SetResourceRequestSenderForTesting(
    std::unique_ptr<ResourceRequestSender> resource_request_sender) {
  context_->SetResourceRequestSenderForTesting(  // IN-TEST
      std::move(resource_request_sender));
}

void URLLoader::Context::SetResourceRequestSenderForTesting(
    std::unique_ptr<blink::ResourceRequestSender> resource_request_sender) {
  resource_request_sender_ = std::move(resource_request_sender);
}

void URLLoader::SetBackgroundResponseProcessorFactory(
    std::unique_ptr<BackgroundResponseProcessorFactory>
        background_response_processor_factory) {
  NOTREACHED();
}

}  // namespace blink
```