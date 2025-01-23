Response:
Let's break down the thought process to analyze the `MojoURLLoaderClient.cc` file.

**1. Initial Understanding: Purpose and Context**

The first thing I notice is the file path: `blink/renderer/platform/loader/fetch/url_loader/mojo_url_loader_client.cc`. This immediately tells me a few things:

* **Blink Renderer:** This code is part of the Blink rendering engine, the core of Chrome's rendering process.
* **Platform Layer:** It resides in the `platform` directory, indicating it's dealing with platform-specific abstractions or interactions.
* **Loader/Fetch:** It's involved in the loading and fetching of resources.
* **URL Loader:** Specifically, it's related to loading resources via URLs.
* **Mojo:** The "mojo" part is crucial. It signifies the use of the Mojo IPC system, Chrome's preferred inter-process communication mechanism.
* **Client:**  The "client" suffix suggests it's acting as a consumer of some service. In this context, it's likely a client of the network service (which runs in a separate process).

Therefore, my initial high-level understanding is: This file implements a class responsible for handling communication *from* the network service (over Mojo) to the Blink renderer during the process of fetching a resource.

**2. Analyzing the Includes:**

The `#include` statements provide further clues about the functionality:

* **Standard Library/Base:**  Includes like `<iterator>`, `"base/containers/queue.h"`, `"base/functional/bind.h"`, etc., point to standard C++ features and Chromium's base library utilities, indicating general-purpose functionality like data structures, callbacks, and memory management.
* **Mojo Specific:**  Includes like `"mojo/public/cpp/system/data_pipe_drainer.h"` and `"mojo/public/mojom/...mojom.h"` confirm the use of Mojo for data streaming and interface definitions.
* **Networking:** Includes like `"net/url_request/redirect_info.h"` and `"services/network/public/cpp/features.h"` clearly indicate interaction with the Chromium networking stack.
* **Blink Specific:** Includes like `"third_party/blink/public/...mojom-blink.h"`, `"third_party/blink/public/platform/platform.h"`, and other `blink/renderer/...` headers point to interaction with other parts of the Blink rendering engine, particularly the resource loading and caching mechanisms.

**3. Examining the Class Structure: `MojoURLLoaderClient`**

I see the main class, `MojoURLLoaderClient`. I start looking at its public methods and members to understand its role:

* **Constructor:** Takes a `ResourceRequestSender`, a task runner, and some flags. This suggests it's being created and used by something that handles resource requests (`ResourceRequestSender`).
* **`Freeze()`:** This is interesting. The name suggests pausing or controlling the processing of network responses. The `LoaderFreezeMode` enum hints at different ways this freezing can occur (e.g., buffering). This immediately makes me think about back/forward cache scenarios where loading might be temporarily halted.
* **`OnReceiveEarlyHints()`, `OnReceiveResponse()`, `OnReceiveRedirect()`, `OnUploadProgress()`, `OnTransferSizeUpdated()`, `OnComplete()`:** These are clearly callbacks from the network service, representing different stages in the resource loading process. The "On..." prefix is a common convention for event handlers.
* **`FlushDeferredMessages()`:** This method, along with `NeedsStoringMessage()` and `StoreAndDispatch()`, suggests a mechanism for delaying or batching the handling of network messages, likely related to the `Freeze()` functionality.
* **`OnConnectionClosed()`:** Handles the case where the network connection is terminated unexpectedly.

**4. Deeper Dive into Key Methods and Inner Classes:**

* **`DeferredMessage` and its derived classes (`DeferredOnReceiveResponse`, `DeferredOnReceiveRedirect`, etc.):** This design pattern is a strong indicator of the deferred message handling. Each derived class encapsulates the data needed for a specific network event.
* **`BodyBuffer`:** This class is responsible for buffering the response body received from the network service. The use of `mojo::DataPipeDrainer` confirms its role in streaming data. The buffering logic within `BodyBuffer` and the interaction with `BackForwardCacheBufferLimitTracker` strongly point to managing resource loading while in the back/forward cache.
* **`Freeze()` and the back/forward cache logic:** The code within `Freeze()`, along with the `back_forward_cache_eviction_timer_`, `evict_from_bfcache_callback_`, and `did_buffer_load_while_in_bfcache_callback_`, clearly demonstrates its role in controlling resource loading and triggering evictions from the back/forward cache.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now that I have a good understanding of the class's mechanics, I can start connecting it to web technologies:

* **HTML:** When a browser parses an HTML document and encounters a `<script>`, `<link>`, `<img>`, or `<iframe>` tag, it needs to fetch those resources. `MojoURLLoaderClient` is involved in the process of fetching these resources from the network.
* **CSS:** Similarly, when a browser encounters a `<link rel="stylesheet">` tag or a `@import` rule in a CSS file, `MojoURLLoaderClient` handles fetching the CSS resource.
* **JavaScript:** Fetching JavaScript files via `<script>` tags or the `fetch()` API relies on components like `MojoURLLoaderClient`. The `fetch()` API directly triggers network requests, and this class is part of the underlying implementation.

**6. Logical Reasoning and Examples:**

* **Assumption:** The `Freeze(LoaderFreezeMode::kBufferIncoming)` is called when a page is being moved into the back/forward cache.
* **Input:** A network response starts arriving for a resource on a page that's being moved to the back/forward cache.
* **Output:** The `OnReceiveResponse()` method will store the response head and start buffering the response body using the `BodyBuffer`. The `FlushDeferredMessages()` will be delayed until `Freeze(LoaderFreezeMode::kNone)` is called (when the page is navigated back to).

* **User Error:** A common programming error in JavaScript using the `fetch()` API is not properly handling network errors or redirects. While `MojoURLLoaderClient` handles the low-level details, if the JavaScript code doesn't check the `response.ok` property or handle exceptions during the fetch, the user might see unexpected behavior or errors.

**7. Refining the Analysis and Structure:**

Finally, I organize the observations into a structured list of functionalities, highlighting the connections to web technologies, providing examples, and noting potential user errors. I make sure to connect the low-level implementation details to the higher-level concepts of web browsing and resource loading. I also pay attention to the language used in the code (e.g., "deferred," "buffering," "eviction") to infer the underlying mechanisms.
这个文件 `mojo_url_loader_client.cc` 是 Chromium Blink 引擎中负责处理通过 Mojo IPC（Inter-Process Communication）从网络进程接收到的资源加载响应的客户端。 它的主要功能是将从网络进程接收到的各种事件和数据转换成 Blink 渲染引擎可以理解和处理的形式，并通知 `ResourceRequestSender`。

以下是它的具体功能列表以及与 JavaScript, HTML, CSS 的关系：

**主要功能:**

1. **接收网络响应头 (OnReceiveResponse):**
   - 接收来自网络进程的 `URLResponseHead` 对象，其中包含 HTTP 响应头信息（例如状态码、Content-Type、缓存策略等）。
   - 如果需要，可以创建一个 `BodyBuffer` 对象来缓冲响应体数据。这通常发生在页面被放入后退/前进缓存时。
   - 将接收到的响应头信息传递给 `ResourceRequestSender`，以便 Blink 渲染引擎可以开始处理响应。

2. **接收重定向 (OnReceiveRedirect):**
   - 接收来自网络进程的重定向信息 (`RedirectInfo`) 和新的响应头。
   - 检查重定向是否安全，如果不安全则终止请求。
   - 将重定向信息传递给 `ResourceRequestSender`，以便 Blink 渲染引擎可以发起新的请求到重定向的 URL。

3. **接收上传进度 (OnUploadProgress):**
   - 接收来自网络进程的上传进度信息（已上传的字节数和总字节数）。
   - 将上传进度信息传递给 `ResourceRequestSender`，以便 Blink 可以通知上层（例如 JavaScript 的 `XMLHttpRequest` 或 `fetch` API）。

4. **接收传输大小更新 (OnTransferSizeUpdated):**
   - 接收来自网络进程的已传输数据大小的增量更新。
   - 将传输大小更新传递给 `ResourceRequestSender`，用于跟踪下载进度。

5. **接收请求完成 (OnComplete):**
   - 接收来自网络进程的请求完成状态 (`URLLoaderCompletionStatus`)，包含错误码、HTTP 状态码等信息。
   - 将请求完成状态传递给 `ResourceRequestSender`，标志着资源加载的结束。

6. **处理后退/前进缓存 (Back/Forward Cache):**
   - 当页面被放入后退/前进缓存时，可以进入 "冻结" 模式 (`Freeze`)，暂停或缓冲消息的处理。
   - 在冻结模式下，接收到的网络事件会被缓存起来，直到页面从缓存中恢复。
   - 使用 `BodyBuffer` 来缓冲响应体数据，防止在缓存期间阻塞网络进程。
   - 可以根据配置的超时时间来决定是否需要将页面从后退/前进缓存中移除 (`EvictFromBackForwardCacheDueToTimeout`)。
   - 监控缓冲数据的大小，如果超过限制，则将页面从后退/前进缓存中移除 (`CanContinueBufferingWhileInBackForwardCache`).

7. **处理连接关闭 (OnConnectionClosed):**
   - 当与网络进程的连接意外关闭时，会调用此方法。
   - 如果请求尚未完成，则会通知 `ResourceRequestSender` 请求已中止。

8. **延迟消息处理 (Deferred Messages):**
   - 在某些情况下（例如后退/前进缓存的冻结模式），需要延迟处理接收到的网络事件。
   - 使用 `DeferredMessage` 及其子类来封装需要延迟处理的消息。
   - `FlushDeferredMessages` 方法用于在适当的时候处理这些延迟的消息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`MojoURLLoaderClient` 处于网络层和渲染引擎之间的关键位置，它处理的网络响应直接影响着 JavaScript, HTML, CSS 的加载和渲染。

* **HTML:**
    - 当浏览器解析 HTML 文件时，遇到 `<img>`, `<link rel="stylesheet">`, `<script>` 等标签，会发起网络请求加载图片、CSS 样式表和 JavaScript 文件。
    - `MojoURLLoaderClient` 负责接收这些请求的响应。例如，当加载 `<img>` 标签的图片时，`OnReceiveResponse` 会接收到包含图片数据的响应，然后传递给渲染引擎进行解码和显示。
    - **例子:** 如果 `OnReceiveResponse` 接收到的响应头中的 `Content-Type` 为 `image/jpeg`，并且响应体包含 JPEG 格式的图片数据，那么渲染引擎会利用这些信息来渲染 `<img>` 标签。

* **CSS:**
    - 当浏览器加载 `<link rel="stylesheet">` 指向的 CSS 文件时，`MojoURLLoaderClient` 接收 CSS 文件的响应。
    - `OnReceiveResponse` 接收到的响应头中的 `Content-Type` 为 `text/css`，响应体包含 CSS 规则。这些规则将被传递给 CSS 解析器，用于构建 CSSOM (CSS Object Model)，最终影响页面的样式。
    - **例子:** 如果 CSS 文件中包含 `body { background-color: red; }`，那么当 `MojoURLLoaderClient` 成功接收到该文件后，浏览器会将页面背景色设置为红色。

* **JavaScript:**
    - 当浏览器加载 `<script>` 标签指向的 JavaScript 文件或者使用 `fetch` API 发起网络请求时，`MojoURLLoaderClient` 负责接收 JavaScript 文件的响应。
    - `OnReceiveResponse` 接收到的响应头中的 `Content-Type` 为 `text/javascript` 或 `application/javascript`，响应体包含 JavaScript 代码。这些代码将被传递给 JavaScript 引擎进行解析和执行。
    - **例子:** 如果 JavaScript 文件中包含 `console.log("Hello from script!");`，那么当 `MojoURLLoaderClient` 成功接收到该文件并执行后，控制台会输出 "Hello from script!"。
    - 当使用 `fetch` API 时，JavaScript 代码会接收到 `Response` 对象，这个对象内部就包含了 `MojoURLLoaderClient` 处理过的响应头和响应体信息。 `OnUploadProgress` 可以将上传进度信息反馈给 `fetch` API 的回调函数。

**逻辑推理与假设输入输出:**

**假设输入:** 网络进程接收到一个对 `https://example.com/data.json` 的请求的响应。响应头如下：

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 25
```

响应体内容为：

```json
{"key": "value"}
```

**MojoURLLoaderClient 的处理流程 (简化):**

1. **输入:** `OnReceiveResponse` 方法接收到 `response_head` (包含上述响应头信息) 和 `body` (包含响应体数据的 Mojo 数据管道)。

2. **处理:**
   - `MojoURLLoaderClient` 会解析 `response_head`，提取 `Content-Type` 和 `Content-Length` 等信息。
   - 它会创建一个 `DeferredOnReceiveResponse` 对象来存储这些信息和数据管道。
   - 如果没有处于冻结模式，它会将这些信息通过 `ResourceRequestSender` 传递给 Blink 渲染引擎。

3. **输出:** `ResourceRequestSender` 接收到响应头和数据管道。渲染引擎会根据 `Content-Type` 判断这是一个 JSON 文件，并开始读取数据管道中的内容。最终，JavaScript 代码可以使用 `response.json()` 方法来解析这个 JSON 数据。

**假设输入 (后退/前进缓存场景):**  用户导航到一个页面，然后点击后退按钮。此时该页面被放入后退/前进缓存，并正在加载一个图片。

1. **输入:** 在页面被放入后退/前进缓存期间，`OnReceiveResponse` 接收到一个图片资源的响应头和数据。`Freeze(LoaderFreezeMode::kBufferIncoming)` 被调用。

2. **处理:**
   - `MojoURLLoaderClient` 检测到处于 `kBufferIncoming` 模式。
   - 它会创建一个 `BodyBuffer` 来缓冲图片数据。
   - 创建 `DeferredOnReceiveResponse` 对象，但不会立即调用 `resource_request_sender->OnReceivedResponse`。消息被存储在 `deferred_messages_` 队列中。

3. **输出:** 图片数据的加载被缓冲。当用户再次前进到该页面时，`Freeze(LoaderFreezeMode::kNone)` 被调用，`FlushDeferredMessages` 会被执行，之前缓存的消息会被处理，图片数据会被传递给渲染引擎进行显示。

**用户或编程常见的使用错误:**

1. **网络请求超时或失败未处理:**
   - **错误:** 开发者在 JavaScript 中使用 `fetch` API 时，没有正确处理网络请求超时或失败的情况。
   - **`MojoURLLoaderClient` 涉及:** `OnComplete` 方法会接收到包含错误信息的 `URLLoaderCompletionStatus`。如果 JavaScript 代码没有检查 `response.ok` 属性或捕获 `fetch` 抛出的异常，用户可能会看到空白页面或错误提示，但开发者可能无法定位问题原因。
   - **例子:**
     ```javascript
     fetch('https://example.com/api/data')
       .then(response => response.json()) // 假设请求成功
       .then(data => console.log(data));
       // 缺少 .catch() 来处理网络错误
     ```

2. **重定向处理不当:**
   - **错误:** 开发者在处理需要重定向的请求时，没有考虑到重定向的次数限制或潜在的安全风险。
   - **`MojoURLLoaderClient` 涉及:** `OnReceiveRedirect` 方法会接收到重定向信息。如果 Blink 配置了不允许过多重定向，`MojoURLLoaderClient` 会终止请求并通知 `ResourceRequestSender`。如果 JavaScript 代码没有妥善处理重定向响应（例如检查 `response.redirected` 属性），可能会导致逻辑错误。
   - **例子:**  一个无限循环的重定向会导致浏览器不断发起新的请求，最终可能被浏览器阻止。

3. **后退/前进缓存相关问题:**
   - **错误:** 开发者可能没有意识到后退/前进缓存的存在，或者不了解其对资源加载的影响。
   - **`MojoURLLoaderClient` 涉及:** `Freeze` 和 `FlushDeferredMessages` 的机制是为了优化后退/前进缓存的性能。如果开发者在页面被缓存后期望某些网络请求立即完成并执行回调，可能会遇到延迟。
   - **例子:**  假设一个页面在 `unload` 事件中发起了一个异步请求，期望在离开页面前完成。但如果页面被放入后退/前进缓存，这个请求可能会被延迟到页面恢复时才完成，这可能不是开发者期望的行为。

4. **MIME 类型错误:**
   - **错误:** 服务器返回了错误的 MIME 类型 (`Content-Type`)。
   - **`MojoURLLoaderClient` 涉及:** `OnReceiveResponse` 接收到的响应头中的 `Content-Type` 会影响 Blink 如何处理响应体。如果 MIME 类型与实际内容不符，可能导致资源加载失败或解析错误。
   - **例子:** 服务器返回一个 JavaScript 文件，但 `Content-Type` 设置为 `text/plain`，浏览器可能不会将其识别为可执行的 JavaScript 代码。

总而言之，`mojo_url_loader_client.cc` 是 Blink 引擎中处理网络请求响应的关键组件，它确保了从网络进程接收到的数据能够被正确地传递和处理，最终影响着网页的渲染和 JavaScript 的执行。理解其功能有助于开发者更好地理解浏览器的工作原理，并避免一些常见的网络请求相关的错误。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/mojo_url_loader_client.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/mojo_url_loader_client.h"

#include <iterator>

#include "base/containers/queue.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "mojo/public/cpp/system/data_pipe_drainer.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/record_ontransfersizeupdate_utils.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/navigation/renderer_eviction_reason.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/back_forward_cache_buffer_limit_tracker.h"
#include "third_party/blink/renderer/platform/back_forward_cache_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/loader_freeze_mode.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {
namespace {

constexpr base::TimeDelta kGracePeriodToFinishLoadingWhileInBackForwardCache =
    base::Seconds(60);

}  // namespace

class MojoURLLoaderClient::DeferredMessage {
 public:
  DeferredMessage() = default;
  DeferredMessage(const DeferredMessage&) = delete;
  DeferredMessage& operator=(const DeferredMessage&) = delete;
  virtual ~DeferredMessage() = default;

  virtual void HandleMessage(
      ResourceRequestSender* resource_request_sender) = 0;
  virtual bool IsCompletionMessage() const = 0;
};

class MojoURLLoaderClient::DeferredOnReceiveResponse final
    : public DeferredMessage {
 public:
  explicit DeferredOnReceiveResponse(
      network::mojom::URLResponseHeadPtr response_head,
      mojo::ScopedDataPipeConsumerHandle body,
      std::optional<mojo_base::BigBuffer> cached_metadata,
      base::TimeTicks response_ipc_arrival_time)
      : response_head_(std::move(response_head)),
        body_(std::move(body)),
        cached_metadata_(std::move(cached_metadata)),
        response_ipc_arrival_time_(response_ipc_arrival_time) {}

  void HandleMessage(ResourceRequestSender* resource_request_sender) override {
    resource_request_sender->OnReceivedResponse(
        std::move(response_head_), std::move(body_),
        std::move(cached_metadata_), response_ipc_arrival_time_);
  }
  bool IsCompletionMessage() const override { return false; }

 private:
  network::mojom::URLResponseHeadPtr response_head_;
  mojo::ScopedDataPipeConsumerHandle body_;
  std::optional<mojo_base::BigBuffer> cached_metadata_;
  const base::TimeTicks response_ipc_arrival_time_;
};

class MojoURLLoaderClient::DeferredOnReceiveRedirect final
    : public DeferredMessage {
 public:
  DeferredOnReceiveRedirect(const net::RedirectInfo& redirect_info,
                            network::mojom::URLResponseHeadPtr response_head,
                            base::TimeTicks redirect_ipc_arrival_time)
      : redirect_info_(redirect_info),
        response_head_(std::move(response_head)),
        redirect_ipc_arrival_time_(redirect_ipc_arrival_time) {}

  void HandleMessage(ResourceRequestSender* resource_request_sender) override {
    resource_request_sender->OnReceivedRedirect(
        redirect_info_, std::move(response_head_), redirect_ipc_arrival_time_);
  }
  bool IsCompletionMessage() const override { return false; }

 private:
  const net::RedirectInfo redirect_info_;
  network::mojom::URLResponseHeadPtr response_head_;
  const base::TimeTicks redirect_ipc_arrival_time_;
};

class MojoURLLoaderClient::DeferredOnUploadProgress final
    : public DeferredMessage {
 public:
  DeferredOnUploadProgress(int64_t current, int64_t total)
      : current_(current), total_(total) {}

  void HandleMessage(ResourceRequestSender* resource_request_sender) override {
    resource_request_sender->OnUploadProgress(current_, total_);
  }
  bool IsCompletionMessage() const override { return false; }

 private:
  const int64_t current_;
  const int64_t total_;
};


class MojoURLLoaderClient::DeferredOnComplete final : public DeferredMessage {
 public:
  explicit DeferredOnComplete(const network::URLLoaderCompletionStatus& status,
                              base::TimeTicks complete_ipc_arrival_time)
      : status_(status),
        complete_ipc_arrival_time_(complete_ipc_arrival_time) {}

  void HandleMessage(ResourceRequestSender* resource_request_sender) override {
    resource_request_sender->OnRequestComplete(status_,
                                               complete_ipc_arrival_time_);
  }
  bool IsCompletionMessage() const override { return true; }

 private:
  const network::URLLoaderCompletionStatus status_;
  const base::TimeTicks complete_ipc_arrival_time_;
};

class MojoURLLoaderClient::BodyBuffer final
    : public mojo::DataPipeDrainer::Client {
 public:
  BodyBuffer(MojoURLLoaderClient* owner,
             mojo::ScopedDataPipeConsumerHandle readable,
             mojo::ScopedDataPipeProducerHandle writable,
             scoped_refptr<base::SequencedTaskRunner> task_runner)
      : owner_(owner),
        writable_(std::move(writable)),
        writable_watcher_(FROM_HERE,
                          mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                          std::move(task_runner)) {
    pipe_drainer_ =
        std::make_unique<mojo::DataPipeDrainer>(this, std::move(readable));
    writable_watcher_.Watch(
        writable_.get(),
        MOJO_HANDLE_SIGNAL_WRITABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
        base::BindRepeating(&BodyBuffer::WriteBufferedBody,
                            base::Unretained(this)));
  }

  bool active() const { return writable_watcher_.IsWatching(); }

  // mojo::DataPipeDrainer::Client
  void OnDataAvailable(base::span<const uint8_t> data) override {
    std::string_view chars = base::as_string_view(data);
    DCHECK(draining_);
    if (owner_->freeze_mode() == LoaderFreezeMode::kBufferIncoming) {
      owner_->DidBufferLoadWhileInBackForwardCache(chars.size());
      if (!owner_->CanContinueBufferingWhileInBackForwardCache()) {
        owner_->EvictFromBackForwardCache(
            mojom::blink::RendererEvictionReason::kNetworkExceedsBufferLimit);
        return;
      }
    }
    buffered_body_.push(std::vector<char>(chars.begin(), chars.end()));
    WriteBufferedBody(MOJO_RESULT_OK);
  }

  void OnDataComplete() override {
    DCHECK(draining_);
    draining_ = false;
    WriteBufferedBody(MOJO_RESULT_OK);
  }

 private:
  void WriteBufferedBody(MojoResult) {
    // Try to write all the remaining chunks in |buffered_body_|.
    while (!buffered_body_.empty()) {
      // Write the chunk at the front of |buffered_body_|.
      const std::vector<char>& current_chunk = buffered_body_.front();
      base::span<const uint8_t> bytes =
          base::as_byte_span(current_chunk).subspan(offset_in_current_chunk_);

      size_t actually_written_bytes = 0;
      MojoResult result = writable_->WriteData(bytes, MOJO_WRITE_DATA_FLAG_NONE,
                                               actually_written_bytes);
      switch (result) {
        case MOJO_RESULT_OK:
          break;
        case MOJO_RESULT_FAILED_PRECONDITION:
          // The pipe is closed unexpectedly, finish writing now.
          draining_ = false;
          Finish();
          return;
        case MOJO_RESULT_SHOULD_WAIT:
          writable_watcher_.ArmOrNotify();
          return;
        default:
          NOTREACHED();
      }
      // We've sent |bytes_sent| bytes, update the current offset in the
      // frontmost chunk.
      offset_in_current_chunk_ += actually_written_bytes;
      DCHECK_LE(offset_in_current_chunk_, current_chunk.size());
      if (offset_in_current_chunk_ == current_chunk.size()) {
        // We've finished writing the chunk at the front of the queue, pop it so
        // that we'll write the next chunk next time.
        buffered_body_.pop();
        offset_in_current_chunk_ = 0;
      }
    }
    // We're finished if we've drained the original pipe and sent all the
    // buffered body.
    if (!draining_)
      Finish();
  }

  void Finish() {
    DCHECK(!draining_);
    // We've read and written all the data from the original pipe.
    writable_watcher_.Cancel();
    writable_.reset();
    // There might be a deferred OnComplete message waiting for us to finish
    // draining the response body, so flush the deferred messages in
    // the owner MojoURLLoaderClient.
    owner_->FlushDeferredMessages();
  }

  const raw_ptr<MojoURLLoaderClient> owner_;
  mojo::ScopedDataPipeProducerHandle writable_;
  mojo::SimpleWatcher writable_watcher_;
  std::unique_ptr<mojo::DataPipeDrainer> pipe_drainer_;
  // We save the received response body as a queue of chunks so that we can free
  // memory as soon as we finish sending a chunk completely.
  base::queue<std::vector<char>> buffered_body_;
  size_t offset_in_current_chunk_ = 0;
  bool draining_ = true;
};

MojoURLLoaderClient::MojoURLLoaderClient(
    ResourceRequestSender* resource_request_sender,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    bool bypass_redirect_checks,
    const GURL& request_url,
    base::OnceCallback<void(mojom::blink::RendererEvictionReason)>
        evict_from_bfcache_callback,
    base::RepeatingCallback<void(size_t)>
        did_buffer_load_while_in_bfcache_callback)
    : back_forward_cache_timeout_(
          base::Seconds(GetLoadingTasksUnfreezableParamAsInt(
              "grace_period_to_finish_loading_in_seconds",
              static_cast<int>(
                  kGracePeriodToFinishLoadingWhileInBackForwardCache
                      .InSeconds())))),
      resource_request_sender_(resource_request_sender),
      task_runner_(std::move(task_runner)),
      bypass_redirect_checks_(bypass_redirect_checks),
      last_loaded_url_(request_url),
      evict_from_bfcache_callback_(std::move(evict_from_bfcache_callback)),
      did_buffer_load_while_in_bfcache_callback_(
          std::move(did_buffer_load_while_in_bfcache_callback)) {}

MojoURLLoaderClient::~MojoURLLoaderClient() = default;

void MojoURLLoaderClient::Freeze(LoaderFreezeMode mode) {
  freeze_mode_ = mode;
  if (mode != LoaderFreezeMode::kBufferIncoming) {
    // Back/forward cache eviction should only be triggered when `freeze_mode_`
    // is kBufferIncoming.
    StopBackForwardCacheEvictionTimer();
  }
  if (mode == LoaderFreezeMode::kNone) {
    task_runner_->PostTask(
        FROM_HERE, WTF::BindOnce(&MojoURLLoaderClient::FlushDeferredMessages,
                                 weak_factory_.GetWeakPtr()));
  } else if (mode == LoaderFreezeMode::kBufferIncoming &&
             !has_received_complete_ &&
             !back_forward_cache_eviction_timer_.IsRunning()) {
    // We should evict the page associated with this load if the connection
    // takes too long until it either finished or failed.
    back_forward_cache_eviction_timer_.SetTaskRunner(task_runner_);
    back_forward_cache_eviction_timer_.Start(
        FROM_HERE, back_forward_cache_timeout_,
        WTF::BindOnce(
            &MojoURLLoaderClient::EvictFromBackForwardCacheDueToTimeout,
            weak_factory_.GetWeakPtr()));
  }
}

void MojoURLLoaderClient::OnReceiveEarlyHints(
    network::mojom::EarlyHintsPtr early_hints) {}

void MojoURLLoaderClient::OnReceiveResponse(
    network::mojom::URLResponseHeadPtr response_head,
    mojo::ScopedDataPipeConsumerHandle body,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  TRACE_EVENT1("loading", "MojoURLLoaderClient::OnReceiveResponse", "url",
               last_loaded_url_.GetString().Utf8());

  has_received_response_head_ = true;
  has_received_response_body_ = !!body;
  base::TimeTicks response_ipc_arrival_time = base::TimeTicks::Now();

  base::WeakPtr<MojoURLLoaderClient> weak_this = weak_factory_.GetWeakPtr();
  if (!NeedsStoringMessage()) {
    resource_request_sender_->OnReceivedResponse(
        std::move(response_head), std::move(body), std::move(cached_metadata),
        response_ipc_arrival_time);
    return;
  }

  if (body && (freeze_mode_ == LoaderFreezeMode::kBufferIncoming)) {
    DCHECK(IsInflightNetworkRequestBackForwardCacheSupportEnabled());
    // We want to run loading tasks while deferred (but without dispatching the
    // messages). Drain the original pipe containing the response body into a
    // new pipe so that we won't block the network service if we're deferred for
    // a long time.
    mojo::ScopedDataPipeProducerHandle new_body_producer;
    mojo::ScopedDataPipeConsumerHandle new_body_consumer;
    MojoResult result =
        mojo::CreateDataPipe(nullptr, new_body_producer, new_body_consumer);
    if (result != MOJO_RESULT_OK) {
      OnComplete(
          network::URLLoaderCompletionStatus(net::ERR_INSUFFICIENT_RESOURCES));
      return;
    }
    body_buffer_ = std::make_unique<BodyBuffer>(
        this, std::move(body), std::move(new_body_producer), task_runner_);
    body = std::move(new_body_consumer);
  }
  StoreAndDispatch(std::make_unique<DeferredOnReceiveResponse>(
      std::move(response_head), std::move(body), std::move(cached_metadata),
      response_ipc_arrival_time));
}

void MojoURLLoaderClient::EvictFromBackForwardCache(
    mojom::blink::RendererEvictionReason reason) {
  DCHECK_EQ(freeze_mode_, LoaderFreezeMode::kBufferIncoming);
  StopBackForwardCacheEvictionTimer();
  if (!evict_from_bfcache_callback_) {
    return;
  }
  std::move(evict_from_bfcache_callback_).Run(reason);
}

void MojoURLLoaderClient::DidBufferLoadWhileInBackForwardCache(
    size_t num_bytes) {
  if (!did_buffer_load_while_in_bfcache_callback_) {
    return;
  }
  did_buffer_load_while_in_bfcache_callback_.Run(num_bytes);
}

bool MojoURLLoaderClient::CanContinueBufferingWhileInBackForwardCache() {
  return BackForwardCacheBufferLimitTracker::Get()
      .IsUnderPerProcessBufferLimit();
}

void MojoURLLoaderClient::EvictFromBackForwardCacheDueToTimeout() {
  EvictFromBackForwardCache(
      mojom::blink::RendererEvictionReason::kNetworkRequestTimeout);
}

void MojoURLLoaderClient::StopBackForwardCacheEvictionTimer() {
  back_forward_cache_eviction_timer_.Stop();
}

void MojoURLLoaderClient::OnReceiveRedirect(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr response_head) {
  base::TimeTicks redirect_ipc_arrival_time = base::TimeTicks::Now();
  DCHECK(!has_received_response_head_);
  if (freeze_mode_ == LoaderFreezeMode::kBufferIncoming) {
    // Evicting a page from the bfcache and aborting the request is not good for
    // a request with keepalive set, which is why we block bfcache when we find
    // such a request.
    // TODO(crbug.com/1356128): This will not be a problem when we move the
    // keepalive request infrastructure to the browser process.

    EvictFromBackForwardCache(
        mojom::blink::RendererEvictionReason::kNetworkRequestRedirected);

    OnComplete(network::URLLoaderCompletionStatus(net::ERR_ABORTED));
    return;
  }
  if (!bypass_redirect_checks_ &&
      !Platform::Current()->IsRedirectSafe(GURL(last_loaded_url_),
                                           redirect_info.new_url)) {
    OnComplete(network::URLLoaderCompletionStatus(net::ERR_UNSAFE_REDIRECT));
    return;
  }

  last_loaded_url_ = KURL(redirect_info.new_url);
  if (NeedsStoringMessage()) {
    StoreAndDispatch(std::make_unique<DeferredOnReceiveRedirect>(
        redirect_info, std::move(response_head), redirect_ipc_arrival_time));
  } else {
    resource_request_sender_->OnReceivedRedirect(
        redirect_info, std::move(response_head), redirect_ipc_arrival_time);
  }
}

void MojoURLLoaderClient::OnUploadProgress(
    int64_t current_position,
    int64_t total_size,
    OnUploadProgressCallback ack_callback) {
  if (NeedsStoringMessage()) {
    StoreAndDispatch(std::make_unique<DeferredOnUploadProgress>(
        current_position, total_size));
  } else {
    resource_request_sender_->OnUploadProgress(current_position, total_size);
  }
  std::move(ack_callback).Run();
}

void MojoURLLoaderClient::OnTransferSizeUpdated(int32_t transfer_size_diff) {
  network::RecordOnTransferSizeUpdatedUMA(
      network::OnTransferSizeUpdatedFrom::kMojoURLLoaderClient);

  if (NeedsStoringMessage()) {
    accumulated_transfer_size_diff_during_deferred_ += transfer_size_diff;
  } else {
    resource_request_sender_->OnTransferSizeUpdated(transfer_size_diff);
  }
}

void MojoURLLoaderClient::OnComplete(
    const network::URLLoaderCompletionStatus& status) {
  base::TimeTicks complete_ipc_arrival_time = base::TimeTicks::Now();
  has_received_complete_ = true;
  StopBackForwardCacheEvictionTimer();

  // Dispatch completion status to the ResourceRequestSender.
  // Except for errors, there must always be a response's body.
  DCHECK(has_received_response_body_ || status.error_code != net::OK);
  if (NeedsStoringMessage()) {
    StoreAndDispatch(std::make_unique<DeferredOnComplete>(
        status, complete_ipc_arrival_time));
  } else {
    resource_request_sender_->OnRequestComplete(status,
                                                complete_ipc_arrival_time);
  }
}

bool MojoURLLoaderClient::NeedsStoringMessage() const {
  return freeze_mode_ != LoaderFreezeMode::kNone ||
         deferred_messages_.size() > 0 ||
         accumulated_transfer_size_diff_during_deferred_ > 0;
}

void MojoURLLoaderClient::StoreAndDispatch(
    std::unique_ptr<DeferredMessage> message) {
  DCHECK(NeedsStoringMessage());
  if (freeze_mode_ != LoaderFreezeMode::kNone) {
    deferred_messages_.emplace_back(std::move(message));
  } else if (deferred_messages_.size() > 0 ||
             accumulated_transfer_size_diff_during_deferred_ > 0) {
    deferred_messages_.emplace_back(std::move(message));
    FlushDeferredMessages();
  } else {
    NOTREACHED();
  }
}

void MojoURLLoaderClient::OnConnectionClosed() {
  // If the connection aborts before the load completes, mark it as aborted.
  if (!has_received_complete_) {
    OnComplete(network::URLLoaderCompletionStatus(net::ERR_ABORTED));
    return;
  }
}

void MojoURLLoaderClient::FlushDeferredMessages() {
  if (freeze_mode_ != LoaderFreezeMode::kNone) {
    return;
  }
  WebVector<std::unique_ptr<DeferredMessage>> messages;
  messages.swap(deferred_messages_);
  bool has_completion_message = false;
  base::WeakPtr<MojoURLLoaderClient> weak_this = weak_factory_.GetWeakPtr();
  // First, dispatch all messages excluding the followings:
  //  - transfer size change
  //  - completion
  // These two types of messages are dispatched later.
  for (size_t index = 0; index < messages.size(); ++index) {
    if (messages[index]->IsCompletionMessage()) {
      // The completion message arrives at the end of the message queue.
      DCHECK(!has_completion_message);
      DCHECK_EQ(index, messages.size() - 1);
      has_completion_message = true;
      break;
    }

    messages[index]->HandleMessage(resource_request_sender_);
    if (!weak_this)
      return;
    if (freeze_mode_ != LoaderFreezeMode::kNone) {
      deferred_messages_.reserve(messages.size() - index - 1);
      for (size_t i = index + 1; i < messages.size(); ++i)
        deferred_messages_.emplace_back(std::move(messages[i]));
      return;
    }
  }

  // Dispatch the transfer size update.
  if (accumulated_transfer_size_diff_during_deferred_ > 0) {
    auto transfer_size_diff = accumulated_transfer_size_diff_during_deferred_;
    accumulated_transfer_size_diff_during_deferred_ = 0;
    resource_request_sender_->OnTransferSizeUpdated(transfer_size_diff);
    if (!weak_this)
      return;
    if (freeze_mode_ != LoaderFreezeMode::kNone) {
      if (has_completion_message) {
        DCHECK_GT(messages.size(), 0u);
        DCHECK(messages.back()->IsCompletionMessage());
        deferred_messages_.emplace_back(std::move(messages.back()));
      }
      return;
    }
  }

  // Dispatch the completion message.
  if (has_completion_message) {
    DCHECK_GT(messages.size(), 0u);
    DCHECK(messages.back()->IsCompletionMessage());
    if (body_buffer_ && body_buffer_->active()) {
      // If we still have an active body buffer, it means we haven't drained all
      // of the contents of the response body yet. We shouldn't dispatch the
      // completion message now, so
      // put the message back into |deferred_messages_| to be sent later after
      // the body buffer is no longer active.
      deferred_messages_.emplace_back(std::move(messages.back()));
      return;
    }
    messages.back()->HandleMessage(resource_request_sender_);
  }
}

}  // namespace blink
```