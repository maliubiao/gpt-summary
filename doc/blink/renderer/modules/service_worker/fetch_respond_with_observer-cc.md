Response:
Let's break down the thought process for analyzing this C++ code and generating the summary.

**1. Initial Scan and Identification of Key Classes:**

My first step is to quickly read through the code, paying attention to class names, function names, and included headers. This gives me a high-level understanding of the code's purpose. I noticed:

* `FetchRespondWithObserver`: This is the central class, so it's likely responsible for the main functionality.
* `#include` directives:  These point to related modules. I see `service_worker`, `fetch`, `core`, `bindings`, `mojo`, `network`. This strongly suggests the code deals with how service workers intercept and respond to network requests.
* `OnResponseRejected`, `OnResponseFulfilled`, `OnNoResponse`: These function names suggest handling different outcomes of a fetch event.
* `ServiceWorkerGlobalScope`, `FetchEvent`, `Response`: These are core concepts in service workers and fetch API interactions.
* `FetchLoaderClient`:  This seems to be involved in handling response bodies as data pipes.
* `UploadingCompletionObserver`: This likely manages the completion of uploading request bodies.

**2. Deciphering the Core Functionality of `FetchRespondWithObserver`:**

Based on the class name and the function names, I hypothesize that `FetchRespondWithObserver` observes the outcome of a `respondWith()` call within a service worker's `fetch` event handler. It then communicates the result (a response, an error, or no response) back to the browser.

**3. Analyzing Key Functions in Detail:**

Now I delve deeper into the important functions:

* **`OnResponseRejected`:**  This function handles cases where the `respondWith()` promise rejects. It logs an error message to the console and sends a network error response back. I notice the `ServiceWorkerResponseError` enum and the `GetMessageForResponseError` function, which explain the different reasons for rejection.
* **`OnResponseFulfilled`:** This is where a successful `respondWith()` happens with a `Response` object. This function performs several crucial checks:
    * **Response Type Validation:** It checks for `error`, `cors`, `opaque`, and `opaqueRedirect` response types in relation to the request mode.
    * **`bodyUsed` and `bodyLocked` Checks:**  Ensures the response body can be used.
    * **Cross-Origin Resource Policy (CORP) Check:**  Uses `CrossOriginResourcePolicyChecker` to see if the response is allowed.
    * **Body Handling:** It checks if the response body is a `Blob` or a `ReadableStream`. If it's a stream, it uses `FetchLoaderClient` to handle it as a data pipe.
* **`OnNoResponse`:** This handles the case where `respondWith()` isn't called or resolves with `undefined`. It deals with potentially sending the request body if it hasn't been consumed yet, using `UploadingCompletionObserver`.

**4. Identifying Relationships with JavaScript, HTML, and CSS:**

My next step is to connect the C++ code's functionality to web technologies:

* **JavaScript:** The `respondWith()` method is a JavaScript API within the service worker. The `FetchEvent` is triggered by JavaScript. The `Response` object is manipulated in JavaScript. Promises are involved in the `respondWith()` mechanism.
* **HTML:** Service workers are registered and interact with HTML pages. Fetch requests originating from HTML trigger the service worker.
* **CSS:** While not directly involved in the core logic of this file, CSS resources can be intercepted and responded to by the service worker.

**5. Reasoning and Hypothetical Scenarios:**

I start thinking about specific scenarios to illustrate the code's behavior:

* **`OnResponseRejected`:**  What if the JavaScript code throws an error within the `fetch` event handler?  This would lead to promise rejection and trigger `OnResponseRejected`. I can create an example JavaScript code snippet.
* **`OnResponseFulfilled`:**  What if the service worker fetches an image from a different origin? This could trigger the CORP check. What if the service worker creates a custom `Response` with a readable stream? This would involve `FetchLoaderClient`.
* **`OnNoResponse`:** What if the service worker simply does nothing in the `fetch` event? This triggers `OnNoResponse`.

**6. Identifying User/Programming Errors:**

I consider common mistakes developers might make:

* Forgetting to call `respondWith()`.
* Calling `respondWith()` with something other than a `Response` object.
* Trying to use a response body that has already been read.
* Violating CORS restrictions within the service worker.

**7. Tracing User Operations to the Code:**

I think about how a user action on a web page leads to the execution of this C++ code:

1. User navigates to a page or performs an action that triggers a network request (e.g., clicking a link, loading an image, submitting a form).
2. The browser checks if a service worker is registered for the current scope.
3. If a service worker is registered and active, a `fetch` event is dispatched to the service worker's JavaScript.
4. The service worker's `fetch` event listener is executed.
5. Inside the listener, the developer might call `event.respondWith(...)`.
6. This `respondWith()` call is what triggers the creation and use of the `FetchRespondWithObserver` in the C++ Blink engine.

**8. Structuring the Output:**

Finally, I organize my findings into the requested categories: functionality, relationship to web technologies (with examples), logical reasoning (with input/output), user errors (with examples), and debugging clues. I ensure the language is clear, concise, and informative. I use code formatting where appropriate to improve readability.
这个文件 `blink/renderer/modules/service_worker/fetch_respond_with_observer.cc` 是 Chromium Blink 引擎中关于 Service Worker 如何响应 `fetch` 事件的关键组成部分。它的主要功能是**观察和处理 Service Worker 中 `respondWith()` 方法的执行结果，并将结果传递回浏览器，最终影响页面的网络请求处理**。

以下是该文件的详细功能分解，以及与 JavaScript、HTML、CSS 的关系，逻辑推理，常见错误，和调试线索：

**主要功能:**

1. **监听 `respondWith()` 的结果:**  `FetchRespondWithObserver` 对象在 Service Worker 的 `fetch` 事件处理程序中，当 JavaScript 代码调用 `event.respondWith(response)` 时被创建。它的主要职责是等待 `respondWith()` 中 Promise 的解决 (resolve) 或拒绝 (reject)。

2. **处理 `respondWith()` 成功 (resolve):**
   - **校验 Response 对象:**  当 `respondWith()` 的 Promise 成功解决，并且提供了一个 `Response` 对象时，这个类会进行一系列的校验：
     - **Response 类型检查:** 检查 `Response` 的类型 (`error`, `cors`, `opaque` 等) 是否与请求的模式 (`same-origin`, `no-cors` 等) 兼容。例如，`same-origin` 的请求不能使用 `cors` 类型的响应。
     - **Body 状态检查:** 检查 `Response` 的 `bodyUsed` 和 `bodyLocked` 属性，确保响应体没有被使用过或者锁定。
     - **跨域资源策略 (CORP) 检查:**  如果配置了 CORP，会检查响应是否允许被客户端获取。
   - **构建 `FetchAPIResponse` 对象:** 将 JavaScript 的 `Response` 对象转换为浏览器进程可以理解的 Mojo 接口 `FetchAPIResponsePtr`。这包括状态码、头部信息、响应体等。
   - **处理响应体:**
     - **Blob 处理:** 如果响应体是 Blob，则直接将其传递给浏览器。
     - **Stream 处理:** 如果响应体是 ReadableStream，则创建一个 Mojo 数据管道 (`DataPipe`)，并将响应流写入该管道。使用 `FetchLoaderClient` 来管理数据管道的加载和完成。
   - **将响应传递回浏览器:** 通过 `ServiceWorkerGlobalScope::RespondToFetchEvent` 或 `ServiceWorkerGlobalScope::RespondToFetchEventWithResponseStream` 将构建好的响应信息（或数据管道）发送回浏览器进程。
   - **解决 `fetch` 事件的 Promise:**  一旦响应成功传递，`fetch` 事件对应的 Promise 会被解决。

3. **处理 `respondWith()` 失败 (reject):**
   - **记录错误信息:** 当 `respondWith()` 的 Promise 被拒绝时，会根据拒绝的原因（例如，Promise 被拒绝、传递的不是 Response 对象、Response 类型错误等）生成相应的错误消息，并记录到控制台。
   - **构建错误响应:** 创建一个默认的网络错误响应 (HTTP 状态码通常为 0)。
   - **将错误响应传递回浏览器:**  通过 `ServiceWorkerGlobalScope::RespondToFetchEvent` 将错误响应信息发送回浏览器进程。
   - **拒绝 `fetch` 事件的 Promise:** `fetch` 事件对应的 Promise 会被拒绝。

4. **处理没有调用 `respondWith()` 的情况:**
   - **检查请求体是否已被使用:** 如果 `respondWith()` 没有被调用，会检查原始请求的 body 是否已经被读取。如果请求体已经被使用，会记录一个性能指标。
   - **将请求传递回网络:**  如果请求体没有被使用，则指示浏览器像没有 Service Worker 拦截一样，继续进行网络请求。可以通过 `ServiceWorkerGlobalScope::RespondToFetchEventWithNoResponse` 实现。如果请求体是一个流，会将其传递回浏览器。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - `FetchRespondWithObserver` 的核心作用是处理 JavaScript 中 Service Worker 的 `fetch` 事件监听器中 `event.respondWith()` 的调用结果。
    - 它接收从 JavaScript 传递过来的 `Response` 对象，并将其转换为浏览器可以理解的格式。
    - 它处理 JavaScript Promise 的 resolve 和 reject。
    - **举例:** 在 Service Worker 的 `fetch` 事件监听器中：
      ```javascript
      self.addEventListener('fetch', event => {
        if (event.request.url.endsWith('.jpg')) {
          event.respondWith(
            fetch('/cached-images/my-image.jpg') // 返回缓存的图片
          );
        } else {
          event.respondWith(fetch(event.request)); // 默认网络请求
        }
      });
      ```
      在这个例子中，当请求的 URL 以 `.jpg` 结尾时，`event.respondWith()` 被调用，并传递了一个从缓存获取的图片的 `Response` 对象。`FetchRespondWithObserver` 会接收这个 `Response` 对象并处理。如果 `fetch('/cached-images/my-image.jpg')` 返回的 Promise 被拒绝，`FetchRespondWithObserver::OnResponseRejected` 会被调用。

* **HTML:**
    - HTML 页面发起网络请求，这些请求可能会被 Service Worker 拦截。
    - Service Worker 的作用域由 HTML 页面注册时决定。
    - **举例:**  HTML 中加载一个图片：
      ```html
      <img src="/images/my-image.png">
      ```
      当浏览器加载这个 `<img>` 标签时，会发起一个对 `/images/my-image.png` 的网络请求。如果存在一个拦截该请求的 Service Worker，`FetchRespondWithObserver` 将参与处理 Service Worker 如何响应该请求。

* **CSS:**
    - 与 HTML 类似，CSS 文件的加载也会触发网络请求，并可能被 Service Worker 拦截。
    - Service Worker 可以缓存 CSS 文件，或者修改 CSS 响应。
    - **举例:** HTML 中引入 CSS 文件：
      ```html
      <link rel="stylesheet" href="/styles/main.css">
      ```
      对 `/styles/main.css` 的请求可能被 Service Worker 拦截，并由 `FetchRespondWithObserver` 处理 Service Worker 提供的响应。

**逻辑推理 (假设输入与输出):**

假设输入是一个 Service Worker 的 `fetch` 事件，并且在 JavaScript 代码中调用了 `event.respondWith(customResponse)`，其中 `customResponse` 是一个构造的 `Response` 对象：

* **假设输入:**
    - `event.request.url`: `https://example.com/api/data`
    - `customResponse` 的 `status`: `200`
    - `customResponse` 的 `body`:  一个包含 JSON 数据的 ReadableStream。

* **逻辑推理过程:**
    1. `FetchRespondWithObserver` 被创建。
    2. `OnResponseFulfilled` 被调用，因为 `respondWith` 的 Promise 成功解决。
    3. 检查 `customResponse` 的类型、body 状态等，假设校验通过。
    4. 由于 `customResponse` 的 body 是一个 ReadableStream，`FetchLoaderClient` 被创建，用于将流数据通过 Mojo 数据管道传输。
    5. `ServiceWorkerGlobalScope::RespondToFetchEventWithResponseStream` 被调用，将响应头信息和数据管道的句柄发送回浏览器。

* **预期输出 (传递给浏览器):**
    - `mojom::blink::FetchAPIResponsePtr` 包含状态码 200，以及 `customResponse` 的头部信息。
    - `mojom::blink::ServiceWorkerStreamHandlePtr` 包含用于读取响应体数据的 Mojo 数据管道句柄。

**用户或编程常见的使用错误:**

1. **忘记调用 `event.respondWith()`:**
   - **错误:**  在 `fetch` 事件监听器中，没有调用 `event.respondWith()`。
   - **后果:** 浏览器会像没有 Service Worker 一样处理请求，可能会导致意外的网络请求。
   - **`FetchRespondWithObserver` 行为:**  会调用 `OnNoResponse`，如果请求体未被使用，则将请求传递回网络。
   - **调试线索:**  在开发者工具的 "Network" 标签中，可能会看到请求没有被 Service Worker 处理的迹象。

2. **在 `respondWith()` 中传递非 `Response` 对象:**
   - **错误:**  例如，`event.respondWith("一些字符串");`
   - **后果:**  `respondWith` 的 Promise 会被拒绝，`FetchRespondWithObserver::OnResponseRejected` 会被调用，并记录错误信息。
   - **`FetchRespondWithObserver` 行为:**  会生成一个网络错误响应并传递回浏览器。
   - **调试线索:**  控制台会显示类似 "The FetchEvent for ... resulted in a network error response: an object that was not a Response was passed to respondWith()." 的警告信息。

3. **尝试使用已经使用过的 Response body:**
   - **错误:**  先读取了 Response 的 body (例如，`response.json()`)，然后尝试在 `respondWith()` 中使用同一个 Response 对象。
   - **后果:**  `FetchRespondWithObserver::OnResponseFulfilled` 中的 `response->IsBodyUsed()` 检查会失败，导致 `OnResponseRejected` 被调用。
   - **`FetchRespondWithObserver` 行为:**  会生成一个网络错误响应并传递回浏览器，并显示 "a Response whose \"bodyUsed\" is \"true\" cannot be used to respond to a request." 的错误信息。
   - **调试线索:**  控制台会显示相应的错误信息。

4. **跨域请求响应类型不匹配:**
   - **错误:**  对于 `same-origin` 的请求，Service Worker 返回了一个 `cors` 类型的响应。
   - **后果:**  `FetchRespondWithObserver::OnResponseFulfilled` 中的类型检查会失败，导致 `OnResponseRejected` 被调用。
   - **`FetchRespondWithObserver` 行为:**  生成网络错误响应，并显示 "a \"cors\" type response was used for a request whose mode is \"same-origin\"." 的错误信息。
   - **调试线索:**  控制台会显示相应的错误信息。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个注册了 Service Worker 的网页。**
2. **网页上的 JavaScript 代码发起一个网络请求 (例如，加载图片、AJAX 请求等)。**  例如，用户点击了一个链接 `<a href="/data">`，或者 JavaScript 代码执行了 `fetch('/api/items')`。
3. **浏览器拦截该网络请求，并查找是否有与当前页面作用域匹配的激活状态的 Service Worker。**
4. **如果找到，浏览器会创建一个 `fetch` 事件，并将该事件派发到 Service Worker 的全局作用域。**
5. **Service Worker 的 `fetch` 事件监听器被执行。**
6. **在监听器中，开发者可能会调用 `event.respondWith()`，并传入一个 `Response` 对象或一个返回 `Response` 对象的 Promise。**
7. **当 `event.respondWith()` 被调用时，`FetchRespondWithObserver` 对象被创建，开始观察 `respondWith()` 的结果。**
8. **根据 `respondWith()` 的 Promise 的解决或拒绝，`FetchRespondWithObserver` 的 `OnResponseFulfilled` 或 `OnResponseRejected` 方法会被调用。**
9. **这些方法会将结果（成功响应或错误信息）通过 Mojo 接口传递回浏览器进程。**
10. **浏览器进程根据 Service Worker 的响应，继续处理网络请求，例如渲染页面内容或将数据返回给 JavaScript 代码。**

**调试线索:**

* **Service Worker 控制台日志:**  使用 `console.log` 和 `console.error` 在 Service Worker 代码中记录关键信息，例如请求的 URL、`respondWith()` 的参数等。
* **Chrome 开发者工具 "Application" 面板 -> "Service Workers" 标签:**
    - 查看 Service Worker 的状态 (激活、停止等)。
    - 查看 Service Worker 的控制台输出。
    - 可以手动触发 Service Worker 事件。
* **Chrome 开发者工具 "Network" 标签:**
    - 检查网络请求的状态码和头部信息。
    - 查看请求是否被 Service Worker 处理 (`from ServiceWorker` 或 `(disk cache)` 如果被缓存)。
    - 查看请求的 "Timing" 信息，了解 Service Worker 处理请求所花费的时间。
* **`chrome://inspect/#service-workers`:**  更详细的 Service Worker 检查工具。
* **Blink 渲染器调试:**  如果需要深入了解 C++ 层的行为，可以使用 Chromium 的调试工具，设置断点在 `FetchRespondWithObserver` 的方法中，例如 `OnResponseFulfilled` 和 `OnResponseRejected`，来观察变量的值和执行流程。

总而言之，`blink/renderer/modules/service_worker/fetch_respond_with_observer.cc` 是 Service Worker 拦截和处理网络请求的核心 C++ 组件，它桥接了 JavaScript 的 `respondWith()` 调用和浏览器的网络处理机制，确保了 Service Worker 能够按照预期控制页面的网络行为。 理解这个文件的工作原理对于调试 Service Worker 相关的问题至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/service_worker/fetch_respond_with_observer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/service_worker/fetch_respond_with_observer.h"

#include <memory>
#include <utility>

#include "base/metrics/histogram_macros.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_response.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_stream_handle.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/modules/service_worker/cross_origin_resource_policy_checker.h"
#include "third_party/blink/renderer/modules/service_worker/fetch_event.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope.h"
#include "third_party/blink/renderer/modules/service_worker/wait_until_observer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/bytes_consumer.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/gc_plugin.h"
#include "v8/include/v8.h"

using blink::mojom::ServiceWorkerResponseError;

namespace blink {
namespace {

// Returns the error message to let the developer know about the reason of the
// unusual failures.
const String GetMessageForResponseError(ServiceWorkerResponseError error,
                                        const KURL& request_url) {
  String error_message = "The FetchEvent for \"" + request_url.GetString() +
                         "\" resulted in a network error response: ";
  switch (error) {
    case ServiceWorkerResponseError::kPromiseRejected:
      error_message = error_message + "the promise was rejected.";
      break;
    case ServiceWorkerResponseError::kDefaultPrevented:
      error_message =
          error_message +
          "preventDefault() was called without calling respondWith().";
      break;
    case ServiceWorkerResponseError::kNoV8Instance:
      error_message =
          error_message +
          "an object that was not a Response was passed to respondWith().";
      break;
    case ServiceWorkerResponseError::kResponseTypeError:
      error_message = error_message +
                      "the promise was resolved with an error response object.";
      break;
    case ServiceWorkerResponseError::kResponseTypeOpaque:
      error_message =
          error_message +
          "an \"opaque\" response was used for a request whose type "
          "is not no-cors";
      break;
    case ServiceWorkerResponseError::kResponseTypeNotBasicOrDefault:
      NOTREACHED();
    case ServiceWorkerResponseError::kBodyUsed:
      error_message =
          error_message +
          "a Response whose \"bodyUsed\" is \"true\" cannot be used "
          "to respond to a request.";
      break;
    case ServiceWorkerResponseError::kResponseTypeOpaqueForClientRequest:
      error_message = error_message +
                      "an \"opaque\" response was used for a client request.";
      break;
    case ServiceWorkerResponseError::kResponseTypeOpaqueRedirect:
      error_message = error_message +
                      "an \"opaqueredirect\" type response was used for a "
                      "request whose redirect mode is not \"manual\".";
      break;
    case ServiceWorkerResponseError::kResponseTypeCorsForRequestModeSameOrigin:
      error_message = error_message +
                      "a \"cors\" type response was used for a request whose "
                      "mode is \"same-origin\".";
      break;
    case ServiceWorkerResponseError::kBodyLocked:
      error_message = error_message +
                      "a Response whose \"body\" is locked cannot be used to "
                      "respond to a request.";
      break;
    case ServiceWorkerResponseError::kRedirectedResponseForNotFollowRequest:
      error_message = error_message +
                      "a redirected response was used for a request whose "
                      "redirect mode is not \"follow\".";
      break;
    case ServiceWorkerResponseError::kDataPipeCreationFailed:
      error_message = error_message + "insufficient resources.";
      break;
    case ServiceWorkerResponseError::kResponseBodyBroken:
      error_message =
          error_message + "a response body's status could not be checked.";
      break;
    case ServiceWorkerResponseError::kDisallowedByCorp:
      error_message = error_message +
                      "Cross-Origin-Resource-Policy prevented from serving the "
                      "response to the client.";
      break;
    case ServiceWorkerResponseError::kUnknown:
    default:
      error_message = error_message + "an unexpected error occurred.";
      break;
  }
  return error_message;
}

bool IsNavigationRequest(mojom::RequestContextFrameType frame_type) {
  return frame_type != mojom::RequestContextFrameType::kNone;
}

bool IsClientRequest(mojom::RequestContextFrameType frame_type,
                     network::mojom::RequestDestination destination) {
  return IsNavigationRequest(frame_type) ||
         destination == network::mojom::RequestDestination::kSharedWorker ||
         destination == network::mojom::RequestDestination::kWorker;
}

// Notifies the result of FetchDataLoader to |callback_|, the other endpoint
// for which is passed to the browser process via
// blink.mojom.ServiceWorkerFetchResponseCallback.OnResponseStream().
class FetchLoaderClient final : public GarbageCollected<FetchLoaderClient>,
                                public FetchDataLoader::Client {
 public:
  FetchLoaderClient(
      std::unique_ptr<ServiceWorkerEventQueue::StayAwakeToken> token,
      ServiceWorkerGlobalScope* service_worker,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : callback_(service_worker), token_(std::move(token)) {
    // We need to make |callback_| callable in the first place because some
    // DidFetchDataLoadXXX() accessing it may be called synchronously from
    // StartLoading().
    callback_receiver_ =
        callback_.BindNewPipeAndPassReceiver(std::move(task_runner));
  }

  FetchLoaderClient(const FetchLoaderClient&) = delete;
  FetchLoaderClient& operator=(const FetchLoaderClient&) = delete;

  void DidFetchDataStartedDataPipe(
      mojo::ScopedDataPipeConsumerHandle pipe) override {
    DCHECK(!body_stream_.is_valid());
    DCHECK(pipe.is_valid());
    body_stream_ = std::move(pipe);
  }
  void DidFetchDataLoadedDataPipe() override {
    callback_->OnCompleted();
    token_.reset();
  }
  void DidFetchDataLoadFailed() override {
    callback_->OnAborted();
    token_.reset();
  }
  void Abort() override {
    // A fetch() aborted via AbortSignal in the ServiceWorker will just look
    // like an ordinary failure to the page.
    // TODO(ricea): Should a fetch() on the page get an AbortError instead?
    callback_->OnAborted();
    token_.reset();
  }

  mojom::blink::ServiceWorkerStreamHandlePtr CreateStreamHandle() {
    if (!body_stream_.is_valid())
      return nullptr;
    return mojom::blink::ServiceWorkerStreamHandle::New(
        std::move(body_stream_), std::move(callback_receiver_));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(callback_);
    FetchDataLoader::Client::Trace(visitor);
  }

 private:
  mojo::ScopedDataPipeConsumerHandle body_stream_;
  mojo::PendingReceiver<mojom::blink::ServiceWorkerStreamCallback>
      callback_receiver_;

  HeapMojoRemote<mojom::blink::ServiceWorkerStreamCallback> callback_;
  std::unique_ptr<ServiceWorkerEventQueue::StayAwakeToken> token_;
};

class UploadingCompletionObserver
    : public GarbageCollected<UploadingCompletionObserver>,
      public BytesUploader::Client {
 public:
  explicit UploadingCompletionObserver(
      int fetch_event_id,
      ScriptPromiseResolver<IDLUndefined>* resolver,
      ServiceWorkerGlobalScope* service_worker_global_scope)
      : fetch_event_id_(fetch_event_id),
        resolver_(resolver),
        service_worker_global_scope_(service_worker_global_scope) {}

  ~UploadingCompletionObserver() override = default;

  void OnComplete() override {
    resolver_->Resolve();
    service_worker_global_scope_->OnStreamingUploadCompletion(fetch_event_id_);
  }

  void OnError() override {
    resolver_->Reject();
    service_worker_global_scope_->OnStreamingUploadCompletion(fetch_event_id_);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(resolver_);
    visitor->Trace(service_worker_global_scope_);
    BytesUploader::Client::Trace(visitor);
  }

 private:
  const int fetch_event_id_;
  const Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  Member<ServiceWorkerGlobalScope> service_worker_global_scope_;
};

}  // namespace

// This function may be called when an exception is scheduled. Thus, it must
// never invoke any code that might throw. In particular, it must never invoke
// JavaScript.
void FetchRespondWithObserver::OnResponseRejected(
    ServiceWorkerResponseError error) {
  DCHECK(GetExecutionContext());
  const String error_message = GetMessageForResponseError(error, request_url_);
  GetExecutionContext()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kWarning, error_message));

  // The default value of FetchAPIResponse's status is 0, which maps to a
  // network error.
  auto response = mojom::blink::FetchAPIResponse::New();
  response->status_text = "";
  response->error = error;
  ServiceWorkerGlobalScope* service_worker_global_scope =
      To<ServiceWorkerGlobalScope>(GetExecutionContext());
  service_worker_global_scope->RespondToFetchEvent(
      event_id_, request_url_, range_request_, std::move(response),
      event_dispatch_time_, base::TimeTicks::Now());
  event_->RejectHandledPromise(error_message);
}

void FetchRespondWithObserver::OnResponseFulfilled(ScriptState* script_state,
                                                   Response* response) {
  DCHECK(GetExecutionContext());
  // "If one of the following conditions is true, return a network error:
  //   - |response|'s type is |error|.
  //   - |request|'s mode is |same-origin| and |response|'s type is |cors|.
  //   - |request|'s mode is not |no-cors| and response's type is |opaque|.
  //   - |request| is a client request and |response|'s type is neither
  //     |basic| nor |default|."
  const network::mojom::FetchResponseType response_type =
      response->GetResponse()->GetType();
  if (response_type == network::mojom::FetchResponseType::kError) {
    OnResponseRejected(ServiceWorkerResponseError::kResponseTypeError);
    return;
  }
  if (response_type == network::mojom::FetchResponseType::kCors &&
      request_mode_ == network::mojom::RequestMode::kSameOrigin) {
    OnResponseRejected(
        ServiceWorkerResponseError::kResponseTypeCorsForRequestModeSameOrigin);
    return;
  }
  if (response_type == network::mojom::FetchResponseType::kOpaque) {
    if (request_mode_ != network::mojom::RequestMode::kNoCors) {
      OnResponseRejected(ServiceWorkerResponseError::kResponseTypeOpaque);
      return;
    }

    // The request mode of client requests should be "same-origin" but it is
    // not explicitly stated in the spec yet. So we need to check here.
    // FIXME: Set the request mode of client requests to "same-origin" and
    // remove this check when the spec will be updated.
    // Spec issue: https://github.com/whatwg/fetch/issues/101
    if (IsClientRequest(frame_type_, request_destination_)) {
      OnResponseRejected(
          ServiceWorkerResponseError::kResponseTypeOpaqueForClientRequest);
      return;
    }
  }
  if (redirect_mode_ != network::mojom::RedirectMode::kManual &&
      response_type == network::mojom::FetchResponseType::kOpaqueRedirect) {
    OnResponseRejected(ServiceWorkerResponseError::kResponseTypeOpaqueRedirect);
    return;
  }
  if (redirect_mode_ != network::mojom::RedirectMode::kFollow &&
      response->redirected()) {
    OnResponseRejected(
        ServiceWorkerResponseError::kRedirectedResponseForNotFollowRequest);
    return;
  }

  if (response->IsBodyLocked()) {
    OnResponseRejected(ServiceWorkerResponseError::kBodyLocked);
    return;
  }

  if (response->IsBodyUsed()) {
    OnResponseRejected(ServiceWorkerResponseError::kBodyUsed);
    return;
  }

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      response->PopulateFetchAPIResponse(request_url_);
  ServiceWorkerGlobalScope* service_worker_global_scope =
      To<ServiceWorkerGlobalScope>(GetExecutionContext());

  // If Cross-Origin-Embedder-Policy is set to require-corp,
  // Cross-Origin-Resource-Policy verification should happen before passing the
  // response to the client. The service worker script must be in the same
  // origin with the requestor, which is a client of the service worker.
  //
  // Here is in the renderer and we don't have a "trustworthy" initiator.
  // Hence we provide |initiator_origin| as |request_initiator_origin_lock|.
  auto initiator_origin =
      url::Origin::Create(GURL(service_worker_global_scope->Url()));
  // |corp_checker_| could be nullptr when the request is for a main resource
  // or the connection to the client which initiated the request is broken.
  // CORP check isn't needed in both cases because a service worker should be
  // in the same origin with the main resource, and the response to the broken
  // connection won't reach to the client.
  if (corp_checker_ &&
      corp_checker_->IsBlocked(
          url::Origin::Create(GURL(service_worker_global_scope->Url())),
          request_mode_, request_destination_, *response)) {
    OnResponseRejected(ServiceWorkerResponseError::kDisallowedByCorp);
    return;
  }

  BodyStreamBuffer* buffer = response->InternalBodyBuffer();
  if (buffer) {
    // The |side_data_blob| must be taken before the body buffer is
    // drained or loading begins.
    fetch_api_response->side_data_blob = buffer->TakeSideDataBlob();

    ExceptionState exception_state(script_state->GetIsolate());

    scoped_refptr<BlobDataHandle> blob_data_handle =
        buffer->DrainAsBlobDataHandle(
            BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize,
            exception_state);

    if (blob_data_handle) {
      // Handle the blob response body.
      fetch_api_response->blob = blob_data_handle;
      service_worker_global_scope->RespondToFetchEvent(
          event_id_, request_url_, range_request_,
          std::move(fetch_api_response), event_dispatch_time_,
          base::TimeTicks::Now());
      event_->ResolveHandledPromise();
      return;
    }

    // Load the Response as a Mojo DataPipe. The resulting pipe consumer
    // handle will be passed to the FetchLoaderClient on start.
    FetchLoaderClient* fetch_loader_client =
        MakeGarbageCollected<FetchLoaderClient>(
            service_worker_global_scope->CreateStayAwakeToken(),
            service_worker_global_scope, task_runner_);
    buffer->StartLoading(FetchDataLoader::CreateLoaderAsDataPipe(task_runner_),
                         fetch_loader_client, exception_state);
    if (exception_state.HadException()) {
      OnResponseRejected(ServiceWorkerResponseError::kResponseBodyBroken);
      return;
    }

    mojom::blink::ServiceWorkerStreamHandlePtr stream_handle =
        fetch_loader_client->CreateStreamHandle();
    // We failed to allocate the Mojo DataPipe.
    if (!stream_handle) {
      OnResponseRejected(ServiceWorkerResponseError::kDataPipeCreationFailed);
      return;
    }

    service_worker_global_scope->RespondToFetchEventWithResponseStream(
        event_id_, request_url_, range_request_, std::move(fetch_api_response),
        std::move(stream_handle), event_dispatch_time_, base::TimeTicks::Now());
    event_->ResolveHandledPromise();
    return;
  }
  service_worker_global_scope->RespondToFetchEvent(
      event_id_, request_url_, range_request_, std::move(fetch_api_response),
      event_dispatch_time_, base::TimeTicks::Now());
  event_->ResolveHandledPromise();
}

void FetchRespondWithObserver::OnNoResponse(ScriptState* script_state) {
  DCHECK(GetExecutionContext());
  if (original_request_body_stream_ &&
      (original_request_body_stream_->IsLocked() ||
       original_request_body_stream_->IsDisturbed())) {
    GetExecutionContext()->CountUse(
        WebFeature::kFetchRespondWithNoResponseWithUsedRequestBody);
  }

  ServiceWorkerGlobalScope* service_worker_global_scope =
      To<ServiceWorkerGlobalScope>(GetExecutionContext());
  auto* body_buffer = event_->request()->BodyBuffer();
  std::optional<network::DataElementChunkedDataPipe> request_body_to_pass;
  if (body_buffer && !request_body_has_source_) {
    auto* body_stream = body_buffer->Stream();
    if (body_stream->IsLocked() || body_stream->IsDisturbed()) {
      OnResponseRejected(
          mojom::blink::ServiceWorkerResponseError::kRequestBodyUnusable);
      return;
    }

    // Keep the service worker alive as long as we are reading from the request
    // body.
    auto* resolver =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
    WaitUntil(script_state, resolver->Promise(), ASSERT_NO_EXCEPTION);
    auto* observer = MakeGarbageCollected<UploadingCompletionObserver>(
        event_id_, resolver, service_worker_global_scope);
    mojo::PendingRemote<network::mojom::blink::ChunkedDataPipeGetter> remote;
    body_buffer->DrainAsChunkedDataPipeGetter(
        script_state, remote.InitWithNewPipeAndPassReceiver(), observer);
    request_body_to_pass.emplace(
        ToCrossVariantMojoType(std::move(remote)),
        network::DataElementChunkedDataPipe::ReadOnlyOnce(true));
  }

  service_worker_global_scope->RespondToFetchEventWithNoResponse(
      event_id_, event_.Get(), request_url_, range_request_,
      std::move(request_body_to_pass), event_dispatch_time_,
      base::TimeTicks::Now());
  event_->ResolveHandledPromise();
}

void FetchRespondWithObserver::SetEvent(FetchEvent* event) {
  DCHECK(!event_);
  DCHECK(!original_request_body_stream_);
  event_ = event;
  // We don't use Body::body() in order to avoid accidental CountUse calls.
  BodyStreamBuffer* body_buffer = event_->request()->BodyBuffer();
  if (body_buffer) {
    original_request_body_stream_ = body_buffer->Stream();
  }
}

FetchRespondWithObserver::FetchRespondWithObserver(
    ExecutionContext* context,
    int fetch_event_id,
    base::WeakPtr<CrossOriginResourcePolicyChecker> corp_checker,
    const mojom::blink::FetchAPIRequest& request,
    WaitUntilObserver* observer)
    : RespondWithObserver(context, fetch_event_id, observer),
      request_url_(request.url),
      request_mode_(request.mode),
      redirect_mode_(request.redirect_mode),
      frame_type_(request.frame_type),
      request_destination_(request.destination),
      request_body_has_source_(request.body.FormBody()),
      range_request_(request.headers.Contains(http_names::kRange)),
      corp_checker_(std::move(corp_checker)),
      task_runner_(context->GetTaskRunner(TaskType::kNetworking)) {}

void FetchRespondWithObserver::Trace(Visitor* visitor) const {
  visitor->Trace(event_);
  visitor->Trace(original_request_body_stream_);
  RespondWithObserver::Trace(visitor);
}

}  // namespace blink

"""

```