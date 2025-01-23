Response:
Let's break down the thought process for analyzing the `threadable_loader.cc` file.

1. **Understand the Core Purpose:** The file name itself, `threadable_loader.cc`, gives a strong hint. It likely deals with loading resources in a way that can be handled across threads. The inclusion of "loader" suggests it's involved in fetching data.

2. **Examine Includes:** The `#include` directives are crucial for understanding dependencies and functionality. Let's categorize them:
    * **Foundation/Utilities:** `memory`, `base/metrics`, `base/numerics`, `base/task`, `base/time`. These indicate general utility functions, time management, and task scheduling.
    * **Networking:**  `services/network/public/cpp/cors`, `services/network/public/mojom/cors.mojom-blink.h`, `services/network/public/mojom/fetch_api.mojom-blink.h`, `third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h`. These strongly point to handling network requests, CORS (Cross-Origin Resource Sharing), and the Fetch API.
    * **Blink Core:** `third_party/blink/renderer/core/...`. This is where the main business logic related to rendering and the DOM resides. Specific includes like `frame/frame_console.h`, `frame/local_dom_window.h`, `frame/local_frame.h` indicate interactions with the frame structure. `loader/threadable_loader_client.h` is particularly important as it defines the interface for interacting with this loader.
    * **Platform:** `third_party/blink/renderer/platform/...`. This layer deals with platform-specific abstractions for things like memory management (`heap`), loading (`loader`), and general utilities (`wtf`). Includes like `loader/cors/cors.h`, `loader/fetch/...` are key to understanding the loading process.

3. **Identify Key Classes:** Look for the main class definition within the file. In this case, it's `ThreadableLoader`. Also, note any nested or helper classes (like `DetachedClient`).

4. **Analyze `ThreadableLoader` Members:**  Examine the member variables of the `ThreadableLoader` class:
    * `resource_loader_options_`: Configuration options for loading resources.
    * `client_`: A pointer to a `ThreadableLoaderClient`, indicating a delegate pattern for handling loading events.
    * `execution_context_`:  Provides context for the loader, like the current frame or worker.
    * `resource_fetcher_`:  Responsible for fetching the actual resource data.
    * `request_mode_`: The mode of the network request (e.g., `kSameOrigin`, `kNoCors`).
    * `timeout_timer_`: A timer for managing request timeouts.
    * `request_started_`: The time when the request started.
    * `timeout_`: The configured timeout duration.
    * `checker_`: Likely related to some internal checks or state management.

5. **Analyze `ThreadableLoader` Methods:** Go through the public and significant private methods:
    * **Constructor:** Initializes the `ThreadableLoader`.
    * **`Start()`:** Initiates the loading process. Pay close attention to how it handles different request contexts (e.g., video, audio, manifest) and synchronous/asynchronous loading.
    * **`SetTimeout()`:**  Allows setting or modifying the request timeout.
    * **`Cancel()`:** Aborts the loading process.
    * **`Detach()`:**  Allows detaching the loader from its original client, often used for `keepalive` requests.
    * **`SetDefersLoading()`:** Pauses or resumes the loading process.
    * **`Clear()`:**  Releases resources and cleans up the loader.
    * **Event Handlers (prefixed with `Did...`):** These methods are callbacks invoked by the lower-level resource loading mechanisms. They correspond to different stages of the loading process (redirect received, data sent, response received, data received, loading finished, loading failed, etc.).
    * **`DispatchDidFail()`:** A helper to handle failures.
    * **`Trace()`:** For debugging and memory management.
    * **`GetTaskRunner()`:**  Returns the task runner for networking operations.

6. **Examine `DetachedClient`:** Understand its purpose. The comments clearly state it's for `keepalive` requests and manages its own lifetime using `SelfKeepAlive`.

7. **Identify Relationships with JavaScript, HTML, and CSS:** Based on the methods and includes, determine how this class interacts with web technologies:
    * **JavaScript:** The loading process is often initiated by JavaScript (e.g., `fetch()`, `XMLHttpRequest`). The `ThreadableLoader` handles the underlying network request. Timeouts set by JavaScript's `XMLHttpRequest` API are likely managed by the `SetTimeout()` method.
    * **HTML:**  Loading resources referenced in HTML (e.g., images, scripts, stylesheets) uses this infrastructure. The `request_context` in the `Start()` method can be set based on the HTML element initiating the request.
    * **CSS:** Similar to HTML, loading CSS stylesheets relies on this loading mechanism.

8. **Look for Logic and Potential Issues:**
    * **CORS:** The code explicitly checks for CORS-related settings and security.
    * **Timeouts:** The `timeout_timer_` and `SetTimeout()` logic are important. Potential errors could involve incorrect timeout calculations or race conditions.
    * **Cancellation:** The `Cancel()` method needs to handle potential re-entrancy.
    * **Detached Requests:** The `DetachedClient` is a specialized case that needs careful handling to avoid memory leaks.
    * **Service Workers:** The code mentions bypassing service workers in DevTools, indicating an interaction with service worker functionality.

9. **Infer User Actions and Debugging:**  Think about how a user's actions in a browser might lead to this code being executed. For example, clicking a link, submitting a form, or JavaScript making a network request. Consider how errors during these actions could involve this class.

10. **Structure the Analysis:** Organize the findings into logical categories (functionality, relationships, logic, errors, debugging). Use examples to illustrate the connections to web technologies and potential issues.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** "This is just about downloading files."
* **Correction:**  The code handles much more than simple downloads. It deals with CORS, timeouts, different request types, service workers, and integrates deeply with the Blink rendering engine.

* **Initial Thought:** "The timeout logic is straightforward."
* **Refinement:** The `SetTimeout()` method has specific handling for `XMLHttpRequest` and needs to account for the elapsed time since the request started. The difference between initial timeout setting and modifying an existing timeout needs to be considered.

* **Initial Thought:** "The `DetachedClient` seems overly complex."
* **Refinement:** Understanding that it's designed for `keepalive` requests and needs to manage its own lifecycle clarifies its purpose and the need for `SelfKeepAlive`.

By following this structured approach, examining the code details, and iteratively refining understanding, a comprehensive analysis of the `threadable_loader.cc` file can be achieved.
好的，让我们来详细分析一下 `blink/renderer/core/loader/threadable_loader.cc` 这个文件。

**文件功能概述**

`ThreadableLoader` 类在 Chromium Blink 渲染引擎中扮演着**发起和管理网络请求**的核心角色。 它的主要功能是：

1. **发起资源请求:**  根据提供的 `ResourceRequest` 对象，利用底层的网络栈（通过 `ResourceFetcher`）发起 HTTP(S) 请求。
2. **处理请求生命周期:**  管理请求的各个阶段，包括：
    * 请求开始
    * 重定向处理
    * 数据发送和接收
    * 响应接收
    * 缓存元数据处理
    * 下载完成或失败
    * 超时处理
    * 请求取消
3. **作为 `ThreadableLoaderClient` 的代理:**  `ThreadableLoader` 本身并不直接处理接收到的数据或错误，而是通过 `ThreadableLoaderClient` 接口将这些事件通知给它的客户端。
4. **支持同步和异步请求:**  可以根据 `ResourceLoaderOptions` 配置，以同步或异步的方式发起请求。
5. **处理请求超时:**  可以设置请求超时时间，并在超时后通知客户端。
6. **支持 "detached" 请求 (keepalive):**  允许在发起请求后解除与原始客户端的关联，用于 `keepalive` 请求，例如 `navigator.sendBeacon()`。
7. **处理 CORS (跨域资源共享):**  虽然代码本身不直接实现 CORS 逻辑，但它会根据请求的 `RequestMode` 等信息，与底层的 CORS 实现进行交互。
8. **集成开发者工具:**  通过 `probe::ShouldBypassServiceWorker` 等机制，与开发者工具集成，例如允许绕过 Service Worker 进行网络请求。

**与 JavaScript, HTML, CSS 的关系及举例**

`ThreadableLoader` 是 Blink 引擎中处理网络请求的关键组件，因此与 JavaScript, HTML, 和 CSS 的加载息息相关。

**1. 与 JavaScript 的关系:**

* **`fetch()` API:** 当 JavaScript 代码使用 `fetch()` API 发起网络请求时，Blink 内部会创建 `ThreadableLoader` 来执行这个请求。
    * **假设输入:** JavaScript 代码 `fetch('https://example.com/data.json')` 被执行。
    * **输出:**  Blink 会创建一个 `ThreadableLoader` 实例，并调用其 `Start()` 方法，传入构造好的 `ResourceRequest` 对象，该对象包含了请求的 URL、方法、头部等信息。
* **`XMLHttpRequest` (XHR):**  `ThreadableLoader` 也被用于处理 `XMLHttpRequest` 发起的请求。XHR 对象的配置（如超时时间）会影响 `ThreadableLoader` 的行为。
    * **假设输入:** JavaScript 代码 `const xhr = new XMLHttpRequest(); xhr.open('GET', 'image.png'); xhr.send();` 被执行。
    * **输出:**  Blink 创建一个 `ThreadableLoader`，并根据 XHR 的配置发起对 `image.png` 的请求。`ThreadableLoader` 的 `SetTimeout()` 方法可能会被调用来设置超时时间。
* **`navigator.sendBeacon()`:**  这个 API 用于发送少量数据到服务器，即使页面已经卸载。 `ThreadableLoader` 的 "detached" 功能被用于实现 `sendBeacon()`，允许请求在页面关闭后继续执行。
    * **假设输入:** JavaScript 代码 `navigator.sendBeacon('/log', 'user action');` 被执行。
    * **输出:**  Blink 创建一个 `ThreadableLoader`，并调用其 `Detach()` 方法，使其在请求完成后可以自行销毁，而不会依赖于原始的页面上下文。

**2. 与 HTML 的关系:**

* **加载图片 (`<img>` 标签):** 当浏览器解析到 `<img>` 标签时，会创建一个 `ThreadableLoader` 来下载图片资源。
    * **用户操作:** 用户在浏览器中打开一个包含 `<img src="logo.png">` 的 HTML 页面。
    * **调试线索:**  如果在开发者工具的网络面板中看到对 `logo.png` 的请求，并且请求的状态是 "pending" 或正在传输，则意味着 `ThreadableLoader` 正在工作。
* **加载脚本 (`<script>` 标签):**  `<script>` 标签用于加载 JavaScript 代码，浏览器会使用 `ThreadableLoader` 来获取脚本文件。
    * **用户操作:** 用户访问一个包含 `<script src="script.js"></script>` 的页面。
    * **调试线索:**  如果在开发者工具中看到对 `script.js` 的请求，并且请求失败或者超时，可能与 `ThreadableLoader` 的错误处理或超时机制有关。
* **加载样式表 (`<link rel="stylesheet">` 标签):**  CSS 样式表也通过 `ThreadableLoader` 加载。
    * **用户操作:** 用户打开一个包含 `<link rel="stylesheet" href="style.css">` 的页面。
    * **调试线索:** 如果页面样式显示异常，开发者可以检查网络面板中 `style.css` 的请求状态，如果请求失败，可能是 `ThreadableLoader` 在加载过程中遇到了问题。

**3. 与 CSS 的关系:** (与 HTML 的例子类似)

* **`url()` 函数:** CSS 中使用 `url()` 函数引用图片、字体等资源时，浏览器也会使用 `ThreadableLoader` 来加载这些资源。
    * **假设输入:** CSS 文件包含 `background-image: url('bg.jpg');`。
    * **输出:**  浏览器创建一个 `ThreadableLoader` 来获取 `bg.jpg`。

**逻辑推理的假设输入与输出**

* **假设输入:** 调用 `ThreadableLoader::Start()` 方法，传入一个 `ResourceRequest` 对象，其 `timeout` 属性设置为 5 秒。
* **输出:**
    * 如果在 5 秒内请求成功完成，则调用 `ThreadableLoaderClient::DidFinishLoading()`。
    * 如果 5 秒超时，且请求仍在进行中，则 `timeout_timer_` 会触发 `ThreadableLoader::DidTimeout()`，然后调用 `ThreadableLoaderClient::DidFail()` 并传入一个超时错误。

* **假设输入:** 调用 `ThreadableLoader::Cancel()` 方法时，请求正在进行中。
* **输出:**  底层网络请求会被取消，并且 `ThreadableLoaderClient::DidFail()` 会被调用，传入一个取消错误。

**用户或编程常见的使用错误**

1. **忘记设置 `ThreadableLoaderClient`:** 如果创建 `ThreadableLoader` 时没有提供有效的 `ThreadableLoaderClient`，则加载事件无法传递给调用者，导致请求的结果无法被处理。
    * **例子:**  在某个加载模块中，错误地创建了 `ThreadableLoader` 但没有正确地将其与客户端关联。
2. **在不适当的时候调用 `Cancel()`:**  如果在请求已经完成或失败后调用 `Cancel()`，可能会导致程序出现意外行为或崩溃（虽然代码中有检查，但仍然可能存在边界情况）。
3. **错误地配置请求超时:**  设置过短的超时时间可能导致请求在网络状况稍差的情况下就被意外取消。
4. **同步请求的滥用:**  在主线程上发起同步请求会阻塞浏览器渲染，导致用户界面卡顿。应该尽可能使用异步请求。
    * **用户操作:** 用户点击一个按钮，触发一个 JavaScript 函数，该函数使用同步的 `XMLHttpRequest` 发送一个耗时的请求。
    * **调试线索:**  在开发者工具的性能面板中可以看到主线程被长时间阻塞。
5. **CORS 相关配置错误:**  如果服务器没有正确配置 CORS 头部，而客户端发起了跨域请求，`ThreadableLoader` 会因为 CORS 检查失败而阻止请求。
    * **用户操作:** 页面 A 的 JavaScript 代码尝试使用 `fetch()` API 请求页面 B 的资源，但页面 B 的服务器没有设置允许页面 A 跨域访问的 CORS 头部。
    * **调试线索:**  浏览器控制台会显示 CORS 相关的错误信息，并且网络面板中请求的状态可能是 "CORS error"。

**用户操作如何一步步到达这里 (作为调试线索)**

假设用户在浏览器中访问一个网页，网页包含一个 JavaScript 代码，该代码使用 `fetch()` API 获取一个 JSON 数据：

1. **用户在地址栏输入 URL 并按下回车，或点击一个链接。**
2. **浏览器开始解析 HTML 页面。**
3. **浏览器解析到 `<script>` 标签，其中包含发起 `fetch()` 请求的代码。**
4. **JavaScript 引擎执行这段代码，调用 `fetch('https://api.example.com/data')`。**
5. **Blink 渲染引擎接收到 `fetch()` 请求，并创建一个 `ThreadableLoader` 实例。**
6. **`ThreadableLoader::Start()` 方法被调用，传入包含了 `https://api.example.com/data` 的 `ResourceRequest` 对象。**
7. **`ThreadableLoader` 使用 `ResourceFetcher` 向网络栈发起请求。**
8. **如果请求成功，`ThreadableLoader` 会依次接收到响应头和响应体，并分别通过 `ThreadableLoaderClient::DidReceiveResponse()` 和 `ThreadableLoaderClient::DidReceiveData()` 通知客户端。**
9. **最终，请求完成，`ThreadableLoaderClient::DidFinishLoading()` 被调用。**

**调试线索:**

* **网络面板:** 开发者工具的网络面板会显示对 `https://api.example.com/data` 的请求，可以查看请求的状态、头部、响应内容、耗时等信息。
* **断点调试:** 可以在 `ThreadableLoader::Start()`, `DidReceiveResponse()`, `DidReceiveData()`, `DidFail()` 等关键方法设置断点，观察请求的执行流程和状态。
* **控制台输出:**  在 `ThreadableLoaderClient` 的实现中添加日志输出，可以追踪请求的生命周期事件。
* **CORS 错误信息:** 如果请求失败，检查浏览器控制台是否输出了 CORS 相关的错误信息。
* **超时错误:** 如果请求超时，检查网络面板中请求的耗时，以及是否触发了 `ThreadableLoader::DidTimeout()`。

希望以上分析能够帮助你理解 `blink/renderer/core/loader/threadable_loader.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/loader/threadable_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011, 2012 Google Inc. All rights reserved.
 * Copyright (C) 2013, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/loader/threadable_loader.h"

#include <memory>

#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "services/network/public/cpp/cors/cors_error_status.h"
#include "services/network/public/mojom/cors.mojom-blink.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/threadable_loader_client.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/self_keep_alive.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/loader_freeze_mode.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"

namespace blink {

namespace {

// DetachedClient is a ThreadableLoaderClient for a "detached"
// ThreadableLoader. It's for fetch requests with keepalive set, so
// it keeps itself alive during loading.
class DetachedClient final : public GarbageCollected<DetachedClient>,
                             public ThreadableLoaderClient {
 public:
  explicit DetachedClient(ThreadableLoader* loader)
      : loader_(loader), detached_time_(base::TimeTicks::Now()) {}
  ~DetachedClient() override = default;

  void DidFinishLoading(uint64_t identifier) override {
    LogKeepAliveDuration();
    self_keep_alive_.Clear();
  }
  void DidFail(uint64_t identifier, const ResourceError&) override {
    LogKeepAliveDuration();
    self_keep_alive_.Clear();
  }
  void DidFailRedirectCheck(uint64_t identifier) override {
    LogKeepAliveDuration();
    self_keep_alive_.Clear();
  }
  void Trace(Visitor* visitor) const override {
    visitor->Trace(loader_);
    ThreadableLoaderClient::Trace(visitor);
  }

 private:
  void LogKeepAliveDuration() {
    base::TimeDelta duration_after_detached =
        base::TimeTicks::Now() - detached_time_;
    // kKeepaliveLoadersTimeout > 10 sec, so UmaHistogramTimes can't be used.
    base::UmaHistogramMediumTimes("FetchKeepAlive.RequestOutliveDuration",
                                  duration_after_detached);
  }

  SelfKeepAlive<DetachedClient> self_keep_alive_{this};
  // Keep it alive.
  const Member<ThreadableLoader> loader_;
  base::TimeTicks detached_time_;
};

}  // namespace

ThreadableLoader::ThreadableLoader(
    ExecutionContext& execution_context,
    ThreadableLoaderClient* client,
    const ResourceLoaderOptions& resource_loader_options,
    ResourceFetcher* resource_fetcher)
    : resource_loader_options_(resource_loader_options),
      client_(client),
      execution_context_(execution_context),
      resource_fetcher_(resource_fetcher),
      request_mode_(network::mojom::RequestMode::kSameOrigin),
      timeout_timer_(execution_context_->GetTaskRunner(TaskType::kNetworking),
                     this,
                     &ThreadableLoader::DidTimeout) {
  DCHECK(client);
  if (!resource_fetcher_) {
    resource_fetcher_ = execution_context_->Fetcher();
  }
}

void ThreadableLoader::Start(ResourceRequest request) {
  const auto request_context = request.GetRequestContext();
  if (request.GetMode() == network::mojom::RequestMode::kNoCors) {
    SECURITY_CHECK(cors::IsNoCorsAllowedContext(request_context));
  }

  // Setting an outgoing referer is only supported in the async code path.
  DCHECK(resource_loader_options_.synchronous_policy ==
             kRequestAsynchronously ||
         request.ReferrerString() == Referrer::ClientReferrerString());

  // kPreventPreflight can be used only when the CORS is enabled.
  DCHECK(request.CorsPreflightPolicy() ==
             network::mojom::CorsPreflightPolicy::kConsiderPreflight ||
         cors::IsCorsEnabledRequestMode(request.GetMode()));

  request_started_ = base::TimeTicks::Now();
  request_mode_ = request.GetMode();

  // Set the service worker mode to none if "bypass for network" in DevTools is
  // enabled.
  bool should_bypass_service_worker = false;
  probe::ShouldBypassServiceWorker(execution_context_,
                                   &should_bypass_service_worker);
  if (should_bypass_service_worker)
    request.SetSkipServiceWorker(true);

  const bool async =
      resource_loader_options_.synchronous_policy == kRequestAsynchronously;
  if (!timeout_.is_zero()) {
    if (!async) {
      request.SetTimeoutInterval(timeout_);
    } else if (!timeout_timer_.IsActive()) {
      timeout_timer_.StartOneShot(timeout_, FROM_HERE);
    }
  }

  FetchParameters params(std::move(request), resource_loader_options_);
  DCHECK(!GetResource());

  checker_.WillAddClient();
  if (request_context == mojom::blink::RequestContextType::VIDEO ||
      request_context == mojom::blink::RequestContextType::AUDIO) {
    DCHECK(async);
    RawResource::FetchMedia(params, resource_fetcher_, this);
  } else if (request_context == mojom::blink::RequestContextType::MANIFEST) {
    DCHECK(async);
    RawResource::FetchManifest(params, resource_fetcher_, this);
  } else if (async) {
    RawResource::Fetch(params, resource_fetcher_, this);
  } else {
    RawResource::FetchSynchronously(params, resource_fetcher_, this);
  }
}

ThreadableLoader::~ThreadableLoader() = default;

void ThreadableLoader::SetTimeout(const base::TimeDelta& timeout) {
  timeout_ = timeout;

  // |request_started_| <= base::TimeTicks() indicates loading is either not yet
  // started or is already finished, and thus we don't need to do anything with
  // timeout_timer_.
  if (request_started_ <= base::TimeTicks()) {
    DCHECK(!timeout_timer_.IsActive());
    return;
  }
  DCHECK_EQ(kRequestAsynchronously,
            resource_loader_options_.synchronous_policy);
  timeout_timer_.Stop();

  // At the time of this method's implementation, it is only ever called for an
  // inflight request by XMLHttpRequest.
  //
  // The XHR request says to resolve the time relative to when the request
  // was initially sent, however other uses of this method may need to
  // behave differently, in which case this should be re-arranged somehow.
  if (!timeout_.is_zero()) {
    base::TimeDelta elapsed_time = base::TimeTicks::Now() - request_started_;
    base::TimeDelta resolved_time =
        std::max(timeout_ - elapsed_time, base::TimeDelta());
    timeout_timer_.StartOneShot(resolved_time, FROM_HERE);
  }
}

void ThreadableLoader::Cancel() {
  // Cancel can re-enter, and therefore |resource()| might be null here as a
  // result.
  if (!client_ || !GetResource()) {
    Clear();
    return;
  }

  DispatchDidFail(ResourceError::CancelledError(GetResource()->Url()));
}

void ThreadableLoader::Detach() {
  Resource* resource = GetResource();
  if (!resource)
    return;
  client_ = MakeGarbageCollected<DetachedClient>(this);
}

void ThreadableLoader::SetDefersLoading(bool value) {
  if (GetResource() && GetResource()->Loader()) {
    GetResource()->Loader()->SetDefersLoading(value ? LoaderFreezeMode::kStrict
                                                    : LoaderFreezeMode::kNone);
  }
}

void ThreadableLoader::Clear() {
  client_ = nullptr;
  timeout_timer_.Stop();
  request_started_ = base::TimeTicks();
  if (GetResource())
    checker_.WillRemoveClient();
  ClearResource();
}

bool ThreadableLoader::RedirectReceived(
    Resource* resource,
    const ResourceRequest& new_request,
    const ResourceResponse& redirect_response) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());
  checker_.RedirectReceived();

  return client_->WillFollowRedirect(resource->InspectorId(), new_request.Url(),
                                     redirect_response);
}

void ThreadableLoader::RedirectBlocked() {
  DCHECK(client_);
  checker_.RedirectBlocked();

  // Tells the client that a redirect was received but not followed (for an
  // unknown reason).
  ThreadableLoaderClient* client = client_;
  Clear();
  uint64_t identifier = 0;  // We don't have an inspector id here.
  client->DidFailRedirectCheck(identifier);
}

void ThreadableLoader::DataSent(Resource* resource,
                                uint64_t bytes_sent,
                                uint64_t total_bytes_to_be_sent) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());
  DCHECK_EQ(kRequestAsynchronously,
            resource_loader_options_.synchronous_policy);

  checker_.DataSent();
  client_->DidSendData(bytes_sent, total_bytes_to_be_sent);
}

void ThreadableLoader::DataDownloaded(Resource* resource,
                                      uint64_t data_length) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());

  checker_.DataDownloaded();
  client_->DidDownloadData(data_length);
}

void ThreadableLoader::DidDownloadToBlob(Resource* resource,
                                         scoped_refptr<BlobDataHandle> blob) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());

  checker_.DidDownloadToBlob();
  client_->DidDownloadToBlob(std::move(blob));
}

void ThreadableLoader::ResponseReceived(Resource* resource,
                                        const ResourceResponse& response) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());

  checker_.ResponseReceived();

  // If "Cache-Control: no-store" header exists in the XHR response,
  // Back/Forward cache will be disabled for the page if the main resource has
  // "Cache-Control: no-store" as well.
  if (response.CacheControlContainsNoStore()) {
    execution_context_->GetScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::
            kJsNetworkRequestReceivedCacheControlNoStoreResource,
        {SchedulingPolicy::DisableBackForwardCache()});
  }

  client_->DidReceiveResponse(resource->InspectorId(), response);
}

void ThreadableLoader::ResponseBodyReceived(Resource* resource,
                                            BytesConsumer& body) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());

  checker_.ResponseBodyReceived();
  client_->DidStartLoadingResponseBody(body);
}

void ThreadableLoader::CachedMetadataReceived(
    Resource* resource,
    mojo_base::BigBuffer cached_metadata) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());

  checker_.SetSerializedCachedMetadata();

  client_->DidReceiveCachedMetadata(std::move(cached_metadata));
}

void ThreadableLoader::DataReceived(Resource* resource,
                                    base::span<const char> data) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());

  checker_.DataReceived();

  client_->DidReceiveData(data);
}

void ThreadableLoader::NotifyFinished(Resource* resource) {
  DCHECK(client_);
  DCHECK_EQ(resource, GetResource());

  checker_.NotifyFinished(resource);

  if (resource->ErrorOccurred()) {
    DispatchDidFail(resource->GetResourceError());
    return;
  }

  ThreadableLoaderClient* client = client_;
  // Protect the resource in |DidFinishLoading| in order not to release the
  // downloaded file.
  Persistent<Resource> protect = GetResource();
  Clear();
  client->DidFinishLoading(resource->InspectorId());
}

void ThreadableLoader::DidTimeout(TimerBase* timer) {
  DCHECK_EQ(kRequestAsynchronously,
            resource_loader_options_.synchronous_policy);
  DCHECK_EQ(timer, &timeout_timer_);
  // ClearResource() may be called in Clear() and some other places. Clear()
  // calls Stop() on |timeout_|. In the other places, the resource is set
  // again. If the creation fails, Clear() is called. So, here, GetResource() is
  // always non-nullptr.
  DCHECK(GetResource());
  // When |client_| is set to nullptr only in Clear() where |timeout_|
  // is stopped. So, |client_| is always non-nullptr here.
  DCHECK(client_);

  DispatchDidFail(ResourceError::TimeoutError(GetResource()->Url()));
}

void ThreadableLoader::DispatchDidFail(const ResourceError& error) {
  Resource* resource = GetResource();
  if (resource)
    resource->SetResponseType(network::mojom::FetchResponseType::kError);
  ThreadableLoaderClient* client = client_;
  Clear();
  client->DidFail(resource->InspectorId(), error);
}

void ThreadableLoader::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(client_);
  visitor->Trace(resource_fetcher_);
  visitor->Trace(timeout_timer_);
  visitor->Trace(resource_loader_options_);
  RawResourceClient::Trace(visitor);
}

scoped_refptr<base::SingleThreadTaskRunner> ThreadableLoader::GetTaskRunner() {
  return execution_context_->GetTaskRunner(TaskType::kNetworking);
}

}  // namespace blink
```