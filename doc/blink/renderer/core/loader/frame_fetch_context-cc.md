Response:
Let's break down the thought process for analyzing this code snippet and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the purpose of the `frame_fetch_context.cc` file within the Chromium Blink rendering engine. This involves identifying its main responsibilities, its relationship with other browser functionalities (especially JavaScript, HTML, CSS), potential user/developer errors, debugging entry points, and a summary.

**2. Initial Scan and Keyword Identification:**

A quick read-through reveals several important keywords and concepts:

* **`FrameFetchContext`:** This is the central entity. It suggests something related to fetching resources within the context of a frame.
* **`ResourceRequest`:**  Indicates handling of network requests.
* **`Client Hints`:**  A prominent feature being handled, related to sending browser information to the server.
* **`Cache`:** Interaction with the browser cache.
* **`Permissions Policy`:**  Enforcing security policies.
* **`User Agent`:**  Managing the browser's user agent string and related hints.
* **`DocumentLoader`:**  Part of the process of loading a web page.
* **`LocalFrame`:** Represents an individual frame within a web page.
* **`JavaScript`, `HTML`, `CSS`:** Explicitly mentioned in the prompt, so connections need to be explored.
* **`mojom`:**  Indicates the use of Mojo interfaces, which are used for inter-process communication in Chromium.

**3. Deeper Dive into Key Functionalities:**

Based on the keywords, I started to analyze specific sections of the code:

* **`FrameFetchContext::CreateFetcherForCommittedDocument`:** This clearly sets up the infrastructure for fetching resources for a given document within a frame. It instantiates `ResourceFetcher` and related components. This is a crucial starting point for resource loading within a frame.
* **`FrameFetchContext::ResourceRequestCachePolicy`:**  Deals with determining how caching should be handled for requests originating from this frame. It considers factors like the frame's load type (reload, back/forward, etc.).
* **`FrameFetchContext::PrepareRequest`:**  This function is central to modifying and preparing a `ResourceRequest` before it's sent. It handles things like setting the user agent, top-frame origin, UKM source ID, storage access API status, attribution reporting, and importantly, calls into the service worker if one is active.
* **`FrameFetchContext::AddClientHintsIfNecessary`:** This section is extensive and dedicated to adding client hints to outgoing requests based on permissions policy, user preferences, and network conditions. It directly addresses a key feature of the class. I noticed the use of `ShouldSendClientHint` and the various `WebClientHintsType` enums.
* **`FrameFetchContext::ModifyRequestForCSP`:**  Handles Content Security Policy considerations for requests.
* **`FrameFetchContext::AllowImage`:**  Determines if images should be loaded based on settings.

**4. Identifying Relationships with JavaScript, HTML, and CSS:**

* **JavaScript:** The code mentions `ScriptController` and checks `GetFrame()->ScriptEnabled()`. This indicates the `FrameFetchContext` is aware of whether JavaScript is allowed to run, which can impact client hints and other behaviors. JavaScript code can trigger resource requests (e.g., fetching data, loading images dynamically), and this class plays a role in preparing those requests.
* **HTML:** The class interacts with `Document` and `LocalFrame`, which are fundamental parts of the HTML DOM structure. When the browser parses HTML and encounters elements that require fetching resources (like `<img>`, `<link>`, `<script>`), the `FrameFetchContext` is involved in the fetching process.
* **CSS:**  Similar to HTML, when the browser encounters CSS files or CSS rules that require fetching resources (like background images), this context is relevant. The `GetDevicePixelRatio()` method, used for client hints, is also relevant for CSS media queries.

**5. Logical Reasoning (Hypothetical Input/Output):**

To illustrate the logic, I considered a simple scenario: a user clicks a link to load a new page.

* **Input:**  User clicks a link (`<a>` tag) pointing to a new URL.
* **Processing:**
    * The browser determines it needs to load a new frame.
    * A `FrameFetchContext` is created (or used).
    * A `ResourceRequest` is created for the new URL.
    * `PrepareRequest` is called:
        * User agent is set.
        * Top-frame origin is determined.
        * Client hints are added (based on policy and preferences).
        * CSP is considered.
    * The request is sent.
* **Output:** The network request is sent with the appropriate headers and settings, eventually leading to the new page being loaded.

**6. Identifying Potential User/Developer Errors:**

I focused on common mistakes related to features the code handles:

* **Incorrect Client Hint Configuration:**  A developer might expect a client hint to be sent, but it's blocked by permissions policy or user settings.
* **Cache Mismanagement:**  Developers might not understand how browser caching works, leading to unexpected behavior (e.g., stale content). The `ResourceRequestCachePolicy` function is relevant here.
* **CSP Violations:**  Incorrectly configured Content Security Policy can block resource loading, and `ModifyRequestForCSP` plays a role in this process.

**7. Tracing User Actions (Debugging Clues):**

I thought about how a developer might end up debugging in this file:

* **Network Request Issues:** If a network request is failing, has incorrect headers, or is not being cached as expected, a developer might set breakpoints in `PrepareRequest` or `ResourceRequestCachePolicy`.
* **Client Hint Problems:**  If client hints are not being sent correctly, `AddClientHintsIfNecessary` would be a key area to investigate.
* **CSP Errors:**  If resources are being blocked by CSP, `ModifyRequestForCSP` would be examined.

**8. Summarization:**

Finally, I synthesized the findings into a concise summary that captures the core purpose of the `FrameFetchContext`.

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on one aspect (e.g., client hints). I then would have revisited the code to ensure a more balanced view of all its responsibilities. I also double-checked the connection between the code and the concepts of JavaScript, HTML, and CSS to provide concrete examples. The "mojom" aspect reminded me of the importance of inter-process communication in Chromium's architecture.
好的，让我们来分析一下 `blink/renderer/core/loader/frame_fetch_context.cc` 文件的功能。

**功能归纳:**

`FrameFetchContext` 的主要职责是为 **Frame (特别是 LocalFrame)** 中发起的资源请求提供上下文信息和配置。它充当一个中心枢纽，收集和管理与资源获取相关的各种设置、策略和状态，并将这些信息应用于即将发起的网络请求。

**具体功能列表:**

1. **构建和配置 `ResourceRequest` 对象:**  这是核心功能。`FrameFetchContext` 负责准备 `ResourceRequest` 对象，使其包含正确的请求头、缓存策略、安全策略等信息。
2. **处理客户端提示 (Client Hints):**  根据 Permissions Policy、用户偏好和网络状态，添加适当的客户端提示请求头（例如 `Device-Memory`, `RTT`, `Downlink`, `ECT`, `UA`, `DPR`, `Save-Data` 等）。
3. **管理缓存策略:**  根据 Frame 的加载类型（例如，标准加载、刷新、后退/前进）和父 Frame 的缓存策略，确定资源请求的缓存模式 (`FetchCacheMode`)。
4. **应用内容安全策略 (CSP):**  在发送请求前，根据 Frame 的 CSP 设置修改请求。
5. **处理用户代理 (User Agent) 信息:**  设置请求的 `User-Agent` 头，并处理与 User-Agent Client Hints 相关的逻辑。
6. **管理 Cookie 策略:**  确定请求的 `Site-For-Cookies`。
7. **处理 Storage Access API 状态:**  将当前文档的 Storage Access API 状态添加到请求中。
8. **支持 Attribution Reporting:**  如果 Frame 启用了 Attribution Reporting，则在请求中添加相应的支持信息。
9. **处理 Shared Storage:**  根据 Permissions Policy 检查是否允许写入 Shared Storage。
10. **支持 Shared Dictionary:**  检查是否启用了共享字典功能。
11. **集成 Service Worker:**  在请求发送前，如果存在 Service Worker，则调用 Service Worker 的 `WillSendRequest` 方法。
12. **记录资源加载时序信息 (Resource Timing):**  将资源加载的时序信息报告给 `DOMWindowPerformance`。
13. **控制图片加载:**  根据 Frame 的设置，决定是否允许加载图片。
14. **处理虚拟时间 (Virtual Time):**  在资源请求期间创建和管理虚拟时间暂停器。
15. **提供 Subresource Filter 上下文:**  提供访问 `SubresourceFilter` 的接口。
16. **管理 LCP (Largest Contentful Paint) 预测回调:**  用于优化 LCP 的相关功能。
17. **与 `ResourceFetcher` 关联:**  为 `ResourceFetcher` 提供必要的上下文信息。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **场景:** JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起网络请求。
    * **`FrameFetchContext` 参与:** 当 JavaScript 发起请求时，Blink 会创建或使用 `FrameFetchContext` 来准备底层的 `ResourceRequest`。`FrameFetchContext` 会根据当前的 Frame 上下文（例如，是否允许 JavaScript 执行，Permissions Policy 等）来配置请求。
    * **举例:**  一个 JavaScript 脚本尝试获取一个 JSON 数据：
        ```javascript
        fetch('/api/data.json')
          .then(response => response.json())
          .then(data => console.log(data));
        ```
        在这个过程中，`FrameFetchContext` 会确保请求头包含正确的 `User-Agent`、可能的客户端提示 (例如，如果 Permissions Policy 允许，并且满足其他条件)，并应用 CSP 策略。

* **HTML:**
    * **场景:** HTML 文档包含需要加载外部资源的元素，例如 `<img>`, `<link rel="stylesheet">`, `<script src="...">`.
    * **`FrameFetchContext` 参与:** 当浏览器解析 HTML 并遇到这些元素时，会触发资源加载。`FrameFetchContext` 负责为这些资源创建并配置 `ResourceRequest`。
    * **举例:**  一个 HTML 页面包含一个图片：
        ```html
        <img src="/images/logo.png" alt="Logo">
        ```
        当浏览器加载这个页面时，`FrameFetchContext` 会为 `/images/logo.png` 创建一个 `ResourceRequest`，并根据 Frame 的设置 (`GetSettings()->GetLoadsImagesAutomatically()`) 来决定是否允许加载图片。如果允许，还会添加适当的客户端提示。

* **CSS:**
    * **场景:** CSS 文件或 `<style>` 标签中的 CSS 规则引用了外部资源，例如 `background-image: url(...)`.
    * **`FrameFetchContext` 参与:**  当浏览器解析 CSS 并遇到需要加载外部资源的规则时，`FrameFetchContext` 会参与创建和配置相应的 `ResourceRequest`。
    * **举例:**  一个 CSS 文件设置了背景图片：
        ```css
        body {
          background-image: url('/images/background.jpg');
        }
        ```
        加载这个 CSS 文件时，`FrameFetchContext` 会为 `/images/background.jpg` 创建 `ResourceRequest`，并可能添加 `DPR` 客户端提示，以便服务器可以根据设备像素比率提供合适的图片。

**逻辑推理 (假设输入与输出):**

假设输入：

* 当前 Frame 的加载类型是标准加载 (`WebFrameLoadType::kStandard`).
* Permissions Policy 允许发送 `Device-Memory` 客户端提示.
* 用户的设备内存约为 8GB.

输出 (添加到 `ResourceRequest` 的相关信息):

* `request.SetCacheMode(mojom::FetchCacheMode::kDefault);`  // 标准加载通常使用默认缓存策略.
* `request.SetHttpHeaderField(http_names::kDeviceMemory, AtomicString("8"));` // 添加 Device-Memory 客户端提示.

假设输入：

* 当前 Frame 正在进行刷新操作 (`WebFrameLoadType::kReloadBypassingCache`).

输出 (添加到 `ResourceRequest` 的相关信息):

* `request.SetCacheMode(mojom::FetchCacheMode::kBypassCache);` // 刷新操作会绕过缓存.

**用户或编程常见的使用错误举例:**

1. **错误配置 Permissions Policy 导致客户端提示无法发送:**
   * **错误:** 开发者期望发送 `Device-Memory` 客户端提示，但忘记在 HTTP 响应头中设置 `Permissions-Policy: ch-device-memory=(self)` 或其他允许的源。
   * **结果:** `FrameFetchContext` 的 `ShouldSendClientHint` 函数会返回 `false`，导致请求头中缺少 `Device-Memory`。

2. **不理解 Frame 加载类型对缓存的影响:**
   * **错误:** 开发者在 JavaScript 中使用 `fetch()` 发起请求，并期望绕过缓存，但 Frame 的加载类型是标准加载。
   * **结果:** `FrameFetchContext` 默认使用缓存，可能不会重新请求服务器的资源。开发者应该在 JavaScript 中显式设置 `cache: 'no-cache'` 或使用其他缓存控制策略。

3. **CSP 配置错误阻止资源加载:**
   * **错误:** 开发者在 CSP 中错误地配置了 `img-src` 指令，导致某些图片资源被阻止加载。
   * **结果:** `FrameFetchContext::ModifyRequestForCSP` 会根据 CSP 策略修改请求，但最终可能因为 CSP 策略而导致资源加载失败。开发者需要在开发者工具的控制台中查看 CSP 错误信息。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并按下回车键:** 这会触发主 Frame 的加载，`FrameFetchContext` 会参与加载初始的 HTML 资源。
2. **用户点击页面上的链接:**  这可能导致一个新的 Frame 或当前 Frame 的导航，`FrameFetchContext` 会参与新资源的加载。
3. **网页上的 JavaScript 代码发起网络请求:** 例如，通过 `fetch()` 或 `XMLHttpRequest` 加载数据或图片，`FrameFetchContext` 会处理这些请求的配置。
4. **浏览器解析 HTML 或 CSS 并遇到需要加载外部资源的元素或规则:** 例如 `<img>`, `<link>`, `background-image`，`FrameFetchContext` 会创建并配置这些资源的请求。
5. **用户刷新页面 (硬刷新或软刷新):**  不同的刷新类型会影响 `FrameFetchContext` 如何设置缓存策略。
6. **用户通过浏览器的后退/前进按钮导航:**  `FrameFetchContext` 会根据加载类型设置相应的缓存策略。

**总结 (本部分功能归纳):**

作为第 1 部分，我们可以总结 `blink/renderer/core/loader/frame_fetch_context.cc` 的主要功能是 **为 Frame 内发起的资源请求提供必要的上下文信息和配置，包括客户端提示、缓存策略、安全策略等，确保资源请求能够按照预期的规则和策略执行**。 它充当连接 Frame 上下文和底层网络请求的关键桥梁，并与 JavaScript, HTML, CSS 的资源加载过程紧密相关。

### 提示词
```
这是目录为blink/renderer/core/loader/frame_fetch_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/loader/frame_fetch_context.h"

#include <algorithm>
#include <memory>
#include <optional>

#include "base/feature_list.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "build/build_config.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "net/http/structured_headers.h"
#include "services/network/public/cpp/client_hints.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/mojom/web_client_hints_types.mojom-blink.h"
#include "services/network/public/mojom/web_client_hints_types.mojom-shared.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/client_hints/client_hints.h"
#include "third_party/blink/public/common/device_memory/approximated_device_memory.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_network_provider.h"
#include "third_party/blink/public/platform/scheduler/web_scoped_virtual_time_pauser.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_effective_connection_type.h"
#include "third_party/blink/public/platform/websocket_handshake_throttle.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/fileapi/public_url_manager.h"
#include "third_party/blink/renderer/core/frame/ad_tracker.h"
#include "third_party/blink/renderer/core/frame/attribution_src_loader.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/back_forward_cache_loader_helper_impl.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/frame_resource_fetcher_properties.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/loader/loader_factory_for_frame.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource.h"
#include "third_party/blink/renderer/core/loader/resource_load_observer_for_frame.h"
#include "third_party/blink/renderer/core/loader/subresource_filter.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/timing/first_meaningful_paint_detector.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image_chrome_client.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/core/url/url_search_params.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/client_hints_preferences.h"
#include "third_party/blink/renderer/platform/loader/fetch/detachable_use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_priority.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loading_log.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/mhtml/mhtml_archive.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

// Creates a serialized AtomicString header value out of the input string, using
// structured headers as described in
// https://www.rfc-editor.org/rfc/rfc8941.html.
const AtomicString SerializeStringHeader(const std::string& str) {
  std::string output;

  // See https://crbug.com/1416925.
  if (str.empty() &&
      !base::FeatureList::IsEnabled(
          blink::features::kQuoteEmptySecChUaStringHeadersConsistently)) {
    return AtomicString(output.c_str());
  }

  output =
      net::structured_headers::SerializeItem(net::structured_headers::Item(str))
          .value_or(std::string());

  return AtomicString(output.c_str());
}

AtomicString GenerateBoolHeaderValue(bool value) {
  const std::string output = net::structured_headers::SerializeItem(
                                 net::structured_headers::Item(value))
                                 .value_or(std::string());
  return AtomicString(output.c_str());
}

// Creates a serialized AtomicString header value out of the input boolean,
// using structured headers as described in
// https://www.rfc-editor.org/rfc/rfc8941.html.
const AtomicString SerializeBoolHeader(const bool value) {
  if (value) {
    DEFINE_STATIC_LOCAL(AtomicString, true_value,
                        (GenerateBoolHeaderValue(true)));
    return true_value;
  }
  DEFINE_STATIC_LOCAL(AtomicString, false_value,
                      (GenerateBoolHeaderValue(false)));
  return false_value;
}

mojom::FetchCacheMode DetermineFrameCacheMode(Frame* frame) {
  if (!frame)
    return mojom::FetchCacheMode::kDefault;
  auto* local_frame = DynamicTo<LocalFrame>(frame);
  if (!local_frame)
    return DetermineFrameCacheMode(frame->Tree().Parent());

  // Does not propagate cache policy for subresources after the load event.
  // TODO(toyoshim): We should be able to remove following parents' policy check
  // if each frame has a relevant WebFrameLoadType for reload and history
  // navigations.
  if (local_frame->GetDocument()->LoadEventFinished())
    return mojom::FetchCacheMode::kDefault;

  // Respects BypassingCache rather than parent's policy.
  WebFrameLoadType load_type =
      local_frame->Loader().GetDocumentLoader()->LoadType();
  if (load_type == WebFrameLoadType::kReloadBypassingCache)
    return mojom::FetchCacheMode::kBypassCache;

  // Respects parent's policy if it has a special one.
  mojom::FetchCacheMode parent_cache_mode =
      DetermineFrameCacheMode(frame->Tree().Parent());
  if (parent_cache_mode != mojom::FetchCacheMode::kDefault)
    return parent_cache_mode;

  // Otherwise, follows WebFrameLoadType.
  switch (load_type) {
    case WebFrameLoadType::kStandard:
    case WebFrameLoadType::kReplaceCurrentItem:
      return mojom::FetchCacheMode::kDefault;
    case WebFrameLoadType::kBackForward:
    case WebFrameLoadType::kRestore:
      // Mutates the policy for POST requests to avoid form resubmission.
      return mojom::FetchCacheMode::kForceCache;
    case WebFrameLoadType::kReload:
      return mojom::FetchCacheMode::kDefault;
    case WebFrameLoadType::kReloadBypassingCache:
      return mojom::FetchCacheMode::kBypassCache;
  }
  NOTREACHED();
}

bool ShouldSendClientHint(const PermissionsPolicy& policy,
                          const url::Origin& resource_origin,
                          bool is_1p_origin,
                          network::mojom::blink::WebClientHintsType type,
                          const ClientHintsPreferences& hints_preferences) {
  // For subresource requests, sending the hint in the fetch request based on
  // the permissions policy.
  if (!policy.IsFeatureEnabledForOrigin(
          GetClientHintToPolicyFeatureMap().at(type), resource_origin)) {
    return false;
  }

  return IsClientHintSentByDefault(type) || hints_preferences.ShouldSend(type);
}

}  // namespace

struct FrameFetchContext::FrozenState final : GarbageCollected<FrozenState> {
  FrozenState(const KURL& url,
              ContentSecurityPolicy* content_security_policy,
              net::SiteForCookies site_for_cookies,
              scoped_refptr<const SecurityOrigin> top_frame_origin,
              const ClientHintsPreferences& client_hints_preferences,
              float device_pixel_ratio,
              const String& user_agent,
              base::optional_ref<const UserAgentMetadata> user_agent_metadata,
              bool is_isolated_svg_chrome_client,
              bool is_prerendering,
              const String& reduced_accept_language)
      : url(url),
        content_security_policy(content_security_policy),
        site_for_cookies(std::move(site_for_cookies)),
        top_frame_origin(std::move(top_frame_origin)),
        client_hints_preferences(client_hints_preferences),
        device_pixel_ratio(device_pixel_ratio),
        user_agent(user_agent),
        user_agent_metadata(user_agent_metadata.CopyAsOptional()),
        is_isolated_svg_chrome_client(is_isolated_svg_chrome_client),
        is_prerendering(is_prerendering),
        reduced_accept_language(reduced_accept_language) {}

  const KURL url;
  const scoped_refptr<const SecurityOrigin> parent_security_origin;
  const Member<ContentSecurityPolicy> content_security_policy;
  const net::SiteForCookies site_for_cookies;
  const scoped_refptr<const SecurityOrigin> top_frame_origin;
  const ClientHintsPreferences client_hints_preferences;
  const float device_pixel_ratio;
  const String user_agent;
  const std::optional<UserAgentMetadata> user_agent_metadata;
  const bool is_isolated_svg_chrome_client;
  const bool is_prerendering;
  const String reduced_accept_language;

  void Trace(Visitor* visitor) const {
    visitor->Trace(content_security_policy);
  }
};

ResourceFetcher* FrameFetchContext::CreateFetcherForCommittedDocument(
    DocumentLoader& loader,
    Document& document) {
  auto& properties = *MakeGarbageCollected<DetachableResourceFetcherProperties>(
      *MakeGarbageCollected<FrameResourceFetcherProperties>(loader, document));
  LocalFrame* frame = document.GetFrame();
  DCHECK(frame);
  auto* frame_fetch_context =
      MakeGarbageCollected<FrameFetchContext>(loader, document, properties);
  ResourceFetcherInit init(
      properties, frame_fetch_context,
      frame->GetTaskRunner(TaskType::kNetworking),
      frame->GetTaskRunner(TaskType::kNetworkingUnfreezable),
      MakeGarbageCollected<LoaderFactoryForFrame>(loader, *frame->DomWindow()),
      frame->DomWindow(),
      MakeGarbageCollected<BackForwardCacheLoaderHelperImpl>(*frame));
  init.use_counter =
      MakeGarbageCollected<DetachableUseCounter>(frame->DomWindow());
  init.console_logger = MakeGarbageCollected<DetachableConsoleLogger>(
      document.GetExecutionContext());
  // Frame loading should normally start with |kTight| throttling, as the
  // frame will be in layout-blocking state until the <body> tag is inserted
  init.initial_throttling_policy =
      ResourceLoadScheduler::ThrottlingPolicy::kTight;
  init.frame_or_worker_scheduler = frame->GetFrameScheduler();
  init.archive = loader.Archive();
  init.loading_behavior_observer = frame_fetch_context;
  ResourceFetcher* fetcher = MakeGarbageCollected<ResourceFetcher>(init);
  fetcher->SetResourceLoadObserver(
      MakeGarbageCollected<ResourceLoadObserverForFrame>(
          loader, document, fetcher->GetProperties()));
  fetcher->SetAutoLoadImages(
      frame->GetSettings()->GetLoadsImagesAutomatically());
  fetcher->SetEarlyHintsPreloadedResources(
      loader.GetEarlyHintsPreloadedResources());
  return fetcher;
}

FrameFetchContext::FrameFetchContext(
    DocumentLoader& document_loader,
    Document& document,
    const DetachableResourceFetcherProperties& properties)
    : BaseFetchContext(properties,
                       MakeGarbageCollected<DetachableConsoleLogger>(
                           document.GetExecutionContext())),
      document_loader_(document_loader),
      document_(document) {}

net::SiteForCookies FrameFetchContext::GetSiteForCookies() const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->site_for_cookies;
  return document_->SiteForCookies();
}

scoped_refptr<const SecurityOrigin> FrameFetchContext::GetTopFrameOrigin()
    const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->top_frame_origin;
  return document_->TopFrameOrigin();
}

const Vector<KURL>& FrameFetchContext::GetPotentiallyUnusedPreloads() const {
  if (LocalFrame* frame = GetFrame()) {
    if (LCPCriticalPathPredictor* lcpp = frame->GetLCPP()) {
      return lcpp->unused_preloads();
    }
  }
  return empty_unused_preloads_;
}

void FrameFetchContext::AddLcpPredictedCallback(base::OnceClosure callback) {
  if (LocalFrame* frame = FrameFetchContext::GetFrame()) {
    if (LCPCriticalPathPredictor* lcpp = frame->GetLCPP()) {
      lcpp->AddLCPPredictedCallback(std::move(callback));
    }
  }
}

SubresourceFilter* FrameFetchContext::GetSubresourceFilter() const {
  if (GetResourceFetcherProperties().IsDetached())
    return nullptr;
  return document_loader_->GetSubresourceFilter();
}

LocalFrame* FrameFetchContext::GetFrame() const {
  return document_->GetFrame();
}

LocalFrameClient* FrameFetchContext::GetLocalFrameClient() const {
  return GetFrame()->Client();
}

// TODO(toyoshim, arthursonzogni): PlzNavigate doesn't use this function to set
// the ResourceRequest's cache policy. The cache policy determination needs to
// be factored out from FrameFetchContext and moved to the FrameLoader for
// instance.
mojom::FetchCacheMode FrameFetchContext::ResourceRequestCachePolicy(
    const ResourceRequest& request,
    ResourceType type,
    FetchParameters::DeferOption defer) const {
  if (GetResourceFetcherProperties().IsDetached())
    return mojom::FetchCacheMode::kDefault;

  DCHECK(GetFrame());
  const auto cache_mode = DetermineFrameCacheMode(GetFrame());

  // TODO(toyoshim): Revisit to consider if this clause can be merged to
  // determineWebCachePolicy or determineFrameCacheMode.
  if (cache_mode == mojom::FetchCacheMode::kDefault &&
      request.IsConditional()) {
    return mojom::FetchCacheMode::kValidateCache;
  }
  return cache_mode;
}

void FrameFetchContext::PrepareRequest(
    ResourceRequest& request,
    ResourceLoaderOptions& options,
    WebScopedVirtualTimePauser& virtual_time_pauser,
    ResourceType resource_type) {
  // TODO(yhirano): Clarify which statements are actually needed when
  // this is called during redirect.
  const bool for_redirect = request.GetRedirectInfo().has_value();
  const bool minimal_prep = RuntimeEnabledFeatures::
      MinimimalResourceRequestPrepBeforeCacheLookupEnabled();

  if (!minimal_prep) {
    SetFirstPartyCookie(request);
  }
  if (request.GetRequestContext() ==
      mojom::blink::RequestContextType::SERVICE_WORKER) {
    // The top frame origin is defined to be null for service worker main
    // resource requests.
    DCHECK(!request.TopFrameOrigin());
  } else {
    request.SetTopFrameOrigin(GetTopFrameOrigin());
  }

  request.SetHTTPUserAgent(AtomicString(GetUserAgent()));

  if (GetResourceFetcherProperties().IsDetached())
    return;

  request.SetUkmSourceId(document_->UkmSourceID());
  request.SetStorageAccessApiStatus(
      document_->GetExecutionContext()->GetStorageAccessApiStatus());

  if (!minimal_prep) {
    if (document_loader_->ForceFetchCacheMode()) {
      request.SetCacheMode(*document_loader_->ForceFetchCacheMode());
    }
    if (const AttributionSrcLoader* attribution_src_loader =
            GetFrame()->GetAttributionSrcLoader()) {
      request.SetAttributionReportingSupport(
          attribution_src_loader->GetSupport());
    }
  }

  // If the original request included the attribute to opt-in to shared storage,
  // then update eligibility for the current (possibly redirected) request. Note
  // that if the original request didn't opt-in, then the original request and
  // any subsequent redirects are ineligible for shared storage writing by
  // response header.
  if (request.GetSharedStorageWritableOptedIn()) {
    auto* policy = GetPermissionsPolicy();
    request.SetSharedStorageWritableEligible(
        policy &&
        request.IsFeatureEnabledForSubresourceRequestAssumingOptIn(
            policy, mojom::blink::PermissionsPolicyFeature::kSharedStorage,
            SecurityOrigin::Create(request.Url())->ToUrlOrigin()));
  }

  request.SetSharedDictionaryWriterEnabled(
      RuntimeEnabledFeatures::CompressionDictionaryTransportEnabled(
          GetExecutionContext()));

  if (!minimal_prep) {
    WillSendRequest(request);
  }
  GetLocalFrameClient()->DispatchFinalizeRequest(request);
  FrameScheduler* frame_scheduler = GetFrame()->GetFrameScheduler();
  if (!for_redirect && frame_scheduler) {
    virtual_time_pauser = frame_scheduler->CreateWebScopedVirtualTimePauser(
        request.Url().GetString(),
        WebScopedVirtualTimePauser::VirtualTaskDuration::kNonInstant);
  }

  probe::PrepareRequest(Probe(), document_loader_, request, options,
                        resource_type);

  // ServiceWorker hook ups.
  if (document_loader_->GetServiceWorkerNetworkProvider()) {
    WrappedResourceRequest webreq(request);
    document_loader_->GetServiceWorkerNetworkProvider()->WillSendRequest(
        webreq);
  }
}

void FrameFetchContext::AddResourceTiming(
    mojom::blink::ResourceTimingInfoPtr info,
    const AtomicString& initiator_type) {
  // Normally, |document_| is cleared on Document shutdown. In that case,
  // early return, as there is nothing to report the resource timing to.
  if (GetResourceFetcherProperties().IsDetached())
    return;

  // Timing for main resource is handled in DocumentLoader.
  // All other resources are reported to the corresponding Document.
  DOMWindowPerformance::performance(*document_->domWindow())
      ->AddResourceTiming(std::move(info), initiator_type);
}

bool FrameFetchContext::AllowImage() const {
  if (GetResourceFetcherProperties().IsDetached())
    return true;

  bool images_enabled = GetFrame()->ImagesEnabled();
  if (!images_enabled) {
    if (auto* settings_client = GetContentSettingsClient()) {
      settings_client->DidNotAllowImage();
    }
  }
  return images_enabled;
}

void FrameFetchContext::ModifyRequestForCSP(ResourceRequest& resource_request) {
  if (GetResourceFetcherProperties().IsDetached())
    return;

  GetFrame()->Loader().ModifyRequestForCSP(
      resource_request,
      &GetResourceFetcherProperties().GetFetchClientSettingsObject(),
      document_->domWindow(), mojom::blink::RequestContextFrameType::kNone);
}

void FrameFetchContext::AddClientHintsIfNecessary(
    const std::optional<float> resource_width,
    ResourceRequest& request) {
  if (GetResourceFetcherProperties().IsDetached()) {
    return;
  }

  // If the feature is enabled, then client hints are allowed only on secure
  // URLs.
  if (!ClientHintsPreferences::IsClientHintsAllowed(request.Url()))
    return;

  // Check if |url| is allowed to run JavaScript. If not, client hints are not
  // attached to the requests that initiate on the render side.
  if (!GetFrame()->ScriptEnabled()) {
    return;
  }

  // The Permissions policy is used to enable hints for all subresources, based
  // on the policy of the requesting document, and the origin of the resource.
  const PermissionsPolicy* policy =
      document_
          ? document_->domWindow()->GetSecurityContext().GetPermissionsPolicy()
          : nullptr;

  if (!policy) {
    return;
  }

  const scoped_refptr<SecurityOrigin> security_origin =
      SecurityOrigin::Create(request.Url());
  bool is_1p_origin = IsFirstPartyOrigin(security_origin.get());
  const url::Origin resource_origin = security_origin->ToUrlOrigin();

  std::optional<UserAgentMetadata> ua = GetUserAgentMetadata();

  const ClientHintsPreferences& hints_preferences = GetClientHintsPreferences();

  using network::mojom::blink::WebClientHintsType;

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kDeviceMemory_DEPRECATED,
                           hints_preferences)) {
    request.SetHttpHeaderField(
        http_names::kDeviceMemory_DEPRECATED,
        AtomicString(String::Number(
            ApproximatedDeviceMemory::GetApproximatedDeviceMemory())));
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kDeviceMemory,
                           hints_preferences)) {
    request.SetHttpHeaderField(
        http_names::kDeviceMemory,
        AtomicString(String::Number(
            ApproximatedDeviceMemory::GetApproximatedDeviceMemory())));
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kRtt_DEPRECATED,
                           hints_preferences)) {
    std::optional<base::TimeDelta> http_rtt =
        GetNetworkStateNotifier().GetWebHoldbackHttpRtt();
    if (!http_rtt) {
      http_rtt = GetNetworkStateNotifier().HttpRtt();
    }

    uint32_t rtt = GetNetworkStateNotifier().RoundRtt(
        request.Url().Host().ToString(), http_rtt);
    request.SetHttpHeaderField(http_names::kRtt_DEPRECATED,
                               AtomicString(String::Number(rtt)));
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kDownlink_DEPRECATED,
                           hints_preferences)) {
    std::optional<double> throughput_mbps =
        GetNetworkStateNotifier().GetWebHoldbackDownlinkThroughputMbps();
    if (!throughput_mbps) {
      throughput_mbps = GetNetworkStateNotifier().DownlinkThroughputMbps();
    }

    double mbps = GetNetworkStateNotifier().RoundMbps(
        request.Url().Host().ToString(), throughput_mbps);
    request.SetHttpHeaderField(http_names::kDownlink_DEPRECATED,
                               AtomicString(String::Number(mbps)));
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kEct_DEPRECATED,
                           hints_preferences)) {
    std::optional<WebEffectiveConnectionType> holdback_ect =
        GetNetworkStateNotifier().GetWebHoldbackEffectiveType();
    if (!holdback_ect) {
      holdback_ect = GetNetworkStateNotifier().EffectiveType();
    }

    request.SetHttpHeaderField(
        http_names::kEct_DEPRECATED,
        AtomicString(NetworkStateNotifier::EffectiveConnectionTypeToString(
            holdback_ect.value())));
  }

  // Only send User Agent hints if the info is available
  if (ua) {
    // ShouldSendClientHint is called to make sure UA is controlled by
    // Permissions Policy.
    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUA, hints_preferences)) {
      if (last_ua_ != *ua) {
        last_ua_ = *ua;
        last_ua_serialized_brand_major_version_list_ =
            AtomicString(ua->SerializeBrandMajorVersionList().c_str());
      }
      request.SetHttpHeaderField(http_names::kUA,
                                 *last_ua_serialized_brand_major_version_list_);
    }

    // We also send Sec-CH-UA-Mobile to all hints. It is a one-bit header
    // identifying if the browser has opted for a "mobile" experience.
    // ShouldSendClientHint is called to make sure it's controlled by
    // PermissionsPolicy.
    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUAMobile,
                             hints_preferences)) {
      request.SetHttpHeaderField(http_names::kUAMobile,
                                 SerializeBoolHeader(ua->mobile));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUAArch, hints_preferences)) {
      request.SetHttpHeaderField(http_names::kUAArch,
                                 SerializeStringHeader(ua->architecture));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUAPlatform,
                             hints_preferences)) {
      request.SetHttpHeaderField(http_names::kUAPlatform,
                                 SerializeStringHeader(ua->platform));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUAPlatformVersion,
                             hints_preferences)) {
      request.SetHttpHeaderField(http_names::kUAPlatformVersion,
                                 SerializeStringHeader(ua->platform_version));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUAModel, hints_preferences)) {
      request.SetHttpHeaderField(http_names::kUAModel,
                                 SerializeStringHeader(ua->model));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUAFullVersion,
                             hints_preferences)) {
      request.SetHttpHeaderField(http_names::kUAFullVersion,
                                 SerializeStringHeader(ua->full_version));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUAFullVersionList,
                             hints_preferences)) {
      request.SetHttpHeaderField(
          http_names::kUAFullVersionList,
          AtomicString(ua->SerializeBrandFullVersionList().c_str()));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUABitness,
                             hints_preferences)) {
      request.SetHttpHeaderField(http_names::kUABitness,
                                 SerializeStringHeader(ua->bitness));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kUAWoW64, hints_preferences)) {
      request.SetHttpHeaderField(http_names::kUAWoW64,
                                 SerializeBoolHeader(ua->wow64));
    }

    if (ShouldSendClientHint(
            *policy, resource_origin, is_1p_origin,
            network::mojom::blink::WebClientHintsType::kUAFormFactors,
            hints_preferences)) {
      request.SetHttpHeaderField(
          http_names::kUAFormFactors,
          AtomicString(ua->SerializeFormFactors().c_str()));
    }
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kSaveData, hints_preferences) &&
      GetNetworkStateNotifier().SaveDataEnabled()) {
    request.SetHttpHeaderField(http_names::kSaveData, http_names::kOn);
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kPrefersReducedTransparency,
                           hints_preferences)) {
    request.SetHttpHeaderField(http_names::kPrefersReducedTransparency,
                               GetSettings()->GetPrefersReducedTransparency()
                                   ? http_names::kReduce
                                   : http_names::kNoPreference);
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kPrefersReducedMotion,
                           hints_preferences)) {
    request.SetHttpHeaderField(http_names::kPrefersReducedMotion,
                               GetSettings()->GetPrefersReducedMotion()
                                   ? http_names::kReduce
                                   : http_names::kNoPreference);
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kPrefersColorScheme,
                           hints_preferences)) {
    request.SetHttpHeaderField(
        http_names::kPrefersColorScheme,
        document_->InDarkMode() ? http_names::kDark : http_names::kLight);
  }

  const float dpr = GetDevicePixelRatio();

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kDpr_DEPRECATED,
                           hints_preferences)) {
    request.SetHttpHeaderField(http_names::kDpr_DEPRECATED,
                               AtomicString(String::Number(dpr)));
  }

  if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                           WebClientHintsType::kDpr, hints_preferences)) {
    request.SetHttpHeaderField(http_names::kDpr,
                               AtomicStrin
```