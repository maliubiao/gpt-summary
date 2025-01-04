Response:
My thought process for analyzing the provided code snippet and generating the summary follows these steps:

1. **Identify the Core Class:** The first and most important step is recognizing the central entity of the code. The filename `fetch_manager.cc` and the prominent class declaration `class FetchManager` clearly point to this being the core component.

2. **Scan for Key Methods and Members:** I quickly skim the code looking for significant methods and member variables. This helps to understand the class's responsibilities. I noticed methods like `Fetch`, `FetchLater`, and inner classes like `Loader`. I also saw mentions of `ResourceRequest`, `ResourceResponse`, `AbortSignal`, and `ScriptPromiseResolver`. These hints suggest the class manages network requests initiated by JavaScript.

3. **Understand the `Fetch` Method:** The `Fetch` method stands out as the primary way to initiate a network request. I noted its parameters (`FetchRequestData`, `ScriptState`, `ScriptPromiseResolver`, `AbortSignal`) and the creation of a `Loader` object. This strongly suggests that `FetchManager` orchestrates the fetch process, and `Loader` handles the actual network communication.

4. **Analyze the `FetchLater` Method:**  The presence of `FetchLater` indicates a specialized functionality. I observed its parameters and that it interacts with a `FetchLaterRegistrationData` and potentially persists requests. The code around `kFetchLaterTrafficAnnotationTag` and `FetchLaterRendererMetricType` suggests this feature deals with requests that might be deferred or executed under specific conditions.

5. **Examine the `Loader` Inner Class:**  The `Loader` class seems to be the workhorse for individual fetch requests. I focused on the `ThreadableLoaderClient` inheritance and the associated callback methods like `DidReceiveResponse`, `DidFinishLoading`, and `DidFail`. This confirms its role in handling the lifecycle of a network request. The `SRIVerifier` nested within `Loader` indicates support for Subresource Integrity.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):** Based on the identified methods and members, I started making connections to web technologies:
    * **JavaScript:** The use of `ScriptPromiseResolver` clearly links the `FetchManager` to JavaScript's `fetch()` API. The class handles the creation and resolution/rejection of Promises.
    * **HTML:**  `FetchLater` suggests potential use cases like sending analytics or small amounts of data when a page unloads or before it enters the back/forward cache – scenarios related to browser navigation and page lifecycle.
    * **CSS:** While not explicitly mentioned in this snippet, I know that fetching CSS resources is a core part of web development. The underlying infrastructure provided by `FetchManager` is used for fetching CSS files as well.

7. **Infer Logical Reasoning and Examples:** Based on the functionality, I started constructing hypothetical scenarios:
    * **Successful Fetch:** A basic `fetch()` call in JavaScript leading to a successful response.
    * **Failed Fetch:**  A network error, CORS issue, or other problem causing a fetch to fail.
    * **`FetchLater`:**  A JavaScript call using the `fetchLater` API (if enabled) to send data after the page unloads.

8. **Consider User Errors:**  I thought about common mistakes developers might make when using `fetch()`:
    * Incorrect URLs
    * CORS configuration issues
    * Network connectivity problems

9. **Trace User Actions:** I outlined a simple sequence of user actions that would trigger the code: a user navigating to a webpage that executes a `fetch()` call in JavaScript.

10. **Focus on the "Part 1" Request:**  The prompt specifically asked for a summary of the *first part*. Therefore, I concentrated on the core functionalities exposed in this particular code snippet, avoiding speculation on what might be in the subsequent parts.

11. **Structure the Summary:** Finally, I organized my findings into clear sections, addressing each point in the prompt (functionality, relation to web technologies, logical reasoning, user errors, debugging clues, and the final summary). I used bullet points and clear language to make the information easily digestible.

Essentially, I worked from the specific code details outward, inferring the broader purpose and connecting it to the context of a web browser engine. The presence of well-known web concepts and APIs within the code was a crucial guide in this process.
```
这是目录为blink/renderer/core/fetch/fetch_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

基于提供的第一部分代码，我们可以归纳出 `blink/renderer/core/fetch/fetch_manager.cc` 的主要功能是**管理和执行由JavaScript发起的网络请求 (fetch API)**。它负责处理 `fetch()` API 的调用，创建和管理请求的生命周期，并最终将结果（`Response` 对象）返回给 JavaScript。同时，它也包含了对 `fetchLater` API 的支持，允许在页面卸载或超时后执行请求。

以下是对其功能的详细列举和说明：

**核心功能:**

1. **接收和处理 `fetch()` API 调用:**  `FetchManager` 接收来自 JavaScript 的 `fetch()` 调用，这些调用携带了请求的 URL、方法、头部、请求体等信息。

2. **创建和管理 `FetchLoader`:**  对于每个 `fetch()` 调用，`FetchManager` 会创建一个 `Loader` 对象（内部类），负责实际的网络请求过程。`Loader` 类继承自 `ThreadableLoaderClient`，表明它使用了 Blink 的网络加载机制。

3. **构建 `ResourceRequest`:**  根据 JavaScript 传递的参数，`FetchManager` 和 `Loader` 会构建一个 `blink::ResourceRequest` 对象，该对象包含了进行网络请求所需的所有信息。

4. **处理请求的生命周期:**  `Loader` 类实现了 `ThreadableLoaderClient` 的接口，负责处理网络请求的各个阶段，包括：
    * 重定向 (`WillFollowRedirect`)
    * 接收响应头 (`DidReceiveResponse`)
    * 接收缓存元数据 (`DidReceiveCachedMetadata`)
    * 开始接收响应体 (`DidStartLoadingResponseBody`)
    * 完成加载 (`DidFinishLoading`)
    * 加载失败 (`DidFail`)
    * 重定向检查失败 (`DidFailRedirectCheck`)

5. **返回 `Response` 对象:**  当网络请求成功完成时，`Loader` 会创建一个 `blink::Response` 对象，并将接收到的响应头和响应体封装到其中，最终通过 `ScriptPromiseResolver` 将其返回给 JavaScript。

6. **处理 Subresource Integrity (SRI):** 代码中包含了 `SRIVerifier` 类，表明 `FetchManager` 支持 SRI 校验，确保加载的资源与预期一致，防止 CDN 劫持等安全问题。

7. **支持 `fetchLater` API:**  `FetchManager` 实现了 `FetchLater` 功能，允许在特定时机（例如页面卸载或超时）执行网络请求。这对于发送分析数据或执行其他非关键性任务非常有用。

8. **处理 AbortSignal:**  `FetchManager` 能够响应 `AbortSignal`，允许 JavaScript 代码在请求进行中取消请求。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  `FetchManager` 是 `fetch()` API 在 Blink 引擎中的实现核心。JavaScript 代码通过调用 `fetch()` 触发 `FetchManager` 的工作。例如：

   ```javascript
   fetch('https://example.com/data.json')
     .then(response => response.json())
     .then(data => console.log(data));

   // 使用 AbortController 取消请求
   const controller = new AbortController();
   const signal = controller.signal;
   fetch('/api/long-running-task', { signal })
     .then(response => { /* ... */ })
     .catch(error => {
       if (error.name === 'AbortError') {
         console.log('Fetch aborted');
       }
     });
   controller.abort();

   // 使用 fetchLater (假设该API已启用)
   navigator.fetchLater('/analytics', { method: 'POST', body: JSON.stringify({ event: 'pageUnload' }) });
   ```

* **HTML:**  HTML 中的 `<script>` 标签引入的 JavaScript 代码可以调用 `fetch()`。`fetchLater` 可能用于在用户离开页面时发送数据，例如通过 `window.addEventListener('beforeunload', ...)` 触发的脚本。

* **CSS:** 虽然这段代码本身不直接涉及 CSS 的解析和应用，但 `FetchManager` 负责加载 CSS 资源。当浏览器解析 HTML 并遇到 `<link rel="stylesheet" href="...">` 时，Blink 会使用类似的机制（可能经过不同的路径，但底层网络请求机制类似）来获取 CSS 文件。`FetchManager` 处理的逻辑，如缓存、CORS 等，同样适用于 CSS 资源的加载。

**逻辑推理 (假设输入与输出):**

**假设输入:** JavaScript 代码调用 `fetch('https://api.example.com/users', { method: 'GET' })`

**逻辑推理过程:**

1. `FetchManager::Fetch` 方法被调用，接收 URL 和请求选项。
2. 创建 `FetchManager::Loader` 实例。
3. `Loader::Start` 方法被调用。
4. 构建 `ResourceRequest` 对象，设置 URL 为 `https://api.example.com/users`，方法为 `GET`。
5. 调用 `ThreadableLoader::Load` 发起网络请求。
6. (假设请求成功) 服务器返回响应头和 JSON 数据。
7. `Loader::DidReceiveResponse` 被调用，处理响应头。
8. `Loader::DidStartLoadingResponseBody` 被调用，开始接收响应体。
9. `Loader::DidFinishLoading` 被调用，表示请求完成。
10. 创建 `Response` 对象，包含响应头和响应体。
11. 通过 `response_resolver_->Resolve(response_)` 将 `Response` 对象传递给 JavaScript 的 Promise。

**假设输出:**  JavaScript 的 `fetch()` Promise 被 resolve，并得到一个 `Response` 对象，该对象的 `url` 属性为 `https://api.example.com/users`，`status` 为 200 (假设成功)，可以通过 `response.json()` 方法解析 JSON 响应体。

**用户或编程常见的使用错误:**

1. **CORS 错误:**  JavaScript 代码尝试 `fetch` 跨域资源，但服务器没有设置正确的 CORS 头部 (`Access-Control-Allow-Origin`)。`FetchManager` 会根据 CORS 策略阻止请求或限制响应内容的访问。这会导致 JavaScript 的 `fetch()` Promise 被 reject，并可能在控制台看到 CORS 相关的错误信息。

   ```javascript
   fetch('https://another-domain.com/api/data') // 可能会触发 CORS 错误
     .then(response => response.json())
     .catch(error => console.error('Fetch error:', error));
   ```

2. **网络连接问题:**  用户的网络断开，或者请求的域名无法解析。`FetchManager` 会接收到网络错误，导致 `Loader::DidFail` 被调用，并将错误信息传递给 JavaScript 的 Promise，通常会是一个 `TypeError: Failed to fetch` 错误。

3. **URL 错误:**  JavaScript 代码提供的 URL 不存在或格式错误。服务器可能会返回 404 Not Found 或其他错误状态码，`FetchManager` 会将这些信息封装到 `Response` 对象中。

4. **`AbortSignal` 使用不当:**  过早或不正确地调用 `AbortController.abort()` 可能导致意外的请求取消。

5. **`fetchLater` 的滥用:**  过度使用 `fetchLater` 发送大量数据可能会影响用户体验或违反浏览器的限制。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接，导航到包含 JavaScript 代码的网页。**
2. **浏览器加载 HTML 页面，并开始解析。**
3. **浏览器遇到 `<script>` 标签，开始执行 JavaScript 代码。**
4. **JavaScript 代码中调用了 `fetch()` 函数，例如 `fetch('https://example.com/api')`。**
5. **Blink 引擎接收到 `fetch()` 调用，并将其路由到 `FetchManager::Fetch` 方法。**
6. **`FetchManager` 创建并启动 `FetchManager::Loader` 来处理该请求。**
7. **`Loader` 构建 `ResourceRequest` 并通过 Blink 的网络层发起实际的网络请求。**
8. **网络层与服务器进行通信，接收响应。**
9. **`Loader` 的回调方法 (`DidReceiveResponse`, `DidFinishLoading`, 等) 被调用，处理响应的各个阶段。**
10. **最终，`Loader` 创建 `Response` 对象并通过 Promise 将结果返回给 JavaScript 代码。**

**对于 `fetchLater`:**

1. **用户在页面上进行操作，触发 JavaScript 代码调用 `navigator.fetchLater(...)`。**
2. **`FetchManager::FetchLater` 方法被调用，存储 `FetchLaterRegistrationData`。**
3. **可能的情况：**
    * **立即执行 (如果满足条件):**  请求可能被立即执行，流程类似于普通的 `fetch()`。
    * **延迟执行 (页面卸载):** 当用户关闭标签页、点击链接跳转到其他页面或触发页面卸载事件时，浏览器会检查是否有待处理的 `fetchLater` 请求，并执行它们。
    * **延迟执行 (超时):** 如果注册了超时时间，当超时时间到达时，请求会被执行。

**归纳一下它的功能 (针对第 1 部分):**

第一部分代码主要关注 `FetchManager` 的基础架构和普通 `fetch()` 请求的处理流程。它定义了 `FetchManager` 类和其内部的 `Loader` 类，以及处理 `fetch()` 调用、构建请求、管理请求生命周期和返回 `Response` 对象的核心逻辑。 此外，它还包含了 `ResponseResolver` 辅助类来处理 Promise 的 resolve 和 reject。初步引入了对 `fetchLater` 的支持，但更详细的 `fetchLater` 逻辑可能在后续部分。  代码中也初步展示了对 SRI 的支持。  总而言之，这部分代码是 Blink 引擎中实现 `fetch` API 及其相关基础功能的关键组件。

Prompt: 
```
这是目录为blink/renderer/core/fetch/fetch_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/fetch_manager.h"

#include <stdint.h>

#include <algorithm>
#include <optional>
#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/strcat.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/unguessable_token.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/header_util.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "services/network/public/cpp/request_mode.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "services/network/public/mojom/trust_tokens.mojom-blink.h"
#include "services/network/public/mojom/url_loader_factory.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/scheme_registry.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/fetch_later.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_request_util.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/body.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/fetch_later_result.h"
#include "third_party/blink/renderer/core/fetch/fetch_request_data.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/place_holder_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/core/fetch/trust_token_to_mojom.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/loader/subresource_integrity_helper.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/core/loader/threadable_loader_client.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/workers/shared_worker_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/thread_debugger.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/cors/cors_error_string.h"
#include "third_party/blink/renderer/platform/loader/fetch/buffering_bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/request_conversion.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_associated_remote.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "v8/include/v8.h"

using network::mojom::CredentialsMode;
using network::mojom::FetchResponseType;
using network::mojom::RedirectMode;
using network::mojom::RequestMode;

namespace blink {

namespace {

// 64 kilobytes.
constexpr uint64_t kMaxScheduledDeferredBytesPerOrigin = 64 * 1024;

constexpr ResourceType kFetchLaterResourceType = ResourceType::kRaw;
constexpr TextResourceDecoderOptions::ContentType kFetchLaterContentType =
    TextResourceDecoderOptions::kPlainTextContent;

constexpr net::NetworkTrafficAnnotationTag kFetchLaterTrafficAnnotationTag =
    net::DefineNetworkTrafficAnnotation("blink_fetch_later_manager",
                                        R"(
    semantics {
      sender: "Blink Fetch Later Manager"
      description:
        "This request is a website-initiated FetchLater request."
      trigger:
        "On document unloaded or after developer specified timeout has passed."
      data: "Anything the initiator wants to send."
      user_data {
        type: ARBITRARY_DATA
      }
      destination: OTHER
      internal {
        contacts {
          email: "pending-beacon-experiment@chromium.org"
        }
      }
      last_reviewed: "2023-10-25"
    }
    policy {
      cookies_allowed: YES
      cookies_store: "user"
      setting: "These requests cannot be fully disabled in settings. "
        "Only for the requests intended to send after document in BFCache, "
        "they can be disabled via the `Background Sync` section under the "
        "`Privacy and security` tab in settings. "
        "This feature is not yet enabled."
      policy_exception_justification: "The policy for Background sync is not "
      "yet implemented."
    })");

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
//
// Must remain in sync with FetchLaterRendererMetricType in
// tools/metrics/histograms/enums.xml.
enum class FetchLaterRendererMetricType {
  kAbortedByUser = 0,
  kContextDestroyed = 1,
  kActivatedByTimeout = 2,
  kActivatedOnEnteredBackForwardCache = 3,
  kMaxValue = kActivatedOnEnteredBackForwardCache,
};

void LogFetchLaterMetric(const FetchLaterRendererMetricType& type) {
  base::UmaHistogramEnumeration("FetchLater.Renderer.Metrics", type);
}

// Tells whether the FetchLater request should use BackgroundSync permission to
// decide whether it should send out deferred requests on entering
// BackForwardCache.
bool IsFetchLaterUseBackgroundSyncPermissionEnabled() {
  return base::GetFieldTrialParamByFeatureAsBool(
      features::kFetchLaterAPI, "use_background_sync_permission", true);
}

// Allows manually overriding the "send-on-enter-bfcache" behavior without
// considering BackgroundSync permission.
// Defaults to true to flush on entering BackForwardCache.
// See also
// https://github.com/WICG/pending-beacon/issues/30#issuecomment-1333869614
bool IsFetchLaterSendOnEnterBackForwardCacheEnabled() {
  return base::GetFieldTrialParamByFeatureAsBool(features::kFetchLaterAPI,
                                                 "send_on_enter_bfcache", true);
}

// Tells whether the FetchLater should use the "deferred-fetch" policy.
// Defaults to false until the discussion is finalized.
// https://github.com/WICG/pending-beacon/issues/87#issuecomment-2315624105
bool IsFetchLaterUsePermissionsPolicyEnabled() {
  return base::GetFieldTrialParamByFeatureAsBool(
      features::kFetchLaterAPI, "use_permissions_policy", false);
}

bool HasNonEmptyLocationHeader(const FetchHeaderList* headers) {
  String value;
  if (!headers->Get(http_names::kLocation, value))
    return false;
  return !value.empty();
}

const char* SerializeTrustTokenOperationType(
    network::mojom::TrustTokenOperationType operation_type) {
  switch (operation_type) {
    case network::mojom::blink::TrustTokenOperationType::kIssuance:
      return "Issuance";
    case network::mojom::blink::TrustTokenOperationType::kRedemption:
      return "Redemption";
    case network::mojom::blink::TrustTokenOperationType::kSigning:
      return "Signing";
  }
}

// Logs a net error describing why a fetch with Trust Tokens parameters
// failed. This is a temporary measure for debugging a surprisingly high
// incidence of "TypeError: Failed to fetch" when executing Trust Tokens
// issuance operations (crbug.com/1128174).
void HistogramNetErrorForTrustTokensOperation(
    network::mojom::blink::TrustTokenOperationType operation_type,
    int net_error) {
  base::UmaHistogramSparse(
      base::StrCat({"Net.TrustTokens.NetErrorForFetchFailure", ".",
                    SerializeTrustTokenOperationType(operation_type)}),
      net_error);
}

ResourceLoadPriority ComputeFetchLaterLoadPriority(
    const FetchParameters& params) {
  // FetchLater's ResourceType is ResourceType::kRaw, which should default to
  // ResourceLoadPriority::kHigh priority. See also TypeToPriority() in
  // resource_fetcher.cc
  return AdjustPriorityWithPriorityHintAndRenderBlocking(
      ResourceLoadPriority::kHigh, kFetchLaterResourceType,
      params.GetResourceRequest().GetFetchPriorityHint(),
      params.GetRenderBlockingBehavior());
  // TODO(crbug.com/1465781): Apply kLow when IsSubframeDeprioritizationEnabled.
}

class FetchManagerResourceRequestContext final : public ResourceRequestContext {
  STACK_ALLOCATED();

 public:
  ~FetchManagerResourceRequestContext() override = default;

  // Computes the ResourceLoadPriority. This is called if the priority was not
  // set.
  ResourceLoadPriority ComputeLoadPriority(
      const FetchParameters& params) override {
    return ComputeFetchLaterLoadPriority(params);
  }

  void RecordTrace() override {}
};

// Stores a resolver for Response objects, and a TypeError exception to reject
// them with. The default exception is created at construction time so it has an
// appropriate JavaScript stack.
class ResponseResolver final : public GarbageCollected<ResponseResolver> {
 public:
  // ResponseResolver uses the ScriptState held by the ScriptPromiseResolver.
  explicit ResponseResolver(ScriptPromiseResolver<Response>*);

  ResponseResolver(const ResponseResolver&) = delete;
  ResponseResolver& operator=(const ResponseResolver&) = delete;

  // Exposed the ExecutionContext from the resolver for use by
  // FetchManager::Loader.
  ExecutionContext* GetExecutionContext() {
    return resolver_->GetExecutionContext();
  }

  // The caller should clear references to this object after calling one of the
  // resolve or reject methods, but just to ensure there are no mistakes this
  // object clears its internal references after resolving or rejecting.

  // Resolves the promise with the specified response.
  void Resolve(Response* response);

  // Rejects the promise with the supplied object.
  void Reject(v8::Local<v8::Value> error);
  void Reject(DOMException*);

  // Rejects the promise with the TypeError exception created at construction
  // time. Also optionally passes `devtools_request_id`, `issue_id`, and
  // `issue_summary` to DevTools if they are set; this happens via a side
  // channel that is inaccessible to the page (so additional information
  // stored in the `issue_summary` about for example CORS policy violations
  // is not leaked to the page).
  void RejectBecauseFailed(std::optional<String> devtools_request_id,
                           std::optional<base::UnguessableToken> issue_id,
                           std::optional<String> issue_summary);

  void Trace(Visitor* visitor) const {
    visitor->Trace(resolver_);
    visitor->Trace(exception_);
  }

 private:
  // Clear all members.
  void Clear();

  Member<ScriptPromiseResolver<Response>> resolver_;
  TraceWrapperV8Reference<v8::Value> exception_;
};

ResponseResolver::ResponseResolver(ScriptPromiseResolver<Response>* resolver)
    : resolver_(resolver) {
  auto* script_state = resolver_->GetScriptState();
  v8::Isolate* isolate = script_state->GetIsolate();
  // Only use a handle scope as we should be in the right context already.
  v8::HandleScope scope(isolate);
  // Create the exception at this point so we get the stack-trace that
  // belongs to the fetch() call.
  v8::Local<v8::Value> exception =
      V8ThrowException::CreateTypeError(isolate, "Failed to fetch");
  exception_.Reset(isolate, exception);
}

void ResponseResolver::Resolve(Response* response) {
  CHECK(resolver_);
  resolver_->Resolve(response);
  Clear();
}

void ResponseResolver::Reject(v8::Local<v8::Value> error) {
  CHECK(resolver_);
  resolver_->Reject(error);
  Clear();
}

void ResponseResolver::Reject(DOMException* dom_exception) {
  CHECK(resolver_);
  resolver_->Reject(dom_exception);
  Clear();
}

void ResponseResolver::RejectBecauseFailed(
    std::optional<String> devtools_request_id,
    std::optional<base::UnguessableToken> issue_id,
    std::optional<String> issue_summary) {
  CHECK(resolver_);
  auto* script_state = resolver_->GetScriptState();
  auto* isolate = script_state->GetIsolate();
  auto context = script_state->GetContext();
  v8::Local<v8::Value> value = exception_.Get(isolate);
  exception_.Reset();
  if (devtools_request_id || issue_id || issue_summary) {
    ThreadDebugger* debugger = ThreadDebugger::From(isolate);
    auto* inspector = debugger->GetV8Inspector();
    if (devtools_request_id) {
      inspector->associateExceptionData(
          context, value, V8AtomicString(isolate, "requestId"),
          V8String(isolate, *devtools_request_id));
    }
    if (issue_id) {
      inspector->associateExceptionData(
          context, value, V8AtomicString(isolate, "issueId"),
          V8String(isolate, IdentifiersFactory::IdFromToken(*issue_id)));
    }
    if (issue_summary) {
      inspector->associateExceptionData(context, value,
                                        V8AtomicString(isolate, "issueSummary"),
                                        V8String(isolate, *issue_summary));
    }
  }
  resolver_->Reject(value);
  Clear();
}

void ResponseResolver::Clear() {
  resolver_.Clear();
  exception_.Clear();
}

// Returns the length of `url` without any fragment parts.
uint64_t GetUrlLengthWithoutFragment(const KURL& url) {
  KURL cloned_url = url;
  cloned_url.RemoveFragmentIdentifier();
  return url.GetString().length();
}

}  // namespace

// FetchLoaderBase provides common logic to prepare a blink::ResourceRequest
// from a FetchRequestData.
class FetchLoaderBase : public GarbageCollectedMixin {
 public:
  explicit FetchLoaderBase(ExecutionContext* ec,
                           FetchRequestData* data,
                           ScriptState* script_state,
                           AbortSignal* signal)
      : execution_context_(ec),
        fetch_request_data_(data),
        script_state_(script_state),
        world_(std::move(&script_state->World())),
        signal_(signal),
        abort_handle_(signal->AddAlgorithm(
            WTF::BindOnce(&FetchLoaderBase::Abort, WrapWeakPersistent(this)))) {
    CHECK(world_);
  }

  // Starts to perform the "Fetching" algorithm.
  // https://fetch.spec.whatwg.org/#fetching
  // Note that the actual loading is delegated to subclass via `CreateLoader()`,
  // which may or may not start loading immediately.
  void Start(ExceptionState&);

  // Disposes this loader.
  // The owner of this loader uses this method to notify disposing of this
  // loader after removing from its container.
  // Depending on how subclass is implemented, this method may be called
  // multiple times before this instance is gone.
  virtual void Dispose() = 0;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(execution_context_);
    visitor->Trace(fetch_request_data_);
    visitor->Trace(script_state_);
    visitor->Trace(signal_);
    visitor->Trace(abort_handle_);
    visitor->Trace(world_);
  }

 protected:
  virtual bool IsDeferred() const = 0;
  virtual void Abort() = 0;
  virtual void CreateLoader(
      ResourceRequest request,
      const ResourceLoaderOptions& resource_loader_options) = 0;
  virtual void Failed(
      const String& message,
      DOMException* dom_exception,
      std::optional<String> devtools_request_id = std::nullopt,
      std::optional<base::UnguessableToken> issue_id = std::nullopt,
      std::optional<String> issue_summary = std::nullopt) = 0;

  void PerformSchemeFetch(ExceptionState&);
  void PerformNetworkError(
      const String& message,
      std::optional<base::UnguessableToken> issue_id = std::nullopt);
  void FileIssueAndPerformNetworkError(RendererCorsIssueCode,
                                       int64_t identifier);
  void PerformHTTPFetch(ExceptionState&);
  void PerformDataFetch();
  bool AddConsoleMessage(const String& message,
                         std::optional<base::UnguessableToken> issue_id);

  ExecutionContext* GetExecutionContext() { return execution_context_.Get(); }
  void SetExecutionContext(ExecutionContext* ec) { execution_context_ = ec; }
  FetchRequestData* GetFetchRequestData() const {
    return fetch_request_data_.Get();
  }
  ScriptState* GetScriptState() { return script_state_.Get(); }
  const DOMWrapperWorld* World() { return world_; }
  AbortSignal* Signal() { return signal_.Get(); }

 private:
  Member<ExecutionContext> execution_context_;
  Member<FetchRequestData> fetch_request_data_;
  Member<ScriptState> script_state_;
  Member<const DOMWrapperWorld> world_;
  Member<AbortSignal> signal_;
  Member<AbortSignal::AlgorithmHandle> abort_handle_;
};

class FetchManager::Loader final
    : public GarbageCollected<FetchManager::Loader>,
      public FetchLoaderBase,
      public ThreadableLoaderClient {
 public:
  Loader(ExecutionContext*,
         FetchManager*,
         ScriptPromiseResolver<Response>*,
         FetchRequestData*,
         ScriptState*,
         AbortSignal*);
  ~Loader() override;
  void Trace(Visitor*) const override;

  void Dispose() override;

  void LogIfKeepalive(std::string_view request_state) const;

  // ThreadableLoaderClient implementation.
  bool WillFollowRedirect(uint64_t,
                          const KURL&,
                          const ResourceResponse&) override;
  void DidReceiveResponse(uint64_t, const ResourceResponse&) override;
  void DidReceiveCachedMetadata(mojo_base::BigBuffer) override;
  void DidStartLoadingResponseBody(BytesConsumer&) override;
  void DidFinishLoading(uint64_t) override;
  void DidFail(uint64_t, const ResourceError&) override;
  void DidFailRedirectCheck(uint64_t) override;

  class SRIVerifier final : public GarbageCollected<SRIVerifier>,
                            public BytesConsumer::Client {
   public:
    SRIVerifier(BytesConsumer* body,
                PlaceHolderBytesConsumer* updater,
                Response* response,
                FetchManager::Loader* loader,
                String integrity_metadata,
                const KURL& url,
                FetchResponseType response_type)
        : body_(body),
          updater_(updater),
          response_(response),
          loader_(loader),
          integrity_metadata_(integrity_metadata),
          url_(url),
          response_type_(response_type) {
      body_->SetClient(this);

      OnStateChange();
    }

    void Cancel() { body_->Cancel(); }

    void OnStateChange() override {
      using Result = BytesConsumer::Result;

      DCHECK(loader_);
      DCHECK(response_);

      Result result = Result::kOk;
      while (result == Result::kOk) {
        base::span<const char> buffer;
        result = body_->BeginRead(buffer);
        if (result == Result::kOk) {
          buffer_.Append(buffer);
          result = body_->EndRead(buffer.size());
        }
        if (result == Result::kShouldWait)
          return;
      }

      finished_ = true;
      if (result == Result::kDone) {
        SubresourceIntegrity::ReportInfo report_info;
        bool check_result = true;
        bool body_is_null = !updater_;
        if (body_is_null || (response_type_ != FetchResponseType::kBasic &&
                             response_type_ != FetchResponseType::kCors &&
                             response_type_ != FetchResponseType::kDefault)) {
          report_info.AddConsoleErrorMessage(
              "Subresource Integrity: The resource '" + url_.ElidedString() +
              "' has an integrity attribute, but the response is not "
              "eligible for integrity validation.");
          check_result = false;
        }
        if (check_result) {
          check_result = SubresourceIntegrity::CheckSubresourceIntegrity(
              integrity_metadata_,
              SubresourceIntegrityHelper::GetFeatures(
                  loader_->GetExecutionContext()),
              &buffer_, url_, report_info);
        }
        SubresourceIntegrityHelper::DoReport(*loader_->GetExecutionContext(),
                                             report_info);
        if (check_result) {
          updater_->Update(
              MakeGarbageCollected<FormDataBytesConsumer>(std::move(buffer_)));
          loader_->response_resolver_->Resolve(response_);
          loader_->response_resolver_.Clear();
          return;
        }
      }
      String error_message =
          "Unknown error occurred while trying to verify integrity.";
      if (updater_) {
        updater_->Update(
            BytesConsumer::CreateErrored(BytesConsumer::Error(error_message)));
      }
      loader_->PerformNetworkError(error_message);
    }

    String DebugName() const override { return "SRIVerifier"; }

    bool IsFinished() const { return finished_; }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(body_);
      visitor->Trace(updater_);
      visitor->Trace(response_);
      visitor->Trace(loader_);
    }

   private:
    Member<BytesConsumer> body_;
    Member<PlaceHolderBytesConsumer> updater_;
    Member<Response> response_;
    Member<FetchManager::Loader> loader_;
    String integrity_metadata_;
    KURL url_;
    const FetchResponseType response_type_;
    SegmentedBuffer buffer_;
    bool finished_ = false;
  };

 private:
  bool IsDeferred() const override;
  void Abort() override;
  void NotifyFinished();
  void CreateLoader(
      ResourceRequest request,
      const ResourceLoaderOptions& resource_loader_options) override;
  // If |dom_exception| is provided, throws the specified DOMException instead
  // of the usual "Failed to fetch" TypeError.
  void Failed(const String& message,
              DOMException* dom_exception,
              std::optional<String> devtools_request_id = std::nullopt,
              std::optional<base::UnguessableToken> issue_id = std::nullopt,
              std::optional<String> issue_summary = std::nullopt) override;

  Member<FetchManager> fetch_manager_;
  Member<ResponseResolver> response_resolver_;
  Member<ThreadableLoader> threadable_loader_;
  Member<PlaceHolderBytesConsumer> place_holder_body_;
  bool failed_;
  bool finished_;
  int response_http_status_code_;
  bool response_has_no_store_header_ = false;
  Member<SRIVerifier> integrity_verifier_;
  Vector<KURL> url_list_;
  Member<ScriptCachedMetadataHandler> cached_metadata_handler_;
  base::TimeTicks request_started_time_;
};

FetchManager::Loader::Loader(ExecutionContext* execution_context,
                             FetchManager* fetch_manager,
                             ScriptPromiseResolver<Response>* resolver,
                             FetchRequestData* fetch_request_data,
                             ScriptState* script_state,
                             AbortSignal* signal)
    : FetchLoaderBase(execution_context,
                      fetch_request_data,
                      script_state,
                      signal),
      fetch_manager_(fetch_manager),
      response_resolver_(MakeGarbageCollected<ResponseResolver>(resolver)),
      failed_(false),
      finished_(false),
      response_http_status_code_(0),
      integrity_verifier_(nullptr),
      request_started_time_(base::TimeTicks::Now()) {
  DCHECK(World());
  url_list_.push_back(fetch_request_data->Url());
}

FetchManager::Loader::~Loader() {
  DCHECK(!threadable_loader_);
}

void FetchManager::Loader::Trace(Visitor* visitor) const {
  visitor->Trace(fetch_manager_);
  visitor->Trace(response_resolver_);
  visitor->Trace(threadable_loader_);
  visitor->Trace(place_holder_body_);
  visitor->Trace(integrity_verifier_);
  visitor->Trace(cached_metadata_handler_);
  FetchLoaderBase::Trace(visitor);
  ThreadableLoaderClient::Trace(visitor);
}

bool FetchManager::Loader::WillFollowRedirect(
    uint64_t identifier,
    const KURL& url,
    const ResourceResponse& response) {
  const auto redirect_mode = GetFetchRequestData()->Redirect();
  if (redirect_mode == network::mojom::RedirectMode::kError) {
    DidFailRedirectCheck(identifier);
    Dispose();
    return false;
  }

  if (redirect_mode == network::mojom::RedirectMode::kManual) {
    const uint64_t unused = 0;
    // There is no need to read the body of redirect response because there is
    // no way to read the body of opaque-redirect filtered response's internal
    // response.
    // TODO(horo): If we support any API which expose the internal body, we
    // will have to read the body. And also HTTPCache changes will be needed
    // because it doesn't store the body of redirect responses.
    DidReceiveResponse(unused, response);
    DidStartLoadingResponseBody(*BytesConsumer::CreateClosed());

    if (threadable_loader_)
      NotifyFinished();

    Dispose();
    return false;
  }

  DCHECK_EQ(redirect_mode, network::mojom::RedirectMode::kFollow);
  url_list_.push_back(url);
  return true;
}

void FetchManager::Loader::DidReceiveResponse(
    uint64_t,
    const ResourceResponse& response) {
  // Verify that we're dealing with the URL we expect (which could be an
  // HTTPS-upgraded variant of `url_list_.back()`.
  DCHECK(
      response.CurrentRequestUrl() == url_list_.back() ||
      (response.CurrentRequestUrl().ProtocolIs("https") &&
       url_list_.back().ProtocolIs("http") &&
       response.CurrentRequestUrl().Host() == url_list_.back().Host() &&
       response.CurrentRequestUrl().GetPath() == url_list_.back().GetPath() &&
       response.CurrentRequestUrl().Query() == url_list_.back().Query()));

  auto response_type = response.GetType();
  DCHECK_NE(response_type, FetchResponseType::kError);

  LogIfKeepalive("Succeeded");

  ScriptState::Scope scope(GetScriptState());

  response_http_status_code_ = response.HttpStatusCode();

  if (response.MimeType() == "application/wasm" &&
      (response.CurrentRequestUrl().ProtocolIsInHTTPFamily() ||
       CommonSchemeRegistry::IsExtensionScheme(
           response.CurrentRequestUrl().Protocol().Ascii()))) {
    // We create a ScriptCachedMetadataHandler for WASM modules.
    cached_metadata_handler_ =
        MakeGarbageCollected<ScriptCachedMetadataHandler>(
            WTF::TextEncoding(),
            CachedMetadataSender::Create(
                response, mojom::blink::CodeCacheType::kWebAssembly,
                GetExecutionContext()->GetSecurityOrigin()));
  }

  place_holder_body_ = MakeGarbageCollected<PlaceHolderBytesConsumer>();
  FetchResponseData* response_data = FetchResponseData::CreateWithBuffer(
      BodyStreamBuffer::Create(GetScriptState(), place_holder_body_, Signal(),
                               cached_metadata_handler_));
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed() ||
      response.GetType() == FetchResponseType::kError) {
    // BodyStreamBuffer::Create() may run scripts and cancel this request.
    // Do nothing in such a case.
    // See crbug.com/1373785 for more details.
    return;
  }

  DCHECK_EQ(response_type, response.GetType());
  DCHECK(!(network_utils::IsRedirectResponseCode(response_http_status_code_) &&
           HasNonEmptyLocationHeader(response_data->HeaderList()) &&
           GetFetchRequestData()->Redirect() != RedirectMode::kManual));

  if (network_utils::IsRedirectResponseCode(response_http_status_code_) &&
      GetFetchRequestData()->Redirect() == RedirectMode::kManual) {
    response_type = network::mojom::FetchResponseType::kOpaqueRedirect;
  }

  response_data->InitFromResourceResponse(
      GetExecutionContext(), response_type, url_list_,
      GetFetchRequestData()->Method(), GetFetchRequestData()->Credentials(),
      response);

  FetchResponseData* tainted_response = nullptr;
  switch (response_type) {
    case FetchResponseType::kBasic:
    case FetchResponseType::kDefault:
      tainted_response = response_data->CreateBasicFilteredResponse();
      break;
    case FetchResponseType::kCors: {
      HTTPHeaderSet header_names = cors::ExtractCorsExposedHeaderNamesList(
          GetFetchRequestData()->Credentials(), response);
      tainted_response =
          response_data->CreateCorsFilteredResponse(header_names);
      break;
    }
    case FetchResponseType::kOpaque:
      tainted_response = response_data->CreateOpaqueFilteredResponse();
      break;
    case FetchResponseType::kOpaqueRedirect:
      tainted_response = response_data->CreateOpaqueRedirectFilteredResponse();
      break;
    case FetchResponseType::kError:
      NOTREACHED();
  }
  // TODO(crbug.com/1288221): Remove this once the investigation is done.
  CHECK(tainted_response);

  response_has_no_store_header_ = response.CacheControlContainsNoStore();

  Response* r = Response::Create(response_resolver_->GetExecutionContext(),
                                 tainted_response);
  r->headers()->SetGuard(Headers::kImmutableGuard);
  if (GetFetchRequestData()->Integrity().empty()) {
    response_resolver_->Resolve(r);
   
"""


```