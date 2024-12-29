Response:
Let's break down the thought process for analyzing the provided C++ code for `link_loader.cc`.

**1. Initial Understanding of the File Path and Name:**

* `blink/renderer/core/loader/link_loader.cc`: This path strongly suggests the file is part of the Blink rendering engine, specifically dealing with loading resources related to `<link>` elements in HTML. The "loader" directory further reinforces this.

**2. Examining the Header Includes:**

The included headers provide significant clues about the file's responsibilities:

* `public/mojom/fetch/fetch_api_request.mojom-shared.h`:  Indicates interaction with the Fetch API, suggesting network requests are involved.
* `core/dom/document.h`:  This signifies that the `LinkLoader` interacts with the DOM structure of the web page.
* `core/frame/local_dom_window.h`, `core/frame/local_frame.h`: Points to interaction with the browsing context and frame structure.
* `core/loader/fetch_priority_attribute.h`, `core/loader/link_load_parameters.h`, `core/loader/link_loader_client.h`, `core/loader/pending_link_preload.h`, `core/loader/preload_helper.h`, `core/loader/prerender_handle.h`: These are all directly related to link loading, preloading, and prerendering. The `LinkLoaderClient` suggests a delegate pattern.
* `core/loader/resource/css_style_sheet_resource.h`: Explicitly shows handling of CSS stylesheets loaded via `<link>`.
* `core/loader/subresource_integrity_helper.h`:  Indicates support for Subresource Integrity (SRI).
* `core/page/viewport_description.h`: Suggests involvement in optimizing loading based on viewport characteristics.
* `platform/heap/prefinalizer.h`, `platform/instrumentation/use_counter.h`:  Lower-level platform concerns like memory management and usage tracking.
* `platform/loader/fetch/resource_client.h`, `platform/loader/fetch/resource_finish_observer.h`, `platform/loader/fetch/resource_loader_options.h`, `platform/loader/subresource_integrity.h`:  More fundamental platform-level fetching and resource handling.

**3. Analyzing the `LinkLoader` Class:**

* **Constructor:** Takes a `LinkLoaderClient*`, confirming the delegate pattern.
* **`NotifyFinished(Resource* resource)`:**  Handles the completion of a resource load, checking for errors and integrity.
* **`NotifyModuleLoadFinished(ModuleScript* module)`:** Specifically handles the completion of module script loading via `<link rel="modulepreload">`.
* **`GetResourceForTesting()`:**  Provides a way to access the underlying resource for testing purposes.
* **`LoadLink(const LinkLoadParameters& params, Document& document)`:** The core method. It seems responsible for initiating the loading of various link types based on the parameters. It handles prefetching, preconnecting, preloading, and prerendering.
* **`LoadStylesheet(...)`:** A specialized method for loading CSS stylesheets. It sets up resource requests with specific options like charset, defer, nonce, crossorigin, and integrity.
* **`Abort()`:** Cleans up any ongoing loading or preloading/prerendering processes.
* **`Trace(Visitor* visitor)`:**  Part of Blink's tracing infrastructure for debugging and memory management.

**4. Identifying Key Functionality:**

Based on the above, the main functions of `LinkLoader` are:

* **Initiating Resource Loading:**  Specifically for resources referenced by `<link>` elements.
* **Handling Different Link Types:** Supporting `preload`, `prefetch`, `preconnect`, `prerender`, and stylesheets.
* **Applying Fetching Optimizations:** Implementing prefetching, preconnecting, and preloading strategies.
* **Managing Prerendering:**  Creating and managing `PrerenderHandle` for speculative page loads.
* **Enforcing Security and Integrity:**  Handling `crossorigin` attributes and Subresource Integrity (SRI).
* **Notifying the Client:** Using the `LinkLoaderClient` to inform the higher-level code about the status of link loading.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **HTML:**  The `<link>` element in HTML is the direct trigger for the `LinkLoader`'s actions. Different `rel` attribute values (e.g., `stylesheet`, `preload`, `prefetch`, `prerender`, `modulepreload`) determine the specific loading behavior.
* **CSS:** The `LoadStylesheet` method directly handles `<link rel="stylesheet">`. It fetches the CSS file and applies the specified attributes.
* **JavaScript:**
    * `<link rel="modulepreload">`: Handled by `NotifyModuleLoadFinished`. This optimizes loading of JavaScript modules.
    *  JavaScript can dynamically create `<link>` elements, triggering the `LinkLoader`.
    *  SRI (Subresource Integrity) applies to JavaScript files loaded via `<link>` as well.

**6. Logic and Assumptions (Hypothetical Inputs/Outputs):**

* **Input:**  A `<link rel="preload" href="image.png" as="image">` tag encountered during HTML parsing.
* **Output:** `LoadLink` is called. `PreloadHelper::PreloadIfNeeded` would be invoked, potentially initiating a high-priority fetch for `image.png`. `pending_preload_` would be involved to track the request.
* **Input:** A `<link rel="stylesheet" href="style.css">` tag.
* **Output:** `LoadStylesheet` is called. A `ResourceRequest` for `style.css` is created with appropriate headers (potentially including `crossorigin`, `integrity`). A `CSSStyleSheetResource` fetch is initiated.

**7. Common User/Programming Errors:**

* **Incorrect `rel` attribute:**  Using an invalid or misspelled `rel` value might lead to unexpected loading behavior or the link being ignored.
* **Incorrect `href`:**  A broken or incorrect URL in the `href` will result in a failed resource load.
* **CORS issues:**  If a stylesheet or other resource is loaded from a different origin without proper CORS headers on the server, the load will be blocked. The `crossorigin` attribute helps manage this.
* **SRI mismatches:** If the `integrity` attribute doesn't match the actual content of the fetched resource, the resource will be rejected.
* **Preload misuse:**  Preloading too many resources or resources that aren't critical can hurt performance.

**8. Debugging Scenario:**

Imagine a user reports that a stylesheet isn't loading correctly. A developer might:

1. **Inspect the HTML:** Verify the `<link>` tag's `href` and `rel` attributes.
2. **Check the Network Tab:** See if the request for the CSS file was made, what the status code was, and if there were any CORS or integrity errors.
3. **Set a breakpoint in `LinkLoader::LoadStylesheet`:**  To examine the `LinkLoadParameters` and the created `ResourceRequest`. This can help determine if the correct URL, CORS settings, and integrity metadata are being used.
4. **Step through the code:** Follow the execution flow in `LoadStylesheet` and related functions like `CSSStyleSheetResource::Fetch` to pinpoint the source of the problem.

This systematic approach of understanding the code's purpose, examining its components, and connecting it to web technologies is key to analyzing and debugging complex systems like a browser engine.
这个文件 `blink/renderer/core/loader/link_loader.cc` 是 Chromium Blink 渲染引擎中的一部分，负责处理 HTML 中 `<link>` 元素的加载和相关操作。它扮演着一个协调者的角色，根据 `<link>` 元素的属性 (如 `rel`, `href`, `as`, `media` 等)，来执行不同的加载策略，并与其他的 Blink 组件进行交互。

以下是 `LinkLoader` 的主要功能：

**1. 加载各种类型的资源：**

*   **样式表 (Stylesheet):** 当 `<link rel="stylesheet">` 时，`LinkLoader` 会负责发起对 CSS 文件的网络请求，并将其解析为样式表。
*   **预加载资源 (Preload):** 当 `<link rel="preload">` 时，`LinkLoader` 会提前发起对指定资源的请求，以便在后续需要时可以更快地使用。可以预加载各种类型的资源，如脚本、样式表、字体、图片等。
*   **预连接 (Preconnect):** 当 `<link rel="preconnect">` 时，`LinkLoader` 会提前与指定的服务器建立连接 (TCP 握手，TLS 协商)，减少后续请求的延迟。
*   **预读取 DNS (DNS Prefetch):** 当 `<link rel="dns-prefetch">` 时，`LinkLoader` 会提前解析指定域名的 IP 地址，加速后续对该域名的请求。
*   **预渲染 (Prerender):** 当 `<link rel="prerender">` 或 `<link rel="next">` 时，`LinkLoader` 会尝试在后台提前渲染整个页面，以便用户点击链接时可以立即显示。
*   **模块预加载 (Module Preload):** 当 `<link rel="modulepreload">` 时，`LinkLoader` 会预先加载 JavaScript 模块，提高模块加载速度。
*   **获取压缩字典 (Fetch Compression Dictionary):**  虽然代码中包含 `PreloadHelper::FetchCompressionDictionaryIfNeeded`, 但这部分功能可能与 HTTP 压缩字典 (如 `Content-Encoding: compress-dictionary`) 的预加载有关，以优化后续资源的解压缩。

**2. 管理加载状态和错误处理：**

*   跟踪正在进行的加载操作。
*   在资源加载完成时 (成功或失败) 通知客户端 (`LinkLoaderClient`)。
*   处理资源加载过程中出现的错误，例如网络错误、Integrity 校验失败等。

**3. 应用各种加载优化策略：**

*   根据 `fetchpriority` 属性设置请求的优先级。
*   处理 `crossorigin` 属性以进行跨域资源请求。
*   支持 Subresource Integrity (SRI) 校验，确保加载的资源未被篡改。
*   根据 `media` 属性判断是否需要加载资源 (例如，仅在特定屏幕尺寸下加载某些样式表)。

**4. 与其他 Blink 组件交互：**

*   与 `Document` 对象交互，获取当前文档的上下文信息。
*   与 `LocalFrame` 对象交互，获取当前框架的信息。
*   使用 `PreloadHelper` 类来执行实际的预加载、预连接等操作。
*   使用 `ResourceRequest` 类创建网络请求。
*   使用 `CSSStyleSheetResource` 类处理样式表资源的加载。
*   使用 `PrerenderHandle` 类管理预渲染操作。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

*   **HTML:** `LinkLoader` 的核心作用是处理 HTML 中的 `<link>` 元素。不同的 `rel` 属性值会触发 `LinkLoader` 的不同功能。
    *   **示例:**
        ```html
        <link rel="stylesheet" href="style.css">  // 加载 CSS 样式表
        <link rel="preload" href="image.png" as="image"> // 预加载图片
        <link rel="preconnect" href="https://example.com"> // 预连接到 example.com
        <link rel="modulepreload" href="module.js"> // 预加载 JavaScript 模块
        ```
*   **CSS:** 当 `<link rel="stylesheet">` 时，`LinkLoader` 会下载 CSS 文件，并将其交给 Blink 的 CSS 解析器进行解析和应用。
    *   **示例:** 上面的 `<link rel="stylesheet" href="style.css">` 会导致 `LinkLoader` 下载 `style.css` 并创建 `CSSStyleSheetResource` 对象。
*   **JavaScript:** 虽然 `LinkLoader` 本身是用 C++ 编写的，但它直接影响 JavaScript 的性能和功能：
    *   **模块预加载:**  `<link rel="modulepreload">` 可以加速 JavaScript 模块的加载，提高页面加载速度，从而提升 JavaScript 应用的性能。
    *   **预加载其他资源:**  通过 `<link rel="preload">` 预加载 JavaScript 文件可以提前下载脚本，减少脚本的执行延迟。
    *   **Subresource Integrity:**  通过 `integrity` 属性可以校验 JavaScript 文件的完整性，防止恶意代码注入。
        *   **示例:**
            ```html
            <link rel="modulepreload" href="module.js" integrity="sha384-...">
            <link rel="preload" href="script.js" as="script">
            ```
    *   **动态创建 `<link>` 元素:** JavaScript 可以动态创建 `<link>` 元素并添加到 DOM 中，从而触发 `LinkLoader` 的功能。

**逻辑推理的假设输入与输出：**

假设输入以下 HTML 片段被解析器处理：

```html
<link rel="preload" href="font.woff2" as="font" type="font/woff2" crossorigin>
```

*   **假设输入:**  一个包含上述 `<link>` 元素的 HTML 代码片段。
*   **逻辑推理:**
    1. 解析器遇到 `<link>` 元素，并提取其属性。
    2. `LinkLoader::LoadLink` 方法被调用，传入包含 `rel="preload"`, `href="font.woff2"`, `as="font"`, `type="font/woff2"`, `crossorigin` 等信息的 `LinkLoadParameters` 对象。
    3. `LinkLoader` 判断 `rel` 属性为 "preload"。
    4. `PreloadHelper::PreloadIfNeeded` 方法被调用，并根据提供的参数创建一个针对 `font.woff2` 的预加载请求。
    5. 由于指定了 `crossorigin`，请求会包含 CORS 相关的头信息。
    6. `pending_preload_` 成员可能会被更新，用于跟踪预加载状态。
*   **预期输出:**  浏览器会发起一个针对 `font.woff2` 的网络请求，优先级较高，并且带有 CORS 相关的头信息。当后续页面渲染需要该字体时，可以更快地加载。

**用户或编程常见的使用错误及举例说明：**

*   **错误使用 `rel="preload"`:**
    *   **错误示例:** `<link rel="preload" href="unused.jpg" as="image">`  预加载了但页面上没有使用的资源，浪费了带宽。
    *   **说明:** 用户或开发者错误地预加载了实际上并不需要的资源，导致不必要的网络请求。
*   **`href` 路径错误:**
    *   **错误示例:** `<link rel="stylesheet" href="styels.css">`  `href` 拼写错误。
    *   **说明:**  常见的拼写错误或路径错误会导致资源加载失败，页面样式或功能不完整。
*   **CORS 配置错误:**
    *   **错误示例:**  `<link rel="stylesheet" href="https://other-domain.com/style.css" crossorigin>`，但 `other-domain.com` 的服务器没有设置正确的 CORS 头信息。
    *   **说明:**  跨域加载资源时，如果服务器没有正确配置 CORS，浏览器会阻止资源的加载。
*   **SRI 校验失败:**
    *   **错误示例:**  `<link rel="stylesheet" href="style.css" integrity="sha384-incorrect-hash">`，`integrity` 属性的值与实际资源的哈希值不匹配。
    *   **说明:**  如果加载的资源被篡改，或者 `integrity` 值不正确，浏览器会拒绝使用该资源。
*   **错误的 `as` 属性:**
    *   **错误示例:** `<link rel="preload" href="script.js" as="image">`，将 JavaScript 文件错误地标记为 "image"。
    *   **说明:**  `as` 属性帮助浏览器确定资源的类型，以便设置正确的请求头和优先级。错误的 `as` 属性可能导致加载优先级不正确，甚至加载失败。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 或点击链接，导航到一个新的网页。**
2. **Blink 的 HTML 解析器开始解析下载的 HTML 文档。**
3. **当解析器遇到 `<link>` 元素时，会创建相应的 DOM 节点。**
4. **根据 `<link>` 元素的 `rel` 属性，会触发不同的加载流程。**
5. **如果 `rel` 属性是 "stylesheet"，则会调用 `LinkLoader::LoadStylesheet`。**
6. **如果 `rel` 属性是 "preload" 或其他预加载相关的属性，则会调用 `LinkLoader::LoadLink`。**
7. **`LinkLoader` 对象会根据 `<link>` 元素的其他属性 (如 `href`, `as`, `media`, `crossorigin`, `integrity` 等) 创建 `ResourceRequest`，并交给网络模块发起请求。**
8. **网络模块下载资源后，会通知 `LinkLoader`。**
9. **`LinkLoader` 会根据资源类型进行相应的处理 (例如，解析 CSS，执行 JavaScript 模块等)，并通知 `LinkLoaderClient` 加载完成或发生错误。**

**作为调试线索，当开发者遇到与 `<link>` 元素加载相关的问题时 (例如，样式没有应用，预加载的资源没有生效，跨域资源加载失败等)，可以：**

*   **检查 HTML 源代码，确认 `<link>` 元素的属性是否正确。**
*   **使用浏览器的开发者工具 (Network 选项卡) 查看网络请求，确认资源是否被请求，状态码是什么，请求头和响应头是否符合预期 (例如，CORS 头)。**
*   **在 `blink/renderer/core/loader/link_loader.cc` 中设置断点，例如在 `LoadLink` 或 `LoadStylesheet` 方法的入口处，以及处理加载完成和错误通知的地方，来跟踪代码执行流程，查看 `LinkLoadParameters` 的值，以及 `ResourceRequest` 的创建过程。**
*   **检查浏览器的控制台，查看是否有与 `<link>` 元素加载相关的错误或警告信息 (例如，CORS 错误，SRI 校验失败)。**

总而言之，`blink/renderer/core/loader/link_loader.cc` 是 Blink 引擎中负责处理 HTML `<link>` 元素的核心组件，它关系到网页资源的加载和性能优化，并与 HTML, CSS, JavaScript 等多种 Web 技术紧密相关。理解其功能对于开发和调试 Web 页面至关重要。

Prompt: 
```
这是目录为blink/renderer/core/loader/link_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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
 *
 */

#include "third_party/blink/renderer/core/loader/link_loader.h"

#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-shared.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/loader/fetch_priority_attribute.h"
#include "third_party/blink/renderer/core/loader/link_load_parameters.h"
#include "third_party/blink/renderer/core/loader/link_loader_client.h"
#include "third_party/blink/renderer/core/loader/pending_link_preload.h"
#include "third_party/blink/renderer/core/loader/preload_helper.h"
#include "third_party/blink/renderer/core/loader/prerender_handle.h"
#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"
#include "third_party/blink/renderer/core/loader/subresource_integrity_helper.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/platform/heap/prefinalizer.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_finish_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"

namespace blink {

class WebPrescientNetworking;

namespace {

// Decide the prerender type based on the link rel attribute. Returns
// std::nullopt if the attribute doesn't indicate the prerender type.
std::optional<mojom::blink::PrerenderTriggerType>
PrerenderTriggerTypeFromRelAttribute(const LinkRelAttribute& rel_attribute,
                                     Document& document) {
  std::optional<mojom::blink::PrerenderTriggerType> trigger_type;
  if (rel_attribute.IsLinkPrerender()) {
    UseCounter::Count(document, WebFeature::kLinkRelPrerender);
    trigger_type = mojom::blink::PrerenderTriggerType::kLinkRelPrerender;
  }
  if (rel_attribute.IsLinkNext()) {
    UseCounter::Count(document, WebFeature::kLinkRelNext);
    // Prioritize mojom::blink::PrerenderTriggerType::kLinkRelPrerender.
    if (!trigger_type)
      trigger_type = mojom::blink::PrerenderTriggerType::kLinkRelNext;
  }
  return trigger_type;
}

}  // namespace

LinkLoader::LinkLoader(LinkLoaderClient* client) : client_(client) {
  DCHECK(client_);
}

void LinkLoader::NotifyFinished(Resource* resource) {
  if (resource->ErrorOccurred() || (resource->ForceIntegrityChecks() &&
                                    !resource->PassedIntegrityChecks())) {
    client_->LinkLoadingErrored();
  } else {
    client_->LinkLoaded();
  }
}

// https://html.spec.whatwg.org/C/#link-type-modulepreload
void LinkLoader::NotifyModuleLoadFinished(ModuleScript* module) {
  // Step 14. "If result is null, fire an event named error at the link element,
  // and return." [spec text]
  // Step 15. "Fire an event named load at the link element." [spec text]
  if (!module)
    client_->LinkLoadingErrored();
  else
    client_->LinkLoaded();
}

Resource* LinkLoader::GetResourceForTesting() {
  return pending_preload_ ? pending_preload_->GetResourceForTesting() : nullptr;
}

bool LinkLoader::LoadLink(const LinkLoadParameters& params,
                          Document& document) {
  if (!client_->ShouldLoadLink()) {
    Abort();
    return false;
  }

  if (!pending_preload_ ||
      (params.reason != LinkLoadParameters::Reason::kMediaChange ||
       !pending_preload_->MatchesMedia())) {
    Abort();
    pending_preload_ = MakeGarbageCollected<PendingLinkPreload>(document, this);
  }

  // If any loading process is in progress, abort it.

  PreloadHelper::DnsPrefetchIfNeeded(params, &document, document.GetFrame(),
                                     PreloadHelper::kLinkCalledFromMarkup);

  PreloadHelper::PreconnectIfNeeded(params, &document, document.GetFrame(),
                                    PreloadHelper::kLinkCalledFromMarkup);

  PreloadHelper::PreloadIfNeeded(
      params, document, NullURL(), PreloadHelper::kLinkCalledFromMarkup,
      nullptr /* viewport_description */,
      client_->IsLinkCreatedByParser() ? kParserInserted : kNotParserInserted,
      pending_preload_);
  if (!pending_preload_->HasResource())
    PreloadHelper::PrefetchIfNeeded(params, document, pending_preload_);
  PreloadHelper::ModulePreloadIfNeeded(
      params, document, nullptr /* viewport_description */, pending_preload_);
  PreloadHelper::FetchCompressionDictionaryIfNeeded(params, document,
                                                    pending_preload_);

  std::optional<mojom::blink::PrerenderTriggerType> trigger_type =
      PrerenderTriggerTypeFromRelAttribute(params.rel, document);
  if (trigger_type) {
    // The previous prerender should already be aborted by Abort().
    DCHECK(!prerender_);
    prerender_ = PrerenderHandle::Create(document, params.href, *trigger_type);
  }
  return true;
}

void LinkLoader::LoadStylesheet(
    const LinkLoadParameters& params,
    const AtomicString& local_name,
    const WTF::TextEncoding& charset,
    FetchParameters::DeferOption defer_option,
    Document& document,
    ResourceClient* link_client,
    RenderBlockingBehavior render_blocking_behavior) {
  ExecutionContext* context = document.GetExecutionContext();
  ResourceRequest resource_request(context->CompleteURL(params.href));
  resource_request.SetReferrerPolicy(params.referrer_policy);

  mojom::blink::FetchPriorityHint fetch_priority_hint =
      GetFetchPriorityAttributeValue(params.fetch_priority_hint);
  resource_request.SetFetchPriorityHint(fetch_priority_hint);

  ResourceLoaderOptions options(context->GetCurrentWorld());
  options.initiator_info.name = local_name;

  FetchParameters link_fetch_params(std::move(resource_request), options);
  link_fetch_params.SetCharset(charset);
  link_fetch_params.SetDefer(defer_option);
  link_fetch_params.SetRenderBlockingBehavior(render_blocking_behavior);
  link_fetch_params.SetContentSecurityPolicyNonce(params.nonce);

  CrossOriginAttributeValue cross_origin = params.cross_origin;
  if (cross_origin != kCrossOriginAttributeNotSet) {
    link_fetch_params.SetCrossOriginAccessControl(context->GetSecurityOrigin(),
                                                  cross_origin);
  }

  String integrity_attr = params.integrity;
  if (!integrity_attr.empty()) {
    IntegrityMetadataSet metadata_set;
    SubresourceIntegrity::ParseIntegrityAttribute(
        integrity_attr, SubresourceIntegrityHelper::GetFeatures(context),
        metadata_set);
    link_fetch_params.SetIntegrityMetadata(metadata_set);
    link_fetch_params.MutableResourceRequest().SetFetchIntegrity(
        integrity_attr);
  }

  CSSStyleSheetResource::Fetch(link_fetch_params, context->Fetcher(),
                               link_client);
}

void LinkLoader::Abort() {
  if (prerender_) {
    prerender_->Cancel();
    prerender_.Clear();
  }
  if (pending_preload_) {
    pending_preload_->Dispose();
    pending_preload_.Clear();
  }
}

void LinkLoader::Trace(Visitor* visitor) const {
  visitor->Trace(client_);
  visitor->Trace(pending_preload_);
  visitor->Trace(prerender_);
}

}  // namespace blink

"""

```