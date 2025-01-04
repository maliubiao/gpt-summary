Response:
Let's break down the thought process for analyzing this C++ source file and generating the comprehensive response.

1. **Understand the Goal:** The core request is to analyze `worker_classic_script_loader.cc` and explain its functionality, especially concerning JavaScript, HTML, CSS, and potential errors.

2. **Identify the Core Class:** The filename itself strongly suggests the central class: `WorkerClassicScriptLoader`. This will be the focus of the analysis.

3. **Analyze Includes:**  The included header files provide crucial context about the class's dependencies and responsibilities. Let's go through some key ones:
    * `third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h`: Hints at fetching resources over the network.
    * `third_party/blink/renderer/core/execution_context/execution_context.h`:  Indicates interaction with the runtime environment where JavaScript executes.
    * `third_party/blink/renderer/core/frame/csp/content_security_policy.h`:  Signals involvement with Content Security Policy.
    * `third_party/blink/renderer/core/html/parser/text_resource_decoder.h`: Suggests handling textual content and character encoding.
    * `third_party/blink/renderer/core/loader/resource/script_resource.h`:  Confirms the class's role in loading scripts.
    * `third_party/blink/renderer/core/workers/worker_global_scope.h`:  Establishes its association with Web Workers.
    * `third_party/blink/renderer/platform/loader/fetch/...`:  A plethora of fetch-related headers reinforces the resource loading aspect.
    * `third_party/blink/renderer/platform/network/...`:  Deals with network concepts like HTTP headers and URLs.

4. **Examine the Class Structure:** Look at the public and private members and methods of `WorkerClassicScriptLoader`.

5. **Analyze Key Methods:** Focus on the methods that seem most important for the core functionality:
    * `LoadSynchronously()` and `LoadTopLevelScriptAsynchronously()`: These clearly handle loading scripts, both synchronously and asynchronously. Notice the different parameters and how they handle different worker scenarios.
    * Callback methods like `DidReceiveResponse()`, `DidReceiveData()`, `DidFinishLoading()`, `DidFail()`:  These are typical for asynchronous resource loading and signal different stages of the process.
    * `Cancel()`: Allows stopping an ongoing load.
    * `SourceText()`:  Provides access to the loaded script content.
    * `ProcessContentSecurityPolicy()`:  Handles CSP for the loaded script.

6. **Identify Relationships to Web Technologies:**

    * **JavaScript:** The primary function is loading and handling JavaScript files for Web Workers. The `SourceText()` method returns the JavaScript code. The handling of errors directly impacts JavaScript execution.
    * **HTML:** While not directly parsing HTML, the loaded scripts are often referenced from HTML (though in the worker context, it's more about the initial worker script URL). CSP, which this class handles, is often set via HTML meta tags or HTTP headers from the main document.
    * **CSS:**  Workers themselves don't directly apply CSS to the main document's rendering. However, workers might fetch CSS files for processing or use within the worker's logic. The `WorkerClassicScriptLoader` could potentially load such CSS files (though the example focuses on scripts). CSP also applies to CSS.

7. **Look for Logic and Reasoning:** Pay attention to conditional statements and specific checks within the methods. The `CheckSameOriginEnforcement()` function is a prime example of logic to enforce security policies.

8. **Consider Potential Errors:** Think about what could go wrong during script loading:
    * Network errors (e.g., 404 Not Found).
    * Security violations (e.g., CORS issues, CSP blocks).
    * Incorrect MIME types.
    * Redirection failures.

9. **Construct Examples:** For each area (functionality, JavaScript/HTML/CSS relation, logic, errors), create specific examples to illustrate the points. This makes the explanation clearer and more concrete.

10. **Organize the Response:** Structure the information logically with clear headings and bullet points. Start with a general overview of the class's purpose, then delve into specifics. Address each part of the original request.

11. **Review and Refine:** Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have missed the detail about synchronous loading or the nuances of how `WorkerMainScriptLoader` is used. Reviewing helps catch these details.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have just stated "loads JavaScript files for workers."  During the analysis, looking at `LoadSynchronously` and `LoadTopLevelScriptAsynchronously` reveals *two* distinct loading paths. Further examination of the asynchronous path shows the involvement of `WorkerMainScriptLoader` for specific worker types. This deeper dive leads to a more accurate and nuanced description of the class's functionality. Similarly, realizing the role of `CheckSameOriginEnforcement` clarifies the security-related logic.

By following these steps, a comprehensive and accurate explanation of the `WorkerClassicScriptLoader` can be generated, addressing all aspects of the original request.
好的，让我们来分析一下 `blink/renderer/core/workers/worker_classic_script_loader.cc` 这个文件的功能。

**核心功能：**

`WorkerClassicScriptLoader` 的主要功能是**负责加载和获取 Web Worker (经典 Worker) 的脚本内容**。它是一个 Blink 渲染引擎中的组件，专门用于处理 Worker 启动时需要加载的 JavaScript 文件。

**功能分解：**

1. **发起脚本请求:**
   - 它接收要加载的脚本的 URL。
   - 使用 `ResourceRequest` 对象创建一个 HTTP 请求，通常是 GET 请求。
   - 可以同步或异步地发起请求（`LoadSynchronously` 和 `LoadTopLevelScriptAsynchronously` 方法）。

2. **处理请求选项:**
   - 设置请求的上下文类型 (`request_context`) 和目标 (`destination`)。
   - 可以设置请求模式 (`request_mode`) 和凭据模式 (`credentials_mode`)，用于控制跨域请求的行为。
   - 支持通过 `ResourceLoaderOptions` 设置各种加载选项，例如是否需要进行同源策略检查（CORS）、是否拒绝 `COEP: unsafe-none` 等。

3. **网络加载:**
   - 使用 `ThreadableLoader` (对于经典 Worker) 或 `WorkerMainScriptLoader` (对于 Dedicated Worker 和 Shared Worker 的主脚本) 来执行实际的网络请求。
   - `ThreadableLoader` 是一个用于执行线程安全网络请求的类。
   - `WorkerMainScriptLoader` 是一个专门用于加载 Worker 主脚本的类，它可能包含一些额外的处理逻辑。

4. **处理服务器响应:**
   - **检查 HTTP 状态码:** 确保响应状态码是 2xx (成功)。
   - **MIME 类型检查:** 验证响应的 `Content-Type` 是否是 JavaScript 相关的 MIME 类型，防止加载非脚本文件。
   - **同源策略检查 (Same-Origin Policy):** 对于顶层 Worker 脚本，会检查响应的 URL 是否与请求的 URL 同源，以确保安全性。如果不同源，会拒绝加载并输出错误信息到控制台。 `CheckSameOriginEnforcement` 函数负责这个逻辑。
   - **内容安全策略 (CSP) 处理:**  解析响应头中的 `Content-Security-Policy`，并存储到 `content_security_policy_` 成员中，用于后续的安全检查。
   - **Origin Trial Tokens 处理:** 解析响应头中的 `Origin-Trial`，用于处理实验性 Web 功能。
   - **Referrer Policy 处理:**  获取响应头中的 `Referrer-Policy`。

5. **接收和解码脚本内容:**
   - 通过 `DidReceiveData` 方法接收响应的数据块。
   - 使用 `TextResourceDecoder` 根据响应的编码 (或默认的 UTF-8) 来解码接收到的二进制数据，将其转换为文本。

6. **处理缓存元数据:**
   - 如果服务器提供了缓存元数据，会通过 `DidReceiveCachedMetadata` 方法接收并存储。

7. **完成和失败处理:**
   - **`DidFinishLoading`:**  当脚本加载成功完成时调用。会刷新解码器，确保所有数据都被处理。
   - **`DidFail`:** 当脚本加载失败时调用，记录失败状态和错误信息。
   - **`DidFailRedirectCheck`:** 当重定向检查失败时调用。

8. **提供脚本内容:**
   - 通过 `SourceText()` 方法返回加载的脚本的文本内容。

9. **取消加载:**
   - `Cancel()` 方法允许取消正在进行的脚本加载。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `WorkerClassicScriptLoader` 的核心职责就是加载 JavaScript 文件，这是 Web Worker 运行的基础。加载的脚本会成为 Worker 的执行代码。
    * **举例:** 当你在 JavaScript 中创建并启动一个 Worker 时：
      ```javascript
      const worker = new Worker('my-worker.js');
      ```
      Blink 引擎会使用 `WorkerClassicScriptLoader` 去加载 `my-worker.js` 的内容。

* **HTML:**  HTML 文件中的 `<script>` 标签可以创建和启动 Worker。虽然 `WorkerClassicScriptLoader` 不直接解析 HTML，但它加载的脚本通常是由 HTML 页面发起的。
    * **举例:**  HTML 中可能包含如下代码：
      ```html
      <script>
        const worker = new Worker('worker.js');
      </script>
      ```
      浏览器解析到这段代码后，会触发 Worker 的创建，并使用 `WorkerClassicScriptLoader` 加载 `worker.js`。

* **CSS:**  `WorkerClassicScriptLoader` 主要处理 JavaScript 文件的加载，与 CSS 的直接关系较少。但是，Worker 内部的 JavaScript 代码可能会去请求和处理 CSS 文件，例如用于布局计算或样式分析等目的。  同时，CSP (Content Security Policy) 可以限制 Worker 可以加载的 CSS 资源的来源。
    * **举例:**  Worker 的 JavaScript 代码可能会使用 `fetch` API 加载 CSS 文件：
      ```javascript
      fetch('styles.css')
        .then(response => response.text())
        .then(cssText => {
          // 处理 CSS 文本
        });
      ```
      虽然 `WorkerClassicScriptLoader` 不负责加载 `styles.css`，但 CSP (由 `WorkerClassicScriptLoader` 处理) 会影响这个 `fetch` 请求是否被允许。

**逻辑推理 (假设输入与输出):**

**假设输入：**

* **同步加载：**
    * `url`: "https://example.com/my-worker.js"
    * `execution_context`: 指向当前 Worker 的执行上下文
* **异步加载 (顶层脚本)：**
    * `url`: "https://another-example.com/main-worker.js"
    * `execution_context`: 指向当前 Worker 的执行上下文
    * 假设服务器响应的 `Content-Type` 为 `application/javascript`
    * 假设服务器响应的 HTTP 状态码为 `200 OK`
    * 假设服务器响应头中没有设置 CSP

**输出：**

* **同步加载：**
    * 如果加载成功，`SourceText()` 将返回 "https://example.com/my-worker.js" 的 JavaScript 代码。
    * 如果加载失败（例如，404 错误），`Failed()` 将返回 `true`。
* **异步加载 (顶层脚本)：**
    * 当接收到完整的响应后，会调用 `finished_callback_`。
    * 如果加载成功，`SourceText()` 将返回 "https://another-example.com/main-worker.js" 的 JavaScript 代码。
    * 如果加载失败，例如同源策略检查失败，会在控制台输出错误信息，并且 `Failed()` 将返回 `true`。

**用户或编程常见的使用错误：**

1. **CORS 错误:**  尝试加载跨域的 Worker 脚本，但服务器没有设置正确的 CORS 头 (例如 `Access-Control-Allow-Origin`).
    * **例子:** HTML 页面在 `domain-a.com`，尝试创建一个加载 `domain-b.com/worker.js` 的 Worker，但 `domain-b.com` 的服务器没有返回允许 `domain-a.com` 访问的 CORS 头。`WorkerClassicScriptLoader` 会因为同源策略检查失败而拒绝加载。

2. **MIME 类型错误:** 服务器返回的脚本的 `Content-Type` 不是 JavaScript 相关的 MIME 类型 (例如，返回的是 `text/plain`)。
    * **例子:** 服务器错误地将 JavaScript 文件配置为以 `text/plain` 发送。`WorkerClassicScriptLoader` 会检测到错误的 MIME 类型，并拒绝加载，因为它认为这不是一个可执行的脚本。

3. **CSP 阻止:**  Content Security Policy 阻止了 Worker 脚本的加载。
    * **例子:**  页面的 CSP 头设置了 `worker-src 'self'`, 但尝试加载一个来自不同源的 Worker 脚本。`WorkerClassicScriptLoader` 会根据 CSP 的指示阻止这次加载。

4. **拼写错误的 Worker 脚本路径:**  在 JavaScript 代码中创建 Worker 时，提供的脚本路径错误，导致 404 错误。
    * **例子:** `const worker = new Worker('workerr.js');` (拼写错误)。`WorkerClassicScriptLoader` 会尝试加载 `workerr.js`，但如果服务器上不存在该文件，将会返回 404 错误，导致加载失败。

5. **在不支持 Worker 的环境中使用 Worker:**  尝试在不支持 Web Worker 的浏览器或环境中使用 Worker API。这通常不是 `WorkerClassicScriptLoader` 的错误，而是 API 使用错误。

总而言之，`WorkerClassicScriptLoader` 在 Web Worker 的生命周期中扮演着至关重要的角色，它确保了 Worker 能够安全可靠地加载其执行所需的 JavaScript 代码，并遵循各种 Web 安全策略。

Prompt: 
```
这是目录为blink/renderer/core/workers/worker_classic_script_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2009 Apple Inc. All Rights Reserved.
 * Copyright (C) 2009, 2011 Google Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "third_party/blink/renderer/core/workers/worker_classic_script_loader.h"

#include <memory>
#include "base/memory/scoped_refptr.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/loader/fetch/detachable_use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_response_headers.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

namespace {

// CheckSameOriginEnforcement() functions return non-null String on error.
//
// WorkerGlobalScope's SecurityOrigin is initialized to request URL's
// origin at the construction of WorkerGlobalScope, while
// WorkerGlobalScope's URL is set to response URL
// (ResourceResponse::ResponseURL()).
// These functions are used to ensure the SecurityOrigin and the URL to be
// consistent. https://crbug.com/861564
//
// TODO(hiroshige): Merge with similar code in other places.
String CheckSameOriginEnforcement(const KURL& request_url,
                                  const KURL& response_url) {
  if (request_url != response_url &&
      !SecurityOrigin::AreSameOrigin(request_url, response_url)) {
    return "Refused to load the top-level worker script from '" +
           response_url.ElidedString() +
           "' because it doesn't match the origin of the request URL '" +
           request_url.ElidedString() + "'";
  }
  return String();
}

String CheckSameOriginEnforcement(const KURL& request_url,
                                  const ResourceResponse& response) {
  // While this check is not strictly necessary as CurrentRequestUrl() is not
  // used as WorkerGlobalScope's URL, it is probably safer to reject cases like
  // Origin A(request_url)
  //   =(cross-origin redirects)=> Origin B(CurrentRequestUrl())
  //   =(ServiceWorker interception)=> Origin A(ResponseUrl())
  // which doesn't seem to have valid use cases.
  String error =
      CheckSameOriginEnforcement(request_url, response.CurrentRequestUrl());
  if (!error.IsNull())
    return error;

  // This check is directly required to ensure the consistency between
  // WorkerGlobalScope's SecurityOrigin and URL.
  return CheckSameOriginEnforcement(request_url, response.ResponseUrl());
}

}  // namespace

WorkerClassicScriptLoader::WorkerClassicScriptLoader() {}

void WorkerClassicScriptLoader::LoadSynchronously(
    ExecutionContext& execution_context,
    ResourceFetcher* fetch_client_settings_object_fetcher,
    const KURL& url,
    mojom::blink::RequestContextType request_context,
    network::mojom::RequestDestination destination) {
  DCHECK(fetch_client_settings_object_fetcher);
  url_ = url;
  fetch_client_settings_object_fetcher_ = fetch_client_settings_object_fetcher;

  ResourceRequest request(url);
  request.SetHttpMethod(http_names::kGET);
  request.SetRequestContext(request_context);
  request.SetRequestDestination(destination);

  SECURITY_DCHECK(execution_context.IsWorkerGlobalScope());

  ResourceLoaderOptions resource_loader_options(
      execution_context.GetCurrentWorld());
  resource_loader_options.parser_disposition =
      ParserDisposition::kNotParserInserted;
  resource_loader_options.synchronous_policy = kRequestSynchronously;

  threadable_loader_ = MakeGarbageCollected<ThreadableLoader>(
      execution_context, this, resource_loader_options,
      fetch_client_settings_object_fetcher);
  threadable_loader_->Start(std::move(request));
}

void WorkerClassicScriptLoader::LoadTopLevelScriptAsynchronously(
    ExecutionContext& execution_context,
    ResourceFetcher* fetch_client_settings_object_fetcher,
    const KURL& url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    mojom::blink::RequestContextType request_context,
    network::mojom::RequestDestination destination,
    network::mojom::RequestMode request_mode,
    network::mojom::CredentialsMode credentials_mode,
    base::OnceClosure response_callback,
    base::OnceClosure finished_callback,
    RejectCoepUnsafeNone reject_coep_unsafe_none,
    mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>
        blob_url_loader_factory,
    std::optional<uint64_t> main_script_identifier) {
  DCHECK(fetch_client_settings_object_fetcher);
  DCHECK(response_callback || finished_callback);
  response_callback_ = std::move(response_callback);
  finished_callback_ = std::move(finished_callback);
  url_ = url;
  fetch_client_settings_object_fetcher_ = fetch_client_settings_object_fetcher;
  is_top_level_script_ = true;
  ResourceRequest request(url);
  request.SetHttpMethod(http_names::kGET);
  request.SetRequestContext(request_context);
  request.SetRequestDestination(destination);
  request.SetMode(request_mode);
  request.SetCredentialsMode(credentials_mode);

  // Use WorkerMainScriptLoader to load the main script for dedicated workers
  // (PlzDedicatedWorker) and shared workers.
  if (worker_main_script_load_params) {
    auto* worker_global_scope = DynamicTo<WorkerGlobalScope>(execution_context);
    DCHECK(worker_global_scope);
    if (main_script_identifier.has_value()) {
      worker_global_scope->SetMainResoureIdentifier(
          main_script_identifier.value());
      request.SetInspectorId(main_script_identifier.value());
    } else {
      request.SetInspectorId(CreateUniqueIdentifier());
    }
    request.SetReferrerString(Referrer::NoReferrer());
    request.SetPriority(ResourceLoadPriority::kHigh);
    FetchParameters fetch_params(
        std::move(request),
        ResourceLoaderOptions(execution_context.GetCurrentWorld()));
    worker_main_script_loader_ = MakeGarbageCollected<WorkerMainScriptLoader>();
    worker_main_script_loader_->Start(
        fetch_params, std::move(worker_main_script_load_params),
        &fetch_client_settings_object_fetcher_->Context(),
        fetch_client_settings_object_fetcher->GetResourceLoadObserver(), this);
    return;
  }

  ResourceLoaderOptions resource_loader_options(
      execution_context.GetCurrentWorld());
  need_to_cancel_ = true;
  resource_loader_options.reject_coep_unsafe_none = reject_coep_unsafe_none;
  if (blob_url_loader_factory) {
    resource_loader_options.url_loader_factory =
        base::MakeRefCounted<base::RefCountedData<
            mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>>>(
            std::move(blob_url_loader_factory));
  }
  threadable_loader_ = MakeGarbageCollected<ThreadableLoader>(
      execution_context, this, resource_loader_options,
      fetch_client_settings_object_fetcher);
  threadable_loader_->Start(std::move(request));
  if (failed_)
    NotifyFinished();
}

const KURL& WorkerClassicScriptLoader::ResponseURL() const {
  DCHECK(!Failed());
  return response_url_;
}

void WorkerClassicScriptLoader::DidReceiveResponse(
    uint64_t identifier,
    const ResourceResponse& response) {
  if (response.HttpStatusCode() / 100 != 2 && response.HttpStatusCode()) {
    NotifyError();
    return;
  }
  if (!AllowedByNosniff::MimeTypeAsScript(
          fetch_client_settings_object_fetcher_->GetUseCounter(),
          &fetch_client_settings_object_fetcher_->GetConsoleLogger(), response,
          fetch_client_settings_object_fetcher_->GetProperties()
              .GetFetchClientSettingsObject()
              .MimeTypeCheckForClassicWorkerScript())) {
    NotifyError();
    return;
  }

  if (is_top_level_script_) {
    String error = CheckSameOriginEnforcement(url_, response);
    if (!error.IsNull()) {
      fetch_client_settings_object_fetcher_->GetConsoleLogger()
          .AddConsoleMessage(mojom::ConsoleMessageSource::kSecurity,
                             mojom::ConsoleMessageLevel::kError, error);
      NotifyError();
      return;
    }
  }

  identifier_ = identifier;
  response_url_ = response.ResponseUrl();
  response_encoding_ = response.TextEncodingName();

  referrer_policy_ = response.HttpHeaderField(http_names::kReferrerPolicy);
  ProcessContentSecurityPolicy(response);
  origin_trial_tokens_ = OriginTrialContext::ParseHeaderValue(
      response.HttpHeaderField(http_names::kOriginTrial));

  if (response_callback_)
    std::move(response_callback_).Run();
}

void WorkerClassicScriptLoader::DidReceiveData(base::span<const char> data) {
  if (failed_)
    return;

  if (!decoder_) {
    decoder_ = std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
        TextResourceDecoderOptions::kPlainTextContent,
        response_encoding_.empty() ? UTF8Encoding()
                                   : WTF::TextEncoding(response_encoding_)));
  }

  if (data.empty()) {
    return;
  }

  source_text_.Append(decoder_->Decode(data));
}

void WorkerClassicScriptLoader::DidReceiveCachedMetadata(
    mojo_base::BigBuffer data) {
  cached_metadata_ = std::make_unique<Vector<uint8_t>>(data.size());
  memcpy(cached_metadata_->data(), data.data(), data.size());
}

void WorkerClassicScriptLoader::DidFinishLoading(uint64_t identifier) {
  need_to_cancel_ = false;
  if (!failed_ && decoder_)
    source_text_.Append(decoder_->Flush());

  NotifyFinished();
}

void WorkerClassicScriptLoader::DidFail(uint64_t, const ResourceError& error) {
  need_to_cancel_ = false;
  canceled_ = error.IsCancellation();
  NotifyError();
}

void WorkerClassicScriptLoader::DidFailRedirectCheck(uint64_t) {
  // When didFailRedirectCheck() is called, the ResourceLoader for the script
  // is not canceled yet. So we don't reset |m_needToCancel| here.
  NotifyError();
}

void WorkerClassicScriptLoader::DidReceiveDataWorkerMainScript(
    base::span<const char> span) {
  if (!decoder_) {
    decoder_ = std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
        TextResourceDecoderOptions::kPlainTextContent,
        worker_main_script_loader_->GetScriptEncoding()));
  }
  if (!span.size())
    return;
  source_text_.Append(decoder_->Decode(span));
}

void WorkerClassicScriptLoader::OnFinishedLoadingWorkerMainScript() {
  DidReceiveResponse(0 /*identifier*/,
                     worker_main_script_loader_->GetResponse());
  if (decoder_)
    source_text_.Append(decoder_->Flush());
  NotifyFinished();
}

void WorkerClassicScriptLoader::OnFailedLoadingWorkerMainScript() {
  failed_ = true;
  NotifyFinished();
}

void WorkerClassicScriptLoader::Trace(Visitor* visitor) const {
  visitor->Trace(threadable_loader_);
  visitor->Trace(worker_main_script_loader_);
  visitor->Trace(content_security_policy_);
  visitor->Trace(fetch_client_settings_object_fetcher_);
  ThreadableLoaderClient::Trace(visitor);
}

void WorkerClassicScriptLoader::Cancel() {
  if (!need_to_cancel_)
    return;
  need_to_cancel_ = false;
  if (threadable_loader_)
    threadable_loader_->Cancel();
}

String WorkerClassicScriptLoader::SourceText() {
  return source_text_.ToString();
}

void WorkerClassicScriptLoader::NotifyError() {
  failed_ = true;
  // NotifyError() could be called before ThreadableLoader::Create() returns
  // e.g. from DidFail(), and in that case threadable_loader_ is not yet set
  // (i.e. still null).
  // Since the callback invocation in NotifyFinished() potentially delete
  // |this| object, the callback invocation should be postponed until the
  // create() call returns. See LoadAsynchronously() for the postponed call.
  if (threadable_loader_)
    NotifyFinished();
}

void WorkerClassicScriptLoader::NotifyFinished() {
  if (!finished_callback_)
    return;

  std::move(finished_callback_).Run();
}

void WorkerClassicScriptLoader::ProcessContentSecurityPolicy(
    const ResourceResponse& response) {
  // Per http://www.w3.org/TR/CSP2/#processing-model-workers, if the Worker's
  // URL is not a GUID, then it grabs its CSP from the response headers
  // directly.  Otherwise, the Worker inherits the policy from the parent
  // document (which is implemented in WorkerMessagingProxy, and
  // m_contentSecurityPolicy should be left as nullptr to inherit the policy).
  if (!response.CurrentRequestUrl().ProtocolIs("blob") &&
      !response.CurrentRequestUrl().ProtocolIs("file") &&
      !response.CurrentRequestUrl().ProtocolIs("filesystem")) {
    content_security_policy_ = MakeGarbageCollected<ContentSecurityPolicy>();
    content_security_policy_->AddPolicies(ParseContentSecurityPolicyHeaders(
        ContentSecurityPolicyResponseHeaders(response)));
  }
}

}  // namespace blink

"""

```