Response:
Let's break down the thought process for analyzing the `WorkerModuleScriptFetcher.cc` file.

1. **Understand the Goal:** The request asks for the functionality of this specific Chromium source file, its relationship to web technologies (JavaScript, HTML, CSS), potential issues, and how a user might reach this code during debugging.

2. **Identify the Core Class:** The filename and the `namespace blink` declaration immediately tell us the main focus is the `WorkerModuleScriptFetcher` class.

3. **Analyze the Class's Purpose:**  The name suggests it's responsible for fetching module scripts within the context of a Web Worker. The `ModuleScriptFetcher` base class hints at shared functionality for fetching module scripts. The "Worker" part is crucial.

4. **Examine Key Methods:**  Focus on the public methods, as they represent the primary actions the class performs. The most important methods to look at are:
    * `WorkerModuleScriptFetcher` (constructor): How is the object created? What dependencies does it have?  (It takes a `WorkerGlobalScope`).
    * `Fetch()`: This is clearly the main entry point for initiating the fetching process. Pay attention to its parameters: `FetchParameters`, `ModuleType`, `ResourceFetcher`, `ModuleGraphLevel`, and `Client`. These give clues about the context and purpose.
    * `NotifyFinished()`:  What happens after a resource is fetched?  This method seems to handle success and error scenarios.
    * `NotifyClient()`:  How does this class communicate results back to its "owner"? It takes data like URL, source text, and response.
    * Methods related to `WorkerMainScriptLoader`: `DidReceiveDataWorkerMainScript`, `OnStartLoadingBodyWorkerMainScript`, `OnFinishedLoadingWorkerMainScript`, `OnFailedLoadingWorkerMainScript`. These suggest a special handling path for the *main* module script of a worker.

5. **Connect to Web Standards (JavaScript, HTML, CSS):**
    * **JavaScript:** The class deals with *module scripts*, which are a JavaScript feature. The `ModuleType` enum confirms this. The file handles parsing and processing JavaScript code.
    * **HTML:** Web Workers are created and managed by HTML. The `<script type="module">` tag is directly related to how module loading begins. The fetch process is triggered by the HTML parser encountering such a tag within a worker's context.
    * **CSS:** While this specific file doesn't *directly* handle CSS, it's important to remember that modules can import CSS modules (via import assertions or other mechanisms). The *fetching* part is handled here, even if CSS processing occurs elsewhere.

6. **Trace Logic Flow (Hypothetical Input/Output):**
    * **Scenario:** A worker script tries to import another module.
    * **Input:** `Fetch()` is called with the URL of the imported module, `ModuleType::kJavaScript`, and a `ResourceFetcher`.
    * **Processing:** The code interacts with the network to fetch the module content. It checks MIME types and handles potential errors.
    * **Output (Success):** `NotifyClient()` is called with the module's code, URL, and metadata.
    * **Output (Error):** `client_->NotifyFetchFinishedError()` is called with error messages.

7. **Identify Potential User/Programming Errors:**
    * **Incorrect MIME Type:**  The code explicitly checks for JavaScript MIME types. Serving a module with the wrong MIME type is a common error.
    * **Cross-Origin Issues:**  The code handles potential cross-origin redirects and enforces security restrictions.
    * **Network Errors:**  Standard network problems can occur during fetching.
    * **CSP Violations:** The interaction with `ContentSecurityPolicyResponseHeaders` points to potential CSP-related errors.

8. **Construct a Debugging Scenario (How to Reach This Code):** Think about the steps a developer would take that would involve module loading in a worker:
    1. Create an HTML page that spawns a Web Worker.
    2. The worker script uses `import` statements to load other modules.
    3. Set breakpoints in `WorkerModuleScriptFetcher::Fetch()` or `NotifyFinished()`.
    4. Observe the execution flow when the worker tries to load a module.

9. **Structure the Explanation:** Organize the information logically, starting with the core functionality and then expanding to related areas. Use clear headings and bullet points for readability. Provide concrete examples where possible.

10. **Refine and Review:**  Read through the explanation to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially I might not have emphasized the "main script" handling as much, but reviewing the code reveals the `worker_main_script_loader_` and its associated methods are important. Also, consider adding the conceptual connection to the browser process handling of reserved clients.

By following these steps, we can systematically analyze the code and produce a comprehensive explanation like the example provided in the initial prompt.好的，让我们来分析一下 `blink/renderer/core/loader/modulescript/worker_module_script_fetcher.cc` 这个文件。

**文件功能概览:**

`WorkerModuleScriptFetcher` 类的主要功能是**负责在 Web Worker 环境中获取（fetch）和加载 JavaScript 模块脚本**。它处理网络请求，检查响应，并最终将模块脚本的内容传递给 worker 以供执行。

更具体地说，这个类负责以下几个方面：

1. **发起网络请求:**  根据提供的 URL 和其他参数，向网络发起获取模块脚本的请求。它会利用 `ResourceFetcher` 或 `WorkerMainScriptLoader` 来完成实际的网络操作。
2. **处理重定向:** 检查顶级 worker 脚本的重定向是否符合安全策略（例如，不允许跨域重定向）。
3. **检查 MIME 类型:** 确保返回的资源是 JavaScript MIME 类型 (`text/javascript`, `application/javascript` 等），这是模块脚本的强制要求。
4. **处理 Content Security Policy (CSP):** 解析响应头中的 CSP 指令，并将其应用于加载的模块。
5. **处理 Origin Trials:** 解析响应头中的 Origin Trial token。
6. **解码响应内容:**  使用 `TextResourceDecoder` 来解码响应的文本内容。
7. **创建模块脚本:** 在成功获取脚本后，创建 `ModuleScriptCreationParams` 对象，包含脚本的 URL、基础 URL、类型、内容等信息，并通知客户端。
8. **处理错误:**  如果加载失败（例如，网络错误、MIME 类型不匹配、CSP 违规），会通知客户端加载失败，并可能生成控制台错误消息。
9. **区分主模块和子模块:**  针对 Worker 的主模块脚本（通过 `global_scope_->TakeWorkerMainScriptLoadingParametersForModules()` 判断），会使用 `WorkerMainScriptLoader` 进行加载，这涉及到一些特殊的处理流程。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  这个文件直接处理 JavaScript 模块脚本的加载。
    * **举例:** 当一个 worker 脚本中使用了 `import` 语句来加载其他 JavaScript 模块时，`WorkerModuleScriptFetcher` 就会被用来获取这些被导入的模块。例如，worker 代码 `import './my-module.js';` 会触发对此文件的调用来加载 `my-module.js`。
* **HTML:** HTML 中的 `<script type="module">` 标签是触发模块加载的入口。虽然这个文件本身不在 HTML 解析器中，但当浏览器解析到 worker 脚本中的 `import` 语句时，会间接地调用到这个 fetcher。
    * **举例:**  在 HTML 中创建并执行一个 worker：
      ```html
      <script>
        const worker = new Worker('my-worker.js', { type: 'module' });
      </script>
      ```
      `my-worker.js` 如果包含 `import` 语句，就会涉及到 `WorkerModuleScriptFetcher` 的工作。
* **CSS:**  虽然这个文件主要处理 JavaScript 模块，但 JavaScript 模块可以导入 CSS 模块 (通过 import assertions 或其他机制)。 `WorkerModuleScriptFetcher` 负责 *获取* 这些 CSS 模块的内容，但具体的 CSS 解析和应用通常由其他 Blink 组件负责。
    * **举例:**  如果一个 JavaScript 模块中包含 `import styles from './my-styles.css' assert { type: 'css' };`，那么 `WorkerModuleScriptFetcher` 会尝试获取 `my-styles.css` 的内容。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `fetch_params`: 包含要加载的模块 URL 的请求参数对象，例如 URL 为 `https://example.com/my-module.js`。
* `expected_module_type`: 期望的模块类型，通常是 `ModuleType::kJavaScript`。
* `fetch_client_settings_object_fetcher`:  用于执行网络请求的 `ResourceFetcher` 对象。
* `level`:  模块图的层级，例如 `ModuleGraphLevel::kRegularModuleFetch` 表示加载一个普通的子模块。
* `client`:  一个回调接口，用于接收加载结果。

**逻辑推理过程:**

1. `Fetch()` 方法被调用。
2. 如果是 Worker 的主模块脚本加载 (通过检查 `global_scope_->TakeWorkerMainScriptLoadingParametersForModules()` )，则会使用 `WorkerMainScriptLoader`。
3. 否则，会调用 `ScriptResource::Fetch()` 发起网络请求。
4. 网络请求完成后，`NotifyFinished()` 方法被调用。
5. `NotifyFinished()` 检查加载是否成功（HTTP 状态码、MIME 类型等）。
6. 如果成功，`NotifyClient()` 方法被调用，传递模块的 URL、内容、响应头等信息。
7. `NotifyClient()` 方法会进一步处理，例如检查重定向、CSP、Origin Trials，并最终创建 `ModuleScriptCreationParams` 对象，并通过 `client` 通知结果。
8. 如果加载失败，`client_->NotifyFetchFinishedError()` 会被调用。

**假设输出 (成功情况):**

* `client` 的 `NotifyFetchFinishedSuccess()` 方法被调用，参数是一个 `ModuleScriptCreationParams` 对象，其中包含 `https://example.com/my-module.js` 的内容、URL 等信息。

**假设输出 (失败情况):**

* `client` 的 `NotifyFetchFinishedError()` 方法被调用，可能携带包含错误信息的 `ConsoleMessage` 对象，例如 "Failed to load module script: The server responded with a non-JavaScript MIME type of "text/plain"."。

**用户或编程常见的使用错误:**

1. **服务器返回错误的 MIME 类型:**  这是最常见的问题。如果服务器将 JavaScript 模块作为 `text/plain` 或其他非 JavaScript MIME 类型发送，`WorkerModuleScriptFetcher` 会拒绝加载。
    * **错误示例:** 用户配置了错误的服务器 MIME 类型设置。
    * **控制台错误:** "Failed to load module script: The server responded with a non-JavaScript MIME type of "text/plain"."
2. **跨域加载问题 (CORS):**  如果模块脚本位于不同的域，并且服务器没有设置正确的 CORS 头 (例如 `Access-Control-Allow-Origin`)，加载将会失败。
    * **错误示例:**  worker 尝试加载位于另一个域的模块，但目标服务器没有允许跨域请求。
    * **控制台错误:**  类似于 "Cross-origin request blocked: The Same Origin Policy disallows reading the remote resource at https://other-domain.com/my-module.js. (Reason: CORS header 'Access-Control-Allow-Origin' missing)."
3. **Content Security Policy (CSP) 违规:**  如果页面的 CSP 策略不允许加载来自特定来源的模块，或者有其他 CSP 限制，加载会失败。
    * **错误示例:**  CSP 头中设置了 `script-src 'self'`，但 worker 尝试加载来自 CDN 的模块。
    * **控制台错误:**  类似于 "Refused to load the script 'https://cdn.example.com/my-module.js' because it violates the following Content Security Policy directive: "script-src 'self'"."
4. **重定向问题 (顶级 Worker 脚本):**  顶级 worker 脚本不允许跨域重定向。
    * **错误示例:**  worker 的入口脚本 URL 重定向到了一个不同的域。
    * **控制台错误:** "Refused to cross-origin redirects of the top-level worker script."

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **网页中的 JavaScript 代码创建了一个 Web Worker，并指定了模块类型的入口脚本。**
   ```javascript
   const worker = new Worker('my-worker.js', { type: 'module' });
   ```
3. **Blink 的 Worker 启动逻辑开始执行，需要加载 `my-worker.js`。**
4. **对于模块类型的 worker，会创建 `WorkerModuleScriptFetcher` 对象。**
5. **`WorkerModuleScriptFetcher::Fetch()` 方法被调用，开始获取 `my-worker.js`。**
6. **如果 `my-worker.js` 中包含 `import` 语句，例如 `import './another-module.js';`，那么在解析 `my-worker.js` 时，会再次创建 `WorkerModuleScriptFetcher` 来加载 `another-module.js`。**
7. **在 Chrome DevTools 中进行调试:**
   * **Sources 面板:** 可以查看 worker 的脚本文件。
   * **Network 面板:** 可以查看模块脚本的网络请求，检查请求头和响应头，以及状态码和 MIME 类型。
   * **Console 面板:** 可以查看加载错误信息。
   * **设置断点:** 可以在 `WorkerModuleScriptFetcher::Fetch()`, `NotifyFinished()`, `NotifyClient()` 等关键方法中设置断点，观察模块加载的流程和参数。

**调试技巧:**

* **检查 Network 面板:**  确认模块脚本的请求是否成功 (HTTP 状态码 200)，响应头中的 `Content-Type` 是否为 JavaScript MIME 类型。
* **检查 Console 面板:**  查看是否有任何加载错误消息，这些消息通常会提供问题的线索 (例如 CORS 问题、CSP 违规)。
* **使用 Sources 面板调试 Worker 代码:**  在 DevTools 的 "Workers" 标签页中找到你的 worker，并连接到它的调试器，然后在 `WorkerModuleScriptFetcher` 的相关代码中设置断点。
* **检查服务器配置:** 确保你的服务器配置正确，能够以正确的 MIME 类型提供 JavaScript 模块，并设置了适当的 CORS 头（如果需要跨域加载）。
* **检查 CSP 配置:**  确认页面的 CSP 策略是否允许加载所需的模块。

希望以上分析能够帮助你理解 `WorkerModuleScriptFetcher.cc` 的功能和在实际开发中可能遇到的问题。

Prompt: 
```
这是目录为blink/renderer/core/loader/modulescript/worker_module_script_fetcher.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/modulescript/worker_module_script_fetcher.h"

#include <memory>

#include "services/network/public/mojom/referrer_policy.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/network_utils.h"
#include "third_party/blink/renderer/bindings/core/v8/script_source_location_type.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_response_headers.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"

namespace blink {

WorkerModuleScriptFetcher::WorkerModuleScriptFetcher(
    WorkerGlobalScope* global_scope,
    base::PassKey<ModuleScriptLoader> pass_key)
    : ModuleScriptFetcher(pass_key), global_scope_(global_scope) {}

// <specdef href="https://html.spec.whatwg.org/C/#run-a-worker">
void WorkerModuleScriptFetcher::Fetch(
    FetchParameters& fetch_params,
    ModuleType expected_module_type,
    ResourceFetcher* fetch_client_settings_object_fetcher,
    ModuleGraphLevel level,
    ModuleScriptFetcher::Client* client) {
  DCHECK_EQ(fetch_params.GetScriptType(), mojom::blink::ScriptType::kModule);
  DCHECK(global_scope_->IsContextThread());
  DCHECK(!fetch_client_settings_object_fetcher_);
  fetch_client_settings_object_fetcher_ = fetch_client_settings_object_fetcher;
  client_ = client;
  level_ = level;
  expected_module_type_ = expected_module_type;

  // Use WorkerMainScriptLoader to load the main script when
  // dedicated workers (PlzDedicatedWorker) and shared workers.
  std::unique_ptr<WorkerMainScriptLoadParameters>
      worker_main_script_load_params =
          global_scope_->TakeWorkerMainScriptLoadingParametersForModules();
  if (worker_main_script_load_params) {
    DCHECK_EQ(level_, ModuleGraphLevel::kTopLevelModuleFetch);

    auto identifier = CreateUniqueIdentifier();
    if (global_scope_->IsServiceWorkerGlobalScope()) {
      global_scope_->SetMainResoureIdentifier(identifier);
    }

    fetch_params.MutableResourceRequest().SetInspectorId(identifier);
    worker_main_script_loader_ = MakeGarbageCollected<WorkerMainScriptLoader>();
    worker_main_script_loader_->Start(
        fetch_params, std::move(worker_main_script_load_params),
        &fetch_client_settings_object_fetcher->Context(),
        fetch_client_settings_object_fetcher->GetResourceLoadObserver(), this);
    return;
  }

  // <spec step="12">In both cases, to perform the fetch given request, perform
  // the following steps if the is top-level flag is set:</spec>
  //
  // <spec step="12.1">Set request's reserved client to inside settings.</spec>
  //
  // This is implemented in the browser process.

  // <spec step="12.2">Fetch request, and asynchronously wait to run the
  // remaining steps as part of fetch's process response for the response
  // response.</spec>

  // If streaming is not allowed, no compile hints are needed either.
  constexpr v8_compile_hints::V8CrowdsourcedCompileHintsProducer*
      kNoCompileHintsProducer = nullptr;
  constexpr v8_compile_hints::V8CrowdsourcedCompileHintsConsumer*
      kNoCompileHintsConsumer = nullptr;
  ScriptResource::Fetch(fetch_params, fetch_client_settings_object_fetcher,
                        this, global_scope_->GetIsolate(),
                        ScriptResource::kNoStreaming, kNoCompileHintsProducer,
                        kNoCompileHintsConsumer,
                        v8_compile_hints::MagicCommentMode::kNever);
}

void WorkerModuleScriptFetcher::Trace(Visitor* visitor) const {
  ModuleScriptFetcher::Trace(visitor);
  visitor->Trace(client_);
  visitor->Trace(global_scope_);
  visitor->Trace(fetch_client_settings_object_fetcher_);
  visitor->Trace(worker_main_script_loader_);
}

// https://html.spec.whatwg.org/C/#worker-processing-model
void WorkerModuleScriptFetcher::NotifyFinished(Resource* resource) {
  DCHECK(global_scope_->IsContextThread());
  ClearResource();

  auto* script_resource = To<ScriptResource>(resource);
  {
    HeapVector<Member<ConsoleMessage>> error_messages;
    if (!WasModuleLoadSuccessful(script_resource, expected_module_type_,
                                 &error_messages)) {
      client_->NotifyFetchFinishedError(error_messages);
      return;
    }
  }

  NotifyClient(resource->Url(), expected_module_type_,
               script_resource->SourceText(), resource->GetResponse(),
               script_resource->CacheHandler());
}

void WorkerModuleScriptFetcher::NotifyClient(
    const KURL& request_url,
    ModuleType module_type,
    const ParkableString& source_text,
    const ResourceResponse& response,
    CachedMetadataHandler* cache_handler) {
  HeapVector<Member<ConsoleMessage>> error_messages;

  const KURL response_url = response.ResponseUrl();

  network::mojom::ReferrerPolicy response_referrer_policy =
      network::mojom::ReferrerPolicy::kDefault;
  const String response_referrer_policy_header =
      response.HttpHeaderField(http_names::kReferrerPolicy);
  if (!response_referrer_policy_header.IsNull()) {
    SecurityPolicy::ReferrerPolicyFromHeaderValue(
        response_referrer_policy_header,
        kDoNotSupportReferrerPolicyLegacyKeywords, &response_referrer_policy);
  }

  if (level_ == ModuleGraphLevel::kTopLevelModuleFetch) {
    // TODO(nhiroki, hiroshige): Access to WorkerGlobalScope in module loaders
    // is a layering violation. Also, updating WorkerGlobalScope ('module map
    // settigns object') in flight can be dangerous because module loaders may
    // refer to it. We should move these steps out of core/loader/modulescript/
    // and run them after module loading. This may require the spec change.
    // (https://crbug.com/845285)

    // Ensure redirects don't affect SecurityOrigin.
    DCHECK(fetch_client_settings_object_fetcher_->GetProperties()
               .GetFetchClientSettingsObject()
               .GetSecurityOrigin()
               ->CanReadContent(request_url))
        << "Top-level worker script request url must be same-origin with "
           "outside settings constructor origin or permitted by the parent "
           "chrome-extension.";

    // |response_url| must be same-origin with request origin or its url's
    // scheme must be "data".
    //
    // https://fetch.spec.whatwg.org/#concept-main-fetch
    // Step 5:
    // - request’s current URL’s origin is same origin with request’s
    // origin (request's current URL indicates |response_url|)
    // - request’s current URL’s scheme is "data"
    // ---> Return the result of performing a scheme fetch using request.
    // - request’s mode is "same-origin"
    // ---> Return a network error. [spec text]
    if (!SecurityOrigin::AreSameOrigin(request_url, response_url) &&
        !response_url.ProtocolIsData()) {
      error_messages.push_back(MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kSecurity,
          mojom::ConsoleMessageLevel::kError,
          "Refused to cross-origin redirects of the top-level worker script."));
      client_->NotifyFetchFinishedError(error_messages);
      return;
    }

    std::unique_ptr<Vector<String>> response_origin_trial_tokens =
        OriginTrialContext::ParseHeaderValue(
            response.HttpHeaderField(http_names::kOriginTrial));

    // Step 12.3-12.6 are implemented in Initialize().
    global_scope_->Initialize(
        response_url, response_referrer_policy,
        ParseContentSecurityPolicyHeaders(
            ContentSecurityPolicyResponseHeaders(response)),
        response_origin_trial_tokens.get());
  }

  // <spec step="12.7">Asynchronously complete the perform the fetch steps with
  // response.</spec>
  // Create an external module script where base_url == source_url.
  // https://html.spec.whatwg.org/multipage/webappapis.html#concept-script-base-url
  client_->NotifyFetchFinishedSuccess(ModuleScriptCreationParams(
      /*source_url=*/response_url, /*base_url=*/response_url,
      ScriptSourceLocationType::kExternalFile, module_type, source_text,
      cache_handler, response_referrer_policy));
}

void WorkerModuleScriptFetcher::DidReceiveDataWorkerMainScript(
    base::span<const char> span) {
  if (!decoder_) {
    decoder_ = std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
        TextResourceDecoderOptions::kPlainTextContent,
        worker_main_script_loader_->GetScriptEncoding()));
  }
  if (!span.size()) {
    return;
  }
  source_text_.Append(decoder_->Decode(span));
}

void WorkerModuleScriptFetcher::OnStartLoadingBodyWorkerMainScript(
    const ResourceResponse& resource_response) {
  if (!MIMETypeRegistry::IsSupportedJavaScriptMIMEType(
          resource_response.HttpContentType())) {
    HeapVector<Member<ConsoleMessage>> error_messages;
    String message =
        "Failed to load module script: The server responded with a "
        "non-JavaScript MIME type of \"" +
        resource_response.HttpContentType() +
        "\". Strict MIME type checking is enforced for module scripts per HTML "
        "spec.";
    error_messages.push_back(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kError, message,
        resource_response.ResponseUrl().GetString(), /*loader=*/nullptr, -1));
    worker_main_script_loader_->Cancel();
    client_->NotifyFetchFinishedError(error_messages);
    return;
  }
}

void WorkerModuleScriptFetcher::OnFinishedLoadingWorkerMainScript() {
  const ResourceResponse& response = worker_main_script_loader_->GetResponse();
  if (decoder_)
    source_text_.Append(decoder_->Flush());
  NotifyClient(worker_main_script_loader_->GetRequestURL(),
               ModuleType::kJavaScript,
               ParkableString(source_text_.ToString().ReleaseImpl()), response,
               worker_main_script_loader_->CreateCachedMetadataHandler());
}

void WorkerModuleScriptFetcher::OnFailedLoadingWorkerMainScript() {
  client_->NotifyFetchFinishedError(HeapVector<Member<ConsoleMessage>>());
}

}  // namespace blink

"""

```