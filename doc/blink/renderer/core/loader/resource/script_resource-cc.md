Response:
Let's break down the thought process for analyzing this `ScriptResource.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), illustrative examples, logic inferences, common user/programming errors, and how a user might trigger this code.

2. **Initial Skim and High-Level Understanding:** Quickly read through the code, paying attention to class names, included headers, and function names. Keywords like `ScriptResource`, `Fetch`, `V8CodeCache`, `Streaming`, `TextResource`, and `Resource` stand out. The copyright notice gives some historical context but isn't directly relevant to the functionality. The initial comment block mentions "loading images, style sheets, and html pages," which is a bit misleading since this specific file is about *scripts*. It's important to note this discrepancy for the final answer.

3. **Identify Core Functionality:**  The class `ScriptResource` is central. The `Fetch` method suggests it's responsible for retrieving script resources. The included headers hint at various aspects:
    * `v8_code_cache.h`: Caching of compiled JavaScript code.
    * `v8_compile_hints_*`: Optimization hints for V8 compilation.
    * `TextResource.h`: Inherited functionality for handling text-based resources.
    * `ResourceFetcher.h`, `ResourceLoader.h`: General resource loading mechanisms.
    * `ResponseBodyLoader.h`: Handling the response body.
    * `ScriptStreamer.h`, `BackgroundResourceScriptStreamer.h`:  Mechanisms for streaming script content.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** This is the primary focus. The file deals with fetching, caching, and potentially streaming JavaScript code.
    * **HTML:**  HTML uses `<script>` tags to include JavaScript. The browser needs to fetch these scripts, and `ScriptResource` is part of that process.
    * **CSS:** While not directly handled by *this* file, the initial comment mentioned stylesheets. It's important to clarify that `ScriptResource` is *not* for CSS; that would likely be a `CSSResource` or similar class.

5. **Illustrative Examples:**  Think about how these technologies interact.
    * **JavaScript:**  A simple `<script src="my_script.js"></script>` demonstrates the loading process. Dynamic imports (`import()`) are another relevant example.
    * **HTML:** The `<script>` tag itself is the key link.
    * **CSS:** Mentioning a `<link rel="stylesheet" href="style.css">` helps contrast with JavaScript.

6. **Logic Inference (Assumptions and Outputs):** Look for conditional logic (if/else, switches).
    * **Streaming:** The `streaming_state_` enum and related methods (`DisableStreaming`, `AdvanceStreamingState`) suggest a state machine for managing script streaming. Consider scenarios:
        * **Input:** A large JavaScript file on an HTTP connection. **Output:** The script might be streamed.
        * **Input:** A small script or a non-HTTP connection (without the relevant feature flag). **Output:** Streaming might be disabled.
    * **Code Caching:** The `consume_cache_state_` enum and `cached_metadata_handler_` indicate logic for retrieving and applying cached compiled code.
        * **Input:** A script previously loaded and cached. **Output:** The cached code might be used.
        * **Input:** A new or modified script. **Output:** The cache might be bypassed or updated.

7. **Common User/Programming Errors:**  Consider what can go wrong from a web developer's perspective:
    * **Incorrect `type` attribute:**  Using the wrong `type` in a `<script>` tag can lead to the browser not executing the script or handling it incorrectly. Mentioning module scripts (`<script type="module">`) and the potential for errors is relevant.
    * **CORS issues:** Trying to load scripts from different origins without proper CORS headers will cause errors.
    * **Subresource Integrity (SRI) failures:** If the `integrity` attribute doesn't match the downloaded script, loading will fail.

8. **User Actions and Debugging:** Trace the user's path:
    1. User enters a URL or clicks a link.
    2. Browser parses the HTML.
    3. Browser encounters a `<script>` tag.
    4. Browser initiates a request for the script resource.
    5. `ScriptResource::Fetch` is likely called.
    6. The resource is downloaded.
    7. The code in `ScriptResource.cc` handles caching, streaming, and ultimately makes the script available for execution by the JavaScript engine.

9. **Structure the Answer:** Organize the information logically. Start with a summary of the file's purpose. Then, detail its specific functions, connections to web technologies, examples, logic, errors, and debugging. Use clear headings and bullet points.

10. **Refine and Review:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have focused too much on the general "resource loading" aspect. It's crucial to emphasize the *specific* role of `ScriptResource` in handling *scripts*. Also, ensure that the examples provided are concise and directly illustrate the concepts being discussed.
这个文件 `blink/renderer/core/loader/resource/script_resource.cc` 是 Chromium Blink 引擎中负责处理 JavaScript 脚本资源加载的核心组件。它继承自 `TextResource`，表明它处理的是基于文本的资源。

**主要功能:**

1. **JavaScript 脚本资源的获取与管理:**
   - **发起和管理脚本的下载请求:**  通过 `Fetch` 方法，根据提供的 `FetchParameters`（包含请求 URL、请求头等信息）和 `ResourceFetcher`，向网络请求脚本资源。
   - **存储下载的脚本内容:**  下载完成后，脚本的内容会存储在 `ScriptResource` 对象中。
   - **处理脚本加载过程中的各种状态:**  例如加载中、加载完成、加载失败等。

2. **JavaScript 代码缓存管理:**
   - **支持 V8 代码缓存:**  与 V8 JavaScript 引擎交互，利用代码缓存来加速脚本的解析和编译。
   - **控制代码缓存的消费:**  通过 `ScriptCacheConsumer`，允许在后台线程消费（反序列化）代码缓存，减少主线程的阻塞。
   - **管理代码缓存的生命周期:**  例如在重新验证资源时清除旧的缓存。
   - **支持带有哈希校验的代码缓存:**  通过 `ScriptCachedMetadataHandlerWithHashing`，提高代码缓存的安全性。

3. **JavaScript 脚本流式加载 (Streaming):**
   - **支持脚本的流式传输:**  通过 `ResourceScriptStreamer` 和 `BackgroundResourceScriptStreamer`，允许在脚本完全下载完成之前就开始解析和编译，提升页面加载性能。
   - **管理流式加载的状态:**  例如等待数据管道、正在流式传输、流式传输已禁用等。
   - **根据条件启用或禁用流式加载:**  例如根据 Feature Flag、协议类型等。

4. **与 V8 编译提示 (Compile Hints) 的集成:**
   - **支持 V8 的众包编译提示 (Crowdsourced Compile Hints):**  允许生产者 (`V8CrowdsourcedCompileHintsProducer`) 和消费者 (`V8CrowdsourcedCompileHintsConsumer`) 与 `ScriptResource` 关联，以便利用编译提示优化脚本执行。

5. **Subresource Integrity (SRI) 支持:**
   - 间接地通过底层的 `Resource` 基类支持 SRI，用于验证下载的脚本内容是否与预期的一致，防止恶意注入。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** `ScriptResource` 直接负责加载和管理 JavaScript 代码。
    * **举例:** 当 HTML 中包含 `<script src="myscript.js"></script>` 时，Blink 引擎会创建一个 `ScriptResource` 对象来下载 `myscript.js` 的内容。
    * **举例:**  动态导入 `import('myModule.js')` 也会触发 `ScriptResource` 的创建和加载过程。
    * **逻辑推理:** 假设一个网页包含一个大型的 JavaScript 文件 `large_script.js`。启用流式加载后，`ScriptResource` 会在 `large_script.js` 的部分内容下载完成后，就将其传递给 V8 引擎开始解析，而无需等待整个文件下载完成。

* **HTML:** HTML 的 `<script>` 标签是触发 `ScriptResource` 工作的关键入口。
    * **举例:**  HTML 解析器遇到 `<script>` 标签时，会根据 `src` 属性创建并启动 `ScriptResource` 来获取脚本。
    * **用户操作:** 用户在浏览器中输入网址并访问一个包含 `<script>` 标签的网页，就会触发 `ScriptResource` 的工作。

* **CSS:**  虽然 `ScriptResource` 主要负责 JavaScript，但其基类 `Resource` 负责处理各种类型的资源，包括 CSS。
    * **区别:**  处理 CSS 资源的是 `CSSResource` 或类似的类，而不是 `ScriptResource`。
    * **举例:** 当 HTML 中包含 `<link rel="stylesheet" href="style.css">` 时，会创建 `CSSResource` 来加载 `style.css`，而不是 `ScriptResource`。

**逻辑推理 (假设输入与输出):**

* **假设输入:**
    * 用户访问一个包含 `<script src="https://example.com/my_script.js"></script>` 的网页。
    * 浏览器没有该脚本的有效代码缓存。
    * 启用了脚本流式加载。
* **输出:**
    1. 创建 `ScriptResource` 对象，URL 为 `https://example.com/my_script.js`。
    2. 发起网络请求下载 `my_script.js`。
    3. 当接收到部分响应体数据后，`ScriptResource` 会创建一个 `ResourceScriptStreamer` 并将数据传递给它。
    4. `ResourceScriptStreamer` 将数据逐步传递给 V8 引擎进行解析和可能的编译。
    5. 当整个脚本下载完成后，V8 引擎完成编译，脚本可以执行。
    6. 如果服务端返回了合适的缓存头，`ScriptResource` 可能会存储编译后的代码到代码缓存中，以便下次加载加速。

**用户或编程常见的使用错误及举例说明:**

* **CORS (跨域资源共享) 问题:**
    * **错误:**  在 HTML 中引用了来自不同域名的 JavaScript 文件，但服务器没有设置正确的 CORS 响应头。
    * **用户操作:** 用户访问该网页。
    * **调试线索:**  浏览器控制台会显示 CORS 相关的错误信息，表明 `ScriptResource` 因为跨域策略阻止了脚本的加载。
* **SRI (子资源完整性) 校验失败:**
    * **错误:**  `<script>` 标签包含了 `integrity` 属性，但下载的脚本内容与 `integrity` 属性指定的哈希值不匹配。可能是脚本被篡改或网络传输错误。
    * **用户操作:** 用户访问该网页。
    * **调试线索:** 浏览器控制台会显示 SRI 校验失败的错误信息，`ScriptResource` 会拒绝执行该脚本。
* **错误的 `script` 标签 `type` 属性:**
    * **错误:** 使用了错误的或不支持的 `type` 属性，例如 `<script type="text/custom-script">`，浏览器可能不会将其识别为 JavaScript 并执行。
    * **用户操作:** 用户访问该网页。
    * **调试线索:**  虽然 `ScriptResource` 可能成功下载了内容，但浏览器可能不会将其当作 JavaScript 处理，导致功能异常。
* **模块脚本加载错误 (Module Scripts):**
    * **错误:**  加载模块脚本时，路径解析错误、循环依赖或者服务器返回了错误的 MIME 类型。
    * **用户操作:** 用户访问一个使用模块脚本的网页。
    * **调试线索:** 浏览器控制台会显示模块加载相关的错误信息，例如 "Failed to resolve module specifier" 或 "Uncaught TypeError: Illegal invocation"。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或点击一个链接。**
2. **Blink 引擎的 Navigation 组件开始处理导航请求。**
3. **下载 HTML 页面。**
4. **HTML Parser 开始解析下载的 HTML 内容。**
5. **当解析器遇到 `<script>` 标签时：**
   - **如果存在 `src` 属性 (外部脚本):**
     - Blink 会创建一个 `ScriptResource` 对象，并使用 `ResourceFetcher` 发起网络请求，请求 `src` 指定的 URL。
     - `ScriptResource::Fetch` 方法会被调用。
     - 下载过程由底层的网络模块处理。
     - `ScriptResource` 对象会监听下载事件，例如接收到响应头 (`ResponseReceived`)、接收到响应体数据 (`ResponseBodyReceived`)、下载完成 (`NotifyFinished`)。
     - 如果启用了流式加载，`ResponseBodyReceived` 可能会创建 `ResourceScriptStreamer` 或 `BackgroundResourceScriptStreamer`。
     - 下载完成后，脚本内容会被存储，并可能进行代码缓存。
   - **如果不存在 `src` 属性 (内联脚本):**
     -  不会创建 `ScriptResource` 对象，因为脚本内容直接嵌入在 HTML 中。
6. **JavaScript 引擎 (V8) 在合适的时机（例如 HTML 解析完成后）会请求执行 `ScriptResource` 中加载的脚本。**
   - 如果有代码缓存，`ScriptCacheConsumer` 会尝试从缓存中恢复编译后的代码。
7. **如果在脚本加载过程中发生错误 (例如 404 错误，CORS 错误，SRI 校验失败)，`ScriptResource` 会将错误状态传递给相关的组件，并可能在浏览器控制台输出错误信息。**

在调试与 JavaScript 加载相关的问题时，可以关注以下 `ScriptResource.cc` 中的关键点：

* **断点设置:** 在 `ScriptResource::Fetch`, `ScriptResource::ResponseReceived`, `ScriptResource::ResponseBodyReceived`, `ScriptResource::NotifyFinished` 等方法中设置断点，观察脚本资源的加载流程和状态变化。
* **查看状态变量:** 观察 `streaming_state_`, `consume_cache_state_`, `no_streamer_reason_` 等变量的值，了解脚本是否正在流式加载、是否使用了代码缓存以及流式加载被禁用的原因。
* **检查关联对象:**  查看 `streamer_`, `cached_metadata_handler_`, `cache_consumer_` 等指针是否为空，以及它们的状态。

理解 `ScriptResource` 的功能和工作原理，对于分析和解决网页加载性能问题、JavaScript 执行错误以及安全漏洞等至关重要。

### 提示词
```
这是目录为blink/renderer/core/loader/resource/script_resource.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
    Copyright (C) 1998 Lars Knoll (knoll@mpi-hd.mpg.de)
    Copyright (C) 2001 Dirk Mueller (mueller@kde.org)
    Copyright (C) 2002 Waldo Bastian (bastian@kde.org)
    Copyright (C) 2006 Samuel Weinig (sam.weinig@gmail.com)
    Copyright (C) 2004, 2005, 2006, 2007, 2008 Apple Inc. All rights reserved.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with this library; see the file COPYING.LIB.  If not, write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA 02110-1301, USA.

    This class provides all functionality needed for loading images, style
    sheets and html pages from the web. It has a memory cache for these objects.
*/

#include "third_party/blink/renderer/core/loader/resource/script_resource.h"

#include <utility>

#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "base/types/expected.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_code_cache.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_producer.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/loader/subresource_integrity_helper.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/web_memory_allocator_dump.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/web_process_memory_dump.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/data_pipe_bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/integrity_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_client_walker.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/background_response_processor.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

namespace {

// Returns true if the given request context is a valid destination for
// scripts or modules. This includes:
// - script-like https://fetch.spec.whatwg.org/#request-destination-script-like
// - json
// - style
// These contextes to the destinations that the request performed by
// https://html.spec.whatwg.org/#fetch-a-single-module-script can have.
bool IsRequestContextSupported(
    mojom::blink::RequestContextType request_context) {
  // TODO(nhiroki): Support "audioworklet" and "paintworklet" destinations.
  switch (request_context) {
    // script-like
    case mojom::blink::RequestContextType::SCRIPT:
    case mojom::blink::RequestContextType::WORKER:
    case mojom::blink::RequestContextType::SERVICE_WORKER:
    case mojom::blink::RequestContextType::SHARED_WORKER:
    // json
    case mojom::blink::RequestContextType::JSON:
    // style
    case mojom::blink::RequestContextType::STYLE:
      return true;
    default:
      break;
  }
  NOTREACHED() << "Incompatible request context type: " << request_context;
}

}  // namespace

ScriptResource* ScriptResource::Fetch(
    FetchParameters& params,
    ResourceFetcher* fetcher,
    ResourceClient* client,
    v8::Isolate* isolate,
    StreamingAllowed streaming_allowed,
    v8_compile_hints::V8CrowdsourcedCompileHintsProducer*
        v8_compile_hints_producer,
    v8_compile_hints::V8CrowdsourcedCompileHintsConsumer*
        v8_compile_hints_consumer,
    v8_compile_hints::MagicCommentMode magic_comment_mode) {
  DCHECK(IsRequestContextSupported(
      params.GetResourceRequest().GetRequestContext()));
  auto* resource = To<ScriptResource>(fetcher->RequestResource(
      params,
      ScriptResourceFactory(isolate, streaming_allowed,
                            v8_compile_hints_producer,
                            v8_compile_hints_consumer, magic_comment_mode,
                            params.GetScriptType()),
      client));
  return resource;
}

ScriptResource* ScriptResource::CreateForTest(
    v8::Isolate* isolate,
    const KURL& url,
    const WTF::TextEncoding& encoding,
    mojom::blink::ScriptType script_type) {
  ResourceRequest request(url);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);
  ResourceLoaderOptions options(nullptr /* world */);
  TextResourceDecoderOptions decoder_options(
      TextResourceDecoderOptions::kPlainTextContent, encoding);
  return MakeGarbageCollected<ScriptResource>(
      request, options, decoder_options, isolate, kNoStreaming,
      /*v8_compile_hints_producer=*/nullptr,
      /*v8_compile_hints_consumer=*/nullptr,
      v8_compile_hints::MagicCommentMode::kNever, script_type);
}

ScriptResource::ScriptResource(
    const ResourceRequest& resource_request,
    const ResourceLoaderOptions& options,
    const TextResourceDecoderOptions& decoder_options,
    v8::Isolate* isolate,
    StreamingAllowed streaming_allowed,
    v8_compile_hints::V8CrowdsourcedCompileHintsProducer*
        v8_compile_hints_producer,
    v8_compile_hints::V8CrowdsourcedCompileHintsConsumer*
        v8_compile_hints_consumer,
    v8_compile_hints::MagicCommentMode magic_comment_mode,
    mojom::blink::ScriptType initial_request_script_type)
    : TextResource(resource_request,
                   ResourceType::kScript,
                   options,
                   decoder_options),
      // Only storing the isolate for the main thread is safe.
      // See variable definition for details.
      isolate_if_main_thread_(IsMainThread() ? isolate : nullptr),
      consume_cache_state_(ConsumeCacheState::kWaitingForCache),
      initial_request_script_type_(initial_request_script_type),
      stream_text_decoder_(
          std::make_unique<TextResourceDecoder>(decoder_options)),
      v8_compile_hints_producer_(v8_compile_hints_producer),
      v8_compile_hints_consumer_(v8_compile_hints_consumer),
      magic_comment_mode_(magic_comment_mode) {
  static bool script_streaming_enabled =
      base::FeatureList::IsEnabled(features::kScriptStreaming);
  static bool script_streaming_for_non_http_enabled =
      base::FeatureList::IsEnabled(features::kScriptStreamingForNonHTTP);
  // TODO(leszeks): This could be static to avoid the cost of feature flag
  // lookup on every ScriptResource creation, but it has to be re-calculated for
  // unit tests.
  bool consume_code_cache_off_thread_enabled =
      base::FeatureList::IsEnabled(features::kConsumeCodeCacheOffThread);

  if (!script_streaming_enabled) {
    DisableStreaming(
        ScriptStreamer::NotStreamingReason::kDisabledByFeatureList);
  } else if (streaming_allowed == kNoStreaming) {
    DisableStreaming(ScriptStreamer::NotStreamingReason::kStreamingDisabled);
  } else if (!Url().ProtocolIsInHTTPFamily() &&
             !script_streaming_for_non_http_enabled) {
    DisableStreaming(ScriptStreamer::NotStreamingReason::kNotHTTP);
  }

  if (!consume_code_cache_off_thread_enabled) {
    DisableOffThreadConsumeCache();
  } else if (initial_request_script_type == mojom::blink::ScriptType::kModule) {
    // TODO(leszeks): Enable off-thread cache consumption for modules.
    DisableOffThreadConsumeCache();
  } else if (!isolate_if_main_thread_) {
    // If we have a null isolate disable off thread cache consumption.
    DisableOffThreadConsumeCache();
  }
}

ScriptResource::~ScriptResource() = default;

void ScriptResource::Trace(Visitor* visitor) const {
  visitor->Trace(streamer_);
  visitor->Trace(cached_metadata_handler_);
  visitor->Trace(cache_consumer_);
  visitor->Trace(v8_compile_hints_producer_);
  visitor->Trace(v8_compile_hints_consumer_);
  visitor->Trace(background_streamer_);
  TextResource::Trace(visitor);
}

void ScriptResource::OnMemoryDump(WebMemoryDumpLevelOfDetail level_of_detail,
                                  WebProcessMemoryDump* memory_dump) const {
  Resource::OnMemoryDump(level_of_detail, memory_dump);
  {
    const String name = GetMemoryDumpName() + "/decoded_script";
    source_text_.OnMemoryDump(memory_dump, name);
  }
  if (cached_metadata_handler_) {
    const String name = GetMemoryDumpName() + "/code_cache";
    cached_metadata_handler_->OnMemoryDump(memory_dump, name);
  }
}

const ParkableString& ScriptResource::SourceText() {
  CHECK(IsLoaded());

  if (source_text_.IsNull() && Data()) {
    SCOPED_UMA_HISTOGRAM_TIMER_MICROS("Blink.Script.SourceTextTime");
    String source_text = DecodedText();
    ClearData();
    SetDecodedSize(source_text.CharactersSizeInBytes());
    source_text_ = ParkableString(source_text.ReleaseImpl());
  }

  return source_text_;
}

String ScriptResource::TextForInspector() const {
  // If the resource buffer exists, we can safely return the decoded text.
  if (ResourceBuffer()) {
    return DecodedText();
  }

  // If there is no resource buffer, then we've finished loading and have
  // already decoded the buffer into the source text, clearing the resource
  // buffer to save space...
  if (IsLoaded() && !source_text_.IsNull()) {
    return source_text_.ToString();
  }

  // ... or we either haven't started loading and haven't received data yet, or
  // we finished loading with an error/cancellation, and thus don't have data.
  // In both cases, we can treat the resource as empty.
  return "";
}

CachedMetadataHandler* ScriptResource::CacheHandler() {
  return cached_metadata_handler_.Get();
}

void ScriptResource::SetSerializedCachedMetadata(mojo_base::BigBuffer data) {
  // Resource ignores the cached metadata.
  Resource::SetSerializedCachedMetadata(mojo_base::BigBuffer());
  if (cached_metadata_handler_) {
    cached_metadata_handler_->SetSerializedCachedMetadata(std::move(data));
  }
  if (consume_cache_state_ == ConsumeCacheState::kWaitingForCache) {
    // If `background_streamer_` has decoded the code cache, use the decoded
    // code cache.
    if (background_streamer_ &&
        background_streamer_->HasConsumeCodeCacheTask()) {
      cache_consumer_ = MakeGarbageCollected<ScriptCacheConsumer>(
          isolate_if_main_thread_,
          V8CodeCache::GetCachedMetadata(
              CacheHandler(), CachedMetadataHandler::kAllowUnchecked),
          background_streamer_->TakeConsumeCodeCacheTask(), Url(),
          InspectorId());
      AdvanceConsumeCacheState(ConsumeCacheState::kRunningOffThread);
      return;
    }

    // If `cached_metadata_handler_` has a valid code cache, use the code cache.
    if (V8CodeCache::HasCodeCache(
            cached_metadata_handler_,
            // It's safe to access unchecked cached metadata here, because the
            // ScriptCacheConsumer result will be ignored if the cached metadata
            // check fails later.
            CachedMetadataHandler::kAllowUnchecked)) {
      CHECK(isolate_if_main_thread_);
      cache_consumer_ = MakeGarbageCollected<ScriptCacheConsumer>(
          isolate_if_main_thread_,
          V8CodeCache::GetCachedMetadata(
              CacheHandler(), CachedMetadataHandler::kAllowUnchecked),
          Url(), InspectorId());
      AdvanceConsumeCacheState(ConsumeCacheState::kRunningOffThread);
      return;
    }
  }

  DisableOffThreadConsumeCache();
}

void ScriptResource::DestroyDecodedDataIfPossible() {
  if (cached_metadata_handler_) {
    // Since we are clearing locally we don't need a CodeCacheHost interface
    // here. It just clears the data in the cached_metadata_handler.
    cached_metadata_handler_->ClearCachedMetadata(
        /*code_cache_host*/ nullptr, CachedMetadataHandler::kClearLocally);
  }
  cache_consumer_ = nullptr;
  DisableOffThreadConsumeCache();
}

void ScriptResource::DestroyDecodedDataForFailedRevalidation() {
  source_text_ = ParkableString();
  // Make sure there's no streaming.
  DCHECK(!streamer_);
  DCHECK_EQ(streaming_state_, StreamingState::kStreamingDisabled);
  SetDecodedSize(0);
  DCHECK(!cache_consumer_);
  cached_metadata_handler_ = nullptr;
  DisableOffThreadConsumeCache();
}

void ScriptResource::SetRevalidatingRequest(
    const ResourceRequestHead& request) {
  CHECK(IsLoaded());
  if (streamer_) {
    CHECK(streamer_->IsFinished());
    streamer_ = nullptr;
  }
  // Revalidation requests don't actually load the current Resource, so disable
  // streaming.
  DisableStreaming(ScriptStreamer::NotStreamingReason::kRevalidate);

  // For the same reason, disable off-thread cache consumption.
  cache_consumer_ = nullptr;
  DisableOffThreadConsumeCache();

  TextResource::SetRevalidatingRequest(request);
}

bool ScriptResource::CanUseCacheValidator() const {
  // Do not revalidate until ClassicPendingScript is removed, i.e. the script
  // content is retrieved in ScriptLoader::ExecuteScriptBlock().
  // crbug.com/692856
  if (HasClientsOrObservers()) {
    return false;
  }

  // Do not revalidate until streaming is complete.
  if (!IsLoaded()) {
    return false;
  }

  return Resource::CanUseCacheValidator();
}

size_t ScriptResource::CodeCacheSize() const {
  return cached_metadata_handler_ ? cached_metadata_handler_->GetCodeCacheSize()
                                  : 0;
}

void ScriptResource::ResponseReceived(const ResourceResponse& response) {
  const bool is_successful_revalidation =
      IsSuccessfulRevalidationResponse(response);
  Resource::ResponseReceived(response);

  if (is_successful_revalidation) {
    return;
  }

  if (background_streamer_ && background_streamer_->HasDecodedData()) {
    source_text_ = background_streamer_->TakeDecodedData();
    SetDecodedSize(source_text_.CharactersSizeInBytes());
  }

  cached_metadata_handler_ = nullptr;
  // Currently we support the metadata caching only for HTTP family and any
  // schemes defined by SchemeRegistry as requiring a hash check.
  bool http_family = GetResourceRequest().Url().ProtocolIsInHTTPFamily() &&
                     response.CurrentRequestUrl().ProtocolIsInHTTPFamily();
  bool code_cache_with_hashing_supported =
      SchemeRegistry::SchemeSupportsCodeCacheWithHashing(
          GetResourceRequest().Url().Protocol()) &&
      GetResourceRequest().Url().ProtocolIs(
          response.CurrentRequestUrl().Protocol());

  // There is also a flag on ResourceResponse so that hash-based code caching
  // can be used on resources other than those specified by the scheme registry.
  code_cache_with_hashing_supported |=
      response.ShouldUseSourceHashForJSCodeCache();

  // Embedders may override whether hash-based code caching can be used for a
  // given resource request.
  code_cache_with_hashing_supported &=
      Platform::Current()->ShouldUseCodeCacheWithHashing(
          WebURL(GetResourceRequest().Url()));

  bool code_cache_supported = http_family || code_cache_with_hashing_supported;
  if (code_cache_supported) {
    std::unique_ptr<CachedMetadataSender> sender = CachedMetadataSender::Create(
        response, mojom::blink::CodeCacheType::kJavascript,
        GetResourceRequest().RequestorOrigin());
    if (code_cache_with_hashing_supported) {
      cached_metadata_handler_ =
          MakeGarbageCollected<ScriptCachedMetadataHandlerWithHashing>(
              Encoding(), std::move(sender));
    } else {
      cached_metadata_handler_ =
          MakeGarbageCollected<ScriptCachedMetadataHandler>(Encoding(),
                                                            std::move(sender));
    }
  }
}

void ScriptResource::ResponseBodyReceived(
    ResponseBodyLoaderDrainableInterface& body_loader,
    scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner) {
  if (streaming_state_ == StreamingState::kStreamingDisabled) {
    return;
  }

  CHECK_EQ(streaming_state_, StreamingState::kWaitingForDataPipe);

  // Checked in the constructor.
  CHECK(Url().ProtocolIsInHTTPFamily() ||
        base::FeatureList::IsEnabled(features::kScriptStreamingForNonHTTP));
  CHECK(base::FeatureList::IsEnabled(features::kScriptStreaming));

  ResponseBodyLoaderClient* response_body_loader_client;
  mojo::ScopedDataPipeConsumerHandle data_pipe =
      body_loader.DrainAsDataPipe(&response_body_loader_client);
  if (!data_pipe) {
    DisableStreaming(ScriptStreamer::NotStreamingReason::kNoDataPipe);
    return;
  }

  CheckStreamingState();
  CHECK(!ErrorOccurred());
  CHECK(!background_streamer_);
  streamer_ = MakeGarbageCollected<ResourceScriptStreamer>(
      this, std::move(data_pipe), response_body_loader_client,
      std::move(stream_text_decoder_), loader_task_runner);
  CHECK_EQ(no_streamer_reason_, ScriptStreamer::NotStreamingReason::kInvalid);
  AdvanceStreamingState(StreamingState::kStreaming);
}

void ScriptResource::DidReceiveDecodedData(
    const String& data,
    std::unique_ptr<ParkableStringImpl::SecureDigest> digest) {
  source_text_ = ParkableString(data.Impl(), std::move(digest));
  SetDecodedSize(source_text_.CharactersSizeInBytes());
}

void ScriptResource::NotifyFinished() {
  DCHECK(IsLoaded());
  switch (streaming_state_) {
    case StreamingState::kWaitingForDataPipe:
      // We never received a response body, otherwise the state would be
      // one of kStreaming or kNoStreaming. So, either there was an error, or
      // there was no response body loader (thus no data pipe) at all. Either
      // way, we want to disable streaming.
      if (ErrorOccurred()) {
        DisableStreaming(ScriptStreamer::NotStreamingReason::kErrorOccurred);
      } else {
        DisableStreaming(ScriptStreamer::NotStreamingReason::kNoDataPipe);
      }
      break;

    case StreamingState::kStreaming:
      DCHECK(streamer_);
      if (!streamer_->IsFinished()) {
        // This notification didn't come from the streaming finishing, so it
        // must be an external error (e.g. cancelling the resource).
        CHECK(ErrorOccurred());
        streamer_->Cancel();
        streamer_.Release();
        DisableStreaming(ScriptStreamer::NotStreamingReason::kErrorOccurred);
      }
      break;

    case StreamingState::kStreamingDisabled:
      // If streaming is already disabled, we can just continue as before.
      break;
  }
  CheckStreamingState();

  if (!source_text_.IsNull() && Data()) {
    // Wait to call ClearData() here instead of in DidReceiveDecodedData() since
    // the integrity check requires Data() to not be null.
    ClearData();
  }

  TextResource::NotifyFinished();
}

void ScriptResource::SetEncoding(const String& chs) {
  TextResource::SetEncoding(chs);
  if (stream_text_decoder_) {
    stream_text_decoder_->SetEncoding(
        WTF::TextEncoding(chs), TextResourceDecoder::kEncodingFromHTTPHeader);
  }
}

ScriptStreamer* ScriptResource::TakeStreamer() {
  CHECK(IsLoaded());
  CHECK(!(streamer_ && background_streamer_));
  ScriptStreamer* streamer;
  // A second use of the streamer is not possible, so we release it out and
  // disable streaming for subsequent uses.
  if (streamer_) {
    streamer = streamer_.Release();
  } else if (background_streamer_) {
    streamer = background_streamer_.Release();
  } else {
    CHECK_NE(NoStreamerReason(), ScriptStreamer::NotStreamingReason::kInvalid);
    return nullptr;
  }
  DisableStreaming(
      ScriptStreamer::NotStreamingReason::kSecondScriptResourceUse);
  return streamer;
}

void ScriptResource::DisableStreaming(
    ScriptStreamer::NotStreamingReason no_streamer_reason) {
  CHECK_NE(no_streamer_reason, ScriptStreamer::NotStreamingReason::kInvalid);
  if (no_streamer_reason_ != ScriptStreamer::NotStreamingReason::kInvalid) {
    // Streaming is already disabled, no need to disable it again.
    return;
  }
  no_streamer_reason_ = no_streamer_reason;
  AdvanceStreamingState(StreamingState::kStreamingDisabled);
}

void ScriptResource::AdvanceStreamingState(StreamingState new_state) {
  switch (streaming_state_) {
    case StreamingState::kWaitingForDataPipe:
      CHECK(new_state == StreamingState::kStreaming ||
            new_state == StreamingState::kStreamingDisabled);
      break;
    case StreamingState::kStreaming:
      CHECK_EQ(new_state, StreamingState::kStreamingDisabled);
      break;
    case StreamingState::kStreamingDisabled:
      CHECK(false);
      break;
  }

  streaming_state_ = new_state;
  CheckStreamingState();
}

void ScriptResource::CheckStreamingState() const {
  // TODO(leszeks): Eventually convert these CHECKs into DCHECKs once the logic
  // is a bit more baked in.
  switch (streaming_state_) {
    case StreamingState::kWaitingForDataPipe:
      CHECK(!streamer_);
      CHECK_EQ(no_streamer_reason_,
               ScriptStreamer::NotStreamingReason::kInvalid);
      break;
    case StreamingState::kStreaming:
      CHECK(streamer_);
      CHECK(streamer_->CanStartStreaming() || streamer_->IsStreamingStarted() ||
            streamer_->IsStreamingSuppressed());
      CHECK(IsLoading() || streamer_->IsFinished());
      break;
    case StreamingState::kStreamingDisabled:
      CHECK(!streamer_);
      CHECK_NE(no_streamer_reason_,
               ScriptStreamer::NotStreamingReason::kInvalid);
      break;
  }
}

ScriptCacheConsumer* ScriptResource::TakeCacheConsumer() {
  CHECK(IsLoaded());
  CheckConsumeCacheState();
  if (!cache_consumer_) {
    return nullptr;
  }
  CHECK_EQ(consume_cache_state_, ConsumeCacheState::kRunningOffThread);

  ScriptCacheConsumer* cache_consumer = cache_consumer_;
  // A second use of the cache consumer is not possible, so we null it out and
  // disable off-thread cache consumption for subsequent uses.
  cache_consumer_ = nullptr;
  DisableOffThreadConsumeCache();
  return cache_consumer;
}

void ScriptResource::DisableOffThreadConsumeCache() {
  AdvanceConsumeCacheState(ConsumeCacheState::kOffThreadConsumeCacheDisabled);
}

void ScriptResource::AdvanceConsumeCacheState(ConsumeCacheState new_state) {
  switch (consume_cache_state_) {
    case ConsumeCacheState::kWaitingForCache:
      CHECK(new_state == ConsumeCacheState::kRunningOffThread ||
            new_state == ConsumeCacheState::kOffThreadConsumeCacheDisabled);
      break;
    case ConsumeCacheState::kRunningOffThread:
      CHECK_EQ(new_state, ConsumeCacheState::kOffThreadConsumeCacheDisabled);
      break;
    case ConsumeCacheState::kOffThreadConsumeCacheDisabled:
      CHECK_EQ(new_state, ConsumeCacheState::kOffThreadConsumeCacheDisabled);
      break;
  }

  consume_cache_state_ = new_state;
  CheckConsumeCacheState();
}

void ScriptResource::CheckConsumeCacheState() const {
  // TODO(leszeks): Eventually convert these CHECKs into DCHECKs once the logic
  // is a bit more baked in.
  switch (consume_cache_state_) {
    case ConsumeCacheState::kWaitingForCache:
      CHECK(!cache_consumer_);
      break;
    case ConsumeCacheState::kRunningOffThread:
      CHECK(cache_consumer_);
      break;
    case ConsumeCacheState::kOffThreadConsumeCacheDisabled:
      CHECK(!cache_consumer_);
      break;
  }
}

std::unique_ptr<BackgroundResponseProcessorFactory>
ScriptResource::MaybeCreateBackgroundResponseProcessorFactory() {
  if (!features::kBackgroundScriptResponseProcessor.Get()) {
    return nullptr;
  }
  CHECK(!streamer_);
  background_streamer_ = nullptr;
  if (no_streamer_reason_ != ScriptStreamer::NotStreamingReason::kInvalid) {
    // Streaming is already disabled.
    return nullptr;
  }
  // We don't support script streaming when this ScriptResource is not created
  // on the main thread.
  CHECK(isolate_if_main_thread_);
  // Set `no_streamer_reason_` to kBackgroundResponseProcessorWillBeUsed. This
  // is intended to prevent starting the ScriptStreamer from the main thread,
  // because BackgroundResourceScriptStreamer will be started from the
  // background thread.
  // TODO(crbug.com/40244488): When BackgroundURLLoader will be able to support
  // all types of script loading, remove the code path of starting
  // ScriptStreamer from the main thread.
  DisableStreaming(ScriptStreamer::NotStreamingReason::
                       kBackgroundResponseProcessorWillBeUsed);

  background_streamer_ =
      MakeGarbageCollected<BackgroundResourceScriptStreamer>(this);
  return background_streamer_->CreateBackgroundResponseProcessorFactory();
}

}  // namespace blink
```