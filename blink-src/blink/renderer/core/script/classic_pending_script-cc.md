Response:
My thought process to analyze the `classic_pending_script.cc` file and generate the response went something like this:

1. **Understand the Goal:** The request asks for the file's functionality, its relation to web technologies (JS, HTML, CSS), examples of logic, common errors, and debugging steps.

2. **Initial Skim and Keyword Identification:** I quickly scanned the code, looking for key terms and patterns. I noticed:
    * `ClassicPendingScript`: The central entity.
    * `Fetch`, `CreateInline`:  Likely how scripts are loaded.
    * `Resource`, `ScriptResource`: Interaction with resource loading.
    * `V8`:  Indicates JavaScript execution.
    * `Document`, `Element`: DOM interaction.
    * `ReadyState`:  Managing the loading process.
    * `Integrity`, `CrossOrigin`: Security features.
    * `Async`: Asynchronous script handling.
    * `LCP`: Largest Contentful Paint, a performance metric.
    * `document.write`: A specific HTML API.

3. **Core Functionality Identification (High-Level):**  Based on the keywords, I hypothesized that this file manages the lifecycle of classic (non-module) JavaScript scripts being loaded and prepared for execution in the Blink rendering engine. This includes fetching external scripts, handling inline scripts, managing loading states, and performing security checks.

4. **Detailed Analysis - Function by Function (Focusing on Key Methods):** I then went through the code more systematically, paying attention to the purpose of each significant function:

    * **`Fetch`:**  Clearly handles the fetching of external scripts. I noted the parameters (URL, document, options, crossorigin, encoding, element, defer) and the involvement of `ScriptResource::Fetch`. I also recognized the `MaybeDisallowFetchForDocWrittenScript` as a potential intervention.
    * **`CreateInline`:** Handles inline scripts. The parameters (element, position, URLs, source, options) are important.
    * **Constructor:**  Initializes the `ClassicPendingScript` object, differentiating between external and inline scripts.
    * **`CheckState`:** A debugging aid to ensure internal consistency.
    * **`NotifyFinished`:**  Crucial for handling the completion of a script resource load. I paid close attention to the SRI checks, MIME type checks, and the creation of `ClassicScript`.
    * **`GetSource`:** Returns the `ClassicScript` object, which contains the script's source code. I noted the handling of inline scripts and the `InlineScriptStreamer`.
    * **`AdvanceReadyState`:** Manages the state transitions of the script loading process.
    * **`IsEligibleForLowPriorityAsyncScriptExecution`:**  Deals with optimizing the loading of asynchronous scripts based on various heuristics (LCP, ad status, etc.).

5. **Relating to Web Technologies:**  As I analyzed the functions, I actively considered how they relate to HTML, JavaScript, and CSS:

    * **JavaScript:** The entire file is about loading and preparing *JavaScript* scripts. The interaction with V8 is a direct link. The handling of `async` and `defer` attributes is also key.
    * **HTML:** The `ScriptElementBase` and `Document` parameters connect the script loading process to HTML `<script>` tags. The mention of `document.write` is a specific HTML API.
    * **CSS:** While the file doesn't directly manipulate CSS, the concept of blocking rendering (mentioned in the context of `document.write` intervention) and the LCP considerations indirectly relate to how scripts can affect the perceived loading of a page, which includes CSS rendering.

6. **Logic and Examples:** I looked for conditional logic and data flow to create examples. The `Fetch` function provides a clear input (script tag attributes) and output (initiation of script fetching). The `IsEligibleForLowPriorityAsyncScriptExecution` function has complex logic based on feature flags and document state, making it suitable for illustrating conditional behavior.

7. **Common Errors:**  I thought about common mistakes developers might make that would interact with this code:
    * Incorrect `crossorigin` attribute.
    * Mismatched integrity metadata.
    * Using `document.write` in a way that blocks rendering.
    * Incorrect MIME types for script files on the server.

8. **Debugging Steps:**  I considered how a developer might end up in this part of the Chromium code:
    * Setting breakpoints related to script loading.
    * Examining network requests.
    * Inspecting the DOM and script elements.
    * Using Chromium's tracing tools.

9. **Structuring the Response:** I organized my findings into the requested categories: functionality, relation to web technologies, logic examples, common errors, and debugging. I used clear headings and bullet points to make the information easy to read and understand.

10. **Refinement and Review:** Finally, I reviewed my response to ensure accuracy, clarity, and completeness. I made sure the examples were concrete and the explanations were easy to follow. I paid attention to the specific wording of the prompt to ensure I addressed all the requirements. For example, the prompt specifically asked for *assumptions* for input/output, so I made sure to frame the logic examples as such.

This iterative process of skimming, detailed analysis, connecting concepts, and structuring the information allowed me to generate a comprehensive and accurate response to the request.
这个文件是 Chromium Blink 引擎中负责处理 **经典 JavaScript 脚本**（区别于模块脚本）加载和执行的 **待处理脚本** 对象。它的主要功能是管理一个 `<script>` 标签所代表的外部或内联脚本的加载状态，并在准备就绪后提供脚本的源代码以供执行。

**具体功能列举:**

1. **脚本获取 (Fetching):**
   - 对于外部脚本 (`<script src="...">`)，负责发起网络请求来下载脚本资源。
   - 管理脚本资源的加载状态，包括等待资源、等待缓存、已就绪、发生错误等。
   - 与 `ScriptResource` 类交互，进行实际的资源加载。
   - 处理跨域 (`crossorigin`) 属性和完整性校验 (`integrity`)。
   - 可以根据 `document.write` 的使用情况进行干预，延迟脚本的加载以避免阻塞页面渲染。

2. **内联脚本处理 (Inline Script Handling):**
   - 对于内联脚本 (`<script>...</script>`)，直接持有脚本的源代码。
   - 提供内联脚本的源代码以供后续编译和执行。
   - 针对内联脚本，可以利用 `InlineScriptStreamer` 进行流式编译优化。

3. **状态管理 (State Management):**
   - 维护脚本的加载状态 (`ready_state_`)，例如：
     - `kWaitingForResource`: 等待外部脚本资源加载完成。
     - `kWaitingForCacheConsumer`: 等待脚本缓存操作完成。
     - `kReady`: 脚本已准备好执行。
     - `kErrorOccurred`: 脚本加载或校验过程中发生错误。
   - 提供方法 (`IsReady()`) 查询脚本是否已准备好执行。
   - 提供方法 (`AdvanceReadyState()`) 来更新脚本的加载状态。

4. **脚本源代码提供 (Source Code Provision):**
   - 提供 `GetSource()` 方法，返回一个 `ClassicScript` 对象，该对象包含了脚本的源代码以及其他相关信息（如 URL、Base URL、编译选项等）。
   - 对于内联脚本，会在此处创建 `ClassicScript` 对象。
   - 对于外部脚本，会在资源加载完成后创建 `ClassicScript` 对象。

5. **异步脚本优化 (Async Script Optimization):**
   - 对于 `async` 属性的脚本，可以根据一些启发式规则（如是否影响 LCP、是否是广告资源、是否通过 `document.write` 插入等）来判断是否可以降低其执行优先级，以提高页面加载性能。
   - `IsEligibleForLowPriorityAsyncScriptExecution()` 方法实现了这一逻辑。

6. **性能监控和追踪 (Performance Monitoring and Tracing):**
   - 使用宏 (`TRACE_EVENT_WITH_FLOW`) 进行性能追踪，用于分析脚本加载和编译过程。
   - 记录与第三方 Cookie 相关的请求，用于统计。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:** `ClassicPendingScript` 的核心功能就是加载和管理 **JavaScript** 代码。它负责将 `<script>` 标签指向的 JavaScript 代码准备好，以便 V8 引擎执行。
    * **例子:** 当浏览器解析到 `<script src="script.js"></script>` 时，会创建一个 `ClassicPendingScript` 对象，调用其 `Fetch()` 方法来下载 `script.js`。下载完成后，`NotifyFinished()` 会被调用，创建一个 `ClassicScript` 对象，并通过 `GetSource()` 提供给 V8 执行。
    * **例子:** 当浏览器解析到 `<script> console.log("Hello"); </script>` 时，会创建一个 `ClassicPendingScript` 对象，调用其 `CreateInline()` 方法，并将内联的 `console.log("Hello");` 代码存储起来。当脚本准备好执行时，`GetSource()` 会创建一个包含这段代码的 `ClassicScript` 对象。

* **HTML:** `ClassicPendingScript` 与 **HTML** 的 `<script>` 标签紧密相关。它解析 `<script>` 标签的属性（如 `src`、`type`、`async`、`defer`、`crossorigin`、`integrity`），并根据这些属性来决定如何加载和处理脚本。
    * **例子:**  `<script async src="async.js"></script>` 中的 `async` 属性会影响 `ClassicPendingScript` 的 `GetSchedulingType()` 方法的返回值，从而影响脚本的执行时机。
    * **例子:**  `<script integrity="sha384-..." src="script.js"></script>` 中的 `integrity` 属性会导致 `ClassicPendingScript` 在 `NotifyFinished()` 中进行完整性校验。

* **CSS:**  虽然 `ClassicPendingScript` 不直接处理 **CSS** 代码，但 JavaScript 的执行可能会影响 CSS 的渲染。例如，通过 `document.write` 插入的脚本可能会阻塞 CSSOM 的构建，从而延迟页面渲染。`ClassicPendingScript` 中对 `document.write` 的干预机制就是为了解决这类问题。
    * **例子:**  如果一个通过 `document.write` 插入的 `<script>` 标签指向一个需要下载的外部脚本，`MaybeDisallowFetchForDocWrittenScript()` 可能会阻止立即下载，以避免阻塞主线程，从而让浏览器可以优先渲染页面内容。

**逻辑推理举例 (假设输入与输出):**

**假设输入:**

1. 一个 HTML 文档包含以下 `<script>` 标签：
    ```html
    <script src="https://example.com/script.js"></script>
    ```
2. `https://example.com/script.js` 的响应头包含 `Content-Type: application/javascript`。
3. 网络请求成功返回了 `script.js` 的内容。

**逻辑推理:**

1. 当解析器遇到 `<script>` 标签时，会创建一个 `ClassicPendingScript` 对象。
2. `Fetch()` 方法被调用，发起对 `https://example.com/script.js` 的请求。
3. 请求完成后，`NotifyFinished()` 方法被调用。
4. 由于 `Content-Type` 是 `application/javascript`，MIME 类型检查通过。
5. 假设没有 `integrity` 属性，完整性校验也通过。
6. `classic_script_` 成员变量被设置为一个新创建的 `ClassicScript` 对象，包含 `script.js` 的内容。
7. 如果脚本没有使用缓存，`AdvanceReadyState()` 将状态更新为 `kReady`。
8. 当脚本需要执行时，调用 `GetSource()` 方法，返回 `classic_script_` 指针。

**输出:**

*   `ClassicPendingScript` 对象的状态最终变为 `kReady`。
*   `GetSource()` 方法返回一个指向 `ClassicScript` 对象的指针，该对象包含了 `script.js` 的源代码。

**用户或编程常见的使用错误举例说明:**

1. **跨域脚本加载问题 (CORS error):**
    * **错误:** 用户在 HTML 中引入了来自其他域的脚本，但服务器没有设置正确的 CORS 头 (`Access-Control-Allow-Origin`).
    * **`ClassicPendingScript` 中的体现:** `Fetch()` 方法会发起跨域请求，如果服务器没有返回允许跨域的响应头，资源加载会失败，`NotifyFinished()` 会将状态设置为 `kErrorOccurred`。浏览器控制台会显示 CORS 相关的错误信息。
    * **用户操作:** 用户直接在浏览器地址栏输入包含该 `<script>` 标签的 HTML 文件 URL，或者通过点击链接访问该页面。

2. **完整性校验失败 (SRI failure):**
    * **错误:**  HTML 中 `<script>` 标签的 `integrity` 属性值与下载到的脚本内容的哈希值不匹配。
    * **`ClassicPendingScript` 中的体现:** 在 `NotifyFinished()` 方法中，`SubresourceIntegrityHelper::DoReport()` 和后续的完整性检查会发现哈希值不匹配，将 `integrity_failure` 设置为 `true`，最终导致状态变为 `kErrorOccurred`。浏览器控制台会显示 SRI 相关的错误信息。
    * **用户操作:** 用户访问一个使用了 SRI 校验的网页，但由于网络传输错误或 CDN 内容被篡改，下载到的脚本内容与预期的不一致。

3. **MIME 类型错误:**
    * **错误:**  服务器返回的脚本资源的 `Content-Type` 不是 JavaScript 相关的 MIME 类型（如 `application/javascript`, `text/javascript` 等）。
    * **`ClassicPendingScript` 中的体现:**  在 `NotifyFinished()` 中，`AllowedByNosniff::MimeTypeAsScript()` 会检查 MIME 类型，如果类型不正确，`mime_type_failure` 会被设置为 `true`，导致状态变为 `kErrorOccurred`。浏览器控制台会显示 MIME 类型相关的错误信息。
    * **用户操作:** 用户访问一个网页，该网页引用的脚本文件在服务器端配置了错误的 MIME 类型。

4. **使用 `document.write` 阻塞渲染:**
    * **错误:**  开发者在页面加载过程中使用 `document.write` 插入大量的同步脚本，导致浏览器主线程被阻塞，延迟页面渲染。
    * **`ClassicPendingScript` 中的体现:** `MaybeDisallowFetchForDocWrittenScript()` 方法可能会检测到这种情况，并延迟脚本的加载。虽然不会直接导致错误，但会影响页面加载性能。
    * **用户操作:** 用户访问一个过度使用了 `document.write` 的网页，会感觉到页面加载缓慢或白屏时间过长。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者在调试一个外部 JavaScript 脚本加载失败的问题，并想了解 `ClassicPendingScript` 的工作流程：

1. **用户在浏览器地址栏输入 URL 或点击链接**，导航到一个包含 `<script src="broken.js"></script>` 的网页。
2. **HTML 解析器开始解析 HTML 文档**，当遇到 `<script>` 标签时，会创建一个 `HTMLScriptElement` 对象。
3. **`HTMLScriptElement` 对象会创建一个 `ClassicPendingScript` 对象**，并根据标签的属性初始化它。
4. **`ClassicPendingScript::Fetch()` 方法被调用**，创建一个 `ScriptResource` 对象，并开始下载 `broken.js`。
5. **如果 `broken.js` 对应的服务器返回 404 错误**，或者由于网络问题导致请求失败，`ScriptResource` 会通知 `ClassicPendingScript` 加载失败。
6. **`ClassicPendingScript::NotifyFinished()` 方法被调用**，此时 `resource->ErrorOccurred()` 返回 `true`。
7. **`AdvanceReadyState(kErrorOccurred)` 被调用**，将脚本的状态设置为错误。
8. **在后续的脚本执行阶段，Blink 引擎会检查 `ClassicPendingScript` 的状态**，发现是 `kErrorOccurred`，就不会执行该脚本，并在控制台输出错误信息。

**作为调试线索，开发者可以在以下几个方面进行排查：**

*   **网络请求:** 使用 Chrome DevTools 的 Network 面板查看 `broken.js` 的请求状态和响应头，确认是否存在 404 或其他网络错误。
*   **脚本 URL:** 检查 `<script src="broken.js">` 中的 URL 是否正确。
*   **服务器配置:** 检查服务器是否正确部署了 `broken.js` 文件，以及是否配置了正确的 CORS 头（如果需要跨域加载）。
*   **完整性校验:** 如果使用了 `integrity` 属性，检查其值是否与 `broken.js` 的实际内容哈希匹配。
*   **MIME 类型:** 检查服务器返回的 `broken.js` 的 `Content-Type` 是否为 JavaScript 相关的 MIME 类型。

通过理解 `ClassicPendingScript` 的功能和状态转换，开发者可以更好地理解脚本加载的流程，并定位问题所在。他们可以在 `ClassicPendingScript` 的关键方法上设置断点，例如 `Fetch()`、`NotifyFinished()` 和 `GetSource()`，来跟踪脚本加载的各个阶段，并检查相关变量的值，从而更有效地进行调试。

Prompt: 
```
这是目录为blink/renderer/core/script/classic_pending_script.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/script/classic_pending_script.h"

#include "base/feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/lcp_critical_path_predictor_util.h"
#include "third_party/blink/public/mojom/script/script_type.mojom-blink-forward.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/script_streamer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_common.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/core/loader/subresource_integrity_helper.h"
#include "third_party/blink/renderer/core/loader/url_matcher.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/script/document_write_intervention.h"
#include "third_party/blink/renderer/core/script/script_loader.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/allowed_by_nosniff.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/detachable_use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {
namespace {

InlineScriptStreamer* GetInlineScriptStreamer(const String& source,
                                              Document& document) {
  ScriptableDocumentParser* scriptable_parser =
      document.GetScriptableDocumentParser();
  if (!scriptable_parser) {
    return nullptr;
  }

  // The inline script streamers are keyed by the full source text to make sure
  // the script that was parsed in the background scanner exactly matches the
  // script we want to compile here.
  return scriptable_parser->TakeInlineScriptStreamer(source);
}

}  // namespace

// <specdef href="https://html.spec.whatwg.org/C/#fetch-a-classic-script">
ClassicPendingScript* ClassicPendingScript::Fetch(
    const KURL& url,
    Document& element_document,
    const ScriptFetchOptions& options,
    CrossOriginAttributeValue cross_origin,
    const WTF::TextEncoding& encoding,
    ScriptElementBase* element,
    FetchParameters::DeferOption defer,
    scheduler::TaskAttributionInfo* parent_task) {
  ExecutionContext* context = element_document.GetExecutionContext();
  FetchParameters params(options.CreateFetchParameters(
      url, context->GetSecurityOrigin(), context->GetCurrentWorld(),
      cross_origin, encoding, defer));

  ClassicPendingScript* pending_script =
      MakeGarbageCollected<ClassicPendingScript>(
          element, TextPosition::MinimumPosition(), KURL(), KURL(), String(),
          ScriptSourceLocationType::kExternalFile, options,
          /*is_external=*/true, parent_task);

  // [Intervention]
  // For users on slow connections, we want to avoid blocking the parser in
  // the main frame on script loads inserted via document.write, since it
  // can add significant delays before page content is displayed on the
  // screen.
  pending_script->intervened_ =
      MaybeDisallowFetchForDocWrittenScript(params, element_document);

  // <spec step="2">Set request's client to settings object.</spec>
  //
  // Note: |element_document| corresponds to the settings object.
  //
  // We allow streaming, as WatchForLoad() is always called when the script
  // needs to execute and the ScriptResource is not finished, so
  // SetClientIsWaitingForFinished is always set on the resource.

  Page* page = element_document.GetPage();
  v8_compile_hints::V8CrowdsourcedCompileHintsProducer* compile_hints_producer =
      nullptr;
  v8_compile_hints::V8CrowdsourcedCompileHintsConsumer* compile_hints_consumer =
      nullptr;
  if (page->MainFrame()->IsLocalFrame()) {
    compile_hints_producer = &page->GetV8CrowdsourcedCompileHintsProducer();
    compile_hints_consumer = &page->GetV8CrowdsourcedCompileHintsConsumer();
  }

  ScriptResource::Fetch(params, element_document.Fetcher(), pending_script,
                        context->GetIsolate(), ScriptResource::kAllowStreaming,
                        compile_hints_producer, compile_hints_consumer,
                        v8_compile_hints::GetMagicCommentMode(
                            element_document.GetExecutionContext()));
  pending_script->CheckState();
  return pending_script;
}

ClassicPendingScript* ClassicPendingScript::CreateInline(
    ScriptElementBase* element,
    const TextPosition& starting_position,
    const KURL& source_url,
    const KURL& base_url,
    const String& source_text,
    ScriptSourceLocationType source_location_type,
    const ScriptFetchOptions& options,
    scheduler::TaskAttributionInfo* parent_task) {
  ClassicPendingScript* pending_script =
      MakeGarbageCollected<ClassicPendingScript>(
          element, starting_position, source_url, base_url, source_text,
          source_location_type, options, /*is_external=*/false, parent_task);
  pending_script->CheckState();
  return pending_script;
}

ClassicPendingScript::ClassicPendingScript(
    ScriptElementBase* element,
    const TextPosition& starting_position,
    const KURL& source_url_for_inline_script,
    const KURL& base_url_for_inline_script,
    const String& source_text_for_inline_script,
    ScriptSourceLocationType source_location_type,
    const ScriptFetchOptions& options,
    bool is_external,
    scheduler::TaskAttributionInfo* parent_task)
    : PendingScript(element, starting_position, parent_task),
      options_(options),
      source_url_for_inline_script_(source_url_for_inline_script),
      base_url_for_inline_script_(base_url_for_inline_script),
      source_text_for_inline_script_(source_text_for_inline_script),
      source_location_type_(source_location_type),
      is_external_(is_external),
      ready_state_(is_external ? kWaitingForResource : kReady) {
  CHECK(GetElement());

  if (is_external_) {
    DCHECK(base_url_for_inline_script_.IsNull());
    DCHECK(source_text_for_inline_script_.IsNull());
  } else {
    DCHECK(!base_url_for_inline_script_.IsNull());
    DCHECK(!source_text_for_inline_script_.IsNull());
  }
}

ClassicPendingScript::~ClassicPendingScript() = default;

NOINLINE void ClassicPendingScript::CheckState() const {
  DCHECK(GetElement());
  DCHECK_EQ(is_external_, !!GetResource());
  switch (ready_state_) {
    case kWaitingForResource:
      DCHECK(is_external_);
      DCHECK(!classic_script_);
      break;
    case kWaitingForCacheConsumer:
      DCHECK(is_external_);
      DCHECK(classic_script_);
      DCHECK(classic_script_->CacheConsumer());
      break;
    case kReady:
      DCHECK(!is_external_ || classic_script_);
      break;
    case kErrorOccurred:
      DCHECK(is_external_);
      DCHECK(!classic_script_);
      break;
  }
}

void ClassicPendingScript::RecordThirdPartyRequestWithCookieIfNeeded(
    const ResourceResponse& response) const {
  // Can be null in some cases where loading failed.
  if (response.IsNull()) {
    return;
  }

  // Ignore cookie-less requests.
  if (!response.WasCookieInRequest()) {
    return;
  }

  // Ignore scripts that can be delayed. This is only async scripts currently.
  // kDefer and kForceDefer don't count as delayable since delaying them
  // artificially further while prerendering would prevent the page from making
  // progress.
  if (GetSchedulingType() == ScriptSchedulingType::kAsync) {
    return;
  }

  ExecutionContext* execution_context = OriginalExecutionContext();
  Document* element_document = OriginalElementDocument();
  if (!execution_context || !element_document) {
    return;
  }

  scoped_refptr<const SecurityOrigin> top_frame_origin =
      element_document->TopFrameOrigin();
  if (!top_frame_origin) {
    return;
  }

  // The use counter is meant to gather data for prerendering: how often do
  // pages make credentialed requests to third parties from first-party frames,
  // that cannot be delayed during prerendering until the page is navigated to.
  // Therefore...
  String doc_registrable_domain =
      execution_context->GetSecurityOrigin()->RegistrableDomain();
  // Ignore third-party frames.
  if (top_frame_origin->RegistrableDomain() != doc_registrable_domain) {
    return;
  }

  scoped_refptr<SecurityOrigin> script_origin =
      SecurityOrigin::Create(response.ResponseUrl());
  // Ignore first-party requests.
  if (doc_registrable_domain == script_origin->RegistrableDomain()) {
    return;
  }

  execution_context->CountUse(
      mojom::blink::WebFeature::
          kUndeferrableThirdPartySubresourceRequestWithCookie);
}

void ClassicPendingScript::DisposeInternal() {
  ClearResource();
}

bool ClassicPendingScript::IsEligibleForLowPriorityAsyncScriptExecution()
    const {
  DCHECK_EQ(GetSchedulingType(), ScriptSchedulingType::kAsync);

  static const bool feature_enabled =
      base::FeatureList::IsEnabled(features::kLowPriorityAsyncScriptExecution);
  if (!feature_enabled) {
    return false;
  }

  Document* element_document = OriginalElementDocument();

  if (!IsA<HTMLDocument>(element_document)) {
    return false;
  }

  // Most LCP elements are provided by the main frame, and delaying subframe's
  // resources seems not to improve LCP.
  const bool main_frame_only =
      features::kLowPriorityAsyncScriptExecutionMainFrameOnlyParam.Get();
  if (main_frame_only && !element_document->IsInOutermostMainFrame()) {
    return false;
  }

  const base::TimeDelta feature_limit =
      features::kLowPriorityAsyncScriptExecutionFeatureLimitParam.Get();
  if (!feature_limit.is_zero() &&
      element_document->GetStartTime().Elapsed() > feature_limit) {
    return false;
  }

  // Do not enable kLowPriorityAsyncScriptExecution on reload.
  // No specific reason to use element document here instead of context
  // document though.
  Document& top_document = element_document->TopDocument();
  if (top_document.Loader() &&
      top_document.Loader()->IsReloadedOrFormSubmitted()) {
    return false;
  }

  // Check if LCP influencing scripts are to be excluded.
  const bool exclude_lcp_influencers =
      features::kLowPriorityAsyncScriptExecutionExcludeLcpInfluencersParam
          .Get();
  if (exclude_lcp_influencers && LcppScriptObserverEnabled()) {
    if (LCPCriticalPathPredictor* lcpp = top_document.GetFrame()->GetLCPP()) {
      if (lcpp->IsLcpInfluencerScript(GetResource()->Url())) {
        return false;
      }
    }
  }

  const bool disable_when_lcp_not_in_html =
      features::kLowPriorityAsyncScriptExecutionDisableWhenLcpNotInHtmlParam
          .Get();
  if (disable_when_lcp_not_in_html && !top_document.IsLcpElementFoundInHtml()) {
    // If LCP element isn't found in main document HTML during preload scanning,
    // disable delaying.
    return false;
  }

  const bool cross_site_only =
      features::kLowPriorityAsyncScriptExecutionCrossSiteOnlyParam.Get();
  if (cross_site_only && GetResource() &&
      element_document->GetExecutionContext()) {
    scoped_refptr<const SecurityOrigin> url_origin =
        SecurityOrigin::Create(GetResource()->Url());
    if (url_origin->IsSameSiteWith(
            element_document->GetExecutionContext()->GetSecurityOrigin())) {
      return false;
    }
  }

  if (GetElement() && GetElement()->IsPotentiallyRenderBlocking()) {
    return false;
  }

  // We don't delay async scripts that have matched a resource in the preload
  // cache, because we're using <link rel=preload> as a signal that the script
  // is higher-than-usual priority, and therefore should be executed earlier
  // rather than later.
  if (GetResource() && GetResource()->IsLinkPreload()) {
    return false;
  }

  bool is_ad_resource =
      GetResource() && GetResource()->GetResourceRequest().IsAdResource();
  switch (features::kLowPriorityAsyncScriptExecutionTargetParam.Get()) {
    case features::AsyncScriptExperimentalSchedulingTarget::kAds:
      if (!is_ad_resource) {
        return false;
      }
      break;
    case features::AsyncScriptExperimentalSchedulingTarget::kNonAds:
      if (is_ad_resource) {
        return false;
      }
      break;
    case features::AsyncScriptExperimentalSchedulingTarget::kBoth:
      break;
  }

  const bool exclude_non_parser_inserted =
      features::kLowPriorityAsyncScriptExecutionExcludeNonParserInsertedParam
          .Get();
  if (exclude_non_parser_inserted && !parser_inserted()) {
    return false;
  }

  const bool exclude_scripts_via_document_write =
      features::kLowPriorityAsyncScriptExecutionExcludeDocumentWriteParam.Get();
  if (exclude_scripts_via_document_write && is_in_document_write()) {
    return false;
  }

  const bool opt_out_low =
      features::kLowPriorityAsyncScriptExecutionOptOutLowFetchPriorityHintParam
          .Get();
  const bool opt_out_auto =
      features::kLowPriorityAsyncScriptExecutionOptOutAutoFetchPriorityHintParam
          .Get();
  const bool opt_out_high =
      features::kLowPriorityAsyncScriptExecutionOptOutHighFetchPriorityHintParam
          .Get();

  if (GetResource()) {
    switch (GetResource()->GetResourceRequest().GetFetchPriorityHint()) {
      case mojom::blink::FetchPriorityHint::kLow:
        if (opt_out_low) {
          return false;
        }
        break;
      case mojom::blink::FetchPriorityHint::kAuto:
        if (opt_out_auto) {
          return false;
        }
        break;
      case mojom::blink::FetchPriorityHint::kHigh:
        if (opt_out_high) {
          return false;
        }
        break;
    }
  }

  return true;
}

void ClassicPendingScript::NotifyFinished(Resource* resource) {
  // The following SRI checks need to be here because, unfortunately, fetches
  // are not done purely according to the Fetch spec. In particular,
  // different requests for the same resource do not have different
  // responses; the memory cache can (and will) return the exact same
  // Resource object.
  //
  // For different requests, the same Resource object will be returned and
  // will not be associated with the particular request.  Therefore, when the
  // body of the response comes in, there's no way to validate the integrity
  // of the Resource object against a particular request (since there may be
  // several pending requests all tied to the identical object, and the
  // actual requests are not stored).
  //
  // In order to simulate the correct behavior, Blink explicitly does the SRI
  // checks here, when a PendingScript tied to a particular request is
  // finished (and in the case of a StyleSheet, at the point of execution),
  // while having proper Fetch checks in the fetch module for use in the
  // fetch JavaScript API. In a future world where the ResourceFetcher uses
  // the Fetch algorithm, this should be fixed by having separate Response
  // objects (perhaps attached to identical Resource objects) per request.
  //
  // See https://crbug.com/500701 for more information.
  CheckState();
  DCHECK(GetResource());

  // If the original execution context/element document is gone, consider this
  // as network error. Anyway the script wouldn't evaluated / no events are
  // fired, so this is not observable.
  ExecutionContext* execution_context = OriginalExecutionContext();
  Document* element_document = OriginalElementDocument();
  if (!execution_context || execution_context->IsContextDestroyed() ||
      !element_document || !element_document->IsActive()) {
    AdvanceReadyState(kErrorOccurred);
    return;
  }

  SubresourceIntegrityHelper::DoReport(*execution_context,
                                       resource->IntegrityReportInfo());

  bool integrity_failure = false;
  if (!options_.GetIntegrityMetadata().empty() ||
      resource->ForceIntegrityChecks()) {
    integrity_failure = !resource->PassedIntegrityChecks();
  }

  if (intervened_) {
    CrossOriginAttributeValue cross_origin =
        GetCrossOriginAttributeValue(GetElement()->CrossOriginAttributeValue());
    PossiblyFetchBlockedDocWriteScript(resource, *element_document, options_,
                                       cross_origin);
  }

  // <specdef href="https://fetch.spec.whatwg.org/#concept-main-fetch">
  // <spec step="17">If response is not a network error and any of the following
  // returns blocked</spec>
  // <spec step="17.C">should internalResponse to request be blocked due to its
  // MIME type</spec>
  // <spec step="17.D">should internalResponse to request be blocked due to
  // nosniff</spec>
  // <spec step="17">then set response and internalResponse to a network
  // error.</spec>
  auto* fetcher = execution_context->Fetcher();
  const bool mime_type_failure = !AllowedByNosniff::MimeTypeAsScript(
      fetcher->GetUseCounter(), &fetcher->GetConsoleLogger(),
      resource->GetResponse(), AllowedByNosniff::MimeTypeCheck::kLaxForElement);

  TRACE_EVENT_WITH_FLOW1(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                         "ClassicPendingScript::NotifyFinished", this,
                         TRACE_EVENT_FLAG_FLOW_OUT, "data",
                         [&](perfetto::TracedValue context) {
                           inspector_parse_script_event::Data(
                               std::move(context), resource->InspectorId(),
                               resource->Url().GetString());
                         });

  // Ordinal ErrorOccurred(), SRI, and MIME check are all considered as network
  // errors in the Fetch spec.
  bool error_occurred =
      resource->ErrorOccurred() || integrity_failure || mime_type_failure;
  if (error_occurred) {
    AdvanceReadyState(kErrorOccurred);
    return;
  }

  // At this point, the load is successful, and ClassicScript is created.
  classic_script_ =
      ClassicScript::CreateFromResource(To<ScriptResource>(resource), options_);

  // We'll still wait for ScriptCacheConsumer before marking this PendingScript
  // ready.
  if (classic_script_->CacheConsumer()) {
    AdvanceReadyState(kWaitingForCacheConsumer);
    // TODO(leszeks): Decide whether kNetworking is the right task type here.
    classic_script_->CacheConsumer()->NotifyClientWaiting(
        this, classic_script_,
        execution_context->GetTaskRunner(TaskType::kNetworking));
  } else {
    // Either there was never a cache consume, or it was dropped. Either way, we
    // are ready.
    AdvanceReadyState(kReady);
  }
}

void ClassicPendingScript::NotifyCacheConsumeFinished() {
  CHECK_EQ(ready_state_, kWaitingForCacheConsumer);
  if (IsDisposed()) {
    // Silently ignore if `this` is already Dispose()d, because `this` is no
    // longer used.
    return;
  }
  AdvanceReadyState(kReady);
}

void ClassicPendingScript::Trace(Visitor* visitor) const {
  visitor->Trace(classic_script_);
  ResourceClient::Trace(visitor);
  PendingScript::Trace(visitor);
}

ClassicScript* ClassicPendingScript::GetSource() const {
  CheckState();
  DCHECK(IsReady());

  if (ready_state_ == kErrorOccurred) {
    return nullptr;
  }

  TRACE_EVENT0("blink", "ClassicPendingScript::GetSource");
  if (!is_external_) {
    InlineScriptStreamer* streamer = nullptr;
    // We only create an inline cache handler for html-embedded scripts, not
    // for scripts produced by document.write, or not parser-inserted. This is
    // because we expect those to be too dynamic to benefit from caching.
    // TODO(leszeks): ScriptSourceLocationType was previously only used for UMA,
    // so it's a bit of a layer violation to use it for affecting cache
    // behaviour. We should decide whether it is ok for this parameter to be
    // used for behavioural changes (and if yes, update its documentation), or
    // otherwise trigger this behaviour differently.
    Document* element_document = OriginalElementDocument();
    if (source_location_type_ == ScriptSourceLocationType::kInline &&
        element_document && element_document->IsActive()) {
      streamer = GetInlineScriptStreamer(source_text_for_inline_script_,
                                         *element_document);
    }

    DCHECK(!GetResource());
    ScriptStreamer::RecordStreamingHistogram(
        GetSchedulingType(), streamer,
        ScriptStreamer::NotStreamingReason::kInlineScript);

    return ClassicScript::Create(
        source_text_for_inline_script_,
        ClassicScript::StripFragmentIdentifier(source_url_for_inline_script_),
        base_url_for_inline_script_, options_, source_location_type_,
        SanitizeScriptErrors::kDoNotSanitize, nullptr, StartingPosition(),
        streamer ? ScriptStreamer::NotStreamingReason::kInvalid
                 : ScriptStreamer::NotStreamingReason::kInlineScript,
        streamer);
  }

  DCHECK(classic_script_);

  // Record histograms here, because these uses `GetSchedulingType()` but it
  // might be unavailable yet at the time of `NotifyFinished()`.
  DCHECK(GetResource()->IsLoaded());
  RecordThirdPartyRequestWithCookieIfNeeded(GetResource()->GetResponse());

  ScriptStreamer::RecordStreamingHistogram(
      GetSchedulingType(), classic_script_->Streamer(),
      classic_script_->NotStreamingReason());

  TRACE_EVENT_WITH_FLOW1(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                         "ClassicPendingScript::GetSource", this,
                         TRACE_EVENT_FLAG_FLOW_IN, "not_streamed_reason",
                         classic_script_->NotStreamingReason());

  return classic_script_.Get();
}

// static
bool ClassicPendingScript::StateIsReady(ReadyState state) {
  return state >= kReady;
}

bool ClassicPendingScript::IsReady() const {
  CheckState();
  return StateIsReady(ready_state_);
}

void ClassicPendingScript::AdvanceReadyState(ReadyState new_ready_state) {
  // We will allow exactly these state transitions:
  //
  // kWaitingForResource -> kWaitingForCacheConsumer -> [kReady, kErrorOccurred]
  //                     |                           ^
  //                     `---------------------------'
  //
  switch (ready_state_) {
    case kWaitingForResource:
      CHECK(new_ready_state == kReady || new_ready_state == kErrorOccurred ||
            new_ready_state == kWaitingForCacheConsumer);
      break;
    case kWaitingForCacheConsumer:
      CHECK(new_ready_state == kReady);
      break;
    case kReady:
    case kErrorOccurred:
      NOTREACHED();
  }

  // All the ready states are marked not reachable above, so we can't have been
  // ready beforehand.
  DCHECK(!StateIsReady(ready_state_));

  ready_state_ = new_ready_state;

  // Did we transition into a 'ready' state?
  if (IsReady() && IsWatchingForLoad()) {
    PendingScriptFinished();
  }
}

bool ClassicPendingScript::WasCanceled() const {
  if (!is_external_) {
    return false;
  }
  return GetResource()->WasCanceled();
}

KURL ClassicPendingScript::UrlForTracing() const {
  if (!is_external_ || !GetResource()) {
    return NullURL();
  }

  return GetResource()->Url();
}

}  // namespace blink

"""

```