Response:
The user wants a summary of the functionality of the `script_loader.cc` file in the Chromium Blink engine. They also want specific examples of how it relates to JavaScript, HTML, and CSS, logical reasoning with input/output examples, common usage errors, and debugging steps. Finally, they want the functionality of the provided code snippet summarized.

Here's a breakdown of how to address each point:

1. **List the functionalities:**  I need to read through the provided code and identify the main tasks and responsibilities of the `ScriptLoader` class. This will involve looking at the methods and the types of operations they perform.

2. **Relationship with JavaScript, HTML, and CSS:**
    * **JavaScript:** The file name itself suggests a strong connection to script loading. I need to find evidence of how it handles JavaScript code, execution, and module loading.
    * **HTML:**  The code includes references to HTML elements (like `<script>`) and parsing. I need to explain how `ScriptLoader` interacts with the HTML structure.
    * **CSS:** While less direct, scripts can interact with CSS. I'll need to see if there's any indication of this, though it's likely less central to this particular file.

3. **Logical Reasoning (Input/Output):** I'll need to identify specific functions or code blocks that perform logical operations. For example, the `PrepareScript` method likely has input (script element attributes) and output (a `PendingScript` object or null). I'll create hypothetical scenarios to illustrate this.

4. **Common Usage Errors:** I should think about common mistakes developers make when using the `<script>` tag and how the `ScriptLoader` might be involved in handling or preventing these errors (e.g., incorrect `type` attribute, CSP violations).

5. **User Operations and Debugging:**  I need to trace the user's actions that would lead to the execution of code within `script_loader.cc`. This would likely start with the browser parsing HTML containing a `<script>` tag. I'll outline the steps a developer could take to debug issues related to script loading.

6. **Summarize Functionality of the Snippet:**  The provided code snippet focuses on the beginning of the `ScriptLoader::PrepareScript` method. I'll need to summarize what this specific part of the code does.

**Mental Sandbox:**

* I'll start by reading the `#include` directives to get a high-level understanding of the dependencies and the areas the `ScriptLoader` interacts with (DOM, networking, CSP, etc.).
* The `PrepareScript` method seems to be central. I'll focus on its steps and what triggers its execution.
* I'll look for conditional logic (if/else statements) to understand how different script attributes and document states influence the loading process.
* I'll consider the different types of scripts (classic, module, importmap, etc.) and how the `ScriptLoader` distinguishes and handles them.
* For debugging, I'll think about what logs or browser developer tools would be useful for diagnosing script loading problems.

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes.
2. JavaScript relation: Yes.
3. HTML relation: Yes.
4. CSS relation: Likely yes (indirectly), but needs careful examination.
5. Logical reasoning: Yes.
6. Input/output: Yes.
7. User errors: Yes.
8. User operations for debugging: Yes.
9. Summarize snippet functionality: Yes.
10. Part 1 of 2: Yes, I need to clearly state this.

Confidence Score: 4/5 (Slight uncertainty about the directness of the CSS relationship, but I can address the indirect interactions).

Strategizing complete. I will now generate the response based on these steps and considerations.
这是 `blink/renderer/core/script/script_loader.cc` 文件的功能列表：

**主要功能:**

1. **`<script>` 元素处理的核心逻辑:**  `ScriptLoader` 类负责处理 HTML 文档中 `<script>` 元素的加载、解析和执行。它管理与特定 `<script>` 标签相关联的脚本的整个生命周期。

2. **脚本准备 (PrepareScript):**  这是核心功能，负责在脚本可以执行之前进行各种检查和准备工作。这包括：
    * 检查脚本是否已经开始加载/执行。
    * 设置脚本的解析器文档状态和 `force_async` 标志。
    * 获取脚本的源代码。
    * 检查脚本是否连接到 DOM。
    * 确定脚本类型（经典、模块、importmap、speculationrules、webbundle）。
    * 应用内容安全策略 (CSP) 检查，防止执行被阻止的内联脚本。
    * 检查是否支持特定事件的脚本。
    * 解析 `crossorigin` 属性以确定 CORS 设置。
    * 获取 `integrity` 属性并进行完整性检查。
    * 解析 `referrerpolicy` 属性以确定引用策略。
    * 获取 `fetchpriority` 属性以确定获取优先级。
    * 设置解析器状态（是否由解析器插入）。
    * 创建 `PendingScript` 对象，用于管理脚本的加载和执行。

3. **脚本类型判断 (GetScriptTypeAtPrepare):**  根据 `<script>` 标签的 `type` 和 `language` 属性，判断脚本的类型，例如：
    * `classic` (传统的 JavaScript)。
    * `module` (ES 模块)。
    * `importmap` (导入映射)。
    * `speculationrules` (推测规则)。
    * `webbundle` (Web Bundle)。

4. **模块脚本凭据模式 (ModuleScriptCredentialsMode):**  根据 `crossorigin` 属性的值，确定模块脚本的凭据模式（`same-origin` 或 `include`）。

5. **处理 `<script>` 元素生命周期事件:**  响应 `<script>` 元素在 DOM 中的变化，例如：
    * `DidNotifySubtreeInsertionsToDocument`: 当脚本元素连接到文档时触发。
    * `ChildrenChanged`: 当脚本元素的子节点发生变化时触发。
    * `HandleSourceAttribute`: 当脚本元素的 `src` 属性被设置时触发。
    * `HandleAsyncAttribute`: 当脚本元素的 `async` 属性被添加时触发。
    * `Removed`: 当脚本元素从 DOM 中移除时触发。
    * `DocumentBaseURLChanged`: 当文档的 Base URL 发生变化时触发 (主要用于 `speculationrules` 类型的脚本)。

6. **与资源加载器交互:**  `ScriptLoader` 使用资源加载器来获取外部脚本文件。

7. **处理 Web Bundle:**  支持加载和处理 Web Bundle 格式的脚本。

8. **处理 Import Map:**  支持加载和解析 Import Map，用于模块解析。

9. **处理推测规则 (Speculation Rules):**  支持加载和解析推测规则，用于预加载等优化。

10. **应用各种浏览器优化策略 (Interventions):**  根据浏览器特性开关，应用一些优化策略，例如：
    * **ForceInOrderScript:** 强制脚本按顺序执行。
    * **DelayAsyncScriptExecution:** 延迟异步脚本的执行。
    * **LowPriorityScriptLoading:** 以较低的优先级加载某些脚本。
    * **SelectiveInOrderScript:**  有选择地强制某些跨域脚本按顺序执行。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** `ScriptLoader` 的核心任务就是加载和准备 JavaScript 代码的执行。它解析 `<script>` 标签，获取 JavaScript 源代码，并与 V8 JavaScript 引擎交互来执行代码。

    * **举例:** 当 HTML 解析器遇到 `<script src="my_script.js"></script>` 时，`ScriptLoader` 会根据 `src` 属性发起网络请求获取 `my_script.js` 的内容，然后将其交给 JavaScript 引擎执行。

* **HTML:** `ScriptLoader` 直接与 HTML 结构交互，特别是 `<script>` 元素。它读取 `<script>` 标签的各种属性（如 `src`、`type`、`async`、`defer`、`crossorigin`、`integrity` 等）来确定如何处理脚本。

    * **举例:**  `parser_inserted_` 标志用于区分通过 HTML 解析器插入的 `<script>` 标签和通过 JavaScript 动态创建的标签，这会影响脚本的加载和执行方式。

* **CSS:**  `ScriptLoader` 与 CSS 的关系较为间接，主要体现在 JavaScript 代码可能会操作 CSS 样式。`ScriptLoader` 本身不直接处理 CSS 文件的加载或解析。

    * **举例:**  一个 JavaScript 文件（通过 `ScriptLoader` 加载）可能会使用 DOM API (如 `document.querySelector` 和元素的 `style` 属性) 来修改页面元素的 CSS 样式。

**逻辑推理的举例说明:**

**假设输入:**

一个 HTML 文档包含以下 `<script>` 标签：

```html
<script type="module" src="my_module.js" crossorigin="anonymous"></script>
```

**ScriptLoader 的逻辑推理和输出:**

1. **脚本类型判断:** `GetScriptTypeAtPrepare` 方法会识别 `type="module"`，将脚本类型设置为 `ScriptTypeAtPrepare::kModule`。
2. **CORS 设置:** `ModuleScriptCredentialsMode` 方法会根据 `crossorigin="anonymous"` 将凭据模式设置为 `network::mojom::CredentialsMode::kSameOrigin`。这意味着在获取 `my_module.js` 时，不会发送 Cookie 或 HTTP 身份验证信息。
3. **资源请求:** `ScriptLoader` 会创建一个资源请求来获取 `my_module.js`，并在请求中设置相应的 CORS 模式。
4. **PendingScript 创建:**  会创建一个 `ModulePendingScript` 对象来管理模块脚本的加载和执行。

**用户或编程常见的使用错误:**

1. **错误的 `type` 属性:**  如果 `<script>` 标签的 `type` 属性设置错误或不支持的值，`GetScriptTypeAtPrepare` 可能会返回 `ScriptTypeAtPrepare::kInvalid`，导致脚本不被执行。

    * **举例:** `<script type="text/vbscript">alert("Hello");</script>`  (VBScript 不是标准的 Web 脚本类型)。

2. **CSP 阻止内联脚本:**  如果网站设置了严格的内容安全策略，禁止执行内联脚本，那么 `PrepareScript` 方法中的 CSP 检查会阻止内联脚本的执行。

    * **举例:**  如果 CSP 头包含 `script-src 'self'`, 那么以下内联脚本会被阻止：
      ```html
      <script>alert("Hello");</script>
      ```

3. **`nomodule` 属性使用不当:**  `nomodule` 属性用于向不支持 ES 模块的旧浏览器提供传统脚本。如果同时加载了模块脚本和带有 `nomodule` 属性的传统脚本，可能会导致重复执行或冲突。

4. **`integrity` 属性值错误:**  如果 `<script>` 标签的 `integrity` 属性值与下载的脚本内容不匹配，Subresource Integrity (SRI) 检查会失败，阻止脚本执行。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 并访问网页，或者点击了一个链接。**
2. **浏览器开始下载 HTML 文档。**
3. **HTML 解析器开始解析下载的 HTML 内容。**
4. **当解析器遇到 `<script>` 标签时，会创建对应的 `HTMLScriptElement` 对象。**
5. **`HTMLScriptElement` 的构造函数会创建 `ScriptLoader` 对象。**
6. **根据 `<script>` 标签的属性和文档状态，以下方法可能会被调用：**
    * 如果是解析器插入的脚本，可能会在解析过程中调用 `PrepareScript`。
    * 如果是通过 JavaScript 动态创建并添加到文档的脚本，`DidNotifySubtreeInsertionsToDocument` 或 `HandleSourceAttribute` 可能会被调用，进而调用 `PrepareScript`。
    * 如果脚本有 `src` 属性，会触发资源加载流程。
7. **在 `PrepareScript` 方法中，会进行各种检查和准备工作，决定脚本是否可以执行。**
8. **如果脚本需要从网络加载，资源加载完成后会通知 `ScriptLoader`。**
9. **最终，脚本会被编译和执行。**

**调试线索:**

* **浏览器开发者工具的 "Network" 标签:**  查看脚本文件的加载状态、HTTP 头信息（如 CSP 头）、CORS 相关信息等。
* **浏览器开发者工具的 "Sources" 标签:**  查看脚本源代码，设置断点，单步调试脚本执行过程。
* **浏览器开发者工具的 "Console" 标签:**  查看是否有与脚本加载或执行相关的错误或警告信息，例如 CSP 阻止、SRI 校验失败等。
* **在 Blink 渲染引擎的调试日志中搜索与 `ScriptLoader` 相关的日志信息。**

**这是第1部分，共2部分，请归纳一下它的功能**

总而言之，`blink/renderer/core/script/script_loader.cc` 文件中的 `ScriptLoader` 类的主要功能是**负责 `<script>` 元素的加载、准备和初步处理，为后续的脚本执行做好准备。** 它充当 HTML 解析器和 JavaScript 引擎之间的桥梁，确保脚本按照规范和安全策略被正确加载和处理。 这部分代码的核心在于 `PrepareScript` 方法，它执行关键的检查和设置，为不同类型的脚本（经典、模块等）配置正确的加载和执行环境。 它还处理与资源加载、CORS、CSP、SRI 等相关的逻辑。

Prompt: 
```
这是目录为blink/renderer/core/script/script_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2008 Nikolas Zimmermann <zimmermann@kde.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/script/script_loader.h"

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "services/network/public/mojom/fetch_api.mojom-shared.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/sanitize_script_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/attribution_src_loader.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/fetch_priority_attribute.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_fetch_request.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/loader/subresource_integrity_helper.h"
#include "third_party/blink/renderer/core/loader/url_matcher.h"
#include "third_party/blink/renderer/core/loader/web_bundle/script_web_bundle.h"
#include "third_party/blink/renderer/core/script/classic_pending_script.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/script/import_map.h"
#include "third_party/blink/renderer/core/script/js_module_script.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/script/module_pending_script.h"
#include "third_party/blink/renderer/core/script/pending_import_map.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/script/script_element_base.h"
#include "third_party/blink/renderer/core/script/script_runner.h"
#include "third_party/blink/renderer/core/script_type_names.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rule_set.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rules_metrics.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_types_util.h"
#include "third_party/blink/renderer/platform/bindings/parkable_string.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"

namespace blink {

namespace {

scheduler::TaskAttributionInfo* GetRunningTask(ScriptState* script_state) {
  auto* tracker =
      scheduler::TaskAttributionTracker::From(script_state->GetIsolate());
  if (!script_state || !script_state->World().IsMainWorld() || !tracker) {
    return nullptr;
  }
  return tracker->RunningTask();
}

}  // namespace

ScriptLoader::ScriptLoader(ScriptElementBase* element,
                           const CreateElementFlags flags)
    : element_(element) {
  // <spec href="https://html.spec.whatwg.org/C/#script-processing-model">
  // The cloning steps for a script element el being cloned to a copy copy are
  // to set copy's already started to el's already started.</spec>
  //
  // TODO(hiroshige): Cloning is implemented together with
  // {HTML,SVG}ScriptElement::cloneElementWithoutAttributesAndChildren().
  // Clean up these later.
  if (flags.WasAlreadyStarted()) {
    already_started_ = true;
  }

  if (flags.IsCreatedByParser()) {
    // <spec href="https://html.spec.whatwg.org/C/#parser-inserted">... script
    // elements with non-null parser documents are known as
    // parser-inserted.</spec>
    //
    // For more information on why this is not implemented in terms of a
    // non-null parser document, see the documentation in the header file.
    parser_inserted_ = true;

    // <spec href="https://html.spec.whatwg.org/C/#parser-document">... It is
    // set by the HTML parser and the XML parser on script elements they insert,
    // ...</spec>
    parser_document_ = flags.ParserDocument();

    // <spec href="https://html.spec.whatwg.org/C/#script-force-async">... It is
    // set to false by the HTML parser and the XML parser on script elements
    // they insert, ...</spec>
    force_async_ = false;
  }
}

ScriptLoader::~ScriptLoader() {}

void ScriptLoader::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  visitor->Trace(parser_document_);
  visitor->Trace(prepared_pending_script_);
  visitor->Trace(resource_keep_alive_);
  visitor->Trace(script_web_bundle_);
  visitor->Trace(speculation_rule_set_);
  ResourceFinishObserver::Trace(visitor);
}

// <specdef
// href="https://html.spec.whatwg.org/C/#script-processing-model">
//
// <spec>When a script element el that is not parser-inserted experiences one of
// the events listed in the following list, the user agent must immediately
// prepare the script element el:</spec>
//
// The following three `PrepareScript()` are for non-parser-inserted scripts and
// thus
// - Should deny ParserBlockingInline scripts.
// - Should return nullptr, i.e. there should no PendingScript to be controlled
//   by parsers.
// - TextPosition is not given.

// <spec step="A">The script element becomes connected.</spec>
void ScriptLoader::DidNotifySubtreeInsertionsToDocument() {
  if (already_started_ &&
      GetScriptTypeAtPrepare(element_->TypeAttributeValue(),
                             element_->LanguageAttributeValue()) ==
          ScriptTypeAtPrepare::kSpeculationRules) {
    // See https://crbug.com/359355331, where this was requested.
    auto* message = MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kJavaScript, ConsoleMessage::Level::kWarning,
        "A speculation rule set was inserted into the document but will be "
        "ignored. This might happen, for example, if it was previously "
        "inserted into another document, or if it was created using the "
        "innerHTML setter.");
    element_->GetDocument().AddConsoleMessage(message,
                                              /*discard_duplicates=*/true);
  }

  if (!parser_inserted_) {
    PendingScript* pending_script = PrepareScript(
        ParserBlockingInlineOption::kDeny, TextPosition::MinimumPosition());
    DCHECK(!pending_script);
  }
}

// <spec step="B">The script element is connected and a node or document
// fragment is inserted into the script element, after any script elements
// inserted at that time.</spec>
void ScriptLoader::ChildrenChanged(
    const ContainerNode::ChildrenChange& change) {
  if (script_type_ == ScriptTypeAtPrepare::kSpeculationRules &&
      (change.type == ContainerNode::ChildrenChangeType::kTextChanged ||
       change.type == ContainerNode::ChildrenChangeType::kNonElementInserted ||
       change.type == ContainerNode::ChildrenChangeType::kNonElementRemoved) &&
      change.sibling_changed->IsCharacterDataNode()) {
    // See https://crbug.com/328100599.
    auto* message = MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kJavaScript, ConsoleMessage::Level::kWarning,
        "Inline speculation rules cannot currently be modified after they are "
        "processed. Instead, a new <script> element must be inserted.");
    element_->GetDocument().AddConsoleMessage(message,
                                              /*discard_duplicates=*/true);
  }

  if (change.IsChildInsertion() && !parser_inserted_ &&
      element_->IsConnected()) {
    PendingScript* pending_script = PrepareScript(
        ParserBlockingInlineOption::kDeny, TextPosition::MinimumPosition());
    DCHECK(!pending_script);
  }
}

// <spec step="C">The script element is connected and has a src attribute set
// where previously the element had no such attribute.</spec>
void ScriptLoader::HandleSourceAttribute(const String& source_url) {
  if (!parser_inserted_ && element_->IsConnected() && !source_url.empty()) {
    PendingScript* pending_script = PrepareScript(
        ParserBlockingInlineOption::kDeny, TextPosition::MinimumPosition());
    DCHECK(!pending_script);
  }
}

void ScriptLoader::HandleAsyncAttribute() {
  // <spec>When an async attribute is added to a script element el, the user
  // agent must set el's force async to false.</spec>
  //
  // <spec href="https://html.spec.whatwg.org/C/#the-script-element"
  // step="1">Set this's force async to false.</spec>
  force_async_ = false;
}

void ScriptLoader::Removed() {
  // Release webbundle resources which are associated to this loader explicitly
  // without waiting for blink-GC.
  if (ScriptWebBundle* bundle = std::exchange(script_web_bundle_, nullptr)) {
    bundle->WillReleaseBundleLoaderAndUnregister();
  }

  RemoveSpeculationRuleSet();
}

void ScriptLoader::DocumentBaseURLChanged() {
  if (GetScriptType() != ScriptTypeAtPrepare::kSpeculationRules) {
    return;
  }
  // We reparse the original source text and generate a new SpeculationRuleSet
  // with the new base URL. Note that any text changes since the first parse
  // will be ignored.
  if (SpeculationRuleSet* rule_set = RemoveSpeculationRuleSet()) {
    AddSpeculationRuleSet(rule_set->source());
  }
}

namespace {

// <specdef href="https://html.spec.whatwg.org/C/#prepare-the-script-element">
bool IsValidClassicScriptTypeAndLanguage(const String& type,
                                         const String& language) {
  if (type.IsNull()) {
    // <spec step="8.B">el has no type attribute but it has a language attribute
    // and that attribute's value is the empty string; or</spec>
    //
    // <spec step="8.C">el has neither a type attribute nor a language
    // attribute</spec>
    if (language.empty()) {
      return true;
    }

    // <spec step="8">... Otherwise, el has a non-empty language attribute; let
    // the script block's type string be the concatenation of "text/" and the
    // value of el's language attribute.</spec>
    if (MIMETypeRegistry::IsSupportedJavaScriptMIMEType("text/" + language)) {
      return true;
    }
  } else if (type.empty()) {
    // <spec step="8.A">el has a type attribute whose value is the empty
    // string;</spec>
    return true;
  } else {
    // <spec step="8">... Otherwise, if el has a type attribute, then let the
    // script block's type string be the value of that attribute with leading
    // and trailing ASCII whitespace stripped. ...</spec>
    //
    // <spec step="9">If the script block's type string is a JavaScript MIME
    // type essence match, then set el's type to "classic".</spec>
    if (MIMETypeRegistry::IsSupportedJavaScriptMIMEType(
            type.StripWhiteSpace())) {
      return true;
    }
  }

  return false;
}

bool IsSameSite(const KURL& url, const Document& element_document) {
  scoped_refptr<const SecurityOrigin> url_origin = SecurityOrigin::Create(url);
  return url_origin->IsSameSiteWith(
      element_document.GetExecutionContext()->GetSecurityOrigin());
}

bool IsDocumentReloadedOrFormSubmitted(const Document& element_document) {
  Document& top_document = element_document.TopDocument();
  return top_document.Loader() &&
         top_document.Loader()->IsReloadedOrFormSubmitted();
}

// Common eligibility conditions for the interventions below.
bool IsEligibleCommon(const Document& element_document) {
  // As some interventions need parser support (e.g. defer), interventions are
  // enabled only for HTMLDocuments, because XMLDocumentParser lacks support for
  // e.g. defer scripts. Thus the parser document (==element document) is
  // checked here.
  if (!IsA<HTMLDocument>(element_document)) {
    return false;
  }

  // Do not enable interventions on reload.
  // No specific reason to use element document here instead of context
  // document though.
  if (IsDocumentReloadedOrFormSubmitted(element_document)) {
    return false;
  }

  return true;
}

// [Intervention, ForceInOrderScript, crbug.com/1344772]
bool IsEligibleForForceInOrder(const Document& element_document) {
  return base::FeatureList::IsEnabled(features::kForceInOrderScript) &&
         IsEligibleCommon(element_document);
}

// [Intervention, DelayAsyncScriptExecution, crbug.com/1340837]
bool IsEligibleForDelay(const Resource& resource,
                        const Document& element_document,
                        const ScriptElementBase& element) {
  if (!base::FeatureList::IsEnabled(features::kDelayAsyncScriptExecution)) {
    return false;
  }

  if (!IsEligibleCommon(element_document)) {
    return false;
  }

  if (element.IsPotentiallyRenderBlocking()) {
    return false;
  }

  // We don't delay async scripts that have matched a resource in the preload
  // cache, because we're using <link rel=preload> as a signal that the script
  // is higher-than-usual priority, and therefore should be executed earlier
  // rather than later.
  if (resource.IsLinkPreload()) {
    return false;
  }

  // Most LCP elements are provided by the main frame, and delaying subframe's
  // resources seems not to improve LCP.
  const bool main_frame_only =
      features::kDelayAsyncScriptExecutionMainFrameOnlyParam.Get();
  if (main_frame_only && !element_document.IsInOutermostMainFrame()) {
    return false;
  }

  const base::TimeDelta feature_limit =
      features::kDelayAsyncScriptExecutionFeatureLimitParam.Get();
  if (!feature_limit.is_zero() &&
      element_document.GetStartTime().Elapsed() > feature_limit) {
    return false;
  }

  bool is_ad_resource = resource.GetResourceRequest().IsAdResource();
  const features::AsyncScriptExperimentalSchedulingTarget target =
      features::kDelayAsyncScriptExecutionTargetParam.Get();
  switch (target) {
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

  const bool opt_out_low =
      features::kDelayAsyncScriptExecutionOptOutLowFetchPriorityHintParam.Get();
  const bool opt_out_auto =
      features::kDelayAsyncScriptExecutionOptOutAutoFetchPriorityHintParam
          .Get();
  const bool opt_out_high =
      features::kDelayAsyncScriptExecutionOptOutHighFetchPriorityHintParam
          .Get();

  switch (resource.GetResourceRequest().GetFetchPriorityHint()) {
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

  const features::DelayAsyncScriptTarget delay_async_script_target =
      features::kDelayAsyncScriptTargetParam.Get();
  switch (delay_async_script_target) {
    case features::DelayAsyncScriptTarget::kAll:
      return true;
    case features::DelayAsyncScriptTarget::kCrossSiteOnly:
      return !IsSameSite(resource.Url(), element_document);
    case features::DelayAsyncScriptTarget::kCrossSiteWithAllowList:
    case features::DelayAsyncScriptTarget::kCrossSiteWithAllowListReportOnly:
      if (IsSameSite(resource.Url(), element_document)) {
        return false;
      }
      DEFINE_STATIC_LOCAL(
          UrlMatcher, url_matcher,
          (UrlMatcher(GetFieldTrialParamByFeatureAsString(
              features::kDelayAsyncScriptExecution, "delay_async_exec_allow_list", ""))));
      return url_matcher.Match(resource.Url());
  }
}

// [Intervention, LowPriorityScriptLoading, crbug.com/1365763]
bool IsEligibleForLowPriorityScriptLoading(const Document& element_document,
                                           const ScriptElementBase& element,
                                           const KURL& url) {
  static const bool enabled =
      base::FeatureList::IsEnabled(features::kLowPriorityScriptLoading);
  if (!enabled) {
    return false;
  }

  if (!IsEligibleCommon(element_document)) {
    return false;
  }

  if (element.IsPotentiallyRenderBlocking()) {
    return false;
  }

  // Most LCP elements are provided by the main frame, and delaying subframe's
  // resources seems not to improve LCP.
  const bool main_frame_only =
      features::kLowPriorityScriptLoadingMainFrameOnlyParam.Get();
  if (main_frame_only && !element_document.IsInOutermostMainFrame()) {
    return false;
  }

  const base::TimeDelta feature_limit =
      features::kLowPriorityScriptLoadingFeatureLimitParam.Get();
  if (!feature_limit.is_zero() &&
      element_document.GetStartTime().Elapsed() > feature_limit) {
    return false;
  }

  const bool cross_site_only =
      features::kLowPriorityScriptLoadingCrossSiteOnlyParam.Get();
  if (cross_site_only && IsSameSite(url, element_document)) {
    return false;
  }

  DEFINE_STATIC_LOCAL(
      UrlMatcher, deny_list,
      (UrlMatcher(features::kLowPriorityScriptLoadingDenyListParam.Get())));
  if (deny_list.Match(url)) {
    return false;
  }

  return true;
}

// [Intervention, SelectiveInOrderScript, crbug.com/1356396]
bool IsEligibleForSelectiveInOrder(const Resource& resource,
                                   const Document& element_document) {
  // The feature flag is checked separately.

  if (!IsEligibleCommon(element_document)) {
    return false;
  }

  // Cross-site scripts only: 1st party scripts are out of scope of the
  // intervention.
  if (IsSameSite(resource.Url(), element_document)) {
    return false;
  }

  // Only script request URLs in the allowlist.
  DEFINE_STATIC_LOCAL(
      UrlMatcher, url_matcher,
      (UrlMatcher(features::kSelectiveInOrderScriptAllowList.Get())));
  return url_matcher.Match(resource.Url());
}

ScriptRunner::DelayReasons DetermineDelayReasonsToWait(
    ScriptRunner* script_runner,
    bool is_eligible_for_delay) {
  using DelayReason = ScriptRunner::DelayReason;
  using DelayReasons = ScriptRunner::DelayReasons;

  DelayReasons reasons = static_cast<DelayReasons>(DelayReason::kLoad);

  if (is_eligible_for_delay &&
      script_runner->IsActive(DelayReason::kMilestone)) {
    reasons |= static_cast<DelayReasons>(DelayReason::kMilestone);
  }

  return reasons;
}

}  // namespace

ScriptLoader::ScriptTypeAtPrepare ScriptLoader::GetScriptTypeAtPrepare(
    const String& type,
    const String& language) {
  if (IsValidClassicScriptTypeAndLanguage(type, language)) {
    // <spec step="9">If the script block's type string is a JavaScript MIME
    // type essence match, then set el's type to "classic".</spec>
    return ScriptTypeAtPrepare::kClassic;
  }

  if (EqualIgnoringASCIICase(type, script_type_names::kModule)) {
    // <spec step="10">Otherwise, if the script block's type string is an ASCII
    // case-insensitive match for the string "module", then set el's type to
    // "module".</spec>
    return ScriptTypeAtPrepare::kModule;
  }

  if (EqualIgnoringASCIICase(type, script_type_names::kImportmap)) {
    return ScriptTypeAtPrepare::kImportMap;
  }

  if (EqualIgnoringASCIICase(type, script_type_names::kSpeculationrules)) {
    return ScriptTypeAtPrepare::kSpeculationRules;
  }
  if (EqualIgnoringASCIICase(type, script_type_names::kWebbundle)) {
    return ScriptTypeAtPrepare::kWebBundle;
  }

  // <spec step="11">Otherwise, return. (No script is executed, and el's type is
  // left as null.)</spec>
  return ScriptTypeAtPrepare::kInvalid;
}

bool ScriptLoader::BlockForNoModule(ScriptTypeAtPrepare script_type,
                                    bool nomodule) {
  return nomodule && script_type == ScriptTypeAtPrepare::kClassic;
}

// Corresponds to
// https://html.spec.whatwg.org/C/#module-script-credentials-mode
// which is a translation of the CORS settings attribute in the context of
// module scripts. This is used in:
//   - Step 17 of
//     https://html.spec.whatwg.org/C/#prepare-the-script-element
//   - Step 6 of obtaining a preloaded module script
//     https://html.spec.whatwg.org/C/#link-type-modulepreload.
network::mojom::CredentialsMode ScriptLoader::ModuleScriptCredentialsMode(
    CrossOriginAttributeValue cross_origin) {
  switch (cross_origin) {
    case kCrossOriginAttributeNotSet:
    case kCrossOriginAttributeAnonymous:
      return network::mojom::CredentialsMode::kSameOrigin;
    case kCrossOriginAttributeUseCredentials:
      return network::mojom::CredentialsMode::kInclude;
  }
  NOTREACHED();
}

// <specdef href="https://html.spec.whatwg.org/C/#prepare-the-script-element">
PendingScript* ScriptLoader::PrepareScript(
    ParserBlockingInlineOption parser_blocking_inline_option,
    const TextPosition& script_start_position) {
  // <spec step="1">If el's already started is true, then return.</spec>
  if (already_started_) {
    return nullptr;
  }

  // <spec step="2">Let parser document be el's parser document.</spec>
  //
  // Here and below we manipulate `parser_inserted_` flag instead of
  // `parser_document_`. See the comment at the `parser_document_` declaration.
  bool was_parser_inserted = parser_inserted_;

  // <spec step="3">Set el's parser document to null.</spec>
  parser_inserted_ = false;

  // <spec step="4">If parser document is non-null and el does not have an async
  // attribute, then set el's force async to true.</spec>
  if (was_parser_inserted && !element_->AsyncAttributeValue()) {
    force_async_ = true;
  }

  // <spec step="5">Let source text be el's child text content.</spec>
  //
  // Trusted Types additionally requires:
  // https://w3c.github.io/trusted-types/dist/spec/#slot-value-verification
  // - Step 4: Execute the Prepare the script URL and text algorithm upon the
  //     script element. If that algorithm threw an error, then return. The
  //     script is not executed.
  // - Step 5: Let source text be the element’s [[ScriptText]] internal slot
  //     value.
  const String source_text = GetScriptText();

  // <spec step="6">If el has no src attribute, and source text is the empty
  // string, then return.</spec>
  if (!element_->HasSourceAttribute() && source_text.empty()) {
    return nullptr;
  }

  // <spec step="7">If el is not connected, then return.</spec>
  if (!element_->IsConnected()) {
    return nullptr;
  }

  Document& element_document = element_->GetDocument();
  LocalDOMWindow* context_window = element_document.domWindow();

  // Steps 8-11.
  script_type_ = GetScriptTypeAtPrepare(element_->TypeAttributeValue(),
                                        element_->LanguageAttributeValue());

  switch (GetScriptType()) {
    case ScriptTypeAtPrepare::kInvalid:
      return nullptr;

    case ScriptTypeAtPrepare::kSpeculationRules:
    case ScriptTypeAtPrepare::kWebBundle:
    case ScriptTypeAtPrepare::kClassic:
    case ScriptTypeAtPrepare::kModule:
    case ScriptTypeAtPrepare::kImportMap:
      break;
  }

  // <spec step="12">If parser document is non-null, then set el's parser
  // document back to parser document and set el's force async to false.</spec>
  if (was_parser_inserted) {
    parser_inserted_ = true;
    force_async_ = false;
  }

  // <spec step="13">Set el's already started to true.</spec>
  already_started_ = true;

  // <spec step="15">If parser document is non-null, and parser document is not
  // equal to el's preparation-time document, then return.</spec>
  if (parser_inserted_ && parser_document_ != &element_->GetDocument()) {
    return nullptr;
  }

  // <spec step="16">If scripting is disabled for el, then return.</spec>
  //
  // <spec href="https://html.spec.whatwg.org/C/#concept-n-noscript">Scripting
  // is disabled for a node when scripting is not enabled, i.e., when its node
  // document's browsing context is null or when scripting is disabled for its
  // relevant settings object.</spec>
  if (!context_window) {
    return nullptr;
  }
  if (!context_window->CanExecuteScripts(kAboutToExecuteScript)) {
    return nullptr;
  }

  // <spec step="17">If el has a nomodule content attribute and its type is
  // "classic", then return.</spec>
  if (BlockForNoModule(GetScriptType(), element_->NomoduleAttributeValue())) {
    return nullptr;
  }

  // TODO(csharrison): This logic only works if the tokenizer/parser was not
  // blocked waiting for scripts when the element was inserted. This usually
  // fails for instance, on second document.write if a script writes twice
  // in a row. To fix this, the parser might have to keep track of raw
  // string position.
  //
  // Also PendingScript's contructor has the same code.
  const bool is_in_document_write = element_document.IsInDocumentWrite();

  // Reset line numbering for nested writes.
  TextPosition position = is_in_document_write ? TextPosition::MinimumPosition()
                                               : script_start_position;

  // <spec step="18">If el does not have a src content attribute, and the Should
  // element's inline behavior be blocked by Content Security Policy? algorithm
  // returns "Blocked" when given el, "script", and source text, then return.
  // [CSP]</spec>
  if (!element_->HasSourceAttribute() &&
      !element_->AllowInlineScriptForCSP(element_->GetNonceForElement(),
                                         position.line_, source_text)) {
    return nullptr;
  }

  // Step 19.
  if (!IsScriptForEventSupported()) {
    return nullptr;
  }

  // 14. is handled below.

  // <spec step="21">Let classic script CORS setting be the current state of
  // el's crossorigin content attribute.</spec>
  CrossOriginAttributeValue cross_origin =
      GetCrossOriginAttributeValue(element_->CrossOriginAttributeValue());

  // <spec step="22">Let module script credentials mode be the CORS settings
  // attribute credentials mode for el's crossorigin content attribute.</spec>
  network::mojom::CredentialsMode credentials_mode =
      ModuleScriptCredentialsMode(cross_origin);

  // <spec step="23">Let cryptographic nonce be el's [[CryptographicNonce]]
  // internal slot's value.</spec>
  String nonce = element_->GetNonceForElement();

  // <spec step="24">If el has an integrity attribute, then let integrity
  // metadata be that attribute's value. Otherwise, let integrity metadata be
  // the empty string.</spec>
  String integrity_attr = element_->IntegrityAttributeValue();
  IntegrityMetadataSet integrity_metadata;
  if (!integrity_attr.empty()) {
    SubresourceIntegrity::IntegrityFeatures integrity_features =
        SubresourceIntegrityHelper::GetFeatures(
            element_->GetExecutionContext());
    SubresourceIntegrity::ReportInfo report_info;
    SubresourceIntegrity::ParseIntegrityAttribute(
        integrity_attr, integrity_features, integrity_metadata, &report_info);
    SubresourceIntegrityHelper::DoReport(*element_->GetExecutionContext(),
                                         report_info);
  }

  // <spec step="25">Let referrer policy be the current state of el's
  // referrerpolicy content attribute.</spec>
  String referrerpolicy_attr = element_->ReferrerPolicyAttributeValue();
  network::mojom::ReferrerPolicy referrer_policy =
      network::mojom::ReferrerPolicy::kDefault;
  if (!referrerpolicy_attr.empty()) {
    SecurityPolicy::ReferrerPolicyFromString(
        referrerpolicy_attr, kDoNotSupportReferrerPolicyLegacyKeywords,
        &referrer_policy);
  }

  // <spec href="https://wicg.github.io/priority-hints/#script" step="8">... Let
  // fetchpriority be the current state of the element’s fetchpriority
  // attribute.</spec>
  String fetch_priority_attr = element_->FetchPriorityAttributeValue();
  mojom::blink::FetchPriorityHint fetch_priority_hint =
      GetFetchPriorityAttributeValue(fetch_priority_attr);

  // <spec step="28">Let parser metadata be "parser-inserted" if el is
  // ...</spec>
  ParserDisposition parser_state =
      IsParserInserted() ? kParserInserted : kNotParserInserted;

  if (GetScriptType() == ScriptLoader::ScriptTypeAtPrepare::kModule) {
    UseCounter::Count(*context_window, WebFeature::kPrepareModuleScript);
  } else if (GetScriptType() == ScriptTypeAtPrepare::kSpeculationRules) {
    UseCounter::Count(*context_window, WebFeature::kSpeculationRules);
  }

  DCHECK(!prepared_pending_script_);

  bool potentially_render_blocking = element_->IsPotentiallyRenderBlocking();
  RenderBlockingBehavior render_blocking_behavior =
      potentially_render_blocking ? RenderBlockingBehavior::kBlocking
                                  : RenderBlockingBehavior::kNonBlocking;

  // <spec step="29">Let options be a script fetch options whose cryptographic
  // nonce is cryptographic nonce, integrity metadata is integrity metadata,
  // parser metadata is parser metadata, credentials mode is module script
  // credentials mode, and referrer policy is referrer policy.</spec>
  ScriptFetchOptions options(nonce, integrity_metadata, integrity_attr,
                             parser_state, credentials_mode, referrer_policy,
                             fetch_priority_hint, render_blocking_behavior,
                             RejectCoepUnsafeNone(false));

  // <spec step="30">Let settings object be el's node document's relevant
  // settings object.</spec>
  //
  // In some cases (mainly for classic scripts) |element_document| is used as
  // the "settings object", while in other cases (mainly for module scripts)
  // |content_document| is used.
  // TODO(hiroshige): Use a consistent Document everywhere.
  auto* fetch_client_settings_object_fetcher = context_window->Fetcher();
  ScriptState* script_state =
      ToScriptStateForMainWorld(context_window->GetFrame());

  bool is_eligible_for_delay = false;
  bool is_eligible_for_selective_in_order = false;

  // <spec step="31">If el has a src content attribute, then:</spec>
  if (element_->HasSourceAttribute()) {
    // <spec step="31.1">If el's t
"""


```