Response:
Let's break down the thought process for analyzing the C++ code and answering the request.

1. **Understand the Goal:** The primary goal is to understand the functionality of `RenderBlockingResourceManager.cc` in the Blink rendering engine, particularly its relationship with JavaScript, HTML, and CSS, along with potential user errors and debugging strategies.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for key terms and patterns. Words like "render blocking," "font," "preload," "stylesheet," "script," "timer," "document," and "element" immediately stand out as important concepts. The presence of `base::FeatureList` suggests feature flags are involved.

3. **Identify Core Responsibilities:** Based on the keywords, it seems the class manages resources that can *block rendering*. This implies a mechanism for tracking these resources and determining when rendering can proceed. The filename itself, "render_blocking_resource_manager," reinforces this.

4. **Analyze Member Variables:** Examine the class's member variables.
    * `document_`:  Indicates the manager operates in the context of a specific HTML document.
    * `pending_font_preloads_`:  Suggests management of font preloading.
    * `imperative_font_loading_count_`:  Implies tracking of fonts loaded via JavaScript.
    * `font_preload_max_blocking_timer_`, `font_preload_max_fcp_delay_timer_`:  Indicates timeouts related to font loading, likely to prevent indefinite blocking.
    * `element_render_blocking_links_`:  Points to a feature related to blocking rendering based on the presence of specific elements (via `<link rel="expect">`).
    * `pending_stylesheet_owner_nodes_`, `pending_scripts_`:  Confirms management of stylesheets and scripts as render-blocking resources.

5. **Analyze Key Methods:**  Focus on the public and important private methods.
    * `AddPendingFontPreload`, `AddImperativeFontLoading`, `RemovePendingFontPreload`, `RemoveImperativeFontLoading`: Clearly related to managing render-blocking fonts.
    * `EnsureStartFontPreloadMaxBlockingTimer`, `FontPreloadingTimerFired`:  Implement the timeout mechanism for font preloads.
    * `AddPendingParsingElementLink`, `RemovePendingParsingElement`, `RemovePendingParsingElementLink`, `ClearPendingParsingElements`: Implement the `<link rel="expect">` functionality.
    * `AddPendingStylesheet`, `RemovePendingStylesheet`, `AddPendingScript`, `RemovePendingScript`:  Manage stylesheets and scripts as render-blocking.
    * `WillInsertDocumentBody`, `RenderBlockingResourceUnblocked`: Lifecycle hooks that trigger or update rendering status.

6. **Connect to HTML, CSS, and JavaScript:**
    * **HTML:** The `<link rel="preload">` tag (for fonts) and `<link rel="expect">` tag are explicitly mentioned. The overall process of parsing HTML and encountering these tags is relevant.
    * **CSS:** Font preloads are directly tied to CSS. The `<link>` tag for CSS stylesheets is also managed.
    * **JavaScript:**  `AddImperativeFontLoading` implies that JavaScript can trigger font loads that block rendering. The `<script>` tag is also directly managed.

7. **Infer Logic and Scenarios:**
    * **Font Preloads:** If a font preload takes too long, the timer will fire, and rendering will proceed, potentially with a fallback font. This prevents indefinite blocking.
    * **`<link rel="expect">`:**  Rendering is blocked until the target elements with matching IDs are found in the DOM. If they are not found, a console warning is issued.
    * **Stylesheets and Scripts:** Rendering is generally blocked until these resources are loaded and processed.

8. **Consider User Errors and Debugging:**
    * **Incorrect `rel="preload"`:**  If `as="font"` is missing or incorrect, the font might not be treated as a render-blocking resource as intended.
    * **Incorrect `rel="expect"`:**  Typos in the `href` or target element IDs will prevent the condition from being met, potentially leading to unexpected blocking and console warnings.
    * **Slow Network:**  Long download times for fonts, stylesheets, or scripts will naturally increase render-blocking time.
    * **Debugging:**  Looking at the "Network" tab in DevTools to check resource loading times, examining the "Console" for warnings related to `<link rel="expect">`, and potentially using breakpoints in the Blink codebase could be useful.

9. **Structure the Answer:** Organize the findings into logical sections: Functionality, Relationship to HTML/CSS/JS, Logic/Assumptions, User Errors, and Debugging. Use clear examples to illustrate the concepts.

10. **Refine and Verify:** Review the answer for clarity, accuracy, and completeness. Ensure the examples are relevant and easy to understand. Double-check the connection between the code and the explanations. For example, the timers are designed to prevent indefinite blocking, and the `RenderBlockingResourceUnblocked` method is central to signaling that a resource is no longer blocking.

This systematic approach, moving from a high-level understanding to detailed code analysis and then connecting the findings to practical scenarios, helps in generating a comprehensive and informative answer.
这个 C++ 源代码文件 `render_blocking_resource_manager.cc` 属于 Chromium Blink 引擎，其主要功能是**管理可能阻止页面首次渲染的资源**，从而优化用户体验，避免页面出现长时间白屏。

以下是它的具体功能以及与 JavaScript, HTML, CSS 的关系：

**主要功能:**

1. **管理字体预加载 (Font Preloading):**
   - 追踪通过 `<link rel="preload" as="font">` 预加载的字体资源。
   - 设置超时机制 (`kMaxRenderingDelayForFontPreloads`)，如果字体预加载时间过长，即使字体尚未加载完成，也会取消阻塞渲染，避免长时间白屏。
   - 记录字体预加载超时事件的统计信息。
   - 处理通过 JavaScript 动态加载的字体 (`FontFace` API)。

2. **管理 `<link rel="expect">` 元素:**
   - 追踪文档中声明了 `<link rel="expect">` 的元素。这个特性允许页面指定某些元素在渲染前必须存在。
   - 当解析到 `<link rel="expect">` 时，会记录其 `href` 属性指向的元素 ID。
   - 当具有对应 ID 的元素被解析到时，会解除对渲染的阻塞。
   - 如果在页面加载完成前，预期的元素没有被解析到，会发出控制台警告。

3. **管理样式表 (Stylesheets):**
   - 追踪尚未加载完成的样式表资源。直到所有关键的样式表加载完成，渲染才会继续。

4. **管理脚本 (Scripts):**
   - 追踪尚未执行完成的脚本。默认情况下，同步脚本会阻塞渲染。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML:**
    - **`<link rel="preload" as="font">`:**  这个 HTML 标签用于预加载字体。`RenderBlockingResourceManager` 负责追踪这些预加载的字体，并在超时后取消阻塞渲染。
        ```html
        <head>
          <link rel="preload" href="/fonts/my-font.woff2" as="font" type="font/woff2" crossorigin>
        </head>
        ```
        当 Blink 解析到这个标签时，`AddPendingFontPreload` 方法会被调用，将这个预加载的字体加入到待阻塞渲染的资源列表中。

    - **`<link rel="expect" href="#my-element">`:** 这个 HTML 标签声明了页面渲染前需要存在的元素。
        ```html
        <head>
          <link rel="expect" href="#content-area">
        </head>
        <body>
          <div id="content-area">...内容...</div>
        </body>
        ```
        当 Blink 解析到这个标签时，`AddPendingParsingElementLink` 方法会被调用，记录需要等待的元素 ID (`content-area`)。当解析到 `<div id="content-area">` 时，`RemovePendingParsingElement` 方法会被调用，解除阻塞。

    - **`<link rel="stylesheet">`:**  外部 CSS 样式表会阻塞渲染。`RenderBlockingResourceManager` 的 `AddPendingStylesheet` 和 `RemovePendingStylesheet` 方法用于追踪这些样式表的状态。
        ```html
        <head>
          <link rel="stylesheet" href="/styles.css">
        </head>
        ```

    - **`<script>`:**  默认情况下，同步脚本会阻塞渲染。`AddPendingScript` 和 `RemovePendingScript` 方法用于管理脚本的阻塞状态.
        ```html
        <head>
          <script src="/script.js"></script>
        </head>
        ```

* **CSS:**
    -  通过 CSS `@font-face` 规则声明的字体，如果需要从网络加载，也会被 `RenderBlockingResourceManager` 管理。
    -  `RenderBlockingResourceManager` 并不会直接解析 CSS 代码，但它会追踪通过 HTML 引入的样式表资源，而这些样式表中可能包含字体声明。

* **JavaScript:**
    - **通过 JavaScript 动态加载字体 (`FontFace` API):** `AddImperativeFontLoading` 方法用于处理这种情况。当 JavaScript 代码使用 `FontFace` API 开始加载字体时，可以通知 `RenderBlockingResourceManager` 将其作为阻塞渲染的资源。
        ```javascript
        const font = new FontFace('MyFont', 'url(/fonts/my-font.woff2)');
        document.fonts.add(font);
        font.load().then(function(loadedFont) {
          // 使用加载完成的字体
        });
        ```
        在这种情况下，`AddImperativeFontLoading` 会被调用，直到字体加载完成（`NotifyLoaded` 或 `NotifyError` 回调）或超时，才会解除阻塞。

**逻辑推理 (假设输入与输出):**

假设用户访问一个页面，该页面包含以下 HTML：

```html
<head>
  <link rel="preload" href="/fonts/my-font.woff2" as="font" type="font/woff2" crossorigin>
  <link rel="stylesheet" href="/styles.css">
  <link rel="expect" href="#content-area">
</head>
<body>
  <div id="content-area">主要内容</div>
  <script src="/script.js"></script>
</body>
```

**假设输入:**

1. 开始解析 HTML。
2. 解析到 `<link rel="preload" ...>`。
3. `AddPendingFontPreload` 被调用，`/fonts/my-font.woff2` 加入阻塞列表。
4. 解析到 `<link rel="stylesheet" ...>`。
5. `AddPendingStylesheet` 被调用，`/styles.css` 加入阻塞列表。
6. 解析到 `<link rel="expect" href="#content-area">`。
7. `AddPendingParsingElementLink` 被调用，记录等待元素 ID `content-area`。
8. 解析到 `<div id="content-area">`。
9. `RemovePendingParsingElement` 被调用，移除对 `content-area` 的等待。
10. 字体 `/fonts/my-font.woff2` 加载完成。
11. `RemovePendingFontPreload` 被调用，移除字体阻塞。
12. 样式表 `/styles.css` 加载完成。
13. `RemovePendingStylesheet` 被调用，移除样式表阻塞。
14. 解析到 `<script src="/script.js">`。
15. `AddPendingScript` 被调用，`/script.js` 加入阻塞列表。
16. 脚本 `/script.js` 执行完成。
17. `RemovePendingScript` 被调用，移除脚本阻塞。

**假设输出:**

- 在步骤 1 到 13 之间，页面渲染被阻塞 (部分或完全阻塞，取决于各个资源加载的顺序和时间)。
- 一旦步骤 13 完成（所有字体预加载完成/超时，关键样式表加载完成，预期的元素被解析到），页面将开始渲染。
- 脚本的执行也可能会阻塞渲染，直到步骤 17 完成后，后续的渲染操作才能继续。

**用户或编程常见的使用错误:**

1. **错误的 `rel="preload"` 使用:**
   - **缺少 `as` 属性:**  如果 `<link rel="preload">` 缺少 `as` 属性，浏览器可能无法正确识别资源类型，导致预加载优先级降低甚至失效，也可能不会被 `RenderBlockingResourceManager` 识别为阻塞渲染的资源。
     ```html
     <link rel="preload" href="/fonts/my-font.woff2" type="font/woff2" crossorigin>  <!-- 错误：缺少 as="font" -->
     ```
   - **`as` 属性值不正确:** 如果 `as` 的值与实际资源类型不符，可能导致资源加载失败或不被正确处理。

2. **`<link rel="expect">` 使用错误:**
   - **`href` 指向不存在的 ID:** 如果 `href` 属性指向的元素 ID 在页面中不存在，`RenderBlockingResourceManager` 会一直等待，直到超时或页面加载完成，并发出控制台警告。这可能导致页面长时间白屏。
     ```html
     <head>
       <link rel="expect" href="#non-existent-element">
     </head>
     ```
     **用户操作:** 用户访问该页面，会看到长时间的白屏，直到超时或页面加载完成。开发者可以在控制台看到 "Did not find element expected to be parsed from: <link rel=expect href="#non-existent-element">" 的警告信息。
   - **`href` 值错误:**  `href` 应该指向元素的 ID，需要包含 `#` 符号。如果格式错误，将无法正确匹配元素。

3. **预加载了非关键字体或资源:**  预加载应该针对页面首次渲染所必需的关键资源。预加载大量非关键资源反而可能降低性能。

4. **阻塞渲染的 JavaScript 代码:**  同步执行的 JavaScript 代码会阻塞渲染。避免在 `<head>` 中放置耗时长的同步脚本。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户遇到了页面加载缓慢或白屏的问题，开发者可能会按照以下步骤进行调试，最终可能会关注到 `RenderBlockingResourceManager` 的行为：

1. **用户访问网页:** 用户在浏览器地址栏输入网址或点击链接。
2. **浏览器发起请求:** 浏览器向服务器请求 HTML 文档。
3. **接收 HTML 文档:** 浏览器接收到 HTML 文档。
4. **开始解析 HTML:** Blink 引擎开始解析 HTML。
5. **遇到 `<link rel="preload" ...>`:**  `RenderBlockingResourceManager::AddPendingFontPreload` 被调用，开始追踪字体加载状态。
6. **遇到 `<link rel="stylesheet" ...>`:** `RenderBlockingResourceManager::AddPendingStylesheet` 被调用，追踪样式表加载状态。
7. **遇到 `<link rel="expect" ...>`:** `RenderBlockingResourceManager::AddPendingParsingElementLink` 被调用，记录需要等待的元素 ID。
8. **遇到 `<script src="...">`:**  如果脚本是同步的，`RenderBlockingResourceManager::AddPendingScript` 被调用。
9. **资源加载/执行:** 浏览器开始加载字体、样式表和执行脚本。
10. **`RenderBlockingResourceManager` 检查状态:**  在资源加载/执行过程中，`RenderBlockingResourceManager` 会不断检查是否有阻塞渲染的资源已完成加载/执行。
11. **渲染阻塞:**  如果存在未完成的阻塞资源，页面渲染会被推迟，用户看到白屏。
12. **资源加载完成或超时:**
    - 字体加载完成: `RenderBlockingResourceManager::RemovePendingFontPreload` 被调用。
    - 样式表加载完成: `RenderBlockingResourceManager::RemovePendingStylesheet` 被调用。
    - 预期元素被解析: `RenderBlockingResourceManager::RemovePendingParsingElement` 被调用。
    - 同步脚本执行完成: `RenderBlockingResourceManager::RemovePendingScript` 被调用。
    - 字体预加载超时: `RenderBlockingResourceManager::FontPreloadingTimerFired` 被调用，取消对该字体的阻塞。
13. **`RenderBlockingResourceUnblocked` 调用:** 当所有阻塞渲染的资源都被解除阻塞后，`RenderBlockingResourceManager::RenderBlockingResourceUnblocked` 会被调用，通知文档可以进行渲染。
14. **页面渲染:** 浏览器开始绘制页面。

**调试线索:**

- **Performance 面板 (Chrome DevTools):**  可以查看资源加载的时序，识别哪些资源阻塞了渲染。
- **Network 面板 (Chrome DevTools):**  查看资源加载状态、耗时。可以检查字体、样式表等资源的加载是否过慢或失败。
- **Console 面板 (Chrome DevTools):**  查看是否有关于 `<link rel="expect">` 的警告信息。
- **"Rendering" 标签 (Chrome DevTools):**  可以查看 "Render Blocking Resources" 信息，了解哪些资源正在阻塞渲染。
- **Blink 内部调试:**  如果需要深入分析，可以使用 Blink 提供的调试工具，例如设置断点在 `RenderBlockingResourceManager` 的相关方法中，查看其状态和执行流程。

总而言之，`RenderBlockingResourceManager` 是 Blink 引擎中负责优化首次渲染体验的关键组件，它通过管理字体预加载、`<link rel="expect">`、样式表和脚本等资源，尽可能地在必要资源准备就绪后立即渲染页面，避免不必要的白屏等待。理解其工作原理对于前端开发者优化页面加载性能至关重要。

### 提示词
```
这是目录为blink/renderer/core/loader/render_blocking_resource_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/css/font_face.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/pending_link_preload.h"
#include "third_party/blink/renderer/core/script/script_element_base.h"

namespace blink {

namespace {

// 50ms is the overall best performing value in our experiments.
const base::TimeDelta kMaxRenderingDelayForFontPreloads =
    base::Milliseconds(50);

class ImperativeFontLoadFinishedCallback final
    : public GarbageCollected<ImperativeFontLoadFinishedCallback>,
      public FontFace::LoadFontCallback {
 public:
  explicit ImperativeFontLoadFinishedCallback(Document& document)
      : document_(document) {}
  ~ImperativeFontLoadFinishedCallback() final = default;

  void Trace(Visitor* visitor) const final {
    visitor->Trace(document_);
    FontFace::LoadFontCallback::Trace(visitor);
  }

 private:
  void NotifyLoaded(FontFace*) final {
    DCHECK(document_->GetRenderBlockingResourceManager());
    document_->GetRenderBlockingResourceManager()
        ->RemoveImperativeFontLoading();
  }

  void NotifyError(FontFace*) final {
    DCHECK(document_->GetRenderBlockingResourceManager());
    document_->GetRenderBlockingResourceManager()
        ->RemoveImperativeFontLoading();
  }

  Member<Document> document_;
};

}  // namespace

RenderBlockingResourceManager::RenderBlockingResourceManager(Document& document)
    : document_(document),
      font_preload_max_blocking_timer_(
          document.GetTaskRunner(TaskType::kInternalFrameLifecycleControl),
          this,
          &RenderBlockingResourceManager::FontPreloadingTimerFired),
      font_preload_max_fcp_delay_timer_(
          document.GetTaskRunner(TaskType::kInternalFrameLifecycleControl),
          this,
          &RenderBlockingResourceManager::FontPreloadingTimerFired),
      font_preload_timeout_(kMaxRenderingDelayForFontPreloads) {}

void RenderBlockingResourceManager::AddPendingFontPreload(
    const PendingLinkPreload& link) {
  if (font_preload_timer_has_fired_ || document_->body()) {
    return;
  }

  pending_font_preloads_.insert(&link);
  EnsureStartFontPreloadMaxBlockingTimer();
}

void RenderBlockingResourceManager::AddImperativeFontLoading(
    FontFace* font_face) {
  if (font_face->LoadStatus() != FontFace::kLoading)
    return;

  if (font_preload_timer_has_fired_ || document_->body())
    return;

  ImperativeFontLoadFinishedCallback* callback =
      MakeGarbageCollected<ImperativeFontLoadFinishedCallback>(*document_);
  font_face->AddCallback(callback);
  ++imperative_font_loading_count_;
  EnsureStartFontPreloadMaxBlockingTimer();
}

void RenderBlockingResourceManager::RemovePendingFontPreload(
    const PendingLinkPreload& link) {
  auto iter = pending_font_preloads_.find(&link);
  if (iter == pending_font_preloads_.end()) {
    return;
  }
  pending_font_preloads_.erase(iter);
  RenderBlockingResourceUnblocked();
}

void RenderBlockingResourceManager::RemoveImperativeFontLoading() {
  if (font_preload_timer_has_fired_)
    return;
  DCHECK(imperative_font_loading_count_);
  --imperative_font_loading_count_;
  RenderBlockingResourceUnblocked();
}

void RenderBlockingResourceManager::EnsureStartFontPreloadMaxBlockingTimer() {
  if (font_preload_timer_has_fired_ ||
      font_preload_max_blocking_timer_.IsActive()) {
    return;
  }
  base::TimeDelta timeout =
      base::FeatureList::IsEnabled(features::kRenderBlockingFonts)
          ? document_->Loader()
                ->RemainingTimeToRenderBlockingFontMaxBlockingTime()
          : font_preload_timeout_;
  font_preload_max_blocking_timer_.StartOneShot(timeout, FROM_HERE);
}

void RenderBlockingResourceManager::FontPreloadingTimerFired(TimerBase*) {
  if (font_preload_timer_has_fired_) {
    return;
  }
  base::UmaHistogramBoolean(
      "WebFont.Clients.RenderBlockingFonts.ExpiredFonts",
      pending_font_preloads_.size() + imperative_font_loading_count_);
  font_preload_timer_has_fired_ = true;
  pending_font_preloads_.clear();
  imperative_font_loading_count_ = 0;
  document_->RenderBlockingResourceUnblocked();
}

void RenderBlockingResourceManager::AddPendingParsingElementLink(
    const AtomicString& id,
    const HTMLLinkElement* link) {
  if (!RuntimeEnabledFeatures::DocumentRenderBlockingEnabled()) {
    return;
  }

  CHECK(link);

  // We can only add resources until the body element is parsed.
  // Also we need a valid id.
  if (document_->body() || id.empty()) {
    return;
  }

  auto it = element_render_blocking_links_.find(id);
  if (it == element_render_blocking_links_.end()) {
    auto result = element_render_blocking_links_.insert(
        id,
        MakeGarbageCollected<HeapHashSet<WeakMember<const HTMLLinkElement>>>());
    result.stored_value->value->insert(link);
  } else {
    it->value->insert(link);
  }
  document_->SetHasRenderBlockingExpectLinkElements(true);
}

void RenderBlockingResourceManager::RemovePendingParsingElement(
    const AtomicString& id,
    Element* element) {
  if (!RuntimeEnabledFeatures::DocumentRenderBlockingEnabled()) {
    return;
  }

  if (element_render_blocking_links_.empty() || id.empty()) {
    return;
  }

  // <link rel=expect> matches elements found using "select the indicated part"
  // https://html.spec.whatwg.org/multipage/browsing-the-web.html#select-the-indicated-part
  // which only matches elements in the document tree (as in, not in a shadow
  // tree)
  if (element->IsInShadowTree() || !element->isConnected()) {
    return;
  }

  element_render_blocking_links_.erase(id);
  element_render_blocking_links_.erase(
      AtomicString(EncodeWithURLEscapeSequences(id)));
  if (element_render_blocking_links_.empty()) {
    document_->SetHasRenderBlockingExpectLinkElements(false);
    RenderBlockingResourceUnblocked();
  }
}

void RenderBlockingResourceManager::RemovePendingParsingElementLink(
    const AtomicString& id,
    const HTMLLinkElement* link) {
  if (!RuntimeEnabledFeatures::DocumentRenderBlockingEnabled()) {
    return;
  }

  // We don't add empty ids.
  if (id.empty()) {
    return;
  }

  auto it = element_render_blocking_links_.find(id);
  if (it == element_render_blocking_links_.end()) {
    return;
  }

  it->value->erase(link);
  if (it->value->empty()) {
    element_render_blocking_links_.erase(it);
  }

  if (element_render_blocking_links_.empty()) {
    document_->SetHasRenderBlockingExpectLinkElements(false);
    RenderBlockingResourceUnblocked();
  }
}

void RenderBlockingResourceManager::ClearPendingParsingElements() {
  if (!RuntimeEnabledFeatures::DocumentRenderBlockingEnabled()) {
    return;
  }

  if (element_render_blocking_links_.empty()) {
    return;
  }

  for (const auto& links : element_render_blocking_links_) {
    for (const auto& link : *(links.value)) {
      document_->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kWarning,
          String("Did not find element expected to be parsed from: <link "
                 "rel=expect "
                 "href=\"") +
              link->FastGetAttribute(html_names::kHrefAttr) + "\">"));
    }
  }

  document_->SetHasRenderBlockingExpectLinkElements(false);
  element_render_blocking_links_.clear();
  RenderBlockingResourceUnblocked();
}

void RenderBlockingResourceManager::SetFontPreloadTimeoutForTest(
    base::TimeDelta timeout) {
  if (font_preload_max_blocking_timer_.IsActive()) {
    font_preload_max_blocking_timer_.Stop();
    font_preload_max_blocking_timer_.StartOneShot(timeout, FROM_HERE);
  }
  font_preload_timeout_ = timeout;
}

void RenderBlockingResourceManager::DisableFontPreloadTimeoutForTest() {
  if (font_preload_max_blocking_timer_.IsActive()) {
    font_preload_max_blocking_timer_.Stop();
  }
}

bool RenderBlockingResourceManager::FontPreloadTimerIsActiveForTest() const {
  return font_preload_max_blocking_timer_.IsActive();
}

bool RenderBlockingResourceManager::AddPendingStylesheet(
    const Node& owner_node) {
  if (document_->body())
    return false;
  DCHECK(!pending_stylesheet_owner_nodes_.Contains(&owner_node));
  pending_stylesheet_owner_nodes_.insert(&owner_node);
  return true;
}

bool RenderBlockingResourceManager::RemovePendingStylesheet(
    const Node& owner_node) {
  auto iter = pending_stylesheet_owner_nodes_.find(&owner_node);
  if (iter == pending_stylesheet_owner_nodes_.end())
    return false;
  pending_stylesheet_owner_nodes_.erase(iter);
  RenderBlockingResourceUnblocked();
  return true;
}

void RenderBlockingResourceManager::AddPendingScript(
    const ScriptElementBase& script) {
  if (document_->body())
    return;
  pending_scripts_.insert(&script);
}

void RenderBlockingResourceManager::RemovePendingScript(
    const ScriptElementBase& script) {
  auto iter = pending_scripts_.find(&script);
  if (iter == pending_scripts_.end())
    return;
  pending_scripts_.erase(iter);
  RenderBlockingResourceUnblocked();
}

void RenderBlockingResourceManager::WillInsertDocumentBody() {
  if (base::FeatureList::IsEnabled(features::kRenderBlockingFonts) &&
      !HasNonFontRenderBlockingResources() && HasRenderBlockingFonts()) {
    EnsureStartFontPreloadMaxFCPDelayTimer();
  }
}

void RenderBlockingResourceManager::RenderBlockingResourceUnblocked() {
  document_->RenderBlockingResourceUnblocked();
  if (base::FeatureList::IsEnabled(features::kRenderBlockingFonts) &&
      !HasNonFontRenderBlockingResources() && HasRenderBlockingFonts() &&
      document_->body()) {
    EnsureStartFontPreloadMaxFCPDelayTimer();
  }
}

void RenderBlockingResourceManager::EnsureStartFontPreloadMaxFCPDelayTimer() {
  if (font_preload_timer_has_fired_ ||
      font_preload_max_fcp_delay_timer_.IsActive()) {
    return;
  }
  base::TimeDelta max_fcp_delay =
      base::Milliseconds(features::kMaxFCPDelayMsForRenderBlockingFonts.Get());
  font_preload_max_fcp_delay_timer_.StartOneShot(max_fcp_delay, FROM_HERE);
}

void RenderBlockingResourceManager::Trace(Visitor* visitor) const {
  visitor->Trace(element_render_blocking_links_);
  visitor->Trace(document_);
  visitor->Trace(pending_stylesheet_owner_nodes_);
  visitor->Trace(pending_scripts_);
  visitor->Trace(pending_font_preloads_);
  visitor->Trace(font_preload_max_blocking_timer_);
  visitor->Trace(font_preload_max_fcp_delay_timer_);
}

}  // namespace blink
```