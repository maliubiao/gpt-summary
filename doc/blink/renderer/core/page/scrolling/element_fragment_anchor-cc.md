Response:
Let's break down the thought process for analyzing the `element_fragment_anchor.cc` file.

**1. Understanding the Purpose from the File Name and Initial Scan:**

* **File Name:** `element_fragment_anchor.cc` immediately suggests it deals with fragment anchors (`#hash`) and elements. The "scrolling" part highlights a core function.
* **Copyright and Includes:** The header confirms it's a Chromium Blink engine file. The includes provide crucial context:
    * `v8_scroll_into_view_options.h`:  Indicates interaction with JavaScript's `scrollIntoView` API.
    * `ax_object_cache.h`:  Points to accessibility concerns.
    * `display_lock/...`:  Suggests synchronization or blocking related to rendering.
    * `dom/...`:  Confirms it manipulates DOM elements and the document structure.
    * `frame/...`:  Indicates involvement with frames and navigation.
    * `html/html_details_element.h`: Shows specific handling for `<details>` elements.
    * `svg/svg_svg_element.h`:  Indicates special handling for SVG documents.
    * `platform/bindings/script_forbidden_scope.h`:  Suggests potential interaction with scripting restrictions.
    * `platform/weborigin/kurl.h`: Deals with URLs.

**2. Deconstructing Key Functions:**

* **`TryCreate()`:**  This looks like a factory function. The arguments (`KURL`, `LocalFrame`, `should_scroll`) tell us when and how it's created. The logic inside reveals several sub-tasks:
    * **Fragment Extraction:** It extracts the fragment identifier from the URL. The `RemoveFragmentDirectives` function hints at handling special fragment directives (not standard anchor names).
    * **Anchor Element Lookup:**  `doc.FindAnchor(fragment)` is the core mechanism for finding the target element.
    * **CSS `:target` Pseudo-class:** `doc.SetCSSTarget(target)` shows how the browser updates the `:target` state.
    * **SVG Handling:** The code specifically deals with `SVGSVGElement` and parsing `viewSpec`.
    * **Display Locking:**  `target->ActivateDisplayLockIfNeeded(...)` indicates synchronization to ensure the target element is rendered before scrolling.
    * **Early Exit Conditions:** Several `return nullptr` statements indicate scenarios where an `ElementFragmentAnchor` isn't needed.
    * **Expanding `<details>`:** `HTMLDetailsElement::ExpandDetailsAncestors(*anchor_node)` highlights specific behavior for expanding collapsed `<details>` elements.
    * **Revealing Hidden Ancestors:** `DisplayLockUtilities::RevealHiddenUntilFoundAncestors(*anchor_node)` points to logic for making hidden elements visible.
    * **Object Creation:**  Finally, it creates and returns an `ElementFragmentAnchor` object.

* **`ElementFragmentAnchor()` (Constructor):**  This initializes the object, importantly noting `needs_focus_`.

* **`Invoke()`:**  This function performs the actual scrolling. Key observations:
    * **Checks for Validity:** It ensures the frame and anchor node still exist.
    * **Render Blocking Resources:**  It waits for resources to load.
    * **Scrolling Logic:** It uses `ScrollIntoViewOptions` to scroll the target element to the top-start.
    * **Accessibility Notification:**  `cache->HandleScrolledToAnchor(...)` informs accessibility services.
    * **`needs_invoke_` Management:** The logic around `needs_invoke_` suggests it might be called multiple times, and it tracks if the scroll action needs to happen again (e.g., after a partial load).

* **`Installed()`:** This seems like a setup function called when the anchor is ready. It handles initial focus and schedules another focus attempt if the initial one fails.

* **`DidScroll()`:**  This is called when scrolling occurs. The crucial part is `needs_invoke_ = false;` when the scroll is explicit (user-initiated), preventing the automatic anchor scroll from overriding user scrolling.

* **`ApplyFocusIfNeeded()`:** This handles setting focus to the anchor element. It includes special handling for caret browsing and checks for focusability.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The use of `ScrollIntoViewOptions` directly links to the JavaScript `element.scrollIntoView()` method and its options.
* **HTML:** The code explicitly handles `<details>` elements, SVG elements, and the concept of fragment identifiers (`#`).
* **CSS:** The interaction with `doc.SetCSSTarget(target)` directly relates to the `:target` CSS pseudo-class.

**4. Logical Reasoning and Examples:**

* **Hypotheses:**  Formulate scenarios to test the code's behavior. For example:  What happens if the target element is inside a closed `<details>`? What if the fragment points to a non-existent element? What if the user scrolls manually after the page loads?
* **Input/Output:**  Consider the input to each function (URL, frame, `should_scroll`) and the expected output (scrolling, focus, updates to the `:target` state).

**5. Common Errors and Debugging:**

* **User Errors:** Think about typical user mistakes, like invalid fragment identifiers or links to hidden content.
* **Debugging:** Consider how a developer would track down issues, focusing on the sequence of function calls and the state variables (`needs_invoke_`, `needs_focus_`). The user interaction steps to reach this code are essential for debugging.

**6. Structuring the Answer:**

Organize the findings logically:

* **Core Functionality:** Start with the main purpose of the file.
* **Key Functions:** Detail the role of each important function.
* **Relationship to Web Technologies:** Clearly explain the connections to JavaScript, HTML, and CSS with concrete examples.
* **Logical Reasoning:** Present hypotheses and input/output scenarios.
* **Common Errors:** Discuss potential issues and how users might encounter them.
* **Debugging:** Outline the steps to reach this code during a debugging session.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just scrolls to an element."  **Correction:**  It's more complex, involving display locking, accessibility, and handling different element types (like `<details>` and SVG).
* **Initial thought:** "The scrolling happens immediately." **Correction:** The `needs_invoke_` and `Installed()` functions show that scrolling might be deferred or retried.
* **Focus on the "why":** Don't just describe *what* the code does, but also *why* it does it (e.g., the reason for the display lock, the purpose of the accessibility notification).

By following these steps, you can systematically analyze the source code and generate a comprehensive and accurate description of its functionality and its relationship to web technologies.
好的，让我们来详细分析一下 `blink/renderer/core/page/scrolling/element_fragment_anchor.cc` 这个文件。

**文件功能概述**

`element_fragment_anchor.cc` 文件的核心功能是处理页面内的**元素片段锚点导航** (Element Fragment Anchor Navigation)。简单来说，它负责实现当用户点击一个带有 `#fragment-identifier` 的链接，或者通过 JavaScript 修改 `location.hash` 时，浏览器如何滚动页面到目标元素，并进行相关的处理，例如焦点设置和 `:target` CSS 伪类的更新。

**具体功能分解**

1. **创建和管理元素片段锚点对象 (`ElementFragmentAnchor`)**:
   - `ElementFragmentAnchor::TryCreate(const KURL& url, LocalFrame& frame, bool should_scroll)`:  这是一个静态方法，用于创建 `ElementFragmentAnchor` 对象。
     - 它接收一个 URL (`url`)，当前所在的 `LocalFrame` (`frame`)，以及一个布尔值 `should_scroll`，指示是否应该进行滚动。
     - 它首先检查 URL 是否包含片段标识符 (`#fragment`).
     - 它使用 `doc.FindAnchor(fragment)` 在文档中查找与片段标识符匹配的元素（通常是具有 `id` 或 `name` 属性的元素）。
     - 它设置文档的 CSS 目标 (`doc.SetCSSTarget(target)`), 这会触发 `:target` CSS 伪类的更新。
     - 对于 SVG 文档，它会解析 SVG 的 `viewSpec` 来处理 SVG 内部的片段。
     - 如果找到了目标元素并且 `should_scroll` 为 `true`，则创建一个 `ElementFragmentAnchor` 对象来管理后续的滚动和焦点操作。
     - 对于包含在 `<details>` 元素中的锚点，它会展开所有的祖先 `<details>` 元素。
     - 它还会调用 `DisplayLockUtilities::RevealHiddenUntilFoundAncestors` 来确保目标元素及其祖先是可见的。

2. **执行滚动操作 (`ElementFragmentAnchor::Invoke()`)**:
   - 当需要执行滚动时，会调用 `Invoke()` 方法。
   - 它会检查必要的条件，例如文档的渲染资源是否加载完成，以及 `FrameView` 是否存在。
   - 它使用 `ScrollIntoViewOptions` 来控制滚动行为，默认会将目标元素的顶部与视口的顶部对齐 (`block: "start"`)，并尽量让元素在水平方向上可见 (`inlinePosition: "nearest"`)。
   - 它会通知无障碍对象缓存 (`AXObjectCache`) 页面已经滚动到锚点。
   - 如果文档尚未完全加载或者需要设置焦点，它会重新设置 `needs_invoke_` 标志，以便在后续的事件循环中再次尝试。

3. **处理焦点 (`ElementFragmentAnchor::ApplyFocusIfNeeded()`)**:
   - `ApplyFocusIfNeeded()` 负责将焦点设置到目标元素。
   - 它首先检查是否需要设置焦点 (`needs_focus_`) 以及渲染资源是否加载完成。
   - 如果启用了 Caret Browsing，它会将光标移动到目标元素的开始位置。
   - 如果目标元素可以获得焦点 (`element->IsFocusable()`)，它会调用 `element->Focus()` 将焦点设置到该元素。
   - 如果目标元素不可获得焦点，它会清除当前聚焦的元素 (`frame_->GetDocument()->ClearFocusedElement()`)，并设置顺序焦点导航的起始点 (`frame_->GetDocument()->SetSequentialFocusNavigationStartingPoint(anchor_node_)`).

4. **安装锚点 (`ElementFragmentAnchor::Installed()`)**:
   - `Installed()` 方法在 `ElementFragmentAnchor` 对象被创建并准备就绪时调用。
   - 如果渲染资源已经加载完成，它会立即尝试设置焦点。
   - 否则，它会将设置焦点的任务添加到动画帧队列中，以确保在合适的时机执行。

5. **处理用户滚动 (`ElementFragmentAnchor::DidScroll(mojom::blink::ScrollType type)`)**:
   - 当页面发生滚动时，会调用 `DidScroll()` 方法。
   - 它会检查滚动的类型是否是用户主动发起的 (`IsExplicitScrollType(type)`，例如通过鼠标滚轮或拖动滚动条)。
   - 如果是用户主动滚动，它会设置 `needs_invoke_ = false`，以避免自动锚点滚动覆盖用户的滚动位置。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **HTML**:
    - **功能关系**:  该文件处理 HTML 中的锚点链接 (`<a href="#target">`) 和具有 `id` 属性的元素 (`<div id="target">`)。
    - **举例说明**:  当 HTML 中有 `<a href="#section2">跳转到第二节</a>` 和 `<div id="section2">这是第二节的内容</div>` 时，点击链接会触发 `ElementFragmentAnchor` 的相关逻辑，将页面滚动到 `id` 为 `section2` 的 `div` 元素。
    - **`<details>` 元素**: 该文件特别处理了包含在 `<details>` 元素内的锚点，确保在滚动到锚点之前，相关的 `<details>` 元素会被展开。 例如：
      ```html
      <details>
        <summary>第一部分</summary>
        <p><a href="#item1">查看项目1</a></p>
      </details>
      <div id="item1">项目 1 的内容</div>
      ```
      点击 "查看项目1" 链接，`ElementFragmentAnchor` 会确保 `<details>` 元素是展开的，然后滚动到 `id="item1"` 的 `div`。

* **CSS**:
    - **功能关系**:  该文件负责更新与 `:target` CSS 伪类相关的状态。当页面滚动到某个锚点时，该锚点对应的元素会匹配 `:target` 选择器。
    - **举例说明**:
      ```html
      <style>
        :target {
          background-color: yellow;
        }
      </style>
      <div id="section1">第一节</div>
      <a href="#section1">跳转到第一节</a>
      ```
      当点击链接跳转到 `id="section1"` 的 `div` 时，该 `div` 会因为匹配 `:target` 选择器而变为黄色背景。`doc.SetCSSTarget(target)` 的调用就是触发这个 CSS 更新的关键。

* **JavaScript**:
    - **功能关系**:  JavaScript 可以通过修改 `window.location.hash` 来触发片段锚点导航。 `ElementFragmentAnchor` 会处理这种由 JavaScript 触发的导航。
    - **举例说明**:
      ```html
      <button onclick="window.location.hash = 'section3'">通过 JavaScript 跳转到第三节</button>
      <div id="section3">这是第三节</div>
      ```
      点击按钮会执行 JavaScript 代码，将 `location.hash` 设置为 `'section3'`，这会触发浏览器的片段导航机制，并最终由 `ElementFragmentAnchor` 处理滚动和焦点。
    - **`scrollIntoView()` 方法**:  虽然 `ElementFragmentAnchor` 主要是处理通过 URL 片段触发的滚动，但它的 `Invoke()` 方法内部使用了 `ScrollIntoViewOptions`，这与 JavaScript 中 `element.scrollIntoView()` 方法的参数对应。

**逻辑推理与假设输入输出**

**假设输入 1:** 用户点击了一个链接 `<a href="#part3">Go to Part 3</a>`，并且页面中存在一个元素 `<div id="part3">Content of Part 3</div>`。

**输出 1:**
1. `TryCreate()` 会被调用，URL 中包含 `#part3`，`should_scroll` 可能为 `true`。
2. `doc.FindAnchor("part3")` 找到 `id` 为 `part3` 的 `div` 元素。
3. `doc.SetCSSTarget()` 将该 `div` 设置为 CSS 目标，触发 `:target` 伪类的更新。
4. 创建 `ElementFragmentAnchor` 对象。
5. `Installed()` 被调用，如果渲染完成，可能尝试设置焦点。
6. `Invoke()` 在合适的时机被调用，使用 `ScrollIntoViewOptions` 将页面滚动到 `div#part3` 的位置。
7. 如果 `div#part3` 可以获得焦点，它将被聚焦。

**假设输入 2:**  用户通过 JavaScript 执行 `window.location.hash = 'nonexistent-section'`.

**输出 2:**
1. `TryCreate()` 会被调用，URL 中包含 `#nonexistent-section`。
2. `doc.FindAnchor("nonexistent-section")` 返回 `nullptr`，因为没有匹配的元素。
3. `doc.SetCSSTarget(nullptr)` 清除之前的 CSS 目标。
4. `TryCreate()` 返回 `nullptr`，不会创建 `ElementFragmentAnchor` 对象，也不会发生滚动。

**用户或编程常见的使用错误**

1. **错误的片段标识符**: 用户提供的 URL 或 JavaScript 代码中的片段标识符与页面中实际存在的元素的 `id` 或 `name` 属性不匹配。这会导致页面不会滚动到预期的位置。
   - **例子**:  ` <a href="#SectionFour">跳转</a>`，但页面中实际的 `id` 是 `section4` (大小写不匹配或拼写错误)。

2. **目标元素被隐藏**:  如果目标元素或其祖先元素通过 CSS 设置了 `display: none` 或 `visibility: hidden`，浏览器可能无法滚动到该元素，或者滚动后的效果不明显。
   - **例子**:
     ```html
     <style>
       #hidden-part { display: none; }
     </style>
     <a href="#hidden-part">跳转到隐藏部分</a>
     <div id="hidden-part">这部分内容是隐藏的</div>
     ```
     `ElementFragmentAnchor` 可能会尝试滚动，但由于元素被隐藏，用户可能看不到滚动的效果。 不过，`DisplayLockUtilities::RevealHiddenUntilFoundAncestors` 的存在表明 Blink 引擎会尝试处理这种情况，至少对于某些类型的隐藏。

3. **在页面加载完成前修改 `location.hash`**:  如果在页面加载完成之前，JavaScript 修改了 `location.hash`，可能会导致滚动行为不稳定或者失败。 浏览器通常会在页面完全解析和渲染后执行片段导航。

4. **误解 `:target` 伪类的作用域**:  开发者可能认为只有一个元素可以同时匹配 `:target` 伪类，这是正确的。但是，如果页面上有多个具有相同 `id` 的元素（虽然这是无效的 HTML），行为可能不可预测。

**用户操作是如何一步步到达这里，作为调试线索**

假设开发者需要调试一个用户点击锚点链接后页面滚动行为异常的问题。以下是可能到达 `element_fragment_anchor.cc` 的步骤：

1. **用户操作**: 用户在浏览器中打开一个网页。
2. **用户操作**: 用户点击了页面上的一个带有 `#fragment-identifier` 的链接，例如 `<a href="#my-section">Jump</a>`。
3. **浏览器处理**: 浏览器解析该链接，识别出这是一个内部的片段导航。
4. **Blink 引擎处理**:
   - 浏览器内核 (Blink) 的导航代码会解析 URL，提取出片段标识符 `#my-section`。
   - `LocalFrame::Navigate()` 或类似的方法会被调用处理导航。
   - 在导航过程中，会检查是否存在片段标识符。
   - 如果存在片段标识符，`ElementFragmentAnchor::TryCreate()`  很可能会被调用，传入当前的 `KURL` 和 `LocalFrame`。
   - `TryCreate()` 内部会尝试查找目标元素 (`doc.FindAnchor()`)，并创建 `ElementFragmentAnchor` 对象（如果需要滚动）。
   - 如果创建了 `ElementFragmentAnchor` 对象，其 `Installed()` 方法会被调用。
   - 在合适的时机（例如，渲染树构建完成后），`Invoke()` 方法会被调用来执行滚动。
   - 如果用户在自动滚动发生前或发生后手动滚动了页面，`DidScroll()` 方法会被调用。
   - 如果需要设置焦点，`ApplyFocusIfNeeded()` 会被调用。

**调试线索**:

* **断点**: 开发者可以在 `ElementFragmentAnchor::TryCreate`, `Invoke`, `ApplyFocusIfNeeded`, `DidScroll` 等关键方法中设置断点，观察代码的执行流程和变量的值。
* **URL 分析**: 检查用户点击的链接的 `href` 属性是否正确，片段标识符是否与目标元素的 `id` 或 `name` 匹配。
* **DOM 结构检查**: 使用开发者工具检查目标元素是否存在，其 `id` 或 `name` 属性是否正确，以及是否存在 CSS 样式导致元素被隐藏。
* **网络请求**: 虽然片段导航通常不涉及网络请求，但如果页面是通过某种框架或动态加载内容，可能需要检查相关资源是否加载完成。
* **日志输出**: 在关键代码路径添加 `DLOG` 或 `TRACE_EVENT` 输出，记录函数的调用和重要变量的状态。
* **模拟用户操作**: 重复用户的操作步骤，确保能够复现问题。

通过理解 `element_fragment_anchor.cc` 的功能和它在浏览器处理片段导航中的作用，开发者可以更有效地诊断和解决相关的问题。

### 提示词
```
这是目录为blink/renderer/core/page/scrolling/element_fragment_anchor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/scrolling/element_fragment_anchor.h"

#include "base/trace_event/typed_macros.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_into_view_options.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_details_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

namespace {
// TODO(bokan): Move this into FragmentDirective after
// https://crrev.com/c/3216206 lands.
String RemoveFragmentDirectives(const String& url_fragment) {
  wtf_size_t directive_delimiter_ix = url_fragment.Find(":~:");
  if (directive_delimiter_ix == kNotFound)
    return url_fragment;

  return url_fragment.Substring(0, directive_delimiter_ix);
}

}  // namespace

ElementFragmentAnchor* ElementFragmentAnchor::TryCreate(const KURL& url,
                                                        LocalFrame& frame,
                                                        bool should_scroll) {
  DCHECK(frame.GetDocument());
  Document& doc = *frame.GetDocument();

  // If our URL has no ref, then we have no place we need to jump to.
  // OTOH If CSS target was set previously, we want to set it to 0, recalc
  // and possibly paint invalidation because :target pseudo class may have been
  // set (see bug 11321).
  // Similarly for svg, if we had a previous svgView() then we need to reset
  // the initial view if we don't have a fragment.
  if (!url.HasFragmentIdentifier() && !doc.CssTarget() && !doc.IsSVGDocument())
    return nullptr;

  String fragment =
      RemoveFragmentDirectives(url.FragmentIdentifier().ToString());
  Node* anchor_node = doc.FindAnchor(fragment);

  // Setting to null will clear the current target.
  auto* target = DynamicTo<Element>(anchor_node);
  doc.SetCSSTarget(target);

  if (doc.IsSVGDocument()) {
    if (auto* svg = DynamicTo<SVGSVGElement>(doc.documentElement())) {
      String decoded = DecodeURLEscapeSequences(fragment, DecodeURLMode::kUTF8);
      svg->SetViewSpec(svg->ParseViewSpec(decoded, target));
    }
  }

  if (target) {
    target->ActivateDisplayLockIfNeeded(
        DisplayLockActivationReason::kFragmentNavigation);
  }

  if (doc.IsSVGDocument() && (!frame.IsMainFrame() || !target))
    return nullptr;

  if (!anchor_node)
    return nullptr;

  // Element fragment anchors only need to be kept alive if they need scrolling.
  if (!should_scroll)
    return nullptr;

  HTMLDetailsElement::ExpandDetailsAncestors(*anchor_node);
  DisplayLockUtilities::RevealHiddenUntilFoundAncestors(*anchor_node);

  return MakeGarbageCollected<ElementFragmentAnchor>(*anchor_node, frame);
}

ElementFragmentAnchor::ElementFragmentAnchor(Node& anchor_node,
                                             LocalFrame& frame)
    : FragmentAnchor(frame),
      anchor_node_(&anchor_node),
      needs_focus_(!anchor_node.IsDocumentNode()) {
  DCHECK(frame_->View());
}

bool ElementFragmentAnchor::Invoke() {
  TRACE_EVENT("blink", "ElementFragmentAnchor::Invoke");
  if (!frame_ || !anchor_node_)
    return false;

  // Don't remove the fragment anchor until focus has been applied.
  if (!needs_invoke_)
    return needs_focus_;

  Document& doc = *frame_->GetDocument();

  if (!doc.HaveRenderBlockingResourcesLoaded() || !frame_->View())
    return true;

  Member<Element> element_to_scroll = DynamicTo<Element>(anchor_node_.Get());
  if (!element_to_scroll)
    element_to_scroll = doc.documentElement();

  if (element_to_scroll) {
    ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
    options->setBlock("start");
    options->setInlinePosition("nearest");
    ScrollElementIntoViewWithOptions(element_to_scroll, options);
  }

  if (AXObjectCache* cache = doc.ExistingAXObjectCache())
    cache->HandleScrolledToAnchor(anchor_node_);

  // Scroll into view above will cause us to clear needs_invoke_ via the
  // DidScroll so recompute it here.
  needs_invoke_ = !doc.IsLoadCompleted() || needs_focus_;

  return needs_invoke_;
}

void ElementFragmentAnchor::Installed() {
  DCHECK(frame_->GetDocument());

  // If rendering isn't ready yet, we'll focus and scroll as part of the
  // document lifecycle.
  if (frame_->GetDocument()->HaveRenderBlockingResourcesLoaded())
    ApplyFocusIfNeeded();

  if (needs_focus_) {
    // Attempts to focus the anchor if we couldn't focus above. This can cause
    // script to run so we can't do it from Invoke.
    frame_->GetDocument()->EnqueueAnimationFrameTask(WTF::BindOnce(
        &ElementFragmentAnchor::ApplyFocusIfNeeded, WrapPersistent(this)));
  }

  needs_invoke_ = true;
}

void ElementFragmentAnchor::DidScroll(mojom::blink::ScrollType type) {
  if (!IsExplicitScrollType(type))
    return;

  // If the user/page scrolled, avoid clobbering the scroll offset by removing
  // the anchor on the next invocation. Note: we may get here as a result of
  // calling Invoke() because of the ScrollIntoView but that's ok because
  // needs_invoke_ is recomputed at the end of that method.
  needs_invoke_ = false;
}

void ElementFragmentAnchor::Trace(Visitor* visitor) const {
  visitor->Trace(anchor_node_);
  visitor->Trace(frame_);
  FragmentAnchor::Trace(visitor);
}

void ElementFragmentAnchor::ApplyFocusIfNeeded() {
  // SVG images can load synchronously during style recalc but it's ok to focus
  // since we disallow scripting. For everything else, focus() could run script
  // so make sure we're at a valid point to do so.
  DCHECK(frame_->GetDocument()->IsSVGDocument() ||
         !ScriptForbiddenScope::IsScriptForbidden());

  if (!needs_focus_)
    return;

  if (!anchor_node_) {
    needs_focus_ = false;
    return;
  }

  if (!frame_->GetDocument()->HaveRenderBlockingResourcesLoaded()) {
    return;
  }

  frame_->GetDocument()->UpdateStyleAndLayoutTree();

  // If caret browsing is enabled, move the caret to the beginning of the
  // fragment, or to the first non-inert position after it.
  if (frame_->IsCaretBrowsingEnabled()) {
    const Position& pos = Position::FirstPositionInOrBeforeNode(*anchor_node_);
    if (pos.IsConnected()) {
      frame_->Selection().SetSelection(
          SelectionInDOMTree::Builder().Collapse(pos).Build(),
          SetSelectionOptions::Builder()
              .SetShouldCloseTyping(true)
              .SetShouldClearTypingStyle(true)
              .SetDoNotSetFocus(true)
              .Build());
    }
  }

  // If the anchor accepts keyboard focus and fragment scrolling is allowed,
  // move focus there to aid users relying on keyboard navigation.
  // If anchorNode is not focusable or fragment scrolling is not allowed,
  // clear focus, which matches the behavior of other browsers.
  auto* element = DynamicTo<Element>(anchor_node_.Get());
  if (element && element->IsFocusable()) {
    element->Focus();
  } else {
    frame_->GetDocument()->SetSequentialFocusNavigationStartingPoint(
        anchor_node_);
    frame_->GetDocument()->ClearFocusedElement();
  }
  needs_focus_ = false;
}

}  // namespace blink
```