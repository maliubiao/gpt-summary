Response:
Let's break down the thought process for analyzing the provided `style_engine.cc` code snippet and answering the user's request.

**1. Understanding the Request:**

The core request is to understand the *functionality* of `style_engine.cc` within the Chromium Blink rendering engine, specifically concerning its relationship with JavaScript, HTML, and CSS. The request also asks for examples, logic inference, common errors, debugging information, and a summary of its functionality as the first part of a larger set.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the included headers and the provided code itself. Look for prominent keywords and classes:

* **Headers:**  `css`, `style`, `resolver`, `font`, `media`, `stylesheet`, `document`, `element`, `layout`. These immediately suggest the file is heavily involved in the processing of CSS styles and how they apply to the DOM (HTML elements).
* **Class Name:** `StyleEngine`. This is the central class, so the file's functionality revolves around this.
* **Methods (from the snippet):**  `StyleEngine`, `EnsureStyleSheetCollectionFor`, `StyleSheetCollectionFor`, `StyleSheetsForStyleSheetList`, `InjectSheet`, `RemoveInjectedSheet`, `EnsureInspectorStyleSheet`, `AddPendingBlockingSheet`, `RemovePendingBlockingSheet`, `SetNeedsActiveStyleUpdate`, `AddStyleSheetCandidateNode`, `RemoveStyleSheetCandidateNode`, `ModifiedStyleSheetCandidateNode`, `AdoptedStyleSheetAdded`, `AdoptedStyleSheetRemoved`, `MediaQueryAffectingValueChanged`, `WatchedSelectorsChanged`, `DocumentRulesSelectorsChanged`, `ShouldUpdateDocumentStyleSheetCollection`, `ShouldUpdateShadowTreeStyleSheetCollection`, `AddTextTrack`, `RemoveTextTrack`, `EnsureVTTOriginatingElement`, `UpdateActiveUserStyleSheets`, `UpdateActiveStyleSheets`, `UpdateCounterStyles`, `MarkPositionTryStylesDirty`, `InvalidatePositionTryStyles`, `UpdateViewport`, `NeedsActiveStyleUpdate`, `UpdateActiveStyle`, `ActiveStyleSheetsForInspector`, `UpdateCounters`, `UpdateLayoutCounters`, `ShadowRootInsertedToDocument`, `ShadowRootRemovedFromDocument`, `ResetAuthorStyle`, `EnsureStyleContainmentScopeTree`, `SetRuleUsageTracker`, `ComputeFont`. Reading these method names gives a strong indication of the file's responsibilities.

**3. Deductive Reasoning and Function Grouping:**

Based on the keywords and method names, we can start grouping functionalities:

* **Style Sheet Management:** Methods like `EnsureStyleSheetCollectionFor`, `InjectSheet`, `RemoveInjectedSheet`, `AddPendingBlockingSheet`, `RemovePendingBlockingSheet`, `AddStyleSheetCandidateNode`, `RemoveStyleSheetCandidateNode`, `AdoptedStyleSheetAdded`, `AdoptedStyleSheetRemoved` clearly deal with managing and tracking CSS stylesheets associated with a document or shadow roots.
* **Style Recalculation and Updates:**  Methods like `SetNeedsActiveStyleUpdate`, `UpdateActiveStyleSheets`, `UpdateActiveStyle`, `NeedsActiveStyleUpdate` point to the core responsibility of triggering and performing style recalculations when changes occur.
* **Media Queries:**  `MediaQueryAffectingValueChanged` indicates the handling of changes in media query states.
* **Selectors and Rule Matching:** `WatchedSelectorsChanged`, `DocumentRulesSelectorsChanged` suggest the engine is aware of and reacts to changes in CSS selectors.
* **Counters:** `UpdateCounterStyles`, `UpdateCounters`, `UpdateLayoutCounters` are related to CSS counters.
* **Viewport:** `UpdateViewport` likely handles viewport-related style updates (e.g., for `@viewport`).
* **Shadow DOM:** `ShadowRootInsertedToDocument`, `ShadowRootRemovedFromDocument`, `ResetAuthorStyle` indicate handling styles within shadow DOM.
* **Inspector Integration:** `EnsureInspectorStyleSheet`, `ActiveStyleSheetsForInspector` suggest providing data for developer tools.
* **Fonts:** `ComputeFont` (the last method in the snippet) suggests involvement in font computation.

**4. Connecting to HTML, CSS, and JavaScript:**

* **HTML:** The `StyleEngine` works directly on the DOM, which is built from HTML. It determines how CSS styles apply to HTML elements. The presence of methods dealing with shadow DOM explicitly connects to HTML's shadow DOM feature.
* **CSS:** This is the primary focus. The engine parses, manages, and applies CSS rules from various sources (author stylesheets, user stylesheets, inline styles, etc.). It handles different types of CSS rules (keyframes, font-face, media queries, etc.).
* **JavaScript:**  JavaScript can manipulate the DOM (adding/removing elements, changing attributes) and CSSOM (adding/removing stylesheets, modifying style rules). The `StyleEngine` reacts to these changes by invalidating and recalculating styles. Methods like `InjectSheet` and `RemoveInjectedSheet` are relevant here, as JavaScript can dynamically inject stylesheets.

**5. Logic Inference and Examples:**

* **Assumption:** When the DOM changes, the `StyleEngine` needs to recalculate styles.
* **Example:**  If JavaScript uses `element.classList.add('new-class')`, and that class has CSS rules associated with it, the `StyleEngine` will detect the change and trigger a style recalculation for that element.
* **Assumption:** Media query changes affect which CSS rules apply.
* **Example:** If a user resizes the browser window, causing a media query to become true, the `StyleEngine` will re-evaluate the stylesheets and apply the relevant rules.

**6. Common Errors and User Actions:**

Think about typical developer mistakes related to CSS and how they might interact with this engine:

* **Incorrect CSS Syntax:** While the *parser* catches these primarily, the `StyleEngine` would be responsible for *not* applying those invalid rules.
* **Specificity Issues:**  Developers might expect a rule to apply but a more specific rule overrides it. The `StyleEngine`'s cascade and specificity calculations are key here.
* **JavaScript Style Manipulation Errors:**  Trying to set invalid CSS property values via JavaScript. The `StyleEngine` would likely ignore or handle these errors.

**7. Debugging Clues:**

The method names themselves provide good debugging clues:

* `SetNeedsActiveStyleUpdate`:  If this isn't being called when expected, styles won't update.
* `UpdateActiveStyleSheets`:  Debugging here could reveal issues with stylesheet loading or activation.
* `MediaQueryAffectingValueChanged`: Helps track down why styles aren't reacting to media query changes.

**8. Structuring the Answer:**

Organize the information logically, starting with a high-level overview and then drilling down into specifics. Use clear headings and bullet points for readability. Address each part of the user's request systematically.

**9. Iteration and Refinement:**

After the initial draft, review and refine the answer. Ensure the language is clear, concise, and accurate. Check for any missing points or areas that could be explained better. For instance, explicitly mentioning the concept of "invalidation" (marking elements as needing style recalculation) is crucial.

By following this kind of process, combining code analysis, deductive reasoning, and knowledge of web technologies, we can arrive at a comprehensive and accurate answer to the user's request.
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 *           (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2011, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) 2008, 2009, 2011, 2012 Google Inc. All rights reserved.
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) Research In Motion Limited 2010-2011. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB. If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/css/style_engine.h"

// ... other includes ...

namespace blink {

namespace {
// ... anonymous namespace for helper functions ...
}  // namespace

StyleEngine::StyleEngine(Document& document)
    : document_(&document),
      style_containment_scope_tree_(
          MakeGarbageCollected<StyleContainmentScopeTree>()),
      document_style_sheet_collection_(
          MakeGarbageCollected<DocumentStyleSheetCollection>(document)),
      preferred_color_scheme_(mojom::blink::PreferredColorScheme::kLight),
      owner_preferred_color_scheme_(mojom::blink::PreferredColorScheme::kLight),
      owner_color_scheme_(mojom::blink::ColorScheme::kLight) {
  if (document.GetFrame()) {
    resolver_ = MakeGarbageCollected<StyleResolver>(document);
    global_rule_set_ = MakeGarbageCollected<CSSGlobalRuleSet>();
    font_selector_ = CreateCSSFontSelectorFor(document);
    font_selector_->RegisterForInvalidationCallbacks(this);
    if (const FrameOwner* owner = document.GetFrame()->Owner()) {
      owner_color_scheme_ = owner->GetColorScheme();
      owner_preferred_color_scheme_ = owner->GetPreferredColorScheme();
    }

    // Viewport styles are only processed in the main frame of a page with an
    // active viewport. That is, a pages that their own independently zoomable
    // viewport: the outermost main frame.
    DCHECK(document.GetPage());
    VisualViewport& viewport = document.GetPage()->GetVisualViewport();
    if (document.IsInMainFrame() && viewport.IsActiveViewport()) {
      viewport_resolver_ =
          MakeGarbageCollected<ViewportStyleResolver>(document);
    }
  }

  UpdateColorScheme();

  // Mostly for the benefit of unit tests.
  UpdateViewportSize();
}

StyleEngine::~StyleEngine() = default;

TreeScopeStyleSheetCollection& StyleEngine::EnsureStyleSheetCollectionFor(
    TreeScope& tree_scope) {
  // ... implementation ...
}

TreeScopeStyleSheetCollection* StyleEngine::StyleSheetCollectionFor(
    TreeScope& tree_scope) {
  // ... implementation ...
}

const HeapVector<Member<StyleSheet>>& StyleEngine::StyleSheetsForStyleSheetList(
    TreeScope& tree_scope) {
  // ... implementation ...
}

void StyleEngine::InjectSheet(const StyleSheetKey& key,
                              StyleSheetContents* sheet,
                              WebCssOrigin origin) {
  // ... implementation ...
}

void StyleEngine::RemoveInjectedSheet(const StyleSheetKey& key,
                                      WebCssOrigin origin) {
  // ... implementation ...
}

CSSStyleSheet& StyleEngine::EnsureInspectorStyleSheet() {
  // ... implementation ...
}

void StyleEngine::AddPendingBlockingSheet(Node& style_sheet_candidate_node,
                                          PendingSheetType type) {
  // ... implementation ...
}

// This method is called whenever a top-level stylesheet has finished loading.
void StyleEngine::RemovePendingBlockingSheet(Node& style_sheet_candidate_node,
                                             PendingSheetType type) {
  // ... implementation ...
}

void StyleEngine::SetNeedsActiveStyleUpdate(TreeScope& tree_scope) {
  // ... implementation ...
}

void StyleEngine::AddStyleSheetCandidateNode(Node& node) {
  // ... implementation ...
}

void StyleEngine::RemoveStyleSheetCandidateNode(
    Node& node,
    ContainerNode& insertion_point) {
  // ... implementation ...
}

void StyleEngine::ModifiedStyleSheetCandidateNode(Node& node) {
  // ... implementation ...
}

void StyleEngine::AdoptedStyleSheetAdded(TreeScope& tree_scope,
                                         CSSStyleSheet* sheet) {
  // ... implementation ...
}

void StyleEngine::AdoptedStyleSheetRemoved(TreeScope& tree_scope,
                                           CSSStyleSheet* sheet) {
  // ... implementation ...
}

void StyleEngine::MediaQueryAffectingValueChanged(TreeScope& tree_scope,
                                                  MediaValueChange change) {
  // ... implementation ...
}

void StyleEngine::WatchedSelectorsChanged() {
  // ... implementation ...
}

void StyleEngine::DocumentRulesSelectorsChanged() {
  // ... implementation ...
}

bool StyleEngine::ShouldUpdateDocumentStyleSheetCollection() const {
  // ... implementation ...
}

bool StyleEngine::ShouldUpdateShadowTreeStyleSheetCollection() const {
  // ... implementation ...
}

void StyleEngine::MediaQueryAffectingValueChanged(
    UnorderedTreeScopeSet& tree_scopes,
    MediaValueChange change) {
  // ... implementation ...
}

void StyleEngine::AddTextTrack(TextTrack* text_track) {
  // ... implementation ...
}

void StyleEngine::RemoveTextTrack(TextTrack* text_track) {
  // ... implementation ...
}

Element* StyleEngine::EnsureVTTOriginatingElement() {
  // ... implementation ...
}

void StyleEngine::MediaQueryAffectingValueChanged(
    HeapHashSet<Member<TextTrack>>& text_tracks,
    MediaValueChange change) {
  // ... implementation ...
}

void StyleEngine::MediaQueryAffectingValueChanged(MediaValueChange change) {
  // ... implementation ...
}

void StyleEngine::UpdateActiveStyleSheetsInShadow(
    TreeScope* tree_scope,
    UnorderedTreeScopeSet& tree_scopes_removed) {
  // ... implementation ...
}

void StyleEngine::UpdateActiveUserStyleSheets() {
  // ... implementation ...
}

void StyleEngine::UpdateActiveStyleSheets() {
  // ... implementation ...
}

void StyleEngine::UpdateCounterStyles() {
  // ... implementation ...
}

void StyleEngine::MarkPositionTryStylesDirty(
    const HeapHashSet<Member<RuleSet>>& changed_rule_sets) {
  // ... implementation ...
}

void StyleEngine::InvalidatePositionTryStyles() {
  // ... implementation ...
}

void StyleEngine::UpdateViewport() {
  // ... implementation ...
}

bool StyleEngine::NeedsActiveStyleUpdate() const {
  // ... implementation ...
}

void StyleEngine::UpdateActiveStyle() {
  // ... implementation ...
}

const ActiveStyleSheetVector StyleEngine::ActiveStyleSheetsForInspector() {
  // ... implementation ...
}

void StyleEngine::UpdateCounters() {
  // ... implementation ...
}

// Recursively look for potential LayoutCounters to update,
// since in case of ::marker they can be deep child of original
// pseudo element's layout object.
void StyleEngine::UpdateLayoutCounters(const LayoutObject& layout_object,
                                       CountersAttachmentContext& context) {
  // ... implementation ...
}

void StyleEngine::UpdateCounters(const Element& element,
                                 CountersAttachmentContext& context) {
  // ... implementation ...
}

void StyleEngine::ShadowRootInsertedToDocument(ShadowRoot& shadow_root) {
  // ... implementation ...
}

void StyleEngine::ShadowRootRemovedFromDocument(ShadowRoot* shadow_root) {
  // ... implementation ...
}

void StyleEngine::ResetAuthorStyle(TreeScope& tree_scope) {
  // ... implementation ...
}

StyleContainmentScopeTree& StyleEngine::EnsureStyleContainmentScopeTree() {
  // ... implementation ...
}

void StyleEngine::SetRuleUsageTracker(StyleRuleUsageTracker* tracker) {
  // ... implementation ...
}

Font StyleEngine::ComputeFont(Element& element,
              
```

## 功能归纳 (第 1 部分)

根据提供的 `blink/renderer/core/css/style_engine.cc` 源代码文件的第 1 部分，其核心功能可以归纳为：

**核心职责：CSS 样式管理与应用**

`StyleEngine` 类是 Blink 渲染引擎中负责管理和应用 CSS 样式的核心组件，它与文档（`Document`）紧密关联，并处理以下关键任务：

1. **样式表集合管理:**
   - 维护和管理文档及其 Shadow DOM 树中所有相关的样式表集合 (`DocumentStyleSheetCollection`, `ShadowTreeStyleSheetCollection`).
   - 提供方法来获取指定作用域的样式表集合 (`EnsureStyleSheetCollectionFor`, `StyleSheetCollectionFor`).
   - 跟踪可作为样式表的节点 (`AddStyleSheetCandidateNode`, `RemoveStyleSheetCandidateNode`, `ModifiedStyleSheetCandidateNode`).
   - 处理 adoptedStyleSheets 的添加和移除 (`AdoptedStyleSheetAdded`, `AdoptedStyleSheetRemoved`).

2. **样式表注入与移除:**
   - 允许动态注入用户样式表和开发者样式表 (`InjectSheet`, `RemoveInjectedSheet`).
   - 管理 Inspector 使用的样式表 (`EnsureInspectorStyleSheet`).

3. **阻塞样式表的处理:**
   - 跟踪和管理阻塞渲染和解析的样式表加载状态 (`AddPendingBlockingSheet`, `RemovePendingBlockingSheet`).

4. **触发样式更新:**
   - 提供机制来标记不同作用域（文档或 Shadow DOM 树）需要进行样式重新计算 (`SetNeedsActiveStyleUpdate`).

5. **媒体查询处理:**
   - 响应媒体查询条件的变化，并触发受影响作用域的样式更新 (`MediaQueryAffectingValueChanged`).

6. **选择器监听与规则更新:**
   - 监听特定 CSS 选择器的变化 (`WatchedSelectorsChanged`).
   - 处理文档规则选择器的变化 (`DocumentRulesSelectorsChanged`).

7. **活动样式表的更新:**
   - 管理和更新当前生效的样式表集合 (`UpdateActiveStyleSheets`, `UpdateActiveUserStyleSheets`).
   - 区分文档样式表和 Shadow DOM 树的样式表更新 (`ShouldUpdateDocumentStyleSheetCollection`, `ShouldUpdateShadowTreeStyleSheetCollection`, `UpdateActiveStyleSheetsInShadow`).

8. **CSS 计数器管理:**
   - 维护和更新 CSS 计数器的状态 (`UpdateCounterStyles`).

9. **`@position-try` 规则处理:**
   - 标记和失效与 `@position-try` 规则相关的样式 (`MarkPositionTryStylesDirty`, `InvalidatePositionTryStyles`).

10. **视口样式处理:**
    - 管理和更新与视口相关的样式 (`UpdateViewport`).

11. **全局规则集管理:**
    - 维护和更新全局 CSS 规则集 (`global_rule_set_`).

12. **提供 Inspector 需要的活动样式表:**
    -  提供当前生效的样式表列表，供开发者工具使用 (`ActiveStyleSheetsForInspector`).

13. **CSS 计数器值更新:**
    - 更新 DOM 元素上 CSS 计数器的值 (`UpdateCounters`, `UpdateLayoutCounters`).

14. **Shadow DOM 生命周期管理:**
    -  响应 ShadowRoot 的插入和移除，并更新相关的样式 (`ShadowRootInsertedToDocument`, `ShadowRootRemovedFromDocument`).
    -  重置特定作用域的作者样式 (`ResetAuthorStyle`).

15. **样式包含范围树管理:**
    -  维护和管理样式包含范围树 (`EnsureStyleContainmentScopeTree`).

16. **规则使用追踪:**
    -  设置用于追踪 CSS 规则使用情况的追踪器 (`SetRuleUsageTracker`).

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** `StyleEngine` 直接作用于由 HTML 构建的 DOM 树。它根据 CSS 规则来决定如何渲染 HTML 元素。例如，当 HTML 元素被添加到文档中时，`StyleEngine` 会根据 CSS 选择器找到匹配的规则，并将样式应用到该元素。
* **CSS:** `StyleEngine` 的核心功能就是解析、管理和应用 CSS 样式。它处理各种 CSS 特性，包括选择器、属性、媒体查询、`@font-face`、`@keyframes` 等。例如，当 CSS 样式表被加载或修改时，`StyleEngine` 会重新解析样式表并更新受影响元素的样式。
* **JavaScript:** JavaScript 可以通过 DOM API (如 `element.style`, `element.classList`) 或 CSSOM API (如 `document.styleSheets`) 来动态修改元素的样式或操作样式表。`StyleEngine` 监听这些变化，并触发样式的重新计算和应用。例如，当 JavaScript 使用 `element.style.color = 'red'` 修改元素颜色时，`StyleEngine` 会捕捉到这个变化并更新元素的渲染。`InjectSheet` 和 `RemoveInjectedSheet` 方法也体现了 JavaScript 动态操作样式表的能力。

**逻辑推理与假设输入输出：**

假设输入：
- 用户在 HTML 中添加了一个 `<div class="container">` 元素。
- CSS 中定义了 `.container { width: 100px; }`。

逻辑推理：
1. 当 `<div class="container">` 被添加到 DOM 中时，Blink 的 DOM 构建模块会通知 `StyleEngine`。
2. `StyleEngine` 会检查所有已加载的样式表，查找与该元素匹配的 CSS 规则。
3. `StyleEngine` 会找到 `.container { width: 100px; }` 这个规则，因为它与元素的 class 属性匹配。
4. `StyleEngine` 会将 `width: 100px` 这个样式属性应用到该 `div` 元素。

输出：
- 该 `div` 元素在渲染时会被赋予 100px 的宽度。

**用户或编程常见的使用错误：**

1. **CSS 语法错误：** 用户编写了不符合 CSS 规范的样式规则。`StyleEngine` 的解析器会尝试处理，但可能会忽略或产生意外结果。例如，拼写错误的属性名 (`colr` 而不是 `color`)。
2. **选择器优先级问题：** 用户定义的样式被浏览器默认样式或更具体的样式覆盖。例如，定义了 `div { color: blue; }`，但又定义了 `#myDiv { color: red; }`，当 ID 为 `myDiv` 的 `div` 元素出现时，会应用红色，用户可能误以为蓝色应该生效。
3. **JavaScript 样式操作冲突：** JavaScript 代码尝试修改的样式被 CSS 样式表覆盖，或者多个 JavaScript 代码片段之间相互覆盖样式。例如，一个脚本设置了 `element.style.display = 'none'`, 另一个脚本设置了 `element.style.display = 'block'`，最终只有一个会生效。
4. **忘记触发样式更新：** 在某些情况下，手动操作 DOM 或 CSSOM 后，如果引擎没有自动检测到变化，可能需要显式地触发样式更新。虽然 `StyleEngine` 通常会自动处理，但在复杂场景下可能出现遗漏。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入网址并回车，或者点击了一个链接。** 这会导致浏览器开始加载 HTML 页面。
2. **浏览器解析 HTML，构建 DOM 树。** 在解析过程中，遇到 `<link>` 标签引入的 CSS 文件或 `<style>` 标签内的 CSS 代码。
3. **CSS 解析器解析 CSS 代码，并创建 CSSOM（CSS Object Model）。**
4. **`StyleEngine` 获取解析后的 CSSOM，并将其与 DOM 树关联。**
5. **当 DOM 结构发生变化（添加、删除、修改元素）或 CSS 样式发生变化（加载新的样式表、修改样式规则）时，`StyleEngine` 会收到通知。**
6. **`StyleEngine` 执行样式匹配，确定哪些 CSS 规则适用于哪些 DOM 元素。**
7. **`StyleEngine` 计算每个元素的最终样式，并将计算结果传递给布局引擎进行页面布局和渲染。**

**调试线索：** 如果开发者在调试样式问题，他们可能会：

* **查看元素的 computed style (计算样式)：**  通过浏览器的开发者工具，查看元素最终应用的样式，这可以揭示 `StyleEngine` 的计算结果。
* **检查样式表的加载顺序和优先级：** 开发者工具会显示样式表的来源和优先级，帮助理解为什么某些样式被覆盖。
* **断点调试 JavaScript 代码：** 检查 JavaScript 代码中对样式的操作是否正确，以及是否按预期触发了样式更新。
* **使用 Performance 面板分析样式计算性能：** 如果页面性能有问题，可以分析样式计算的时间，找出性能瓶颈。

这是 `style_engine.cc` 文件第 1 部分的功能归纳。后续部分可能会涉及更具体的样式计算、继承、层叠等方面的内容。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 *           (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2011, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) 2008, 2009, 2011, 2012 Google Inc. All rights reserved.
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) Research In Motion Limited 2010-2011. All rights reserved.
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

#include "third_party/blink/renderer/core/css/style_engine.h"

#include "base/auto_reset.h"
#include "base/containers/adapters.h"
#include "base/hash/hash.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/check_pseudo_has_cache_scope.h"
#include "third_party/blink/renderer/core/css/container_query_data.h"
#include "third_party/blink/renderer/core/css/container_query_evaluator.h"
#include "third_party/blink/renderer/core/css/counter_style_map.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_uri_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/document_style_environment_variables.h"
#include "third_party/blink/renderer/core/css/document_style_sheet_collection.h"
#include "third_party/blink/renderer/core/css/font_face_cache.h"
#include "third_party/blink/renderer/core/css/invalidation/invalidation_set.h"
#include "third_party/blink/renderer/core/css/media_feature_overrides.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/out_of_flow_data.h"
#include "third_party/blink/renderer/core/css/property_registration.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/selector_filter_parent_scope.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_stats.h"
#include "third_party/blink/renderer/core/css/resolver/style_rule_usage_tracker.h"
#include "third_party/blink/renderer/core/css/resolver/viewport_style_resolver.h"
#include "third_party/blink/renderer/core/css/shadow_tree_style_sheet_collection.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_containment_scope_tree.h"
#include "third_party/blink/renderer/core/css/style_environment_variables.h"
#include "third_party/blink/renderer/core/css/style_rule_font_feature_values.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css/vision_deficiency.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/nth_index_cache.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/frame_owner.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/track/text_track.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/invalidation_set_to_selector_map.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_size.h"
#include "third_party/blink/renderer/core/layout/layout_counter.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/list/layout_inline_list_item.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_item.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_popup_controller.h"
#include "third_party/blink/renderer/core/preferences/preference_overrides.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/filter_operations.h"
#include "third_party/blink/renderer/core/style/style_initial_data.h"
#include "third_party/blink/renderer/core/svg/svg_resource.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_selector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

namespace {

CSSFontSelector* CreateCSSFontSelectorFor(Document& document) {
  DCHECK(document.GetFrame());
  if (document.GetFrame()->PagePopupOwner()) [[unlikely]] {
    return PagePopupController::CreateCSSFontSelector(document);
  }
  return MakeGarbageCollected<CSSFontSelector>(document);
}

enum RuleSetFlags {
  kFontFaceRules = 1 << 0,
  kKeyframesRules = 1 << 1,
  kPropertyRules = 1 << 2,
  kCounterStyleRules = 1 << 3,
  kLayerRules = 1 << 4,
  kFontPaletteValuesRules = 1 << 5,
  kPositionTryRules = 1 << 6,
  kFontFeatureValuesRules = 1 << 7,
  kViewTransitionRules = 1 << 8,
  kFunctionRules = 1 << 9,
};

const unsigned kRuleSetFlagsAll = ~0u;

unsigned GetRuleSetFlags(const HeapHashSet<Member<RuleSet>> rule_sets) {
  unsigned flags = 0;
  for (auto& rule_set : rule_sets) {
    if (!rule_set->KeyframesRules().empty()) {
      flags |= kKeyframesRules;
    }
    if (!rule_set->FontFaceRules().empty()) {
      flags |= kFontFaceRules;
    }
    if (!rule_set->FontPaletteValuesRules().empty()) {
      flags |= kFontPaletteValuesRules;
    }
    if (!rule_set->FontFeatureValuesRules().empty()) {
      flags |= kFontFeatureValuesRules;
    }
    if (!rule_set->PropertyRules().empty()) {
      flags |= kPropertyRules;
    }
    if (!rule_set->CounterStyleRules().empty()) {
      flags |= kCounterStyleRules;
    }
    if (rule_set->HasCascadeLayers()) {
      flags |= kLayerRules;
    }
    if (!rule_set->PositionTryRules().empty()) {
      flags |= kPositionTryRules;
    }
    if (!rule_set->ViewTransitionRules().empty()) {
      flags |= kViewTransitionRules;
    }
    if (!rule_set->FunctionRules().empty()) {
      flags |= kFunctionRules;
    }
  }
  return flags;
}

const Vector<AtomicString> ConvertFontFamilyToVector(const CSSValue* value) {
  const CSSValueList* family_list = DynamicTo<CSSValueList>(value);
  if (!family_list) {
    return Vector<AtomicString>();
  }
  wtf_size_t length = family_list->length();
  if (!length) {
    return Vector<AtomicString>();
  }
  Vector<AtomicString> families(length);
  for (wtf_size_t i = 0; i < length; i++) {
    const CSSFontFamilyValue* family_value =
        DynamicTo<CSSFontFamilyValue>(family_list->Item(i));
    if (!family_value) {
      return Vector<AtomicString>();
    }
    families[i] = family_value->Value();
  }
  return families;
}

}  // namespace

StyleEngine::StyleEngine(Document& document)
    : document_(&document),
      style_containment_scope_tree_(
          MakeGarbageCollected<StyleContainmentScopeTree>()),
      document_style_sheet_collection_(
          MakeGarbageCollected<DocumentStyleSheetCollection>(document)),
      preferred_color_scheme_(mojom::blink::PreferredColorScheme::kLight),
      owner_preferred_color_scheme_(mojom::blink::PreferredColorScheme::kLight),
      owner_color_scheme_(mojom::blink::ColorScheme::kLight) {
  if (document.GetFrame()) {
    resolver_ = MakeGarbageCollected<StyleResolver>(document);
    global_rule_set_ = MakeGarbageCollected<CSSGlobalRuleSet>();
    font_selector_ = CreateCSSFontSelectorFor(document);
    font_selector_->RegisterForInvalidationCallbacks(this);
    if (const FrameOwner* owner = document.GetFrame()->Owner()) {
      owner_color_scheme_ = owner->GetColorScheme();
      owner_preferred_color_scheme_ = owner->GetPreferredColorScheme();
    }

    // Viewport styles are only processed in the main frame of a page with an
    // active viewport. That is, a pages that their own independently zoomable
    // viewport: the outermost main frame.
    DCHECK(document.GetPage());
    VisualViewport& viewport = document.GetPage()->GetVisualViewport();
    if (document.IsInMainFrame() && viewport.IsActiveViewport()) {
      viewport_resolver_ =
          MakeGarbageCollected<ViewportStyleResolver>(document);
    }
  }

  UpdateColorScheme();

  // Mostly for the benefit of unit tests.
  UpdateViewportSize();
}

StyleEngine::~StyleEngine() = default;

TreeScopeStyleSheetCollection& StyleEngine::EnsureStyleSheetCollectionFor(
    TreeScope& tree_scope) {
  if (tree_scope == document_) {
    return GetDocumentStyleSheetCollection();
  }

  StyleSheetCollectionMap::AddResult result =
      style_sheet_collection_map_.insert(&tree_scope, nullptr);
  if (result.is_new_entry) {
    result.stored_value->value =
        MakeGarbageCollected<ShadowTreeStyleSheetCollection>(
            To<ShadowRoot>(tree_scope));
  }
  return *result.stored_value->value.Get();
}

TreeScopeStyleSheetCollection* StyleEngine::StyleSheetCollectionFor(
    TreeScope& tree_scope) {
  if (tree_scope == document_) {
    return &GetDocumentStyleSheetCollection();
  }

  StyleSheetCollectionMap::iterator it =
      style_sheet_collection_map_.find(&tree_scope);
  if (it == style_sheet_collection_map_.end()) {
    return nullptr;
  }
  return it->value.Get();
}

const HeapVector<Member<StyleSheet>>& StyleEngine::StyleSheetsForStyleSheetList(
    TreeScope& tree_scope) {
  DCHECK(document_);
  TreeScopeStyleSheetCollection& collection =
      EnsureStyleSheetCollectionFor(tree_scope);
  if (document_->IsActive()) {
    collection.UpdateStyleSheetList();
  }
  return collection.StyleSheetsForStyleSheetList();
}

void StyleEngine::InjectSheet(const StyleSheetKey& key,
                              StyleSheetContents* sheet,
                              WebCssOrigin origin) {
  HeapVector<std::pair<StyleSheetKey, Member<CSSStyleSheet>>>&
      injected_style_sheets =
          origin == WebCssOrigin::kUser ? injected_user_style_sheets_
                                        : injected_author_style_sheets_;
  injected_style_sheets.push_back(std::make_pair(
      key, MakeGarbageCollected<CSSStyleSheet>(sheet, *document_)));
  if (origin == WebCssOrigin::kUser) {
    MarkUserStyleDirty();
  } else {
    MarkDocumentDirty();
  }
}

void StyleEngine::RemoveInjectedSheet(const StyleSheetKey& key,
                                      WebCssOrigin origin) {
  HeapVector<std::pair<StyleSheetKey, Member<CSSStyleSheet>>>&
      injected_style_sheets =
          origin == WebCssOrigin::kUser ? injected_user_style_sheets_
                                        : injected_author_style_sheets_;
  // Remove the last sheet that matches.
  const auto& it = base::ranges::find(
      base::Reversed(injected_style_sheets), key,
      &std::pair<StyleSheetKey, Member<CSSStyleSheet>>::first);
  if (it != injected_style_sheets.rend()) {
    injected_style_sheets.erase(std::next(it).base());
    if (origin == WebCssOrigin::kUser) {
      MarkUserStyleDirty();
    } else {
      MarkDocumentDirty();
    }
  }
}

CSSStyleSheet& StyleEngine::EnsureInspectorStyleSheet() {
  if (inspector_style_sheet_) {
    return *inspector_style_sheet_;
  }

  auto* contents = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(*document_));
  inspector_style_sheet_ =
      MakeGarbageCollected<CSSStyleSheet>(contents, *document_);
  MarkDocumentDirty();
  // TODO(futhark@chromium.org): Making the active stylesheets up-to-date here
  // is required by some inspector tests, at least. I theory this should not be
  // necessary. Need to investigate to figure out if/why.
  UpdateActiveStyle();
  return *inspector_style_sheet_;
}

void StyleEngine::AddPendingBlockingSheet(Node& style_sheet_candidate_node,
                                          PendingSheetType type) {
  DCHECK(type == PendingSheetType::kBlocking ||
         type == PendingSheetType::kDynamicRenderBlocking);

  auto* manager = GetDocument().GetRenderBlockingResourceManager();
  bool is_render_blocking =
      manager && manager->AddPendingStylesheet(style_sheet_candidate_node);

  if (type != PendingSheetType::kBlocking) {
    return;
  }

  pending_script_blocking_stylesheets_++;

  if (!is_render_blocking) {
    pending_parser_blocking_stylesheets_++;
    if (GetDocument().body()) {
      GetDocument().CountUse(
          WebFeature::kPendingStylesheetAddedAfterBodyStarted);
    }
    GetDocument().DidAddPendingParserBlockingStylesheet();
  }
}

// This method is called whenever a top-level stylesheet has finished loading.
void StyleEngine::RemovePendingBlockingSheet(Node& style_sheet_candidate_node,
                                             PendingSheetType type) {
  DCHECK(type == PendingSheetType::kBlocking ||
         type == PendingSheetType::kDynamicRenderBlocking);

  if (style_sheet_candidate_node.isConnected()) {
    SetNeedsActiveStyleUpdate(style_sheet_candidate_node.GetTreeScope());
  }

  auto* manager = GetDocument().GetRenderBlockingResourceManager();
  bool is_render_blocking =
      manager && manager->RemovePendingStylesheet(style_sheet_candidate_node);

  if (type != PendingSheetType::kBlocking) {
    return;
  }

  if (!is_render_blocking) {
    DCHECK_GT(pending_parser_blocking_stylesheets_, 0);
    pending_parser_blocking_stylesheets_--;
    if (!pending_parser_blocking_stylesheets_) {
      GetDocument().DidLoadAllPendingParserBlockingStylesheets();
    }
  }

  // Make sure we knew this sheet was pending, and that our count isn't out of
  // sync.
  DCHECK_GT(pending_script_blocking_stylesheets_, 0);

  pending_script_blocking_stylesheets_--;
  if (pending_script_blocking_stylesheets_) {
    return;
  }

  GetDocument().DidRemoveAllPendingStylesheets();
}

void StyleEngine::SetNeedsActiveStyleUpdate(TreeScope& tree_scope) {
  DCHECK(tree_scope.RootNode().isConnected());
  if (GetDocument().IsActive()) {
    MarkTreeScopeDirty(tree_scope);
  }
}

void StyleEngine::AddStyleSheetCandidateNode(Node& node) {
  if (!node.isConnected() || GetDocument().IsDetached()) {
    return;
  }

  DCHECK(!IsXSLStyleSheet(node));
  TreeScope& tree_scope = node.GetTreeScope();
  EnsureStyleSheetCollectionFor(tree_scope).AddStyleSheetCandidateNode(node);

  SetNeedsActiveStyleUpdate(tree_scope);
  if (tree_scope != document_) {
    active_tree_scopes_.insert(&tree_scope);
  }
}

void StyleEngine::RemoveStyleSheetCandidateNode(
    Node& node,
    ContainerNode& insertion_point) {
  DCHECK(!IsXSLStyleSheet(node));
  DCHECK(insertion_point.isConnected());

  ShadowRoot* shadow_root = node.ContainingShadowRoot();
  if (!shadow_root) {
    shadow_root = insertion_point.ContainingShadowRoot();
  }

  static_assert(std::is_base_of<TreeScope, ShadowRoot>::value,
                "The ShadowRoot must be subclass of TreeScope.");
  TreeScope& tree_scope =
      shadow_root ? static_cast<TreeScope&>(*shadow_root) : GetDocument();
  TreeScopeStyleSheetCollection* collection =
      StyleSheetCollectionFor(tree_scope);
  // After detaching document, collection could be null. In the case,
  // we should not update anything. Instead, just return.
  if (!collection) {
    return;
  }
  collection->RemoveStyleSheetCandidateNode(node);

  SetNeedsActiveStyleUpdate(tree_scope);
}

void StyleEngine::ModifiedStyleSheetCandidateNode(Node& node) {
  if (node.isConnected()) {
    SetNeedsActiveStyleUpdate(node.GetTreeScope());
  }
}

void StyleEngine::AdoptedStyleSheetAdded(TreeScope& tree_scope,
                                         CSSStyleSheet* sheet) {
  if (GetDocument().IsDetached()) {
    return;
  }
  sheet->AddedAdoptedToTreeScope(tree_scope);
  if (!tree_scope.RootNode().isConnected()) {
    return;
  }
  EnsureStyleSheetCollectionFor(tree_scope);
  if (tree_scope != document_) {
    active_tree_scopes_.insert(&tree_scope);
  }
  SetNeedsActiveStyleUpdate(tree_scope);
}

void StyleEngine::AdoptedStyleSheetRemoved(TreeScope& tree_scope,
                                           CSSStyleSheet* sheet) {
  if (GetDocument().IsDetached()) {
    return;
  }
  sheet->RemovedAdoptedFromTreeScope(tree_scope);
  if (!tree_scope.RootNode().isConnected()) {
    return;
  }
  if (!StyleSheetCollectionFor(tree_scope)) {
    return;
  }
  SetNeedsActiveStyleUpdate(tree_scope);
}

void StyleEngine::MediaQueryAffectingValueChanged(TreeScope& tree_scope,
                                                  MediaValueChange change) {
  auto* collection = StyleSheetCollectionFor(tree_scope);
  DCHECK(collection);
  if (AffectedByMediaValueChange(collection->ActiveStyleSheets(), change)) {
    SetNeedsActiveStyleUpdate(tree_scope);
  }
}

void StyleEngine::WatchedSelectorsChanged() {
  DCHECK(global_rule_set_);
  global_rule_set_->InitWatchedSelectorsRuleSet(GetDocument());
  // TODO(futhark@chromium.org): Should be able to use RuleSetInvalidation here.
  MarkAllElementsForStyleRecalc(StyleChangeReasonForTracing::Create(
      style_change_reason::kDeclarativeContent));
}

void StyleEngine::DocumentRulesSelectorsChanged() {
  DCHECK(global_rule_set_);
  Member<RuleSet> old_rule_set =
      global_rule_set_->DocumentRulesSelectorsRuleSet();
  global_rule_set_->UpdateDocumentRulesSelectorsRuleSet(GetDocument());
  Member<RuleSet> new_rule_set =
      global_rule_set_->DocumentRulesSelectorsRuleSet();
  DCHECK_NE(old_rule_set, new_rule_set);

  HeapHashSet<Member<RuleSet>> changed_rule_sets;
  if (old_rule_set) {
    changed_rule_sets.insert(old_rule_set);
  }
  if (new_rule_set) {
    changed_rule_sets.insert(new_rule_set);
  }

  const unsigned changed_rule_flags = GetRuleSetFlags(changed_rule_sets);
  InvalidateForRuleSetChanges(GetDocument(), changed_rule_sets,
                              changed_rule_flags, kInvalidateAllScopes);

  // The global rule set must be updated immediately, so that any DOM mutations
  // that happen after this (but before the next style update) can use the
  // updated invalidation sets.
  UpdateActiveStyle();
}

bool StyleEngine::ShouldUpdateDocumentStyleSheetCollection() const {
  return document_scope_dirty_;
}

bool StyleEngine::ShouldUpdateShadowTreeStyleSheetCollection() const {
  return !dirty_tree_scopes_.empty();
}

void StyleEngine::MediaQueryAffectingValueChanged(
    UnorderedTreeScopeSet& tree_scopes,
    MediaValueChange change) {
  for (TreeScope* tree_scope : tree_scopes) {
    DCHECK(tree_scope != document_);
    MediaQueryAffectingValueChanged(*tree_scope, change);
  }
}

void StyleEngine::AddTextTrack(TextTrack* text_track) {
  text_tracks_.insert(text_track);
}

void StyleEngine::RemoveTextTrack(TextTrack* text_track) {
  text_tracks_.erase(text_track);
}

Element* StyleEngine::EnsureVTTOriginatingElement() {
  if (!vtt_originating_element_) {
    vtt_originating_element_ = MakeGarbageCollected<Element>(
        QualifiedName(g_null_atom, g_empty_atom, g_empty_atom), document_);
  }
  return vtt_originating_element_.Get();
}

void StyleEngine::MediaQueryAffectingValueChanged(
    HeapHashSet<Member<TextTrack>>& text_tracks,
    MediaValueChange change) {
  if (text_tracks.empty()) {
    return;
  }

  for (auto text_track : text_tracks) {
    bool style_needs_recalc = false;
    auto style_sheets = text_track->GetCSSStyleSheets();
    for (const auto& sheet : style_sheets) {
      StyleSheetContents* contents = sheet->Contents();
      if (contents->HasMediaQueries()) {
        style_needs_recalc = true;
        contents->ClearRuleSet();
      }
    }

    if (style_needs_recalc && text_track->Owner()) {
      // Use kSubtreeTreeStyleChange instead of RuleSet style invalidation
      // because it won't be expensive for tracks and we won't have dynamic
      // changes.
      text_track->Owner()->SetNeedsStyleRecalc(
          kSubtreeStyleChange,
          StyleChangeReasonForTracing::Create(style_change_reason::kShadow));
    }
  }
}

void StyleEngine::MediaQueryAffectingValueChanged(MediaValueChange change) {
  if (AffectedByMediaValueChange(active_user_style_sheets_, change)) {
    MarkUserStyleDirty();
  }
  MediaQueryAffectingValueChanged(GetDocument(), change);
  MediaQueryAffectingValueChanged(active_tree_scopes_, change);
  MediaQueryAffectingValueChanged(text_tracks_, change);
  if (resolver_) {
    resolver_->UpdateMediaType();
  }
}

void StyleEngine::UpdateActiveStyleSheetsInShadow(
    TreeScope* tree_scope,
    UnorderedTreeScopeSet& tree_scopes_removed) {
  DCHECK_NE(tree_scope, document_);
  auto* collection =
      To<ShadowTreeStyleSheetCollection>(StyleSheetCollectionFor(*tree_scope));
  DCHECK(collection);
  collection->UpdateActiveStyleSheets(*this);
  if (!collection->HasStyleSheetCandidateNodes() &&
      !tree_scope->HasAdoptedStyleSheets()) {
    tree_scopes_removed.insert(tree_scope);
    // When removing TreeScope from ActiveTreeScopes,
    // its resolver should be destroyed by invoking resetAuthorStyle.
    DCHECK(!tree_scope->GetScopedStyleResolver());
  }
}

void StyleEngine::UpdateActiveUserStyleSheets() {
  DCHECK(user_style_dirty_);

  ActiveStyleSheetVector new_active_sheets;
  for (auto& sheet : injected_user_style_sheets_) {
    if (RuleSet* rule_set = RuleSetForSheet(*sheet.second)) {
      new_active_sheets.push_back(std::make_pair(sheet.second, rule_set));
    }
  }

  ApplyUserRuleSetChanges(active_user_style_sheets_, new_active_sheets);
  new_active_sheets.swap(active_user_style_sheets_);
}

void StyleEngine::UpdateActiveStyleSheets() {
  if (!NeedsActiveStyleSheetUpdate()) {
    return;
  }

  DCHECK(!GetDocument().InStyleRecalc());
  DCHECK(GetDocument().IsActive());

  TRACE_EVENT0("blink,blink_style", "StyleEngine::updateActiveStyleSheets");

  if (user_style_dirty_) {
    UpdateActiveUserStyleSheets();
  }

  if (ShouldUpdateDocumentStyleSheetCollection()) {
    GetDocumentStyleSheetCollection().UpdateActiveStyleSheets(*this);
  }

  if (ShouldUpdateShadowTreeStyleSheetCollection()) {
    UnorderedTreeScopeSet tree_scopes_removed;
    for (TreeScope* tree_scope : dirty_tree_scopes_) {
      UpdateActiveStyleSheetsInShadow(tree_scope, tree_scopes_removed);
    }
    for (TreeScope* tree_scope : tree_scopes_removed) {
      active_tree_scopes_.erase(tree_scope);
    }
  }

  probe::ActiveStyleSheetsUpdated(document_);

  dirty_tree_scopes_.clear();
  document_scope_dirty_ = false;
  tree_scopes_removed_ = false;
  user_style_dirty_ = false;
}

void StyleEngine::UpdateCounterStyles() {
  if (!counter_styles_need_update_) {
    return;
  }
  CounterStyleMap::MarkAllDirtyCounterStyles(GetDocument(),
                                             active_tree_scopes_);
  CounterStyleMap::ResolveAllReferences(GetDocument(), active_tree_scopes_);
  counter_styles_need_update_ = false;
}

void StyleEngine::MarkPositionTryStylesDirty(
    const HeapHashSet<Member<RuleSet>>& changed_rule_sets) {
  for (RuleSet* rule_set : changed_rule_sets) {
    CHECK(rule_set);
    for (StyleRulePositionTry* try_rule : rule_set->PositionTryRules()) {
      if (try_rule) {
        dirty_position_try_names_.insert(try_rule->Name());
      }
    }
  }
  // TODO(crbug.com/1381623): Currently invalidating all elements in the
  // document with position-options, regardless of where the @position-try rules
  // are added. In order to make invalidation more targeted we would need to add
  // per tree-scope dirtiness, but also adding at-rules in one tree-scope may
  // affect multiple other tree scopes through :host, ::slotted, ::part,
  // exportparts, and inheritance. Doing that is going to be a lot more
  // complicated.
  position_try_styles_dirty_ = true;
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

void StyleEngine::InvalidatePositionTryStyles() {
  if (!position_try_styles_dirty_) {
    return;
  }
  position_try_styles_dirty_ = false;
  const bool mark_style_dirty = true;
  GetDocument().GetLayoutView()->InvalidateSubtreePositionTry(mark_style_dirty);
}

void StyleEngine::UpdateViewport() {
  if (viewport_resolver_) {
    viewport_resolver_->UpdateViewport();
  }
}

bool StyleEngine::NeedsActiveStyleUpdate() const {
  return (viewport_resolver_ && viewport_resolver_->NeedsUpdate()) ||
         NeedsActiveStyleSheetUpdate() ||
         (global_rule_set_ && global_rule_set_->IsDirty());
}

void StyleEngine::UpdateActiveStyle() {
  DCHECK(GetDocument().IsActive());
  DCHECK(IsMainThread());
  TRACE_EVENT0("blink", "Document::updateActiveStyle");
  InvalidationSetToSelectorMap::StartOrStopTrackingIfNeeded(*this);
  UpdateViewport();
  UpdateActiveStyleSheets();
  UpdateGlobalRuleSet();
}

const ActiveStyleSheetVector StyleEngine::ActiveStyleSheetsForInspector() {
  if (GetDocument().IsActive()) {
    UpdateActiveStyle();
  }

  if (active_tree_scopes_.empty()) {
    return GetDocumentStyleSheetCollection().ActiveStyleSheets();
  }

  ActiveStyleSheetVector active_style_sheets;

  active_style_sheets.AppendVector(
      GetDocumentStyleSheetCollection().ActiveStyleSheets());
  for (TreeScope* tree_scope : active_tree_scopes_) {
    if (TreeScopeStyleSheetCollection* collection =
            style_sheet_collection_map_.at(tree_scope)) {
      active_style_sheets.AppendVector(collection->ActiveStyleSheets());
    }
  }

  // FIXME: Inspector needs a vector which has all active stylesheets.
  // However, creating such a large vector might cause performance regression.
  // Need to implement some smarter solution.
  return active_style_sheets;
}

void StyleEngine::UpdateCounters() {
  if (!CountersChanged() || !GetDocument().documentElement()) {
    return;
  }
  counters_changed_ = false;
  CountersAttachmentContext context;
  context.SetAttachmentRootIsDocumentElement();
  UpdateCounters(*GetDocument().documentElement(), context);
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

// Recursively look for potential LayoutCounters to update,
// since in case of ::marker they can be deep child of original
// pseudo element's layout object.
void StyleEngine::UpdateLayoutCounters(const LayoutObject& layout_object,
                                       CountersAttachmentContext& context) {
  // Check out the parameter list ^^^
  for (LayoutObject* child = layout_object.NextInPreOrder(&layout_object);
       child; child = child->NextInPreOrder(&layout_object)) {
    if (auto* layout_counter = DynamicTo<LayoutCounter>(child)) {
      Vector<int> counter_values =
          context.GetCounterValues(layout_object, layout_counter->Identifier(),
                                   layout_counter->Separator().IsNull());
      layout_counter->UpdateCounter(std::move(counter_values));
    }
  }
}

void StyleEngine::UpdateCounters(const Element& element,
                                 CountersAttachmentContext& context) {
  LayoutObject* layout_object = element.GetLayoutObject();
  // Manually update list item ordinals here.
  if (layout_object) {
    context.EnterObject(*layout_object);
    if (auto* ng_list_item = DynamicTo<LayoutListItem>(layout_object)) {
      if (!ng_list_item->Ordinal().UseExplicitValue()) {
        ng_list_item->Ordinal().MarkDirty();
        ng_list_item->OrdinalValueChanged();
      }
    } else if (auto* inline_list_item =
                   DynamicTo<LayoutInlineListItem>(layout_object)) {
      if (!inline_list_item->Ordinal().UseExplicitValue()) {
        inline_list_item->Ordinal().MarkDirty();
        inline_list_item->OrdinalValueChanged();
      }
    }
    if (element.GetComputedStyle() &&
        !element.GetComputedStyle()->ContentBehavesAsNormal()) {
      UpdateLayoutCounters(*layout_object, context);
    }
  }
  for (Node* child = LayoutTreeBuilderTraversal::FirstChild(element); child;
       child = LayoutTreeBuilderTraversal::NextSibling(*child)) {
    if (Element* child_element = DynamicTo<Element>(child)) {
      UpdateCounters(*child_element, context);
    }
  }
  if (layout_object) {
    context.LeaveObject(*layout_object);
  }
}

void StyleEngine::ShadowRootInsertedToDocument(ShadowRoot& shadow_root) {
  DCHECK(shadow_root.isConnected());
  if (GetDocument().IsDetached() || !shadow_root.HasAdoptedStyleSheets()) {
    return;
  }
  EnsureStyleSheetCollectionFor(shadow_root);
  SetNeedsActiveStyleUpdate(shadow_root);
  active_tree_scopes_.insert(&shadow_root);
}

void StyleEngine::ShadowRootRemovedFromDocument(ShadowRoot* shadow_root) {
  style_sheet_collection_map_.erase(shadow_root);
  active_tree_scopes_.erase(shadow_root);
  dirty_tree_scopes_.erase(shadow_root);
  tree_scopes_removed_ = true;
  ResetAuthorStyle(*shadow_root);
}

void StyleEngine::ResetAuthorStyle(TreeScope& tree_scope) {
  ScopedStyleResolver* scoped_resolver = tree_scope.GetScopedStyleResolver();
  if (!scoped_resolver) {
    return;
  }

  if (global_rule_set_) {
    global_rule_set_->MarkDirty();
  }
  if (tree_scope.RootNode().IsDocumentNode()) {
    scoped_resolver->ResetStyle();
    return;
  }

  tree_scope.ClearScopedStyleResolver();
}

StyleContainmentScopeTree& StyleEngine::EnsureStyleContainmentScopeTree() {
  if (!style_containment_scope_tree_) {
    style_containment_scope_tree_ =
        MakeGarbageCollected<StyleContainmentScopeTree>();
  }
  return *style_containment_scope_tree_;
}

void StyleEngine::SetRuleUsageTracker(StyleRuleUsageTracker* tracker) {
  tracker_ = tracker;

  if (resolver_) {
    resolver_->SetRuleUsageTracker(tracker_);
  }
}

Font StyleEngine::ComputeFont(Element& element,
```