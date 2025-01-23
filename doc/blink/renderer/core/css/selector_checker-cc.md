Response:
The user wants to understand the functionality of the `selector_checker.cc` file in the Chromium Blink rendering engine. I need to:

1. **Identify the core purpose:**  Based on the file name and included headers, it's clear this file is responsible for checking if a given DOM element matches a CSS selector.
2. **Explain the relationship with HTML, CSS, and JavaScript:**
    - **HTML:** The selectors target HTML elements and their attributes.
    - **CSS:**  This file implements the CSS selector matching logic.
    - **JavaScript:** While this file isn't directly JavaScript, its functionality is crucial for the browser's ability to apply CSS styles to the DOM, which is often triggered or manipulated by JavaScript.
3. **Provide examples:** Illustrate how the selector checking works with concrete HTML, CSS, and potential JavaScript scenarios.
4. **Explain logical reasoning:**  Break down the matching process with hypothetical inputs and outputs.
5. **Describe common user/programming errors:**  Focus on mistakes related to CSS selector syntax or understanding how selectors are applied.
6. **Outline the debugging process:** Explain how a developer might end up investigating this file during debugging.
7. **Summarize the functionality:**  Provide a concise overview of the file's role.
这是 `blink/renderer/core/css/selector_checker.cc` 文件的第一部分，其主要功能是 **实现 CSS 选择器的匹配逻辑**。 换句话说，它负责判断一个特定的 DOM 元素是否与给定的 CSS 选择器相匹配。

以下是更详细的功能归纳以及与 HTML, CSS, JavaScript 的关系和举例说明：

**功能归纳：**

1. **核心的 CSS 选择器匹配引擎:**  这个文件包含了用于实现各种 CSS 选择器规则（例如：标签选择器、类选择器、ID 选择器、属性选择器、伪类、伪元素和各种组合器）的逻辑。
2. **遍历 DOM 树进行匹配:**  它需要能够根据选择器的规则，在 DOM 树中向上（祖先选择器）、向下（后代选择器）、向旁边（兄弟选择器）遍历元素以进行匹配。
3. **处理伪类和伪元素:**  实现了各种伪类（如 `:hover`, `:active`, `:first-child` 等）和伪元素（如 `::before`, `::after`, `::slotted` 等）的匹配逻辑。 这包括检查元素的状态、在 DOM 树中的位置以及其他特定条件。
4. **处理作用域 (Scoping):**  考虑了 CSS 作用域的概念，例如 `@scope` 规则，确保选择器在正确的上下文范围内进行匹配。
5. **处理 Shadow DOM:** 能够正确地处理 Shadow DOM 的边界，例如通过 `::slotted`, `::part`, `:host` 等伪元素和伪类进行匹配。
6. **支持动态伪类:**  能够处理依赖于运行时状态的伪类，例如 `:hover`（鼠标悬停）、`:focus`（元素获得焦点）等。
7. **处理 VTT (Video Text Tracks):**  包含针对 WebVTT 元素的特殊匹配逻辑。
8. **性能优化考量:**  虽然代码中没有直接体现，但作为渲染引擎的核心部分，该文件的实现会非常注重性能，以避免在复杂的页面上造成性能瓶颈。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML:**
    * **功能关系:**  `selector_checker.cc` 的核心任务是匹配 HTML 元素。
    * **举例:**  当 CSS 规则 `.my-class { color: red; }` 应用到一个 HTML 元素 `<div class="my-class"></div>` 时，`selector_checker.cc` 的代码会判断 `<div>` 元素是否具有 `my-class` 这个类名，从而决定是否应用该样式。
* **CSS:**
    * **功能关系:**  这个文件直接实现了 CSS 选择器的语法和匹配规则。
    * **举例:**  对于 CSS 选择器 `div p > span`,  `selector_checker.cc` 会先找到所有的 `div` 元素，然后在这些 `div` 元素下查找直接子元素 `p`，最后在这些 `p` 元素下查找直接子元素 `span`。
* **JavaScript:**
    * **功能关系:**  JavaScript 可以通过 DOM API 操作 HTML 结构和元素的属性。当 HTML 结构或元素属性发生变化时，浏览器需要重新进行样式计算和选择器匹配。此外，JavaScript 还可以通过 `querySelector` 和 `querySelectorAll` 等方法直接调用选择器匹配功能。
    * **举例:**  如果 JavaScript 代码执行了 `document.querySelector('.active')`,  浏览器会调用 `selector_checker.cc` 的相关代码来找到文档中第一个类名为 `active` 的元素。

**逻辑推理 (假设输入与输出):**

假设有以下 HTML 结构：

```html
<div id="container">
  <p class="text">
    <span>Hello</span>
  </p>
</div>
```

以及以下 CSS 规则：

```css
#container > p.text span {
  font-weight: bold;
}
```

**假设输入:**

* **元素:** `<span>Hello</span>` 这个 span 元素
* **选择器:** `#container > p.text span`

**逻辑推理过程 (简化):**

1. **最右侧选择器匹配 (`span`):**  首先检查当前元素 (`<span>`) 的标签名是否为 `span`，结果为真。
2. **组合器匹配 (`>`):**  检查当前元素的父元素 (`<p>`)。
3. **中间选择器匹配 (`p.text`):** 检查父元素 (`<p>`) 的标签名是否为 `p` 并且是否具有类名 `text`，结果为真。
4. **组合器匹配 (`>`):** 检查当前父元素的父元素 (`<div>`)。
5. **最左侧选择器匹配 (`#container`):** 检查父元素的父元素 (`<div>`) 的 ID 是否为 `container`，结果为真。

**输出:**

* **匹配结果:**  `<span>Hello</span>` 元素与选择器 `#container > p.text span` 匹配。

**用户或编程常见的使用错误举例说明：**

* **CSS 选择器语法错误:** 用户可能写出不符合 CSS 语法的选择器，例如 `#id .class#another-id` (ID 选择器后不能紧跟类选择器，除非有组合器)。`selector_checker.cc` 在解析和匹配这些选择器时可能会报错或产生意想不到的结果。
* **对伪类和伪元素的误解:** 用户可能不清楚某些伪类或伪元素的适用场景，例如在非表单元素上使用 `:checked` 伪类。`selector_checker.cc` 会根据规范进行匹配，可能导致样式不生效。
* **Shadow DOM 边界问题:**  开发者在操作 Shadow DOM 时，可能会不理解选择器的作用域，导致选择器无法穿透 Shadow DOM 边界，或者错误地跨越边界进行匹配。例如，在外部样式表中直接使用 `::slotted` 选择器可能无法匹配到 Shadow DOM 中的内容。

**用户操作如何一步步的到达这里作为调试线索：**

1. **用户在浏览器中打开一个网页:** 浏览器开始解析 HTML，构建 DOM 树。
2. **浏览器解析 CSS 样式:**  浏览器解析 CSS 文件或 `<style>` 标签中的样式规则，构建 CSSOM 树。
3. **样式计算:**  浏览器将 CSSOM 树与 DOM 树结合，计算每个元素的最终样式。  在这个过程中，`selector_checker.cc` 的代码会被大量调用，用于判断每个 CSS 规则是否适用于当前元素。
4. **渲染树构建:**  根据计算出的样式和 DOM 树，浏览器构建渲染树。
5. **布局和绘制:**  浏览器根据渲染树进行布局和绘制，将内容显示在屏幕上。

**调试线索:**

当开发者发现网页的样式与预期不符时，可能会进行以下调试：

* **检查 CSS 规则:**  使用浏览器的开发者工具查看应用的 CSS 规则，确认选择器是否正确。
* **检查元素:**  使用开发者工具查看元素的 Computed 样式，了解哪些 CSS 规则生效了，哪些没有生效。
* **断点调试:**  如果怀疑是选择器匹配逻辑的问题，开发者可能会尝试在 Blink 渲染引擎的 `selector_checker.cc` 文件中设置断点，逐步跟踪选择器的匹配过程，查看在哪个环节匹配失败，从而找到问题所在。例如，他们可能会怀疑某个伪类没有按预期工作，或者组合器的使用方式有误。

总而言之，`selector_checker.cc` 是 Blink 渲染引擎中一个至关重要的组件，它负责将 CSS 样式应用于正确的 HTML 元素，是实现网页样式渲染的核心逻辑。

### 提示词
```
这是目录为blink/renderer/core/css/selector_checker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 * Copyright (C) 2007, 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/selector_checker.h"

#include "base/auto_reset.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/core/css/check_pseudo_has_argument_context.h"
#include "third_party/blink/renderer/core/css/check_pseudo_has_cache_scope.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/part_names.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_scope_data.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/nth_index_cache.h"
#include "third_party/blink/renderer/core/dom/popover_data.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/picture_in_picture_controller.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_details_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_permission_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/fragment_anchor.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

static bool IsFrameFocused(const Element& element) {
  return element.GetDocument().GetFrame() && element.GetDocument()
                                                 .GetFrame()
                                                 ->Selection()
                                                 .FrameIsFocusedAndActive();
}

static bool MatchesSpatialNavigationFocusPseudoClass(const Element& element) {
  auto* option_element = DynamicTo<HTMLOptionElement>(element);
  return option_element && option_element->SpatialNavigationFocused() &&
         IsFrameFocused(element);
}

static bool MatchesHasDatalistPseudoClass(const Element& element) {
  auto* html_input_element = DynamicTo<HTMLInputElement>(element);
  return html_input_element && html_input_element->DataList();
}

static bool MatchesListBoxPseudoClass(const Element& element) {
  auto* html_select_element = DynamicTo<HTMLSelectElement>(element);
  return html_select_element && !html_select_element->UsesMenuList();
}

static bool MatchesMultiSelectFocusPseudoClass(const Element& element) {
  auto* option_element = DynamicTo<HTMLOptionElement>(element);
  return option_element && option_element->IsMultiSelectFocused() &&
         IsFrameFocused(element);
}

static bool MatchesTagName(const Element& element,
                           const QualifiedName& tag_q_name) {
  if (tag_q_name == AnyQName()) {
    return true;
  }
  const AtomicString& local_name = tag_q_name.LocalName();
  if (local_name != CSSSelector::UniversalSelectorAtom() &&
      local_name != element.localName()) {
    if (element.IsHTMLElement() || !IsA<HTMLDocument>(element.GetDocument())) {
      return false;
    }
    // Non-html elements in html documents are normalized to their camel-cased
    // version during parsing if applicable. Yet, type selectors are lower-cased
    // for selectors in html documents. Compare the upper case converted names
    // instead to allow matching SVG elements like foreignObject.
    if (element.TagQName().LocalNameUpper() != tag_q_name.LocalNameUpper()) {
      return false;
    }
  }
  const AtomicString& namespace_uri = tag_q_name.NamespaceURI();
  return namespace_uri == g_star_atom ||
         namespace_uri == element.namespaceURI();
}

static Element* ParentElement(
    const SelectorChecker::SelectorCheckingContext& context) {
  // - If context.scope is a shadow root, we should walk up to its shadow host.
  // - If context.scope is some element in some shadow tree and querySelector
  //   initialized the context, e.g. shadowRoot.querySelector(':host *'),
  //   (a) context.element has the same treescope as context.scope, need to walk
  //       up to its shadow host.
  //   (b) Otherwise, should not walk up from a shadow root to a shadow host.
  if (context.scope &&
      (context.scope == context.element->ContainingShadowRoot() ||
       context.scope->GetTreeScope() == context.element->GetTreeScope())) {
    return context.element->ParentOrShadowHostElement();
  }
  return context.element->parentElement();
}

// If context has scope, return slot that matches the scope, otherwise return
// the assigned slot for scope-less matching of ::slotted pseudo element.
static const HTMLSlotElement* FindSlotElementInScope(
    const SelectorChecker::SelectorCheckingContext& context) {
  if (!context.scope) {
    return context.element->AssignedSlot();
  }

  for (const HTMLSlotElement* slot = context.element->AssignedSlot(); slot;
       slot = slot->AssignedSlot()) {
    if (slot->GetTreeScope() == context.scope->GetTreeScope()) {
      return slot;
    }
  }
  return nullptr;
}

static inline bool NextSelectorExceedsScope(
    const SelectorChecker::SelectorCheckingContext& context) {
  if (context.scope && context.scope->IsInShadowTree()) {
    return context.element == context.scope->OwnerShadowHost();
  }

  return false;
}

static bool ShouldMatchHoverOrActive(
    const SelectorChecker::SelectorCheckingContext& context) {
  // If we're in quirks mode, then :hover and :active should never match anchors
  // with no href and *:hover and *:active should not match anything. This is
  // specified in https://quirks.spec.whatwg.org/#the-:active-and-:hover-quirk
  if (!context.element->GetDocument().InQuirksMode()) {
    return true;
  }
  if (context.is_sub_selector) {
    return true;
  }
  if (context.element->IsLink()) {
    return true;
  }
  const CSSSelector* selector = context.selector;
  while (selector->Relation() == CSSSelector::kSubSelector &&
         selector->NextSimpleSelector()) {
    selector = selector->NextSimpleSelector();
    if (selector->Match() != CSSSelector::kPseudoClass) {
      return true;
    }
    if (selector->GetPseudoType() != CSSSelector::kPseudoHover &&
        selector->GetPseudoType() != CSSSelector::kPseudoActive) {
      return true;
    }
  }
  return false;
}

static bool Impacts(const SelectorChecker::SelectorCheckingContext& context,
                    SelectorChecker::Impact impact) {
  return static_cast<int>(context.impact) & static_cast<int>(impact);
}

static bool ImpactsSubject(
    const SelectorChecker::SelectorCheckingContext& context) {
  return Impacts(context, SelectorChecker::Impact::kSubject);
}

static bool ImpactsNonSubject(
    const SelectorChecker::SelectorCheckingContext& context) {
  return Impacts(context, SelectorChecker::Impact::kNonSubject);
}

static bool IsFirstChild(const Element& element) {
  return !ElementTraversal::PreviousSibling(element);
}

static bool IsLastChild(const Element& element) {
  return !ElementTraversal::NextSibling(element);
}

static bool IsFirstOfType(const Element& element, const QualifiedName& type) {
  return !ElementTraversal::PreviousSibling(element, HasTagName(type));
}

static bool IsLastOfType(const Element& element, const QualifiedName& type) {
  return !ElementTraversal::NextSibling(element, HasTagName(type));
}

static void DisallowMatchVisited(
    SelectorChecker::SelectorCheckingContext& context) {
  context.had_match_visited |= context.match_visited;
  context.match_visited = false;
}

Element& SelectorChecker::SelectorCheckingContext::GetElementForMatching(
    wtf_size_t index) const {
  // If we don't match for pseudo element, just return element.
  if (!pseudo_element || index == kNotFound) {
    return *element;
  }
  // If we have exhausted the pseudo elements, return the last pseudo element,
  // to collect pseudo styles presence or pseudo class states.
  // This check is to prevent situations where selector for nested
  // pseudo elements is deeper than the one requested initially, it would be
  // marked as failing in other places, so just checking here.
  // E.g. when we match for #div::column, but selector is
  // #div::column::scroll-marker::marker, we would fail when going from
  // ::scroll-marker to ::marker.
  CHECK(index <= pseudo_element_ancestors.size());
  index = std::min(index, wtf_size_t(pseudo_element_ancestors.size()) - 1);
  return *pseudo_element_ancestors[index];
}

bool SelectorChecker::Match(const SelectorCheckingContext& context,
                            MatchResult& result) const {
  DCHECK(context.selector);
  DCHECK(!context.had_match_visited);
#if DCHECK_IS_ON()
  DCHECK(!inside_match_) << "Do not re-enter Match: use MatchSelector instead";
  base::AutoReset<bool> reset_inside_match(&inside_match_, true);
#endif  // DCHECK_IS_ON()

  if (context.vtt_originating_element) [[unlikely]] {
    // A kUAShadow combinator is required for VTT matching.
    if (context.selector->IsLastInComplexSelector()) {
      return false;
    }
  }
  // Don't try to match explicit non-pseudo element selectors for pseudo
  // elements.
  if (context.pseudo_element && !context.selector->MatchesPseudoElement() &&
      !context.selector->IsImplicit()) {
    return false;
  }
  return MatchSelector(context, result) == kSelectorMatches;
}

namespace {

bool NeedsScopeActivation(
    const SelectorChecker::SelectorCheckingContext& context) {
  // If we reach the end of the selector without handling context.style_scope,
  // it means that we didn't find any selectors with the IsScopeContaining
  // flag set, but we still need to ensure that we're in scope.
  // This can happen for stylesheets imported using "@import scope(...)".
  return context.style_scope && (context.selector->IsScopeContaining() ||
                                 context.selector->IsLastInComplexSelector());
}

}  // namespace

// Recursive check of selectors and combinators
// It can return 4 different values:
// * SelectorMatches          - the selector matches the element e
// * SelectorFailsLocally     - the selector fails for the element e
// * SelectorFailsAllSiblings - the selector fails for e and any sibling of e
// * SelectorFailsCompletely  - the selector fails for e and any sibling or
//   ancestor of e
SelectorChecker::MatchStatus SelectorChecker::MatchSelector(
    const SelectorCheckingContext& context,
    MatchResult& result) const {
  if (NeedsScopeActivation(context)) {
    // This function invokes`MatchSelector` again, but with context.scope
    // set to the appropriate scoping root.
    return MatchForScopeActivation(context, result);
  }
  SubResult sub_result(result);
  bool is_covered_by_bucketing =
      context.selector->IsCoveredByBucketing() &&
      !context
           .is_sub_selector &&  // Don't trust bucketing in sub-selectors; we
                                // may be in a child selector (a nested rule).
      !context.scope;           // May be featureless; see CheckOne().
#if DCHECK_IS_ON()
  SubResult dummy_result(result);
  if (is_covered_by_bucketing) {
    DCHECK(CheckOne(context, dummy_result))
        << context.selector->SimpleSelectorTextForDebug()
        << " unexpectedly didn't match element " << context.element;
    DCHECK_EQ(0, dummy_result.flags);
  }
#endif
  if (!is_covered_by_bucketing && !CheckOne(context, sub_result)) {
    return kSelectorFailsLocally;
  }

  // Doing it manually here instead of destructor as result is later used in
  // MatchForSubSelector below.
  sub_result.PropagatePseudoAncestorIndex();
  if (sub_result.dynamic_pseudo != kPseudoIdNone || context.pseudo_element) {
    result.dynamic_pseudo = sub_result.dynamic_pseudo;
    result.custom_highlight_name = std::move(sub_result.custom_highlight_name);
  }

  if (context.selector->IsLastInComplexSelector()) {
    return kSelectorMatches;
  }

  switch (context.selector->Relation()) {
    case CSSSelector::kSubSelector:
      return MatchForSubSelector(context, result);
    default: {
      if (NextSelectorExceedsScope(context)) {
        return kSelectorFailsCompletely;
      }

      if (context.pseudo_id != kPseudoIdNone &&
          context.pseudo_id != result.dynamic_pseudo) {
        return kSelectorFailsCompletely;
      }

      base::AutoReset<PseudoId> dynamic_pseudo_scope(&result.dynamic_pseudo,
                                                     kPseudoIdNone);
      return MatchForRelation(context, result);
    }
  }
}

static inline SelectorChecker::SelectorCheckingContext
PrepareNextContextForRelation(
    const SelectorChecker::SelectorCheckingContext& context) {
  SelectorChecker::SelectorCheckingContext next_context(context);
  DCHECK(context.selector->NextSimpleSelector());
  next_context.selector = context.selector->NextSimpleSelector();
  return next_context;
}

SelectorChecker::MatchStatus SelectorChecker::MatchForSubSelector(
    const SelectorCheckingContext& context,
    MatchResult& result) const {
  SelectorCheckingContext next_context = PrepareNextContextForRelation(context);

  // Index can be the size of the vector, which would mean we are
  // still at the last element. It's needed to mark that e.g. column pseudo
  // element has ::scroll-marker style in #div::column::scroll-marker selector,
  // when matching for column. But we can't go past the size of the vector: E.g.
  // #div::column::scroll-marker:focus matching for column pseudo element should
  // fail here, but it won't fail when matching the same selector for scroll
  // marker pseudo element that is generated by column pseudo element.
  if (next_context.pseudo_element &&
      result.pseudo_ancestor_index != kNotFound &&
      result.pseudo_ancestor_index >
          next_context.pseudo_element_ancestors.size()) {
    return MatchStatus::kSelectorFailsLocally;
  }

  PseudoId dynamic_pseudo = result.dynamic_pseudo;
  next_context.has_scrollbar_pseudo =
      dynamic_pseudo != kPseudoIdNone &&
      (scrollbar_ || dynamic_pseudo == kPseudoIdScrollbarCorner ||
       dynamic_pseudo == kPseudoIdResizer);

  // If we saw a pseudo element while not computing pseudo element styles, do
  // not try to match any simple selectors after the pseudo element as those
  // selectors need to match the actual pseudo element.
  //
  // Examples:
  //
  // span::selection:window-inactive {}
  // #id::before:initial {}
  // .class::before:hover {}
  //
  // In all of those cases we need to skip matching the pseudo classes after the
  // pseudo element on the originating element.
  if (context.in_rightmost_compound && dynamic_pseudo != kPseudoIdNone &&
      !context.pseudo_element && context.pseudo_id == kPseudoIdNone) {
    // We are in the rightmost compound and have matched a pseudo element
    // (dynamic_pseudo is not kPseudoIdNone), which means we are looking at
    // pseudo classes after the pseudo element. We are also matching the
    // originating element (context.pseudo_id is kPseudoIdnone), which means we
    // are matching for tracking the existence of such pseudo elements which
    // results in SetHasPseudoElementStyle() on the originating element's
    // ComputedStyle.
    if (!next_context.has_scrollbar_pseudo &&
        dynamic_pseudo == kPseudoIdScrollbar) {
      // Fail ::-webkit-scrollbar:hover because HasPseudoElementStyle for
      // scrollbars will remove the native scrollbar. Having only
      // ::-webkit-scrollbar rules that have pseudo class modifiers will end up
      // with not adding a custom scrollbar which means we end up with no
      // scrollbar.
      return kSelectorFailsCompletely;
    }
    // When matching for e.g. <div> and div::column::scroll-marker, set that
    // <div> has ::column style.
    if (next_context.selector->Match() == CSSSelector::kPseudoElement) {
      return kSelectorMatches;
    }
    // This means we will end up with false positives for pseudo elements like
    // ::before with only pseudo class modifiers where we end up trying to
    // create the pseudo element but end up not doing it because we have no
    // matching rules without modifiers. That is also already the case if you
    // have ::before elements without content properties.
    return kSelectorMatches;
  }

  next_context.previously_matched_pseudo_element = dynamic_pseudo;
  next_context.is_sub_selector = true;
  return MatchSelector(next_context, result);
}

SelectorChecker::MatchStatus SelectorChecker::MatchForScopeActivation(
    const SelectorCheckingContext& context,
    MatchResult& result) const {
  CHECK(context.style_scope);
  SelectorCheckingContext next_context = context;
  next_context.is_sub_selector = true;

  const StyleScopeActivations& activations =
      EnsureActivations(context, *context.style_scope);
  if (ImpactsSubject(context)) {
    // For e.g. @scope (:hover) { :scope { ...} },
    // the StyleScopeActivations may have stored MatchFlags that we
    // need to propagate. However, this is only needed if :scope
    // appears in the subject position, since MatchFlags are only
    // used for subject invalidation. Non-subject flags are set on
    // Elements directly (e.g. SetChildrenOrSiblingsAffectedByHover)
    result.flags |= activations.match_flags;
  }
  if (activations.vector.empty()) {
    return kSelectorFailsCompletely;
  }
  // Activations are stored in decreasing order of proxmity (parent
  // activations are added first in CalculateActivations, then any activation
  // for this element). We want to the most proximate match, hence traverse
  // activations in reverse order.
  for (const StyleScopeActivation& activation :
       base::Reversed(activations.vector)) {
    next_context.match_visited = context.match_visited;
    next_context.impact = context.impact;
    next_context.style_scope = nullptr;
    next_context.scope = activation.root;
    CHECK(!NeedsScopeActivation(next_context));  // Keeps recursing otherwise.
    if (MatchSelector(next_context, result) == kSelectorMatches) {
      result.proximity = activation.proximity;
      return kSelectorMatches;
    }
  }
  return kSelectorFailsLocally;
}

SelectorChecker::MatchStatus SelectorChecker::MatchForRelation(
    const SelectorCheckingContext& context,
    MatchResult& result) const {
  SelectorCheckingContext next_context = PrepareNextContextForRelation(context);

  CSSSelector::RelationType relation = context.selector->Relation();

  // Disable :visited matching when we see the first link or try to match
  // anything else than an ancestor.
  if ((!context.is_sub_selector || context.in_nested_complex_selector) &&
      (context.element->IsLink() || (relation != CSSSelector::kDescendant &&
                                     relation != CSSSelector::kChild))) {
    DisallowMatchVisited(next_context);
  }

  next_context.in_rightmost_compound = false;
  next_context.impact = Impact::kNonSubject;
  next_context.is_sub_selector = false;
  next_context.previous_element = context.element;
  next_context.pseudo_id = kPseudoIdNone;
  next_context.pseudo_element = nullptr;

  switch (relation) {
    case CSSSelector::kRelativeDescendant:
      DCHECK(result.has_argument_leftmost_compound_matches);
      result.has_argument_leftmost_compound_matches->push_back(context.element);
      [[fallthrough]];
    case CSSSelector::kDescendant:
      for (next_context.element = ParentElement(next_context);
           next_context.element;
           next_context.element = ParentElement(next_context)) {
        MatchStatus match = MatchSelector(next_context, result);
        if (match == kSelectorMatches || match == kSelectorFailsCompletely) {
          return match;
        }
        if (NextSelectorExceedsScope(next_context)) {
          return kSelectorFailsCompletely;
        }
        if (next_context.element->IsLink()) {
          DisallowMatchVisited(next_context);
        }
      }
      return kSelectorFailsCompletely;
    case CSSSelector::kRelativeChild:
      DCHECK(result.has_argument_leftmost_compound_matches);
      result.has_argument_leftmost_compound_matches->push_back(context.element);
      [[fallthrough]];
    case CSSSelector::kChild: {
      next_context.element = ParentElement(next_context);
      if (!next_context.element) {
        return kSelectorFailsCompletely;
      }
      return MatchSelector(next_context, result);
    }
    case CSSSelector::kRelativeDirectAdjacent:
      DCHECK(result.has_argument_leftmost_compound_matches);
      result.has_argument_leftmost_compound_matches->push_back(context.element);
      [[fallthrough]];
    case CSSSelector::kDirectAdjacent:
      if (mode_ == kResolvingStyle) {
        if (ContainerNode* parent =
                context.element->ParentElementOrShadowRoot()) {
          parent->SetChildrenAffectedByDirectAdjacentRules();
        }
      }
      next_context.element =
          ElementTraversal::PreviousSibling(*context.element);
      if (!next_context.element) {
        return kSelectorFailsAllSiblings;
      }
      return MatchSelector(next_context, result);
    case CSSSelector::kRelativeIndirectAdjacent:
      DCHECK(result.has_argument_leftmost_compound_matches);
      result.has_argument_leftmost_compound_matches->push_back(context.element);
      [[fallthrough]];
    case CSSSelector::kIndirectAdjacent:
      if (mode_ == kResolvingStyle) {
        if (ContainerNode* parent =
                context.element->ParentElementOrShadowRoot()) {
          parent->SetChildrenAffectedByIndirectAdjacentRules();
        }
      }
      next_context.element =
          ElementTraversal::PreviousSibling(*context.element);
      for (; next_context.element;
           next_context.element =
               ElementTraversal::PreviousSibling(*next_context.element)) {
        MatchStatus match = MatchSelector(next_context, result);
        if (match == kSelectorMatches || match == kSelectorFailsAllSiblings ||
            match == kSelectorFailsCompletely) {
          return match;
        }
      }
      return kSelectorFailsAllSiblings;

    case CSSSelector::kUAShadow: {
      // Note: context.scope should be non-null unless we're checking user or
      // UA origin rules, or VTT rules.  (We could CHECK() this if it weren't
      // for the user rules part.)

      // If we're in the same tree-scope as the scoping element, then following
      // a kUAShadow combinator would escape that and thus the scope.
      if (context.scope && context.scope->OwnerShadowHost() &&
          context.scope->OwnerShadowHost()->GetTreeScope() ==
              context.element->GetTreeScope()) {
        return kSelectorFailsCompletely;
      }

      Element* shadow_host = context.element->OwnerShadowHost();
      if (!shadow_host) {
        return kSelectorFailsCompletely;
      }
      // Match against featureless-like Element described by spec:
      // https://w3c.github.io/webvtt/#obtaining-css-boxes
      if (context.vtt_originating_element) {
        shadow_host = context.vtt_originating_element;
      }
      next_context.element = shadow_host;

      // If this is the *last* time that we cross shadow scopes, then make
      // sure that we've crossed *enough* shadow scopes.  This prevents
      // ::pseudo1 from matching in a scope where it shouldn't match but where
      // ::part(p)::pseudo1 or where ::pseudo2::pseudo1 should match.
      if (context.scope &&
          context.scope->GetTreeScope() !=
              next_context.element->GetTreeScope() &&
          !next_context.selector->CrossesTreeScopes()) {
        return kSelectorFailsCompletely;
      }

      return MatchSelector(next_context, result);
    }

    case CSSSelector::kShadowSlot: {
      if (ToHTMLSlotElementIfSupportsAssignmentOrNull(*context.element)) {
        return kSelectorFailsCompletely;
      }
      const HTMLSlotElement* slot = FindSlotElementInScope(context);
      if (!slot) {
        return kSelectorFailsCompletely;
      }

      next_context.element = const_cast<HTMLSlotElement*>(slot);
      return MatchSelector(next_context, result);
    }

    case CSSSelector::kShadowPart:
      // We ascend through ancestor shadow host elements until we reach the host
      // in the TreeScope associated with the style rule. We then match against
      // that host.
      while (true) {
        next_context.element = next_context.element->OwnerShadowHost();
        if (!next_context.element) {
          return kSelectorFailsCompletely;
        }

        // Generally a ::part() rule needs to be in the host’s tree scope, but
        // if (and only if) we are preceded by :host or :host(), then the rule
        // could also be in the same scope as the subject.
        TreeScope& host_tree_scope =
            next_context.selector->IsHostPseudoClass()
                ? *context.scope->GetTreeScope().ParentTreeScope()
                : context.scope->GetTreeScope();

        if (next_context.element->GetTreeScope() == host_tree_scope) {
          return MatchSelector(next_context, result);
        }
      }
    case CSSSelector::kSubSelector:
      break;
  }
  NOTREACHED();
}

static bool AttributeValueMatches(const Attribute& attribute_item,
                                  CSSSelector::MatchType match,
                                  const AtomicString& selector_value,
                                  bool case_insensitive) {
  const AtomicString& value = attribute_item.Value();
  switch (match) {
    case CSSSelector::kAttributeExact:
      // Comparing AtomicStrings for equality is very cheap,
      // so even for a case-insensitive match, we test that first.
      return selector_value == value ||
             (case_insensitive &&
              EqualIgnoringASCIICase(selector_value, value));
    case CSSSelector::kAttributeSet:
      return true;
    case CSSSelector::kAttributeList: {
      // Ignore empty selectors or selectors containing HTML spaces
      if (selector_value.empty() ||
          selector_value.Find(&IsHTMLSpace<UChar>) != kNotFound) {
        return false;
      }

      unsigned start_search_at = 0;
      while (true) {
        wtf_size_t found_pos = value.Find(
            selector_value, start_search_at,
            case_insensitive ? kTextCaseASCIIInsensitive : kTextCaseSensitive);
        if (found_pos == kNotFound) {
          return false;
        }
        if (!found_pos || IsHTMLSpace<UChar>(value[found_pos - 1])) {
          unsigned end_str = found_pos + selector_value.length();
          if (end_str == value.length() || IsHTMLSpace<UChar>(value[end_str])) {
            break;  // We found a match.
          }
        }

        // No match. Keep looking.
        start_search_at = found_pos + 1;
      }
      return true;
    }
    case CSSSelector::kAttributeContain:
      if (selector_value.empty()) {
        return false;
      }
      return value.Contains(selector_value, case_insensitive
                                                ? kTextCaseASCIIInsensitive
                                                : kTextCaseSensitive);
    case CSSSelector::kAttributeBegin:
      if (selector_value.empty()) {
        return false;
      }
      return value.StartsWith(selector_value, case_insensitive
                                                  ? kTextCaseASCIIInsensitive
                                                  : kTextCaseSensitive);
    case CSSSelector::kAttributeEnd:
      if (selector_value.empty()) {
        return false;
      }
      return value.EndsWith(selector_value, case_insensitive
                                                ? kTextCaseASCIIInsensitive
                                                : kTextCaseSensitive);
    case CSSSelector::kAttributeHyphen:
      if (value.length() < selector_value.length()) {
        return false;
      }
      if (!value.StartsWith(selector_value, case_insensitive
                                                ? kTextCaseASCIIInsensitive
                                                : kTextCaseSensitive)) {
        return false;
      }
      // It they start the same, check for exact match or following '-':
      if (value.length() != selector_value.length() &&
          value[selector_value.length()] != '-') {
        return false;
      }
      return true;
    default:
      NOTREACHED();
  }
}

static bool AnyAttributeMatches(Element& element,
                                CSSSelector::MatchType match,
                                const CSSSelector& selector) {
  const QualifiedName& selector_attr = selector.Attribu
```