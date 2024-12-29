Response:
My thought process for summarizing the `StyleResolver::ResolveStyle` function based on the provided code snippet goes like this:

1. **Identify the core task:** The filename `style_resolver.cc` and the function name `ResolveStyle` strongly suggest this function is responsible for determining the final styles applied to an element. The comments and includes within the file reinforce this idea, referencing CSS properties, rules, selectors, and animations.

2. **Scan for keywords and key concepts:** I look for recurring terms and important data structures. These include:
    * `ComputedStyle`: This likely represents the final, calculated style of an element.
    * `StyleResolverState`:  This appears to be a context object holding information needed during the style resolution process.
    * `ElementRuleCollector`:  This seems to gather relevant CSS rules that might apply to the current element.
    * `StyleCascade`: This is probably used to manage the order and precedence of CSS rules.
    * `CSSStyleRule`, `CSSSelector`:  These are fundamental CSS concepts related to defining and selecting styles.
    * `Animation`, `Transition`: The code explicitly deals with CSS animations and transitions.
    * `Pseudo-elements`: The code has logic for handling styles of pseudo-elements.
    * `Shadow DOM`, `Slotted`: There are clear references to Shadow DOM and the `slot` element, indicating this function handles styling within Shadow DOM.
    * `User-Agent Styles`, `Author Styles`: The code distinguishes between these different origins of styles.

3. **Analyze the function's steps (even without the full code):**  Based on the partial code and the identified concepts, I can infer a general flow:
    * **Initialization:** Set up the `StyleResolverState` and `ElementRuleCollector`.
    * **Rule Matching:**  The code contains several `Match...Rules` functions (e.g., `MatchHostRules`, `MatchSlottedRules`, `MatchVTTRules`, `MatchStyleAttribute`). This strongly implies the function iterates through different sources of CSS rules and identifies those that match the current element.
    * **Cascade Application:** The `StyleCascade` likely plays a role in resolving conflicts between matching rules based on specificity and origin.
    * **Style Calculation/Computation:**  The `ComputedStyleBuilder` and the assignment to `computed_style` indicate the process of calculating the final style values.
    * **Animation/Transition Handling:** There's explicit logic for dealing with animations and transitions.
    * **Pseudo-element Styling:**  The code specifically handles styling of pseudo-elements.
    * **Return Value:** The function returns a `ComputedStyle` object.

4. **Consider the relationships with HTML, CSS, and JavaScript:**
    * **HTML:** The function operates on `Element` objects, which are fundamental components of the HTML DOM. It also interacts with Shadow DOM features (`ShadowRoot`, `slot`).
    * **CSS:** This is the core domain of the function. It parses and applies CSS rules, handles selectors, and computes style properties.
    * **JavaScript:** While the provided snippet doesn't show direct JavaScript interaction, I know that JavaScript can manipulate the DOM and CSS styles, triggering style recalculations that would involve this function. Furthermore, CSSOM APIs allow JavaScript to inspect and modify styles.

5. **Think about potential errors and debugging:** The complexity of style resolution suggests potential for errors. Common user errors might involve incorrect CSS syntax, overly specific selectors, or unintended interactions between different style rules. For debugging, knowing this function is involved in the final style calculation is crucial. Stepping through the rule matching and cascade application would be key.

6. **Formulate the summary:** Based on these steps, I can create a concise summary highlighting the core responsibility of the `StyleResolver::ResolveStyle` function. I emphasize its role in taking an element and CSS rules as input and producing the final computed style. I also mention the involvement of related concepts like the cascade, animations, and Shadow DOM.

7. **Refine the summary:**  I make sure the language is clear and avoids overly technical jargon where possible. I also ensure that the summary addresses the specific requirements of the prompt (listing functionalities and their relation to HTML, CSS, and JavaScript).

By following these steps, I can extract the essential information and formulate a meaningful summary of the `StyleResolver::ResolveStyle` function even when presented with only a portion of the code. The key is to leverage the context provided by the filename, function name, included headers, and keywords within the code snippet.
这是 Blink 渲染引擎源代码文件 `blink/renderer/core/css/resolver/style_resolver.cc` 的第一部分，主要负责 CSS 样式的解析和计算。 从提供的代码片段来看，它的核心功能可以归纳如下：

**核心功能：CSS 样式解析和计算 (Style Resolution)**

`StyleResolver` 类是 Blink 渲染引擎中负责将 CSS 规则应用到 HTML 元素并计算出最终样式 (ComputedStyle) 的关键组件。 它完成了以下主要任务：

1. **收集匹配的 CSS 规则:**  根据元素的标签、类名、ID、伪类、属性等特征，以及 CSS 规则的选择器，找出所有适用于当前元素的 CSS 规则。这包括来自：
    * **User-Agent 样式表:** 浏览器默认的样式。
    * **作者样式表:** 开发者编写的 `<style>` 标签或外部 CSS 文件。
    * **内联样式:**  HTML 元素的 `style` 属性。
    * **Shadow DOM 样式:**  作用域样式和主机样式。
    * **VTT 样式:** 用于 WebVTT 字幕的样式。

2. **应用 CSS 规则并构建样式层叠 (Cascade):**  根据 CSS 的层叠规则 (specificity, origin, order)，对匹配的规则进行排序和应用，确定最终应用的属性值。

3. **计算最终样式 (ComputedStyle):**  将层叠后的样式属性值组合起来，计算出元素最终的渲染样式，包括颜色、字体、大小、布局等。

4. **处理 CSS 动画和过渡:**  检测和处理 CSS 动画和过渡效果，确保它们在样式解析过程中被考虑。

5. **处理伪元素:**  对元素的伪元素 (如 `::before`, `::after`, `::first-letter`) 应用相应的样式规则。

6. **处理 Shadow DOM:**  正确处理 Shadow DOM 中样式的作用域和继承关系，包括 `:host`, `:host-context`, `::slotted` 等伪类和伪元素。

7. **处理容器查询:** 评估容器查询条件，并应用相应的样式。

8. **处理锚点定位 (Anchor Positioning):** 解析和处理与锚点定位相关的 CSS 属性。

9. **处理 `@position-try` 规则:**  解析和处理 `@position-try` 规则，用于定义定位回退策略。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML:**  `StyleResolver` 接收 HTML 元素作为输入，并根据元素的属性 (如 `class`, `id`, `style`) 和在 DOM 树中的位置来查找和应用 CSS 规则。
    * **举例:** 当 HTML 中有 `<div class="container">` 时，`StyleResolver` 会查找 `.container` 选择器定义的 CSS 规则。

* **CSS:**  `StyleResolver` 的核心任务是解析和应用 CSS 规则。它处理各种 CSS 选择器、属性和值。
    * **举例:**  当 CSS 中有 `p { color: blue; }` 时，`StyleResolver` 会将颜色属性设置为蓝色应用到所有的 `<p>` 元素。

* **JavaScript:**  虽然 `StyleResolver` 本身是用 C++ 编写的，但它与 JavaScript 紧密相关。JavaScript 可以动态修改 HTML 结构和 CSS 样式，这些修改会触发 `StyleResolver` 重新计算样式。
    * **举例:**  当 JavaScript 使用 `element.style.color = 'red'` 修改元素样式时，会触发样式的重新计算。
    * **举例:**  当 JavaScript 使用 `element.classList.add('active')` 添加类名时，会触发 `StyleResolver` 重新评估与 `.active` 类相关的 CSS 规则。

**逻辑推理的假设输入与输出:**

假设输入一个 `<div>` 元素，其 `class` 属性为 "box"，并且存在以下 CSS 规则：

```css
.box {
  width: 100px;
  height: 100px;
  background-color: red;
}

div {
  border: 1px solid black;
}
```

**假设输入:**  一个 `<div>` 元素，`element->tagName() == "div"`, `element->hasClass("box") == true`

**逻辑推理过程:**

1. `StyleResolver` 会查找所有与 `<div>` 元素匹配的 CSS 规则。
2. 它会匹配到 `.box` 选择器和 `div` 选择器。
3. 根据 CSS 的 specificity 规则，`.box` 选择器比 `div` 选择器更具体。
4. 因此，来自 `.box` 规则的 `width`, `height`, `background-color` 属性值会被应用。
5. 来自 `div` 规则的 `border` 属性值也会被应用。

**假设输出 (部分 ComputedStyle):**

```
width: 100px;
height: 100px;
background-color: red;
border-top-width: 1px;
border-right-width: 1px;
border-bottom-width: 1px;
border-left-width: 1px;
border-top-style: solid;
border-right-style: solid;
border-bottom-style: solid;
border-left-style: solid;
border-top-color: black;
border-right-color: black;
border-bottom-color: black;
border-left-color: black;
```

**用户或编程常见的使用错误及举例:**

* **CSS 语法错误:**  如果 CSS 规则中有语法错误，`StyleResolver` 可能无法正确解析，导致样式不生效或产生意外效果。
    * **举例:**  `color: roouge;` (错误的颜色值)。
* **选择器优先级问题:**  开发者可能不理解 CSS 选择器的优先级规则，导致期望的样式被其他优先级更高的规则覆盖。
    * **举例:**  同时定义了 `div { color: blue; }` 和 `#myDiv { color: red; }`，如果一个 `id` 为 "myDiv" 的 `<div>` 元素，其颜色将是红色，而不是蓝色。
* **拼写错误:**  CSS 属性或值的拼写错误会导致样式无法应用。
    * **举例:**  `text-aligh: center;` (应为 `text-align`)。
* **Shadow DOM 样式作用域问题:**  在 Shadow DOM 中，样式的作用域受到限制，如果开发者不理解作用域规则，可能会导致样式无法正确应用到 Shadow Root 中的元素。
    * **举例:**  尝试在外部样式表中直接选择 Shadow DOM 内部的元素，而没有使用 `:host` 或 `::slotted`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户加载网页:** 当用户在浏览器中输入网址或点击链接时，浏览器开始加载 HTML 文档。
2. **HTML 解析:**  Blink 引擎解析 HTML 文档，构建 DOM 树。
3. **CSS 解析:**  Blink 引擎解析 HTML 中引用的 CSS 文件和 `<style>` 标签中的 CSS 规则。
4. **样式计算触发:** 当 DOM 树构建完成或 CSS 规则加载完成后，或者当元素的样式需要更新时 (例如，添加了类名，修改了 `style` 属性，触发了伪类状态)，Blink 引擎会触发样式计算。
5. **`StyleResolver::ResolveStyle` 调用:**  在样式计算过程中，Blink 引擎会遍历 DOM 树，并为每个需要计算样式的元素调用 `StyleResolver::ResolveStyle` 函数。
6. **规则匹配和应用:**  `ResolveStyle` 函数会根据元素的特征和 CSS 规则的选择器，收集匹配的 CSS 规则，并根据层叠规则应用它们。
7. **ComputedStyle 生成:**  最终，`ResolveStyle` 函数会计算出元素的 `ComputedStyle` 对象，其中包含了元素所有生效的样式属性值。
8. **渲染:**  渲染引擎使用 `ComputedStyle` 信息来布局和绘制网页。

**总结 (针对第 1 部分):**

`blink/renderer/core/css/resolver/style_resolver.cc` 文件的这一部分定义了 `StyleResolver` 类的核心功能，即负责 CSS 样式的解析和计算。 它接收 HTML 元素作为输入，结合 CSS 规则，根据 CSS 的层叠规则计算出元素最终的渲染样式 (ComputedStyle)。这个过程是网页渲染的关键步骤，涉及到 HTML 结构、CSS 样式和可能的 JavaScript 交互。 理解 `StyleResolver` 的工作原理对于理解浏览器如何呈现网页至关重要，并且可以帮助开发者调试 CSS 相关的问题。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
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
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"

#include <optional>

#include "base/containers/adapters.h"
#include "base/types/optional_util.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_value_factory.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/invalidatable_interpolation.h"
#include "third_party/blink/renderer/core/css/anchor_evaluator.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/container_query_evaluator.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_inherited_value.h"
#include "third_party/blink/renderer/core/css/css_initial_color_value.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_position_try_rule.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_selector_watch.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/element_rule_collector.h"
#include "third_party/blink/renderer/core/css/font_face.h"
#include "third_party/blink/renderer/core/css/out_of_flow_data.h"
#include "third_party/blink/renderer/core/css/page_margins_style.h"
#include "third_party/blink/renderer/core/css/page_rule_collector.h"
#include "third_party/blink/renderer/core/css/part_names.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_filter.h"
#include "third_party/blink/renderer/core/css/resolver/match_result.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/selector_filter_parent_scope.h"
#include "third_party/blink/renderer/core/css/resolver/style_adjuster.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/resolver/style_cascade.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_stats.h"
#include "third_party/blink/renderer/core/css/resolver/style_rule_usage_tracker.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule_import.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/first_letter_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/space_split_string.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html/track/text_track.h"
#include "third_party/blink/renderer/core/html/track/text_track_cue.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_cue.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/mathml/mathml_fraction_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_operator_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_padded_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_space_element.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/media_type_names.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/style_initial_data.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

bool ShouldStoreOldStyle(const StyleRecalcContext& style_recalc_context,
                         StyleResolverState& state) {
  // Storing the old style is only relevant if we risk computing the style
  // more than once for the same element. This can happen if we are currently
  // inside a size query container, or doing multiple style resolutions for
  // position-try-fallbacks.
  //
  // For anchored elements that generate pseudo elements, we also need to store
  // the old style for animating pseudo elements because style recalc for the
  // originating anchored elements will always update its pseudo elements,
  // causing the pseudo element styling to also have multiple passes.
  //
  // If we are not inside a size query container or an element with
  // position-try-fallbacks, we can fall back to the default behavior (in
  // CSSAnimations) of using the current style on Element as the old style.
  //
  // TODO(crbug.com/40943044): We also need to check whether we are a descendant
  // of an element with position-try-fallbacks to cover the case where the
  // descendant explicitly inherits insets or other valid @position-try
  // properties from the element with position-try-fallbacks. This applies to
  // descendants of elements with anchor queries as well.
  return (style_recalc_context.container ||
          state.StyleBuilder().HasAnchorFunctions() ||
          state.StyleBuilder().PositionAnchor() ||
          ((state.GetElement().IsPseudoElement() ||
            state.IsForPseudoElement()) &&
           (state.ParentStyle()->HasAnchorFunctions() ||
            state.ParentStyle()->PositionAnchor())) ||
          state.StyleBuilder().GetPositionTryFallbacks() != nullptr) &&
         state.CanAffectAnimations();
}

bool ShouldSetPendingUpdate(StyleResolverState& state, Element& element) {
  if (!state.AnimationUpdate().IsEmpty()) {
    return true;
  }
  // Even when the animation update is empty, we must still set the pending
  // update in order to clear PreviousActiveInterpolationsForAnimations.
  //
  // See CSSAnimations::MaybeApplyPendingUpdate
  if (const ElementAnimations* element_animations =
          element.GetElementAnimations()) {
    return element_animations->CssAnimations()
        .HasPreviousActiveInterpolationsForAnimations();
  }
  return false;
}

void SetAnimationUpdateIfNeeded(const StyleRecalcContext& style_recalc_context,
                                StyleResolverState& state,
                                Element& element) {
  if (auto* data = PostStyleUpdateScope::CurrentAnimationData()) {
    if (ShouldStoreOldStyle(style_recalc_context, state)) {
      data->StoreOldStyleIfNeeded(element);
    }
  }

  // If any changes to CSS Animations were detected, stash the update away for
  // application after the layout object is updated if we're in the appropriate
  // scope.
  if (!ShouldSetPendingUpdate(state, element)) {
    return;
  }

  if (auto* data = PostStyleUpdateScope::CurrentAnimationData()) {
    data->SetPendingUpdate(element, state.AnimationUpdate());
  }
}

ElementAnimations* GetElementAnimations(const StyleResolverState& state) {
  if (!state.GetAnimatingElement()) {
    return nullptr;
  }
  return state.GetAnimatingElement()->GetElementAnimations();
}

const Element& UltimateOriginatingElementOrSelf(const Element& element) {
  if (!element.IsPseudoElement()) {
    return element;
  }
  return *To<PseudoElement>(element).UltimateOriginatingElement();
}

bool HasAnimationsOrTransitions(const StyleResolverState& state) {
  return state.StyleBuilder().Animations() ||
         state.StyleBuilder().Transitions() ||
         (state.GetAnimatingElement() &&
          state.GetAnimatingElement()->HasAnimations());
}

bool HasTimelines(const StyleResolverState& state) {
  if (state.StyleBuilder().ScrollTimelineName()) {
    return true;
  }
  if (state.StyleBuilder().ViewTimelineName()) {
    return true;
  }
  if (state.StyleBuilder().TimelineScope()) {
    return true;
  }
  if (ElementAnimations* element_animations = GetElementAnimations(state)) {
    return element_animations->CssAnimations().HasTimelines();
  }
  return false;
}

bool IsAnimationStyleChange(Element& element) {
  if (auto* element_animations = element.GetElementAnimations()) {
    return element_animations->IsAnimationStyleChange();
  }
  return false;
}

#if DCHECK_IS_ON()
// Compare the base computed style with the one we compute to validate that the
// optimization is sound. A return value of g_null_atom means the diff was
// empty (which is what we want).
String ComputeBaseComputedStyleDiff(const ComputedStyle* base_computed_style,
                                    const ComputedStyle& computed_style) {
  using DebugDiff = ComputedStyleBase::DebugDiff;
  using DebugField = ComputedStyleBase::DebugField;

  if (!base_computed_style) {
    return g_null_atom;
  }
  if (*base_computed_style == computed_style) {
    return g_null_atom;
  }

  HashSet<DebugField> exclusions;

  // Under certain conditions ComputedStyle::operator==() may return false for
  // differences that are permitted during an animation.
  // The FontFaceCache version number may be increased without forcing a style
  // recalc (see crbug.com/471079).
  if (!base_computed_style->GetFont().IsFallbackValid()) {
    exclusions.insert(DebugField::font_);
  }

  // Images use instance equality rather than value equality (see
  // crbug.com/781461).
  if (!CSSPropertyEquality::PropertiesEqual(
          PropertyHandle(CSSProperty::Get(CSSPropertyID::kBackgroundImage)),
          *base_computed_style, computed_style)) {
    exclusions.insert(DebugField::background_);
  }
  if (!CSSPropertyEquality::PropertiesEqual(
          PropertyHandle(CSSProperty::Get(CSSPropertyID::kMaskImage)),
          *base_computed_style, computed_style)) {
    exclusions.insert(DebugField::mask_);
  }
  if (!CSSPropertyEquality::PropertiesEqual(
          PropertyHandle(CSSProperty::Get(CSSPropertyID::kBorderImageSource)),
          *base_computed_style, computed_style)) {
    exclusions.insert(DebugField::border_image_);
  }

  // clip_path_ too, for the reference.
  if (!CSSPropertyEquality::PropertiesEqual(
          PropertyHandle(CSSProperty::Get(CSSPropertyID::kClipPath)),
          *base_computed_style, computed_style)) {
    exclusions.insert(DebugField::clip_path_);
  }

  // Changes to this flag caused by history.pushState do not always mark
  // for recalc in time, yet VisitedLinkState::DetermineLinkState will provide
  // the up-to-date answer when polled.
  //
  // See crbug.com/1158076.
  exclusions.insert(DebugField::inside_link_);

  // HighlightData is calculated after StyleResolver::ResolveStyle, hence any
  // freshly resolved style for diffing purposes will not contain the updated
  // HighlightData. We can safely ignore this because animations and inline
  // styles do not affect the presence or absence of the various highlight
  // styles, and we will invariably update those styles when we return to
  // RecalcOwnStyle, regardless of how ResolveStyle produces its result.
  exclusions.insert(DebugField::highlight_data_);

  Vector<DebugDiff> diff = base_computed_style->DebugDiffFields(computed_style);

  StringBuilder builder;

  for (const DebugDiff& d : diff) {
    if (exclusions.Contains(d.field)) {
      continue;
    }
    builder.Append(ComputedStyleBase::DebugFieldToString(d.field));
    builder.Append("(was ");
    builder.Append(d.actual.c_str());
    builder.Append(", should be ");
    builder.Append(d.correct.c_str());
    builder.Append(") ");
  }

  if (builder.empty()) {
    return g_null_atom;
  }

  return String("Field diff: ") + builder.ReleaseString();
}
#endif  // DCHECK_IS_ON()

// When force-computing the base computed style for validation purposes,
// we need to reset the StyleCascade when the base computed style optimization
// is used. This is because we don't want the computation of the base to
// populate the cascade, as they are supposed to be empty when the optimization
// is in use. This is to match the behavior of non-DCHECK builds.
void MaybeResetCascade(StyleCascade& cascade) {
#if DCHECK_IS_ON()
  cascade.Reset();
#endif  // DCHECK_IS_ON()
}

bool TextAutosizingMultiplierChanged(const StyleResolverState& state,
                                     const ComputedStyle& base_computed_style) {
  // Note that |old_style| can be a style replaced by
  // TextAutosizer::ApplyMultiplier.
  const ComputedStyle* old_style = state.GetElement().GetComputedStyle();
  return old_style && (old_style->TextAutosizingMultiplier() !=
                       base_computed_style.TextAutosizingMultiplier());
}

PseudoId GetPseudoId(const Element& element, ElementRuleCollector* collector) {
  if (element.IsPseudoElement()) {
    return element.GetPseudoIdForStyling();
  }

  return collector ? collector->GetPseudoId() : kPseudoIdNone;
}

void UseCountLegacyOverlapping(Document& document,
                               const ComputedStyle& a,
                               const ComputedStyleBuilder& b) {
  if (a.PerspectiveOrigin() != b.PerspectiveOrigin()) {
    document.CountUse(WebFeature::kCSSLegacyPerspectiveOrigin);
  }
  if (a.GetTransformOrigin() != b.GetTransformOrigin()) {
    document.CountUse(WebFeature::kCSSLegacyTransformOrigin);
  }
  if (a.BorderImage() != b.BorderImage()) {
    document.CountUse(WebFeature::kCSSLegacyBorderImage);
  }
  if ((a.BorderTopWidth() != b.BorderTopWidth()) ||
      (a.BorderRightWidth() != b.BorderRightWidth()) ||
      (a.BorderBottomWidth() != b.BorderBottomWidth()) ||
      (a.BorderLeftWidth() != b.BorderLeftWidth())) {
    document.CountUse(WebFeature::kCSSLegacyBorderImageWidth);
  }
}

void ApplyLengthConversionFlags(StyleResolverState& state) {
  using Flags = CSSToLengthConversionData::Flags;
  using Flag = CSSToLengthConversionData::Flag;

  Flags flags = state.TakeLengthConversionFlags();
  if (!flags) {
    return;
  }

  ComputedStyleBuilder& builder = state.StyleBuilder();

  if (flags & static_cast<Flags>(Flag::kEm)) {
    builder.SetHasEmUnits();
  }
  if (flags & static_cast<Flags>(Flag::kRootFontRelative)) {
    builder.SetHasRootFontRelativeUnits();
  }
  if (flags & static_cast<Flags>(Flag::kGlyphRelative)) {
    builder.SetHasGlyphRelativeUnits();
  }
  if (flags & static_cast<Flags>(Flag::kStaticViewport)) {
    builder.SetHasStaticViewportUnits();
  }
  if (flags & static_cast<Flags>(Flag::kDynamicViewport)) {
    builder.SetHasDynamicViewportUnits();
  }
  if (flags & static_cast<Flags>(Flag::kContainerRelative)) {
    builder.SetDependsOnSizeContainerQueries(true);
    builder.SetHasContainerRelativeUnits();
  }
  if (flags & static_cast<Flags>(Flag::kTreeScopedReference)) {
    state.SetHasTreeScopedReference();
  }
  if (flags & static_cast<Flags>(Flag::kAnchorRelative)) {
    builder.SetHasAnchorFunctions();
  }
  if (flags & static_cast<Flags>(Flag::kLogicalDirectionRelative)) {
    builder.SetHasLogicalDirectionRelativeUnits();
  }
  if (flags & static_cast<Flags>(Flag::kCapRelative)) {
    UseCounter::Count(state.GetDocument(), WebFeature::kHasCapUnits);
  }
  if (flags & static_cast<Flags>(Flag::kRcapRelative)) {
    UseCounter::Count(state.GetDocument(), WebFeature::kHasRcapUnits);
  }
  if (flags & static_cast<Flags>(Flag::kIcRelative)) {
    UseCounter::Count(state.GetDocument(), WebFeature::kHasIcUnits);
  }
  if (flags & static_cast<Flags>(Flag::kRicRelative)) {
    UseCounter::Count(state.GetDocument(), WebFeature::kHasRicUnits);
  }
  if (flags & static_cast<Flags>(Flag::kLhRelative)) {
    builder.SetHasLineHeightRelativeUnits();
    UseCounter::Count(state.GetDocument(), WebFeature::kHasLhUnits);
  }
  if (flags & static_cast<Flags>(Flag::kRlhRelative)) {
    builder.SetHasLineHeightRelativeUnits();
    UseCounter::Count(state.GetDocument(), WebFeature::kHasRlhUnits);
  }
  if (flags & static_cast<Flags>(Flag::kChRelative)) {
    UseCounter::Count(state.GetDocument(), WebFeature::kHasChUnits);
  }
  if (flags & static_cast<Flags>(Flag::kRchRelative)) {
    UseCounter::Count(state.GetDocument(), WebFeature::kHasRchUnits);
  }
  if (flags & static_cast<Flags>(Flag::kSiblingRelative)) {
    builder.SetHasSiblingFunctions();
  }
}

}  // namespace

static CSSPropertyValueSet* LeftToRightDeclaration() {
  DEFINE_STATIC_LOCAL(
      Persistent<MutableCSSPropertyValueSet>, left_to_right_decl,
      (MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode)));
  if (left_to_right_decl->IsEmpty()) {
    left_to_right_decl->SetLonghandProperty(CSSPropertyID::kDirection,
                                            CSSValueID::kLtr);
  }
  return left_to_right_decl;
}

static CSSPropertyValueSet* RightToLeftDeclaration() {
  DEFINE_STATIC_LOCAL(
      Persistent<MutableCSSPropertyValueSet>, right_to_left_decl,
      (MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode)));
  if (right_to_left_decl->IsEmpty()) {
    right_to_left_decl->SetLonghandProperty(CSSPropertyID::kDirection,
                                            CSSValueID::kRtl);
  }
  return right_to_left_decl;
}

static CSSPropertyValueSet* DocumentElementUserAgentDeclarations() {
  DEFINE_STATIC_LOCAL(
      Persistent<MutableCSSPropertyValueSet>, document_element_ua_decl,
      (MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode)));
  if (document_element_ua_decl->IsEmpty()) {
    document_element_ua_decl->SetProperty(CSSPropertyID::kColor,
                                          *CSSInitialColorValue::Create());
  }
  return document_element_ua_decl;
}

// The 'color' property conditionally inherits from the *used* value of its
// parent, and we rely on an explicit value in the cascade to implement this.
// https://drafts.csswg.org/css-color-adjust-1/#propdef-forced-color-adjust
static CSSPropertyValueSet* ForcedColorsUserAgentDeclarations() {
  DEFINE_STATIC_LOCAL(
      Persistent<MutableCSSPropertyValueSet>, decl,
      (MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode)));
  if (decl->IsEmpty()) {
    decl->SetProperty(CSSPropertyID::kColor, *CSSInheritedValue::Create());
  }
  return decl;
}

// UA rule: * { overlay: none !important }
static CSSPropertyValueSet* UniversalOverlayUserAgentDeclaration() {
  DEFINE_STATIC_LOCAL(
      Persistent<MutableCSSPropertyValueSet>, decl,
      (MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode)));

  if (decl->IsEmpty()) {
    decl->SetProperty(CSSPropertyID::kOverlay,
                      *CSSIdentifierValue::Create(CSSValueID::kNone),
                      true /* important */);
  }
  return decl;
}

// UA rule: ::scroll-marker-group { contain: layout size !important; }
// The generation of ::scroll-marker pseudo-elements
// cannot invalidate layout outside of this pseudo-element.
static CSSPropertyValueSet* ScrollMarkerGroupUserAgentDeclaration() {
  DEFINE_STATIC_LOCAL(
      Persistent<MutableCSSPropertyValueSet>, decl,
      (MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode)));

  if (decl->IsEmpty()) {
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kLayout));
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kSize));
    decl->SetProperty(CSSPropertyID::kContain, *list, /*important=*/true);
  }
  return decl;
}

static void CollectScopedResolversForHostedShadowTrees(
    const Element& element,
    HeapVector<Member<ScopedStyleResolver>, 8>& resolvers) {
  ShadowRoot* root = element.GetShadowRoot();
  if (!root) {
    return;
  }

  // Adding scoped resolver for active shadow roots for shadow host styling.
  if (ScopedStyleResolver* resolver = root->GetScopedStyleResolver()) {
    resolvers.push_back(resolver);
  }
}

StyleResolver::StyleResolver(Document& document)
    : initial_style_(ComputedStyle::GetInitialStyleSingleton()),
      initial_style_for_img_(ComputedStyle::GetInitialStyleForImgSingleton()),
      document_(document) {
  UpdateMediaType();
}

StyleResolver::~StyleResolver() = default;

void StyleResolver::Dispose() {
  matched_properties_cache_.Clear();
}

void StyleResolver::SetRuleUsageTracker(StyleRuleUsageTracker* tracker) {
  tracker_ = tracker;
}

namespace {

inline ScopedStyleResolver* ScopedResolverFor(const Element& element) {
  TreeScope* tree_scope = &element.GetTreeScope();
  if (ScopedStyleResolver* resolver = tree_scope->GetScopedStyleResolver()) {
    DCHECK(!element.IsVTTElement());
    return resolver;
  }

  return nullptr;
}

inline bool UseParentResolverForUAShadowPseudo(
    const Element& element,
    bool* style_attribute_cascaded_in_parent_scope) {
  // Rules for ::cue and custom pseudo elements like
  // ::-webkit-meter-bar pierce through a single shadow dom boundary and apply
  // to elements in sub-scopes.
  TreeScope* tree_scope = element.GetTreeScope().ParentTreeScope();
  if (!tree_scope) {
    return false;
  }
  const AtomicString& shadow_pseudo_id = element.ShadowPseudoId();
  bool is_vtt = element.IsVTTElement();
  if (shadow_pseudo_id.empty() && !is_vtt) {
    return false;
  }
  ScopedStyleResolver* parent_resolver = tree_scope->GetScopedStyleResolver();
  if (!parent_resolver) {
    return true;
  }
  // Going forward, for shadow pseudo IDs that we standardize as
  // pseudo-elements, we expect styles specified by the author using the
  // pseudo-element to override styles specified in style attributes in
  // the user agent shadow DOM.  However, since we have a substantial
  // number of existing uses with :-webkit-* and :-internal-* pseudo
  // elements that do not override the style attribute, we do not apply
  // this (developer-expected) behavior to those existing
  // pseudo-elements.  (It's possible that we could, but it would
  // require a good bit of compatibility analysis.)
  DCHECK(shadow_pseudo_id.empty() || !shadow_pseudo_id.StartsWith("-") ||
         shadow_pseudo_id.StartsWith("-webkit-") ||
         shadow_pseudo_id.StartsWith("-internal-"))
      << "shadow pseudo IDs should either begin with -webkit- or -internal- "
         "or not begin with a -";
  *style_attribute_cascaded_in_parent_scope = shadow_pseudo_id.StartsWith("-");
  return true;
}

// Matches :host and :host-context rules if the element is a shadow host.
// It matches rules from the ShadowHostRules of the ScopedStyleResolver
// of the attached shadow root.
void MatchHostRules(const Element& element,
                    ElementRuleCollector& collector,
                    StyleRuleUsageTracker* tracker) {
  ShadowRoot* shadow_root = element.GetShadowRoot();
  ScopedStyleResolver* resolver =
      shadow_root ? shadow_root->GetScopedStyleResolver() : nullptr;
  if (!resolver) {
    return;
  }
  collector.ClearMatchedRules();
  collector.BeginAddingAuthorRulesForTreeScope(resolver->GetTreeScope());
  resolver->CollectMatchingShadowHostRules(collector);
  collector.SortAndTransferMatchedRules(
      CascadeOrigin::kAuthor, /*is_vtt_embedded_style=*/false, tracker);
}

void MatchSlottedRules(const Element&,
                       ElementRuleCollector&,
                       StyleRuleUsageTracker* tracker);
void MatchSlottedRulesForUAHost(const Element& element,
                                ElementRuleCollector& collector,
                                StyleRuleUsageTracker* tracker) {
  if (element.ShadowPseudoId() !=
      shadow_element_names::kPseudoInputPlaceholder) {
    return;
  }

  // We allow ::placeholder pseudo element after ::slotted(). Since we are
  // matching such pseudo elements starting from inside the UA shadow DOM of
  // the element having the placeholder, we need to match ::slotted rules from
  // the scopes to which the placeholder's host element may be slotted.
  //
  // Example:
  //
  // <div id=host>
  //   <:shadow-root>
  //     <style>::slotted(input)::placeholder { color: green }</style>
  //     <slot />
  //   </:shadow-root>
  //   <input placeholder="PLACEHOLDER-TEXT">
  //     <:ua-shadow-root>
  //       ... <placeholder>PLACEHOLDER-TEXT</placeholder> ...
  //     </:ua-shadow-root>
  //   </input>
  // </div>
  //
  // Here we need to match the ::slotted rule from the #host shadow tree where
  // the input is slotted on the placeholder element.
  DCHECK(element.OwnerShadowHost());
  MatchSlottedRules(*element.OwnerShadowHost(), collector, tracker);
}

// Matches `::slotted` selectors. It matches rules in the element's slot's
// scope. If that slot is itself slotted it will match rules in the slot's
// slot's scope and so on. The result is that it considers a chain of scopes
// descending from the element's own scope.
void MatchSlottedRules(const Element& element,
                       ElementRuleCollector& collector,
                       StyleRuleUsageTracker* tracker) {
  MatchSlottedRulesForUAHost(element, collector, tracker);
  HeapVector<std::pair<Member<HTMLSlotElement>, Member<ScopedStyleResolver>>>
      resolvers;
  {
    HTMLSlotElement* slot = element.AssignedSlot();
    if (!slot) {
      return;
    }

    for (; slot; slot = slot->AssignedSlot()) {
      if (ScopedStyleResolver* resolver =
              slot->GetTreeScope().GetScopedStyleResolver()) {
        resolvers.push_back(std::make_pair(slot, resolver));
      }
    }
  }

  for (const auto& [slot, resolver] : base::Reversed(resolvers)) {
    ElementRuleCollector::SlottedRulesScope scope(collector, *slot);
    collector.ClearMatchedRules();
    collector.BeginAddingAuthorRulesForTreeScope(slot->GetTreeScope());
    resolver->CollectMatchingSlottedRules(collector);
    collector.SortAndTransferMatchedRules(
        CascadeOrigin::kAuthor, /*is_vtt_embedded_style=*/false, tracker);
  }
}

const TextTrack* GetTextTrackFromElement(const Element& element) {
  if (auto* vtt_element = DynamicTo<VTTElement>(element)) {
    return vtt_element->GetTrack();
  }
  if (auto* vtt_cue_background_box = DynamicTo<VTTCueBackgroundBox>(element)) {
    return vtt_cue_background_box->GetTrack();
  }
  return nullptr;
}

void MatchVTTRules(const Element& element,
                   ElementRuleCollector& collector,
                   StyleRuleUsageTracker* tracker) {
  const TextTrack* text_track = GetTextTrackFromElement(element);
  if (!text_track) {
    return;
  }
  const HeapVector<Member<CSSStyleSheet>>& styles =
      text_track->GetCSSStyleSheets();
  if (!styles.empty()) {
    int style_sheet_index = 0;
    collector.ClearMatchedRules();
    for (CSSStyleSheet* style : styles) {
      StyleEngine& style_engine = element.GetDocument().GetStyleEngine();
      RuleSet* rule_set = style_engine.RuleSetForSheet(*style);
      if (rule_set) {
        collector.CollectMatchingRules(
            MatchRequest(rule_set, nullptr /* scope */, style,
                         style_sheet_index,
                         style_engine.EnsureVTTOriginatingElement()),
            /*part_names*/ nullptr);
        style_sheet_index++;
      }
    }
    collector.SortAndTransferMatchedRules(
        CascadeOrigin::kAuthor, true /* is_vtt_embedded_style */, tracker);
  }
}

void MatchHostPartRules(const Element& element,
                        ElementRuleCollector& collector,
                        StyleRuleUsageTracker* tracker) {
  DOMTokenList* part = element.GetPart();
  if (!part || !part->length() || !element.IsInShadowTree()) {
    return;
  }

  PartNames current_names(part->TokenSet());

  // Consider ::part rules in this element’s tree scope, which only match if
  // preceded by a :host or :host() that matches one of its containing shadow
  // hosts (see MatchForRelation).
  TreeScope& tree_scope = element.GetTreeScope();
  if (ScopedStyleResolver* resolver = tree_scope.GetScopedStyleResolver()) {
    // PartRulesScope must be provided with the host where we want to start
    // the search for container query containers.  For matching :host::part(),
    // we want to start the search at `element`'s host.
    const Element* host = element.OwnerShadowHost();
    ElementRuleCollector::PartRulesScope scope(collector,
                                               const_cast<Element&>(*host));
    resolver->CollectMatchingPartPseudoRules(collector, &current_names, false);
  }
}

void MatchStyleAttribute(const Element& element,
                         ElementRuleCollector& collector,
                         StyleRuleUsageTracker* tracker) {
  if (element.IsStyledElement() && element.
"""


```