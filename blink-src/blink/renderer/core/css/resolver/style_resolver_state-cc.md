Response:
Let's break down the thought process to analyze the `style_resolver_state.cc` file.

1. **Understand the Context:** The first and most crucial step is to recognize the file's location: `blink/renderer/core/css/resolver/`. This immediately tells us it's part of the CSS resolution process within the Blink rendering engine. Keywords here are "CSS," "resolver," and "state."  "State" suggests this class holds information needed during the resolution.

2. **Examine the Copyright and License:**  Quickly skimming the copyright and license information tells us the code has historical roots (Lars Knoll, KDE) and is under the GNU Library General Public License. This isn't directly relevant to the file's function, but good to note for context.

3. **Identify Key Includes:** The `#include` directives are goldmines. Let's analyze the most important ones:
    * `"third_party/blink/renderer/core/css/resolver/style_resolver_state.h"`:  This confirms that we're looking at the implementation file for the `StyleResolverState` class. The header file would define the public interface.
    * `"third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"`: This hints at usage tracking for web features. The `CountUse` calls later in the code confirm this.
    * `"third_party/blink/renderer/core/animation/css/css_animations.h"`:  Indicates interaction with CSS animations.
    * `"third_party/blink/renderer/core/css/container_query_evaluator.h"`:  Relates to CSS Container Queries.
    * `"third_party/blink/renderer/core/css/css_light_dark_value_pair.h"`:  Points to the handling of `light-dark()` color functions.
    * `"third_party/blink/renderer/core/css/css_property_value_set.h"`:  Suggests manipulation of CSS property values.
    * `"third_party/blink/renderer/core/dom/node.h"` and `"third_party/blink/renderer/core/dom/pseudo_element.h"`: Essential for understanding the DOM interaction. Style resolution happens *on* DOM elements.
    * `"third_party/blink/renderer/core/style/computed_style.h"`: This is the *output* of the style resolution process. `StyleResolverState` is involved in creating or managing the `ComputedStyle`.

4. **Analyze the Class Definition:** Look at the constructor and member variables:
    * The constructor takes `Document`, `Element`, `StyleRecalcContext`, and `StyleRequest`. This signifies its role within a larger style recalculation process. The `StyleRequest` is particularly important, as it dictates what kind of style resolution is needed (e.g., for an element, a pseudo-element).
    * Member variables like `element_context_`, `document_`, `parent_style_`, `layout_parent_style_`, `old_style_`, `font_builder_`, `styled_element_`, `element_style_resources_`, and `container_unit_context_` are all crucial pieces of information needed during style resolution. They represent the context, inputs, and intermediate results.

5. **Examine Key Methods and their Functionality:** Focus on the most prominent methods:
    * `ComputeStyledElement`:  Determines the specific element or pseudo-element being styled.
    * `InsideLink`:  Calculates if the current element is within a link. The logic for pseudo-elements inheriting link status is interesting.
    * `TakeStyle`:  Returns the final `ComputedStyle` object.
    * `UpdateLengthConversionData`:  Handles the conversion of CSS length units (px, em, rem, vw, vh, etc.) to pixels. This is a complex but critical part of styling. The dependencies on parent styles, viewport size, container queries, and zoom are evident.
    * `SetParentStyle`, `SetLayoutParentStyle`: Allow setting the parent's computed style, crucial for inheritance.
    * `LoadPendingResources`:  Handles loading resources like images referenced in stylesheets. The optimization for `display: none` elements is worth noting.
    * `SetZoom`, `SetEffectiveZoom`:  Manage zoom levels.
    * `SetWritingMode`, `SetTextSizeAdjust`, `SetTextOrientation`: Handle CSS properties that affect text rendering.
    * `ResolveLightDarkPair`: Implements the `light-dark()` color function based on the preferred color scheme.
    * `UpdateFont`, `UpdateLineHeight`:  Update font and line height information.

6. **Connect to Web Development Concepts:** Now, start relating the code to how web developers write HTML, CSS, and JavaScript:
    * **HTML:** The `Element` and `PseudoElement` objects directly represent HTML elements and pseudo-elements. The code handles styling based on the HTML structure.
    * **CSS:** The entire file is about CSS resolution. It takes CSS rules and applies them to HTML elements. The handling of inheritance, specificity (implicitly through the resolver), and different CSS properties is central. Examples of specific CSS features like container queries, `light-dark()`, `text-size-adjust`, and zoom are explicitly handled.
    * **JavaScript:** While this file is C++, it interacts with JavaScript indirectly. JavaScript can manipulate the DOM (adding/removing elements, changing attributes), which triggers style recalculations that involve this code. JavaScript can also access the computed styles of elements.

7. **Infer Logic and Give Examples:** For methods like `InsideLink` or `ComputeStyledElement`, try to come up with scenarios and predict the input and output. This demonstrates a deeper understanding.

8. **Identify Potential User/Programming Errors:** Think about what mistakes a web developer might make that would lead to this code being executed or reveal issues within it. Incorrect CSS, complex selectors, and dynamic style changes are good candidates.

9. **Trace User Actions (Debugging):**  Imagine a user interacting with a web page and how those actions trigger style calculations. This helps understand the debugging context. Simple actions like page load, scrolling, hovering, and more complex interactions involving JavaScript are relevant.

10. **Structure the Answer:** Organize the findings into logical sections like "Functionality," "Relationship to Web Technologies," "Logic and Examples," "Common Errors," and "Debugging." This makes the information clear and easy to understand.

11. **Refine and Iterate:**  Review the analysis. Are there any ambiguities? Can the explanations be clearer?  Did I miss any key aspects? For instance, initially, I might not have emphasized the role of `StyleRecalcContext` as much, but upon closer inspection, it's crucial for understanding the incremental nature of style recalculations.

By following these steps, we can systematically analyze a complex source code file like `style_resolver_state.cc` and understand its purpose and interactions within the larger system.
`blink/renderer/core/css/resolver/style_resolver_state.cc` 文件是 Chromium Blink 渲染引擎中负责 CSS 样式解析状态管理的核心组件。它在样式解析过程中维护着各种必要的状态信息，以便正确地计算和应用 CSS 规则到 HTML 元素上。

以下是该文件的主要功能：

**1. 存储样式解析的上下文信息:**

* **当前正在处理的元素 (`element_context_` 和 `GetElement()`):**  记录了当前正在进行样式解析的 HTML 元素。
* **文档信息 (`document_` 和 `GetDocument()`):**  存储了当前元素所属的文档对象，可以访问文档级别的属性和方法。
* **父元素的样式信息 (`parent_style_` 和 `layout_parent_style_`):**  保存了父元素的计算样式，用于处理样式的继承。`layout_parent_style_` 通常用于布局相关的样式计算。
* **旧的样式信息 (`old_style_`):**  在样式重计算时，会存储元素的旧样式，用于优化和增量更新。
* **样式请求类型 (`pseudo_request_type_`):**  指示当前的样式解析是针对普通元素还是伪元素。
* **字体构建器 (`font_builder_`):**  用于构建和管理字体相关的属性。
* **正在被样式化的元素 (`styled_element_` 和 `GetStyledElement()`):** 对于伪元素，这可能指向创建该伪元素的原始元素。
* **元素样式资源 (`element_style_resources_`):**  管理与元素样式相关的资源，例如背景图片。
* **元素类型 (`element_type_`):**  标识当前处理的是普通元素还是伪元素。
* **容器查询上下文 (`container_unit_context_`):**  用于评估 CSS 容器查询。
* **锚点求值器 (`anchor_evaluator_`):**  用于解析和计算 CSS 锚点定位。
* **原始元素的样式 (`originating_element_style_`):**  用于高亮伪元素，指向其来源元素的样式。
* **是否为高亮伪元素 (`is_for_highlight_`):**  标记当前是否正在解析高亮伪元素 (例如 `::selection`)。
* **是否使用高亮伪元素继承 (`uses_highlight_pseudo_inheritance_`):**  标记高亮伪元素是否需要从其来源元素继承某些属性。
* **是否在扁平树之外 (`is_outside_flat_tree_`):**  用于 Shadow DOM 和 Slots 的场景。
* **是否可以触发动画 (`can_trigger_animations_`):**  指示当前的样式计算是否可能触发 CSS 动画。

**2. 提供获取和设置样式相关信息的方法:**

* **`InsideLink()`:**  确定当前元素是否在链接内部，考虑到继承和伪元素的情况。
* **`TakeStyle()`:**  返回最终计算出的 `ComputedStyle` 对象。
* **`UpdateLengthConversionData()`:**  更新长度单位转换所需的数据，例如基于父元素、根元素、视口大小、容器查询等。
* **`UnzoomedLengthConversionData()` 和 `FontSizeConversionData()`:**  提供未缩放的长度转换数据，用于特定的计算。
* **`SetParentStyle()` 和 `SetLayoutParentStyle()`:**  设置父元素的计算样式。
* **`LoadPendingResources()`:**  加载样式中引用的尚未加载的资源，例如背景图片。
* **`ParentFontDescription()`:**  获取父元素的字体描述。
* **`SetZoom()` 和 `SetEffectiveZoom()`:**  设置缩放级别。
* **`SetWritingMode()`, `SetTextSizeAdjust()`, `SetTextOrientation()`:**  设置文本相关的 CSS 属性。
* **`SetPositionAnchor()` 和 `SetPositionAreaOffsets()`:**  设置 CSS 锚点定位相关属性。
* **`GetParserMode()`:**  获取 CSS 解析模式 (quirks mode 或 standard mode)。
* **`GetAnimatingElement()` 和 `GetPseudoElement()`:**  获取可能触发动画的元素或当前的伪元素。
* **`ResolveLightDarkPair()`:**  解析 `light-dark()` CSS 函数的值。
* **`UpdateFont()` 和 `UpdateLineHeight()`:**  更新字体和行高信息。
* **`CanAffectAnimations()`:**  判断当前的样式更改是否会影响 CSS 动画。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  `StyleResolverState` 接收一个 HTML 元素作为输入，并根据应用于该元素的 CSS 规则计算其样式。
    * **例子:** 当浏览器解析到 `<div id="myDiv" class="container">` 时，会创建一个对应的 `Element` 对象，并传递给 `StyleResolverState` 进行样式解析。
* **CSS:**  这是该文件最核心的关联。`StyleResolverState` 的主要任务就是将 CSS 规则（通过 CSSOM 表示）应用到 HTML 元素上。
    * **例子:**  如果 CSS 中有规则 `.container { color: blue; font-size: 16px; }`，`StyleResolverState` 会读取这些规则，并将其计算后的值存储在 `ComputedStyle` 对象中。
    * **例子 (伪元素):** 当解析 `::before` 伪元素的样式时，`style_request.pseudo_id` 会被设置为 `kBefore`，`styled_element_` 可能指向原始元素，但 `element_type_` 会是 `kPseudoElement`。
    * **例子 (容器查询):** 如果 CSS 中有 `@container (min-width: 300px) { ... }`，`container_unit_context_` 会帮助评估当前元素所在的容器是否满足条件。
* **JavaScript:**  JavaScript 可以通过 DOM API 获取和修改元素的样式，这会导致 Blink 重新计算样式，从而涉及到 `StyleResolverState`。
    * **例子:**  当 JavaScript 执行 `document.getElementById('myDiv').style.color = 'red';` 时，会触发样式重计算，并创建一个新的 `StyleResolverState` 来计算 `myDiv` 的新样式。
    * **例子:**  `window.getComputedStyle(document.getElementById('myDiv'))` 会返回一个 `CSSStyleDeclaration` 对象，其内部数据来源于 `StyleResolverState` 计算出的 `ComputedStyle`。

**逻辑推理的假设输入与输出:**

假设输入为一个 `StyleRequest` 对象，指示需要为 ID 为 "test-element" 的 `<div>` 元素计算样式，且该元素有一个父元素，并且 CSS 中定义了以下规则：

```css
#test-element {
  color: green;
  font-size: 14px;
}

.parent-class {
  font-size: 16px;
}
```

假设该 `<div>` 元素的父元素拥有类名 "parent-class"。

**假设输入:**

* `element`: 指向 ID 为 "test-element" 的 `<div>` 元素的指针。
* `style_request.type`: `StyleRequest::kForRenderer` (假设是为了渲染目的计算样式)
* `style_request.pseudo_id`: `kNoPseudo` (不是伪元素)
* `style_request.parent_override`: 指向父元素计算样式的指针 (其中 `font-size` 为 16px)。

**逻辑推理与输出:**

1. `ComputeStyledElement` 会返回指向 "test-element" 的 `Element` 指针。
2. `parent_style_` 将被设置为 `style_request.parent_override`。
3. 在样式解析过程中，会应用 `#test-element` 的规则，设置 `color` 为 `green`。
4. 由于 `#test-element` 中定义了 `font-size: 14px;`，它会覆盖父元素的 `font-size: 16px;` (因为选择器更具体)。
5. `TakeStyle()` 最终返回的 `ComputedStyle` 对象中，`color` 属性的值为 green，`font-size` 属性的值为 14px。

**用户或编程常见的使用错误及举例说明:**

* **CSS 语法错误:**  如果 CSS 中存在语法错误，可能会导致样式解析失败或产生意外的结果。`StyleResolverState` 可能会尝试处理这些错误，但最终的渲染结果可能不符合预期。
    * **例子:**  CSS 中写了 `color: bluu;` (拼写错误)，`StyleResolverState` 可能无法识别该颜色值，从而使用默认值或忽略该属性。
* **CSS 优先级理解错误:**  开发者可能不清楚 CSS 选择器的优先级规则，导致样式没有按照预期应用。`StyleResolverState` 严格按照 CSS 优先级规则进行解析。
    * **例子:**  HTML 中有 `<div id="myDiv" class="container" style="color: red;"></div>`，CSS 中有 `#myDiv { color: blue; }` 和 `.container { color: green; }`。由于内联样式优先级最高，`StyleResolverState` 计算出的最终颜色将是红色，即使开发者可能认为应该是蓝色或绿色。
* **动态修改样式时的性能问题:**  频繁地使用 JavaScript 修改元素的样式可能导致大量的样式重计算，而 `StyleResolverState` 在每次重计算时都会被调用。不合理的样式修改可能会导致性能问题。
    * **例子:**  在 `scroll` 事件中，每次都使用 JavaScript 修改大量元素的 `style` 属性，会导致浏览器频繁进行样式计算和重排。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页:** 浏览器开始解析 HTML 文档，构建 DOM 树。
2. **浏览器解析到 `<style>` 标签或 `<link>` 标签:**  CSS 解析器开始解析 CSS 规则，构建 CSSOM 树。
3. **布局引擎需要计算元素的样式以进行布局:**  对于 DOM 树中的每个需要渲染的元素，布局引擎会触发样式解析。
4. **创建 `StyleResolverState` 对象:**  对于每个元素（或伪元素），会创建一个 `StyleResolverState` 对象，并传入相关的上下文信息，例如当前元素、父元素、文档等。
5. **应用匹配的 CSS 规则:**  `StyleResolverState` 会查找与当前元素匹配的 CSS 规则（来自 CSSOM），并按照优先级和继承规则进行计算。
6. **计算属性值:**  对于每个 CSS 属性，`StyleResolverState` 会计算其最终值，考虑到单位转换、继承、默认值等。
7. **生成 `ComputedStyle` 对象:**  所有计算出的属性值会被存储在一个 `ComputedStyle` 对象中。
8. **布局引擎使用 `ComputedStyle` 进行布局:**  布局引擎获取 `ComputedStyle` 对象，并根据其中的属性值（例如 `width`, `height`, `display` 等）来确定元素在页面上的位置和大小。
9. **用户交互或 JavaScript 操作触发样式更改:**  当用户与页面交互（例如鼠标悬停、点击）或 JavaScript 修改了元素的样式时，会触发样式重计算，重复步骤 4-8。

**调试线索:**

如果在调试过程中遇到样式问题，可以关注以下几点：

* **断点设置:**  在 `StyleResolverState` 的构造函数或关键方法（例如 `UpdateLengthConversionData`, `TakeStyle`) 中设置断点，可以查看样式解析的中间状态。
* **检查 `StyleRequest` 对象:**  查看传递给 `StyleResolverState` 的 `StyleRequest` 对象，了解请求的类型和目标元素。
* **查看父元素的样式:**  检查 `parent_style_`，确认继承是否按预期工作。
* **检查匹配的 CSS 规则:**  了解哪些 CSS 规则与当前元素匹配，以及它们的优先级。
* **使用开发者工具:**  浏览器的开发者工具 (Elements 面板) 提供了查看元素计算样式、匹配的 CSS 规则等功能，可以辅助理解 `StyleResolverState` 的工作过程。

总而言之，`blink/renderer/core/css/resolver/style_resolver_state.cc` 文件是 Blink 引擎中 CSS 样式解析的核心，它负责维护解析过程中的状态，应用 CSS 规则，并最终生成元素的计算样式，为后续的布局和渲染阶段提供关键信息。理解其功能对于深入理解浏览器渲染原理和调试 CSS 问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_resolver_state.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc.
 * All rights reserved.
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
 *
 */

#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/css/container_query_evaluator.h"
#include "third_party/blink/renderer/core/css/css_light_dark_value_pair.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {

namespace {

Element* ComputeStyledElement(const StyleRequest& style_request,
                              Element& element) {
  Element* styled_element = style_request.styled_element;
  if (!styled_element) {
    styled_element = &element;
  }
  if (style_request.IsPseudoStyleRequest()) {
    styled_element = styled_element->GetStyledPseudoElement(
        style_request.pseudo_id, style_request.pseudo_argument);
  }
  return styled_element;
}

}  // namespace

StyleResolverState::StyleResolverState(
    Document& document,
    Element& element,
    const StyleRecalcContext* style_recalc_context,
    const StyleRequest& style_request)
    : element_context_(element),
      document_(&document),
      css_to_length_conversion_data_(&element),
      parent_style_(style_request.parent_override),
      layout_parent_style_(style_request.layout_parent_override),
      old_style_(style_recalc_context ? style_recalc_context->old_style
                                      : nullptr),
      pseudo_request_type_(style_request.type),
      font_builder_(&document),
      styled_element_(ComputeStyledElement(style_request, element)),
      element_style_resources_(
          GetStyledElement() ? *GetStyledElement() : GetElement(),
          document.DevicePixelRatio()),
      element_type_(style_request.IsPseudoStyleRequest() ||
                            element.IsPseudoElement()
                        ? ElementType::kPseudoElement
                        : ElementType::kElement),
      container_unit_context_(
          style_recalc_context
              ? style_recalc_context->container
              : ContainerQueryEvaluator::ParentContainerCandidateElement(
                    element)),
      anchor_evaluator_(style_recalc_context
                            ? style_recalc_context->anchor_evaluator
                            : nullptr),
      originating_element_style_(style_request.originating_element_style),
      is_for_highlight_(IsHighlightPseudoElement(style_request.pseudo_id)),
      uses_highlight_pseudo_inheritance_(
          ::blink::UsesHighlightPseudoInheritance(style_request.pseudo_id)),
      is_outside_flat_tree_(style_recalc_context
                                ? style_recalc_context->is_outside_flat_tree
                                : false),
      can_trigger_animations_(style_request.can_trigger_animations) {
  DCHECK(!!parent_style_ == !!layout_parent_style_);

  if (UsesHighlightPseudoInheritance()) {
    DCHECK(originating_element_style_);
  } else {
    if (!parent_style_) {
      parent_style_ = element_context_.ParentStyle();
    }
    if (!layout_parent_style_) {
      layout_parent_style_ = element_context_.LayoutParentStyle();
    }
  }

  if (!layout_parent_style_) {
    layout_parent_style_ = parent_style_;
  }

  DCHECK(document.IsActive());
}

StyleResolverState::~StyleResolverState() {
  // For performance reasons, explicitly clear HeapVectors and
  // HeapHashMaps to avoid giving a pressure on Oilpan's GC.
  animation_update_.Clear();
}

bool StyleResolverState::IsInheritedForUnset(
    const CSSProperty& property) const {
  return property.IsInherited() || UsesHighlightPseudoInheritance();
}

EInsideLink StyleResolverState::InsideLink() const {
  if (inside_link_.has_value()) {
    return *inside_link_;
  }
  if (ParentStyle()) {
    inside_link_ = ParentStyle()->InsideLink();
  } else {
    inside_link_ = EInsideLink::kNotInsideLink;
  }
  if (element_type_ != ElementType::kPseudoElement && GetElement().IsLink()) {
    inside_link_ = ElementLinkState();
  } else if (uses_highlight_pseudo_inheritance_) {
    // Highlight pseudo-elements acquire the link status of the originating
    // element. Note that highlight pseudo-elements do not *inherit* from
    // the originating element [1], and therefore ParentStyle()->InsideLink()
    // would otherwise always be kNotInsideLink.
    //
    // [1] https://drafts.csswg.org/css-pseudo-4/#highlight-cascade
    inside_link_ = ElementLinkState();
  }
  return *inside_link_;
}

const ComputedStyle* StyleResolverState::TakeStyle() {
  if (had_no_matched_properties_ &&
      pseudo_request_type_ == StyleRequest::kForRenderer) {
    return nullptr;
  }
  return style_builder_->TakeStyle();
}

void StyleResolverState::UpdateLengthConversionData() {
  css_to_length_conversion_data_ = CSSToLengthConversionData(
      *style_builder_, ParentStyle(), RootElementStyle(),
      GetDocument().GetStyleEngine().GetViewportSize(),
      CSSToLengthConversionData::ContainerSizes(container_unit_context_),
      CSSToLengthConversionData::AnchorData(
          anchor_evaluator_, StyleBuilder().PositionAnchor(),
          StyleBuilder().PositionAreaOffsets()),
      StyleBuilder().EffectiveZoom(), length_conversion_flags_, &GetElement());
  element_style_resources_.UpdateLengthConversionData(
      &css_to_length_conversion_data_);
}

CSSToLengthConversionData StyleResolverState::UnzoomedLengthConversionData(
    const FontSizeStyle& font_size_style) {
  const ComputedStyle* root_font_style = RootElementStyle();
  CSSToLengthConversionData::FontSizes font_sizes(font_size_style,
                                                  root_font_style);
  CSSToLengthConversionData::LineHeightSize line_height_size(
      ParentStyle() ? ParentStyle()->GetFontSizeStyle()
                    : style_builder_->GetFontSizeStyle(),
      root_font_style);
  CSSToLengthConversionData::ViewportSize viewport_size(
      GetDocument().GetLayoutView());
  CSSToLengthConversionData::ContainerSizes container_sizes(
      container_unit_context_);
  CSSToLengthConversionData::AnchorData anchor_data(
      anchor_evaluator_, StyleBuilder().PositionAnchor(),
      StyleBuilder().PositionAreaOffsets());
  return CSSToLengthConversionData(StyleBuilder().GetWritingMode(), font_sizes,
                                   line_height_size, viewport_size,
                                   container_sizes, anchor_data, 1,
                                   length_conversion_flags_, &GetElement());
}

CSSToLengthConversionData StyleResolverState::FontSizeConversionData() {
  return UnzoomedLengthConversionData(ParentStyle()->GetFontSizeStyle());
}

CSSToLengthConversionData StyleResolverState::UnzoomedLengthConversionData() {
  return UnzoomedLengthConversionData(style_builder_->GetFontSizeStyle());
}

void StyleResolverState::SetParentStyle(const ComputedStyle* parent_style) {
  parent_style_ = std::move(parent_style);
  if (style_builder_) {
    // Need to update conversion data for 'lh' units.
    UpdateLengthConversionData();
  }
}

void StyleResolverState::SetLayoutParentStyle(
    const ComputedStyle* parent_style) {
  layout_parent_style_ = parent_style;
}

void StyleResolverState::LoadPendingResources() {
  if (pseudo_request_type_ == StyleRequest::kForComputedStyle ||
      (ParentStyle() && ParentStyle()->IsEnsuredInDisplayNone()) ||
      StyleBuilder().IsEnsuredOutsideFlatTree()) {
    return;
  }
  if (StyleBuilder().Display() == EDisplay::kNone &&
      !GetElement().LayoutObjectIsNeeded(style_builder_->GetDisplayStyle())) {
    // Don't load resources for display:none elements unless we are animating
    // display. If we are animating display, we might otherwise have ended up
    // caching a base style with pending images.
    Element* animating_element = GetAnimatingElement();
    if (!animating_element || !CSSAnimations::IsAnimatingDisplayProperty(
                                  animating_element->GetElementAnimations())) {
      return;
    }
  }

  if (StyleBuilder().StyleType() == kPseudoIdSearchText ||
      StyleBuilder().StyleType() == kPseudoIdTargetText) {
    // Do not load any resources for these pseudos, since that could leak text
    // content to external stylesheets.
    return;
  }

  element_style_resources_.LoadPendingResources(StyleBuilder());
}

const FontDescription& StyleResolverState::ParentFontDescription() const {
  return parent_style_->GetFontDescription();
}

void StyleResolverState::SetZoom(float f) {
  float parent_effective_zoom = ParentStyle()
                                    ? ParentStyle()->EffectiveZoom()
                                    : ComputedStyleInitialValues::InitialZoom();

  StyleBuilder().SetZoom(f);

  if (f != 1.f) {
    GetDocument().CountUse(WebFeature::kCascadedCSSZoomNotEqualToOne);
  }

  if (StyleBuilder().SetEffectiveZoom(parent_effective_zoom * f)) {
    font_builder_.DidChangeEffectiveZoom();
  }
}

void StyleResolverState::SetEffectiveZoom(float f) {
  if (StyleBuilder().SetEffectiveZoom(f)) {
    font_builder_.DidChangeEffectiveZoom();
  }
}

void StyleResolverState::SetWritingMode(WritingMode new_writing_mode) {
  if (StyleBuilder().GetWritingMode() == new_writing_mode) {
    return;
  }
  StyleBuilder().SetWritingMode(new_writing_mode);
  UpdateLengthConversionData();
  font_builder_.DidChangeWritingMode();
}

void StyleResolverState::SetTextSizeAdjust(
    TextSizeAdjust new_text_size_adjust) {
  if (StyleBuilder().GetTextSizeAdjust() == new_text_size_adjust) {
    return;
  }

  if (!new_text_size_adjust.IsAuto()) {
    GetDocument().CountUse(WebFeature::kTextSizeAdjustNotAuto);
    if (new_text_size_adjust.Multiplier() != 1.f) {
      GetDocument().CountUse(WebFeature::kTextSizeAdjustPercentNot100);
    }
  }

  StyleBuilder().SetTextSizeAdjust(new_text_size_adjust);
  // When `TextSizeAdjustImprovements` is enabled, text-size-adjust affects
  // font-size during style building.
  if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
    UpdateLengthConversionData();
    font_builder_.DidChangeTextSizeAdjust();
  }
}

void StyleResolverState::SetTextOrientation(ETextOrientation text_orientation) {
  if (StyleBuilder().GetTextOrientation() != text_orientation) {
    StyleBuilder().SetTextOrientation(text_orientation);
    font_builder_.DidChangeTextOrientation();
  }
}

void StyleResolverState::SetPositionAnchor(ScopedCSSName* position_anchor) {
  if (StyleBuilder().PositionAnchor() != position_anchor) {
    StyleBuilder().SetPositionAnchor(position_anchor);
    css_to_length_conversion_data_.SetAnchorData(
        CSSToLengthConversionData::AnchorData(
            anchor_evaluator_, position_anchor,
            StyleBuilder().PositionAreaOffsets()));
  }
}

void StyleResolverState::SetPositionAreaOffsets(
    const std::optional<PositionAreaOffsets>& position_area_offsets) {
  if (StyleBuilder().PositionAreaOffsets() != position_area_offsets) {
    StyleBuilder().SetPositionAreaOffsets(position_area_offsets);
    css_to_length_conversion_data_.SetAnchorData(
        CSSToLengthConversionData::AnchorData(anchor_evaluator_,
                                              StyleBuilder().PositionAnchor(),
                                              position_area_offsets));
  }
}

CSSParserMode StyleResolverState::GetParserMode() const {
  return GetDocument().InQuirksMode() ? kHTMLQuirksMode : kHTMLStandardMode;
}

Element* StyleResolverState::GetAnimatingElement() const {
  // When querying pseudo element styles for an element that does not generate
  // such a pseudo element, the styled_element_ is the originating element. Make
  // sure we only do animations for true pseudo elements.
  return IsForPseudoElement() ? GetPseudoElement() : styled_element_;
}

PseudoElement* StyleResolverState::GetPseudoElement() const {
  return DynamicTo<PseudoElement>(styled_element_);
}

const CSSValue& StyleResolverState::ResolveLightDarkPair(
    const CSSValue& value) {
  if (const auto* pair = DynamicTo<CSSLightDarkValuePair>(value)) {
    if (StyleBuilder().UsedColorScheme() == mojom::blink::ColorScheme::kLight) {
      return pair->First();
    }
    return pair->Second();
  }
  return value;
}

void StyleResolverState::UpdateFont() {
  GetFontBuilder().CreateFont(StyleBuilder(), ParentStyle());
  SetConversionFontSizes(CSSToLengthConversionData::FontSizes(
      style_builder_->GetFontSizeStyle(), RootElementStyle()));
  SetConversionZoom(StyleBuilder().EffectiveZoom());
}

void StyleResolverState::UpdateLineHeight() {
  css_to_length_conversion_data_.SetLineHeightSize(
      CSSToLengthConversionData::LineHeightSize(
          style_builder_->GetFontSizeStyle(),
          GetDocument().documentElement()->GetComputedStyle()));
}

bool StyleResolverState::CanAffectAnimations() const {
  return conditionally_affects_animations_ ||
         StyleBuilder().CanAffectAnimations();
}

}  // namespace blink

"""

```