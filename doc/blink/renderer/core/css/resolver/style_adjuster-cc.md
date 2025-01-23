Response:
My thinking process to answer the request about `style_adjuster.cc` goes like this:

1. **Understand the Goal:** The core request is to understand the *functionality* of the `style_adjuster.cc` file in the Chromium Blink rendering engine, particularly its relationship with CSS, HTML, and JavaScript. I also need to identify potential user errors and debugging entry points.

2. **Analyze the File Path:**  The path `blink/renderer/core/css/resolver/style_adjuster.cc` is very informative. It tells me this file is:
    * Part of the `blink` rendering engine.
    * Located within the `core` module.
    * Specifically in the `css` subsystem.
    * Further down in the `resolver` component.
    * Named `style_adjuster`, implying it *modifies* or *fine-tunes* styles.

3. **Scan the Header Includes:** The included headers offer valuable clues about the file's responsibilities. I look for recognizable classes and namespaces:
    * `third_party/blink/renderer/core/css/...`:  Confirms it's deeply involved with CSS. Specific headers like `properties/longhands.h`, `resolver/style_resolver.h`, `style/computed_style.h` are strong indicators of CSS processing.
    * `third_party/blink/renderer/core/dom/...`:  Indicates interaction with the Document Object Model (DOM). Headers like `container_node.h`, `document.h`, `element.h`, `pseudo_element.h`, and `shadow_root.h` are key DOM elements.
    * `third_party/blink/renderer/core/html/...`:  Shows awareness of specific HTML elements (e.g., `html_div_element.h`, `html_input_element.h`).
    * `third_party/blink/renderer/core/frame/...`: Suggests involvement with the browser frame structure and settings.
    * `third_party/blink/renderer/platform/...`:  Points to lower-level platform utilities and features.
    * `third_party/blink/public/common/features.h`: Implies feature flags and conditional behavior.

4. **Examine the Code Structure (Initial Impression):** I quickly scan the code for the main class (`StyleAdjuster`) and its methods. The presence of methods like `AdjustStyleForSvgElement`, `AdjustStyleForEditing`, `AdjustStyleForTextCombine`, `AdjustStyleForDisplay`, etc., strongly suggests the file contains logic for making element-specific style modifications.

5. **Identify Key Functionality (Based on Headers and Method Names):** Based on the information gathered so far, I can start formulating the main functions:
    * **Element-Specific Style Adjustments:**  The core function is to modify computed styles based on the specific HTML or SVG element type.
    * **CSS Property Overrides/Adjustments:** It seems to enforce certain CSS rules or make adjustments based on browser behavior or specifications.
    * **Handling Special Cases:**  The file likely deals with edge cases and specific rendering requirements for certain elements.
    * **Interaction with DOM:** It uses the DOM structure to understand element context.

6. **Connect to HTML, CSS, and JavaScript:**
    * **HTML:** The file directly interacts with HTML elements, applying style adjustments based on the element's tag name.
    * **CSS:**  It manipulates CSS properties (e.g., `display`, `overflow`, `text-decoration`, `position`). It's part of the CSS resolution process.
    * **JavaScript:** While not directly executing JavaScript, the adjustments made by this code *influence* how JavaScript interacts with the DOM and CSSOM. For instance, if JavaScript tries to get the computed style of an element, the adjustments made here will be reflected. JavaScript-driven changes to the DOM or CSS properties can trigger the style resolution process, potentially involving `style_adjuster.cc`.

7. **Infer Logic and Provide Examples:** Now, I can start to create hypothetical scenarios and expected outputs. For example:
    * **Input:** An `<img>` element with `display: contents`.
    * **Output:** The `style_adjuster` will likely change the display to `none`.
    * **Input:** A `<textarea>` element with `overflow: visible`.
    * **Output:** The `style_adjuster` will likely change the overflow to `auto`.

8. **Consider User/Programming Errors:** I think about common mistakes developers make:
    * Trying to apply `overflow: scroll` to a `<table>`.
    * Expecting `text-decoration` to propagate across certain block boundaries.
    * Incorrectly using `display: contents` on specific elements.

9. **Outline the Debugging Process:**  I consider how a developer might end up investigating this file:
    * Seeing unexpected rendering behavior.
    * Stepping through the style resolution process in a debugger.
    * Observing how computed styles are being altered.

10. **Summarize the Functionality for Part 1:** Based on the analysis, I create a concise summary of the file's purpose, focusing on the key aspects identified.

11. **Refine and Organize:** Finally, I review the entire answer, ensuring clarity, accuracy, and logical flow. I make sure the examples are relevant and the explanations are easy to understand. I specifically address each part of the prompt.

By following this structured approach, I can effectively analyze the provided code snippet and generate a comprehensive answer that addresses the user's request. The key is to leverage the information available in the file path, header includes, and code structure to infer the file's purpose and behavior.
这是 Chromium Blink 引擎源代码文件 `blink/renderer/core/css/resolver/style_adjuster.cc` 的第一部分，其主要功能是 **在 CSS 样式解析过程中，根据 HTML 元素的类型和特定的 CSS 属性值，对计算后的样式进行调整和修正**。

简单来说，它负责应用一些浏览器特定的样式调整规则，确保渲染结果符合预期，并处理一些 CSS 规范中没有明确定义或浏览器实现存在差异的情况。

以下是更详细的归纳，并结合了与 JavaScript、HTML 和 CSS 的关系进行说明：

**功能归纳：**

1. **基于 HTML 元素的特定样式调整:**  `StyleAdjuster` 会根据当前正在处理的 HTML 元素的类型，应用一些预定义的样式调整规则。例如：
    * **`<img>` 元素：** 如果 `display` 属性被设置为 `contents`，则会被强制设置为 `none`，使其不渲染。
    * **`<textarea>` 元素：**  将 `overflow: visible` 视为 `overflow: auto`。
    * **`<table>` 元素：**  会重置 `-webkit-left`, `-webkit-center`, `-webkit-right` 的 `text-align` 值为 `start`。
    * **`<frame>` 和 `<frameset>` 元素：** 强制 `position` 为 `static`， `display` 为 `block`， `float` 为 `none`。
    * **`<legend>` 元素：** 允许任何块级 `display` 值。
    * **`<marquee>` 元素：**  强制 `overflow` 为 `hidden`。
    * **`<input type="image">` 或 `<iframe>` 等元素:** 如果 `display` 为 `contents`，则会被设置为 `none`。
    * **列表元素 (`<ul>`, `<ol>`)：** 设置内部列表元素的标记。

2. **处理 `display: contents` 的行为：**  对于某些特定的 HTML 元素，`display: contents` 的行为会被强制设置为 `display: none`。这是因为这些元素在规范中并没有明确定义 `display: contents` 的行为，或者浏览器的实现方式有所不同。

3. **处理 `overflow` 属性的组合和限制：**  `StyleAdjuster` 会检查 `overflow-x` 和 `overflow-y` 的值，并根据 CSS 规范和浏览器行为进行调整。例如，当一个轴的 `overflow` 不是 `visible` 或 `clip` 时，另一个轴的 `visible` 或 `clip` 值会被重置为 `auto` 或 `hidden`。对于 `<table>` 元素，只支持 `overflow: hidden` 和 `overflow: visible`。

4. **处理 SVG 元素的特定样式：** 对于 SVG 元素，会禁用一些文本装饰属性，并根据 SVG 规范调整 `position` 和 `display` 属性。

5. **处理可编辑内容 (editing)：**  如果元素与 `EditContext` 关联，会将 `-webkit-user-modify` 设置为 `read-write`。对于 `user-modify: read-write-plaintext-only` 的元素，会调整 `white-space` 属性以避免空格折叠。

6. **处理文本组合 (text-combine)：**  为使用 `text-combine-upright` 的元素设置特定的尺寸、对齐方式和文本属性。

7. **处理伪元素样式：**  例如，对于 `::first-letter` 伪元素，会强制 `display` 为 `inline` (除非它是浮动的，此时为 `block`)。对于 `::marker` 伪元素，会根据父元素的 `list-style-position` 调整外边距和 `display`。

8. **处理文本装饰的传播：**  在某些情况下（如浮动元素、绝对/相对定位元素、行内块等），会阻止文本装饰属性的传播。

9. **处理触摸动作 (touch-action)：**  根据元素是否可滚动，调整 `touch-action` 属性，以控制触摸事件的处理方式。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML：** `StyleAdjuster` 接收一个 HTML 元素作为输入，并根据其标签名和属性进行样式调整。例如，对于 `<input type="text">` 和 `<textarea>`，可能会有不同的样式调整规则。
    * **例子：**  当 `StyleAdjuster` 处理一个 `<textarea>` 元素时，如果 CSS 中设置了 `overflow: visible`，它会将其调整为 `overflow: auto`。

* **CSS：** `StyleAdjuster` 在 CSS 样式解析过程的后期介入，它接收已经计算出的样式值，并根据预定义的规则进行修改。它处理了一些 CSS 规范中没有明确定义或浏览器实现存在差异的情况，以确保跨浏览器的兼容性。
    * **例子：**  CSS 规范中对于 `display: contents` 在某些元素上的行为可能没有明确定义，`StyleAdjuster` 会根据 Blink 的实现将其强制设置为 `none`。

* **JavaScript：** JavaScript 可以动态地修改 HTML 结构和 CSS 样式。当 JavaScript 修改了元素的样式或结构后，会触发 Blink 的样式重新解析流程，这时 `StyleAdjuster` 就会再次被调用，对新计算出的样式进行调整。
    * **假设输入：** JavaScript 代码修改了一个 `<div>` 元素的 `display` 属性为 `contents`。
    * **逻辑推理：** `StyleAdjuster` 可能会检查这个 `<div>` 元素，并根据其内部的子元素和上下文，决定是否需要进一步调整 `display` 属性。
    * **输出：**  最终计算出的样式中，`display` 的值可能会保持 `contents`，也可能被调整为其他值，这取决于 `StyleAdjuster` 的具体规则。

**用户或编程常见的使用错误：**

1. **错误地期望 `display: contents` 在所有元素上都有相同的行为：**  用户可能会期望 `display: contents` 能够让元素“消失”并让其子元素像直接存在于父元素中一样渲染。但是，如代码所示，Blink 对于某些元素（如 `<img>`、`<textarea>` 等）会将 `display: contents` 强制设为 `none`。
    * **例子：**  用户可能在 CSS 中设置一个 `<canvas>` 元素的 `display: contents;`，期望它不显示，但其子元素仍然显示。然而，Blink 会将其 `display` 设置为 `none`，导致包括子元素在内的所有内容都不显示。

2. **误解 `overflow` 属性在 `<table>` 元素上的行为：**  用户可能尝试在 `<table>` 元素上使用 `overflow: scroll` 或 `overflow: auto`，但 `StyleAdjuster` 会将其限制为 `overflow: hidden` 或 `overflow: visible`。
    * **例子：**  用户设置了 `<table style="overflow: scroll;">`，希望表格内容溢出时出现滚动条。但实际上，由于 `StyleAdjuster` 的调整，`overflow` 会被视为 `hidden` 或 `visible`，滚动条不会出现。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中加载一个包含复杂样式和各种 HTML 元素的网页。**
2. **浏览器开始解析 HTML 结构，构建 DOM 树。**
3. **浏览器解析 CSS 样式表（包括外部样式表、`<style>` 标签和内联样式）。**
4. **对于 DOM 树中的每个元素，Blink 的样式解析器开始计算其最终的样式（Computed Style）。**
5. **在计算样式值的过程中，`StyleAdjuster` 会被调用。**  它接收当前元素的类型和已经计算出的样式值作为输入。
6. **`StyleAdjuster` 根据预定义的规则，检查这些样式值是否需要调整。** 例如，检查是否是特定的 HTML 元素，或者是否设置了需要特殊处理的 CSS 属性组合。
7. **如果需要调整，`StyleAdjuster` 会修改计算后的样式值。**
8. **最终计算出的样式会被用于布局和渲染网页。**

**作为调试线索：** 如果你发现某个元素的样式行为与你预期的不符，例如 `display: contents` 没有按照你的想法工作，或者 `overflow` 在表格上的行为很奇怪，那么 `blink/renderer/core/css/resolver/style_adjuster.cc` 就是一个很好的起点去查看是否有一些浏览器特定的调整规则影响了该元素的最终样式。你可以通过断点调试或者查看该文件的源代码来了解具体的调整逻辑。

**总结（针对第 1 部分）：**

`blink/renderer/core/css/resolver/style_adjuster.cc` 的主要功能是在 Blink 引擎的 CSS 样式解析过程中，对计算后的样式进行一系列基于 HTML 元素类型和特定 CSS 属性值的调整和修正。它确保了渲染结果的一致性和符合浏览器预期的行为，并处理了一些 CSS 规范中未明确定义或浏览器实现存在差异的情况。 这部分代码主要关注各种 HTML 元素，并对其 `display`, `overflow` 等属性进行调整。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_adjuster.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
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
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/resolver/style_adjuster.h"

#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element.h"
#include "third_party/blink/renderer/core/html/html_frame_set_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_marquee_element.h"
#include "third_party/blink/renderer/core/html/html_meter_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html/html_wbr_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/list/list_marker.h"
#include "third_party/blink/renderer/core/mathml/mathml_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/style_intrinsic_length.h"
#include "third_party/blink/renderer/core/svg/svg_foreign_object_element.h"
#include "third_party/blink/renderer/core/svg/svg_g_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_text_element.h"
#include "third_party/blink/renderer/core/svg/svg_tspan_element.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/transforms/transform_operations.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "ui/base/ui_base_features.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

bool IsOverflowClipOrVisible(EOverflow overflow) {
  return overflow == EOverflow::kClip || overflow == EOverflow::kVisible;
}

TouchAction AdjustTouchActionForElement(TouchAction touch_action,
                                        const ComputedStyleBuilder& builder,
                                        const ComputedStyle& parent_style,
                                        Element* element) {
  Element* document_element = element->GetDocument().documentElement();
  bool scrolls_overflow = builder.ScrollsOverflow();
  if (element == element->GetDocument().FirstBodyElement()) {
    // Body scrolls overflow if html root overflow is not visible or the
    // propagation of overflow is stopped by containment.
    if (parent_style.IsOverflowVisibleAlongBothAxes()) {
      if (!parent_style.ShouldApplyAnyContainment(*document_element) &&
          !builder.ShouldApplyAnyContainment(*element)) {
        scrolls_overflow = false;
      }
    }
  }
  bool is_child_document =
      element == document_element && element->GetDocument().LocalOwner();
  if (scrolls_overflow || is_child_document) {
    return touch_action | TouchAction::kPan |
           TouchAction::kInternalPanXScrolls |
           TouchAction::kInternalNotWritable;
  }
  return touch_action;
}

bool HostIsInputFile(const Element* element) {
  if (!element || !element->IsInUserAgentShadowRoot()) {
    return false;
  }
  if (const Element* shadow_host = element->OwnerShadowHost()) {
    if (const auto* input = DynamicTo<HTMLInputElement>(shadow_host)) {
      return input->FormControlType() == FormControlType::kInputFile;
    }
  }
  return false;
}

}  // namespace

void StyleAdjuster::AdjustStyleForSvgElement(
    const SVGElement& element,
    ComputedStyleBuilder& builder,
    const ComputedStyle& layout_parent_style) {
  if (builder.Display() != EDisplay::kNone) {
    // Disable some of text decoration properties.
    //
    // Note that SetFooBar() is more efficient than ResetFooBar() if the current
    // value is same as the reset value.
    builder.SetTextDecorationSkipInk(ETextDecorationSkipInk::kAuto);
    builder.SetTextDecorationStyle(
        ETextDecorationStyle::kSolid);  // crbug.com/1246719
    builder.SetTextDecorationThickness(TextDecorationThickness(Length::Auto()));
    builder.SetTextEmphasisMark(TextEmphasisMark::kNone);
    builder.SetTextUnderlineOffset(Length());  // crbug.com/1247912
    builder.SetTextUnderlinePosition(TextUnderlinePosition::kAuto);
  }

  bool is_svg_root = element.IsOutermostSVGSVGElement();
  if (!is_svg_root) {
    // Only the root <svg> element in an SVG document fragment tree honors css
    // position.
    builder.SetPosition(ComputedStyleInitialValues::InitialPosition());
  }

  if (builder.Display() == EDisplay::kContents &&
      (is_svg_root ||
       (!IsA<SVGSVGElement>(element) && !IsA<SVGGElement>(element) &&
        !IsA<SVGUseElement>(element) && !IsA<SVGTSpanElement>(element)))) {
    // According to the CSS Display spec[1], nested <svg> elements, <g>,
    // <use>, and <tspan> elements are not rendered and their children are
    // "hoisted". For other elements display:contents behaves as display:none.
    //
    // [1] https://drafts.csswg.org/css-display/#unbox-svg
    builder.SetDisplay(EDisplay::kNone);
  }

  // SVG text layout code expects us to be a block-level style element.
  if ((IsA<SVGForeignObjectElement>(element) || IsA<SVGTextElement>(element)) &&
      builder.IsDisplayInlineType()) {
    builder.SetDisplay(EDisplay::kBlock);
  }

  // Columns don't apply to svg text elements.
  if (IsA<SVGTextElement>(element)) {
    AdjustForSVGTextElement(builder);
  }

  // Copy DominantBaseline to CssDominantBaseline without 'no-change',
  // 'reset-size', and 'use-script'.
  auto baseline = builder.DominantBaseline();
  if (baseline == EDominantBaseline::kUseScript) {
    // TODO(fs): The dominant-baseline and the baseline-table components
    // are set by determining the predominant script of the character data
    // content.
    baseline = EDominantBaseline::kAlphabetic;
  } else if (baseline == EDominantBaseline::kNoChange ||
             baseline == EDominantBaseline::kResetSize) {
    baseline = layout_parent_style.CssDominantBaseline();
  }
  builder.SetCssDominantBaseline(baseline);
}

// https://drafts.csswg.org/css-display/#transformations
static EDisplay EquivalentBlockDisplay(EDisplay display) {
  switch (display) {
    case EDisplay::kFlowRootListItem:
    case EDisplay::kBlock:
    case EDisplay::kTable:
    case EDisplay::kWebkitBox:
    case EDisplay::kFlex:
    case EDisplay::kGrid:
    case EDisplay::kBlockMath:
    case EDisplay::kBlockRuby:
    case EDisplay::kListItem:
    case EDisplay::kFlowRoot:
    case EDisplay::kLayoutCustom:
    case EDisplay::kMasonry:
      return display;
    case EDisplay::kInlineTable:
      return EDisplay::kTable;
    case EDisplay::kWebkitInlineBox:
      return EDisplay::kWebkitBox;
    case EDisplay::kInlineFlex:
      return EDisplay::kFlex;
    case EDisplay::kInlineGrid:
      return EDisplay::kGrid;
    case EDisplay::kMath:
      return EDisplay::kBlockMath;
    case EDisplay::kRuby:
      return EDisplay::kBlockRuby;
    case EDisplay::kInlineLayoutCustom:
      return EDisplay::kLayoutCustom;
    case EDisplay::kInlineListItem:
      return EDisplay::kListItem;
    case EDisplay::kInlineFlowRootListItem:
      return EDisplay::kFlowRootListItem;
    case EDisplay::kInlineMasonry:
      return EDisplay::kMasonry;

    case EDisplay::kContents:
    case EDisplay::kInline:
    case EDisplay::kInlineBlock:
    case EDisplay::kTableRowGroup:
    case EDisplay::kTableHeaderGroup:
    case EDisplay::kTableFooterGroup:
    case EDisplay::kTableRow:
    case EDisplay::kTableColumnGroup:
    case EDisplay::kTableColumn:
    case EDisplay::kTableCell:
    case EDisplay::kTableCaption:
    case EDisplay::kRubyText:
      return EDisplay::kBlock;
    case EDisplay::kNone:
      NOTREACHED();
  }
  NOTREACHED();
}

// https://drafts.csswg.org/css-display/#inlinify
static EDisplay EquivalentInlineDisplay(EDisplay display) {
  switch (display) {
    case EDisplay::kFlowRootListItem:
      return EDisplay::kInlineFlowRootListItem;
    case EDisplay::kBlock:
    case EDisplay::kFlowRoot:
      return EDisplay::kInlineBlock;
    case EDisplay::kTable:
      return EDisplay::kInlineTable;
    case EDisplay::kWebkitBox:
      return EDisplay::kWebkitInlineBox;
    case EDisplay::kFlex:
      return EDisplay::kInlineFlex;
    case EDisplay::kGrid:
      return EDisplay::kInlineGrid;
    case EDisplay::kMasonry:
      return EDisplay::kInlineMasonry;
    case EDisplay::kBlockMath:
      return EDisplay::kMath;
    case EDisplay::kBlockRuby:
      return EDisplay::kRuby;
    case EDisplay::kListItem:
      return EDisplay::kInlineListItem;
    case EDisplay::kLayoutCustom:
      return EDisplay::kInlineLayoutCustom;

    case EDisplay::kInlineFlex:
    case EDisplay::kInlineFlowRootListItem:
    case EDisplay::kInlineGrid:
    case EDisplay::kInlineLayoutCustom:
    case EDisplay::kInlineListItem:
    case EDisplay::kInlineMasonry:
    case EDisplay::kInlineTable:
    case EDisplay::kMath:
    case EDisplay::kRuby:
    case EDisplay::kWebkitInlineBox:

    case EDisplay::kContents:
    case EDisplay::kInline:
    case EDisplay::kInlineBlock:
    case EDisplay::kTableRowGroup:
    case EDisplay::kTableHeaderGroup:
    case EDisplay::kTableFooterGroup:
    case EDisplay::kTableRow:
    case EDisplay::kTableColumnGroup:
    case EDisplay::kTableColumn:
    case EDisplay::kTableCell:
    case EDisplay::kTableCaption:
    case EDisplay::kRubyText:
      return display;

    case EDisplay::kNone:
      NOTREACHED();
  }
  NOTREACHED();
}

static bool IsOutermostSVGElement(const Element* element) {
  auto* svg_element = DynamicTo<SVGElement>(element);
  return svg_element && svg_element->IsOutermostSVGSVGElement();
}

static bool IsAtMediaUAShadowBoundary(const Element* element) {
  if (!element) {
    return false;
  }
  if (ContainerNode* parent = element->parentNode()) {
    if (auto* shadow_root = DynamicTo<ShadowRoot>(parent)) {
      return shadow_root->host().IsMediaElement();
    }
  }
  return false;
}

// CSS requires text-decoration to be reset at each DOM element for inline
// blocks, inline tables, floating elements, and absolute or relatively
// positioned elements. Outermost <svg> roots are considered to be atomic
// inline-level. Media elements have a special rendering where the media
// controls do not use a proper containing block model which means we need
// to manually stop text-decorations to apply to text inside media controls.
static bool StopPropagateTextDecorations(const ComputedStyleBuilder& builder,
                                         const Element* element) {
  return builder.IsDisplayReplacedType() ||
         IsAtMediaUAShadowBoundary(element) || builder.IsFloating() ||
         builder.HasOutOfFlowPosition() || IsOutermostSVGElement(element) ||
         builder.Display() == EDisplay::kRubyText;
}

static bool LayoutParentStyleForcesZIndexToCreateStackingContext(
    const ComputedStyle& layout_parent_style) {
  return layout_parent_style.IsDisplayFlexibleOrGridBox();
}

void StyleAdjuster::AdjustStyleForEditing(ComputedStyleBuilder& builder,
                                          Element* element) {
  if (element && element->editContext()) {
    // If an element is associated with an EditContext, it should
    // become editable and should have -webkit-user-modify set to
    // read-write. This overrides any other values that have been
    // specified for contenteditable or -webkit-user-modify on that element.
    builder.SetUserModify(EUserModify::kReadWrite);
  }

  if (builder.UserModify() != EUserModify::kReadWritePlaintextOnly) {
    return;
  }
  // Collapsing whitespace is harmful in plain-text editing.
  if (builder.WhiteSpace() == EWhiteSpace::kNormal) {
    builder.SetWhiteSpace(EWhiteSpace::kPreWrap);
  } else if (builder.WhiteSpace() == EWhiteSpace::kNowrap) {
    builder.SetWhiteSpace(EWhiteSpace::kPre);
  } else if (builder.WhiteSpace() == EWhiteSpace::kPreLine) {
    builder.SetWhiteSpace(EWhiteSpace::kPreWrap);
  }
}

void StyleAdjuster::AdjustStyleForTextCombine(ComputedStyleBuilder& builder) {
  DCHECK_EQ(builder.Display(), EDisplay::kInlineBlock);
  // Set box sizes
  const Font& font = builder.GetFont();
  DCHECK(font.GetFontDescription().IsVerticalBaseline());
  const auto one_em = ComputedStyle::ComputedFontSizeAsFixed(builder.GetFont());
  const auto line_height = builder.FontHeight();
  const auto size =
      LengthSize(Length::Fixed(line_height), Length::Fixed(one_em));
  builder.SetContainIntrinsicWidth(StyleIntrinsicLength(false, size.Width()));
  builder.SetContainIntrinsicHeight(StyleIntrinsicLength(false, size.Height()));
  builder.SetHeight(size.Height());
  builder.SetLineHeight(size.Height());
  builder.SetMaxHeight(size.Height());
  builder.SetMaxWidth(size.Width());
  builder.SetMinHeight(size.Height());
  builder.SetMinWidth(size.Width());
  builder.SetWidth(size.Width());
  AdjustStyleForCombinedText(builder);
}

void StyleAdjuster::AdjustStyleForCombinedText(ComputedStyleBuilder& builder) {
  builder.ResetTextCombine();
  builder.SetLetterSpacing(0.0f);
  builder.SetTextAlign(ETextAlign::kCenter);
  builder.SetTextDecorationLine(TextDecorationLine::kNone);
  builder.SetTextEmphasisMark(TextEmphasisMark::kNone);
  builder.SetVerticalAlign(EVerticalAlign::kMiddle);
  builder.SetWordBreak(EWordBreak::kKeepAll);
  builder.SetWordSpacing(0.0f);
  builder.SetWritingMode(WritingMode::kHorizontalTb);

  builder.SetBaseTextDecorationData(nullptr);
  builder.ResetTextIndent();
  builder.UpdateFontOrientation();

#if DCHECK_IS_ON()
  DCHECK_EQ(builder.GetFont().GetFontDescription().Orientation(),
            FontOrientation::kHorizontal);
  const ComputedStyle* cloned_style = builder.CloneStyle();
  LayoutTextCombine::AssertStyleIsValid(*cloned_style);
#endif
}

static void AdjustStyleForFirstLetter(ComputedStyleBuilder& builder) {
  if (builder.StyleType() != kPseudoIdFirstLetter) {
    return;
  }

  // Force inline display (except for floating first-letters).
  builder.SetDisplay(builder.IsFloating() ? EDisplay::kBlock
                                          : EDisplay::kInline);
}

static void AdjustStyleForMarker(ComputedStyleBuilder& builder,
                                 const ComputedStyle& parent_style,
                                 const Element* parent_element) {
  if (builder.StyleType() != kPseudoIdMarker) {
    return;
  }

  if (parent_element->IsPseudoElement()) {
    parent_element = parent_element->parentElement();
  }

  if (parent_style.MarkerShouldBeInside(*parent_element,
                                        builder.GetDisplayStyle())) {
    Document& document = parent_element->GetDocument();
    auto margins =
        ListMarker::InlineMarginsForInside(document, builder, parent_style);
    LogicalToPhysicalSetter setter(builder.GetWritingDirection(), builder,
                                   &ComputedStyleBuilder::SetMarginTop,
                                   &ComputedStyleBuilder::SetMarginRight,
                                   &ComputedStyleBuilder::SetMarginBottom,
                                   &ComputedStyleBuilder::SetMarginLeft);
    setter.SetInlineStart(Length::Fixed(margins.first));
    setter.SetInlineEnd(Length::Fixed(margins.second));
  } else {
    // Outside list markers should generate a block container.
    builder.SetDisplay(EDisplay::kInlineBlock);

    // Do not break inside the marker, and honor the trailing spaces.
    builder.SetWhiteSpace(EWhiteSpace::kPre);

    // Compute margins for 'outside' during layout, because it requires the
    // layout size of the marker.
    // TODO(kojii): absolute position looks more reasonable, and maybe required
    // in some cases, but this is currently blocked by crbug.com/734554
    // builder.SetPosition(EPosition::kAbsolute);
  }
}

static void AdjustStyleForHTMLElement(ComputedStyleBuilder& builder,
                                      HTMLElement& element) {
  if (builder.HasBaseSelectAppearance()) {
    builder.SetInBaseSelectAppearance(true);
  }

  // <div> and <span> are the most common elements on the web, we skip all the
  // work for them.
  if (IsA<HTMLDivElement>(element) || IsA<HTMLSpanElement>(element)) {
    return;
  }

  if (auto* image = DynamicTo<HTMLImageElement>(element)) {
    if (image->IsCollapsed() || builder.Display() == EDisplay::kContents) {
      builder.SetDisplay(EDisplay::kNone);
    }
    return;
  }

  if (IsA<HTMLTableElement>(element)) {
    // Tables never support the -webkit-* values for text-align and will reset
    // back to the default.
    if (builder.GetTextAlign() == ETextAlign::kWebkitLeft ||
        builder.GetTextAlign() == ETextAlign::kWebkitCenter ||
        builder.GetTextAlign() == ETextAlign::kWebkitRight) {
      builder.SetTextAlign(ETextAlign::kStart);
    }
    return;
  }

  if (IsA<HTMLFrameElement>(element) || IsA<HTMLFrameSetElement>(element)) {
    // Frames and framesets never honor position:relative or position:absolute.
    // This is necessary to fix a crash where a site tries to position these
    // objects. They also never honor display nor floating.
    builder.SetPosition(EPosition::kStatic);
    builder.SetDisplay(EDisplay::kBlock);
    builder.SetFloating(EFloat::kNone);
    return;
  }

  if (IsA<HTMLFrameElementBase>(element)) {
    if (builder.Display() == EDisplay::kContents) {
      builder.SetDisplay(EDisplay::kNone);
      return;
    }
    return;
  }

  if (IsA<HTMLFencedFrameElement>(element)) {
    // Force the CSS style `zoom` property to 1 so that the embedder cannot
    // communicate into the fenced frame by adjusting it, but still include
    // the page zoom factor in the effective zoom, which is safe because it
    // comes from user intervention. crbug.com/1285327
    builder.SetEffectiveZoom(
        element.GetDocument().GetStyleResolver().InitialZoom());
  }

  if (IsA<HTMLLegendElement>(element) &&
      builder.Display() != EDisplay::kContents) {
    // Allow any blockified display value for legends. Note that according to
    // the spec, this shouldn't affect computed style (like we do here).
    // Instead, the display override should be determined during box creation,
    // and even then only be applied to the rendered legend inside a
    // fieldset. However, Blink determines the rendered legend during layout
    // instead of during layout object creation, and also generally makes
    // assumptions that the computed display value is the one to use.
    builder.SetDisplay(EquivalentBlockDisplay(builder.Display()));
    return;
  }

  if (IsA<HTMLMarqueeElement>(element)) {
    // For now, <marquee> requires an overflow clip to work properly.
    builder.SetOverflowX(EOverflow::kHidden);
    builder.SetOverflowY(EOverflow::kHidden);
    return;
  }

  if (IsA<HTMLTextAreaElement>(element)) {
    // Textarea considers overflow visible as auto.
    builder.SetOverflowX(builder.OverflowX() == EOverflow::kVisible
                             ? EOverflow::kAuto
                             : builder.OverflowX());
    builder.SetOverflowY(builder.OverflowY() == EOverflow::kVisible
                             ? EOverflow::kAuto
                             : builder.OverflowY());
    if (builder.Display() == EDisplay::kContents) {
      builder.SetDisplay(EDisplay::kNone);
    }
    return;
  }

  if (auto* html_plugin_element = DynamicTo<HTMLPlugInElement>(element)) {
    builder.SetRequiresAcceleratedCompositingForExternalReasons(
        html_plugin_element->ShouldAccelerate());
    if (builder.Display() == EDisplay::kContents) {
      builder.SetDisplay(EDisplay::kNone);
    }
    return;
  }

  if (IsA<HTMLUListElement>(element) || IsA<HTMLOListElement>(element)) {
    builder.SetIsInsideListElement();
    return;
  }

  if (builder.Display() == EDisplay::kContents) {
    // See https://drafts.csswg.org/css-display/#unbox-html
    // Some of these elements are handled with other adjustments above.
    if (IsA<HTMLBRElement>(element) || IsA<HTMLWBRElement>(element) ||
        IsA<HTMLMeterElement>(element) || IsA<HTMLProgressElement>(element) ||
        IsA<HTMLCanvasElement>(element) || IsA<HTMLMediaElement>(element) ||
        IsA<HTMLInputElement>(element) || IsA<HTMLTextAreaElement>(element) ||
        IsA<HTMLSelectElement>(element)) {
      builder.SetDisplay(EDisplay::kNone);
    }
  }

  if (IsA<HTMLBodyElement>(element) &&
      element.GetDocument().FirstBodyElement() != element) {
    builder.SetIsSecondaryBodyElement();
  }
}

void StyleAdjuster::AdjustOverflow(ComputedStyleBuilder& builder,
                                   Element* element) {
  DCHECK(builder.OverflowX() != EOverflow::kVisible ||
         builder.OverflowY() != EOverflow::kVisible);

  bool overflow_is_clip_or_visible =
      IsOverflowClipOrVisible(builder.OverflowY()) &&
      IsOverflowClipOrVisible(builder.OverflowX());
  if (!overflow_is_clip_or_visible && builder.IsDisplayTableBox()) {
    // Tables only support overflow:hidden and overflow:visible and ignore
    // anything else, see https://drafts.csswg.org/css2/visufx.html#overflow. As
    // a table is not a block container box the rules for resolving conflicting
    // x and y values in CSS Overflow Module Level 3 do not apply. Arguably
    // overflow-x and overflow-y aren't allowed on tables but all UAs allow it.
    if (builder.OverflowX() != EOverflow::kHidden) {
      builder.SetOverflowX(EOverflow::kVisible);
    }
    if (builder.OverflowY() != EOverflow::kHidden) {
      builder.SetOverflowY(EOverflow::kVisible);
    }
    // If we are left with conflicting overflow values for the x and y axes on a
    // table then resolve both to OverflowVisible. This is interoperable
    // behaviour but is not specced anywhere.
    if (builder.OverflowX() == EOverflow::kVisible) {
      builder.SetOverflowY(EOverflow::kVisible);
    } else if (builder.OverflowY() == EOverflow::kVisible) {
      builder.SetOverflowX(EOverflow::kVisible);
    }
  } else if (!IsOverflowClipOrVisible(builder.OverflowY())) {
    // Values of 'clip' and 'visible' can only be used with 'clip' and
    // 'visible.' If they aren't, 'clip' and 'visible' is reset.
    if (builder.OverflowX() == EOverflow::kVisible) {
      builder.SetOverflowX(EOverflow::kAuto);
    } else if (builder.OverflowX() == EOverflow::kClip) {
      builder.SetOverflowX(EOverflow::kHidden);
    }
  } else if (!IsOverflowClipOrVisible(builder.OverflowX())) {
    // Values of 'clip' and 'visible' can only be used with 'clip' and
    // 'visible.' If they aren't, 'clip' and 'visible' is reset.
    if (builder.OverflowY() == EOverflow::kVisible) {
      builder.SetOverflowY(EOverflow::kAuto);
    } else if (builder.OverflowY() == EOverflow::kClip) {
      builder.SetOverflowY(EOverflow::kHidden);
    }
  }

  if (element && !element->IsPseudoElement() &&
      (builder.OverflowX() == EOverflow::kClip ||
       builder.OverflowY() == EOverflow::kClip)) {
    UseCounter::Count(element->GetDocument(),
                      WebFeature::kOverflowClipAlongEitherAxis);
  }

  // overlay is a legacy alias of auto.
  // https://drafts.csswg.org/css-overflow-3/#valdef-overflow-auto
  if (builder.OverflowY() == EOverflow::kOverlay) {
    builder.SetOverflowY(EOverflow::kAuto);
  }
  if (builder.OverflowX() == EOverflow::kOverlay) {
    builder.SetOverflowX(EOverflow::kAuto);
  }
}

// g-issues.chromium.org/issues/349835587
// https://github.com/WICG/canvas-place-element
static bool IsCanvasPlacedElement(const Element* element) {
  if (RuntimeEnabledFeatures::CanvasPlaceElementEnabled() && element) {
    // Only want to do the different layout if placeElement has been called.
    if (const auto* canvas =
            DynamicTo<HTMLCanvasElement>(element->parentElement())) {
      return canvas->HasPlacedElements();
    }
  }

  return false;
}

void StyleAdjuster::AdjustStyleForDisplay(
    ComputedStyleBuilder& builder,
    const ComputedStyle& layout_parent_style,
    const Element* element,
    Document* document) {
  bool is_canvas_placed_element = IsCanvasPlacedElement(element);

  if ((layout_parent_style.BlockifiesChildren() && !HostIsInputFile(element)) ||
      is_canvas_placed_element) {
    builder.SetIsInBlockifyingDisplay();
    if (builder.Display() != EDisplay::kContents) {
      builder.SetDisplay(EquivalentBlockDisplay(builder.Display()));
      if (!builder.HasOutOfFlowPosition()) {
        builder.SetIsFlexOrGridOrCustomItem();
      }
    }
    if (layout_parent_style.IsDisplayFlexibleOrGridBox() ||
        layout_parent_style.IsDisplayMathType() || is_canvas_placed_element) {
      builder.SetIsInsideDisplayIgnoringFloatingChildren();
    }

    if (is_canvas_placed_element) {
      builder.SetPosition(EPosition::kStatic);
    }
  }

  // We need to avoid to inlinify children of a <fieldset>, which creates a
  // dedicated LayoutObject and it assumes only block children.
  if (layout_parent_style.InlinifiesChildren() &&
      !builder.HasOutOfFlowPosition() &&
      !(element && IsA<HTMLFieldSetElement>(element->parentNode()))) {
    if (builder.IsFloating()) {
      builder.SetFloating(EFloat::kNone);
      if (document) {
        document->AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                ConsoleMessage::Source::kRendering,
                ConsoleMessage::Level::kInfo,
                "`float` property is not supported correctly inside an element "
                "with `display: ruby` or `display: ruby-text`."),
            true);
      }
    }
    if (!builder.IsFloating()) {
      builder.SetIsInInlinifyingDisplay();
      builder.SetDisplay(EquivalentInlineDisplay(builder.Display()));
    }
  }

  if (builder.Display() == EDisplay::kBlock) {
    return;
  }

  // FIXME: Don't support this mutation for pseudo styles like first-letter or
  // first-line, since it's not completely clear how that should work.
  if (builder.Display() == EDisplay::kInline &&
      builder.StyleType() == kPseudoIdNone &&
      builder.GetWritingMode() != layout_parent_style.GetWritingMode()) {
    builder.SetDisplay(EDisplay::kInlineBlock);
  }

  // writing-mode does not apply to table row groups, table column groups, table
  // rows, and table columns.
  // TODO(crbug.com/736072): Borders specified with logical css properties will
  // not change to reflect new writing mode. ex: border-block-start.
  if (builder.Display() == EDisplay::kTableColumn ||
      builder.Display() == EDisplay::kTableColumnGroup ||
      builder.Display() == EDisplay::kTableFooterGroup ||
      builder.Display() == EDisplay::kTableHeaderGroup ||
      builder.Display() == EDisplay::kTableRow ||
      builder.Display() == EDisplay::kTableRowGroup) {
    builder.SetWritingMode(layout_parent_style.GetWritingMode());
    builder.SetTextOrientation(layout_parent_style.GetTextOrientation());
    builder.UpdateFontOrientation();
  }

  // Blockify the child boxes of media elements. crbug.com/1379779.
  if (IsAtMediaUAShadowBoundary(element)) {
    builder.SetDisplay(EquivalentBlockDisplay(builder.Display()));
  }

  // display: -webkit-box when used with (-webkit)-line-clamp
  if (RuntimeEnabledFeatures::CSSLineClampWebkitBoxBlockificationEnabled() &&
      builder.BoxOrient() == EBoxOrient::kVertical &&
      (builder.WebkitLineClamp() != 0 || builder.StandardLineClamp() != 0 ||
       builder.HasAutoStandardLineClamp())) {
    if (builder.Display() == EDisplay::kWebkitBox) {
      builder.SetDisplay(EDisplay::kFlowRoot);
      builder.SetIsSpecifiedDisplayWebkitBox();
    } else if (builder.Display() == EDisplay::kWebkitInlineBox) {
      builder.SetDisplay(EDisplay::kInlineBlock);
      builder.SetIsSpecifiedDisplayWebkitBox();
    }
  }
}

bool StyleAdjuster::IsEditableElement(Element* element,
                                      const ComputedStyleBuilder& builder) {
  if (builder.UserModify() != EUserModify::kReadOnly) {
    return true;
  }

  if (!element) {
    return false;
  }

  if (auto* textarea = DynamicTo<HTMLTextAreaEleme
```