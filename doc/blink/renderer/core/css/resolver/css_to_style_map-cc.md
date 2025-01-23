Response:
Let's break down the thought process for analyzing the `css_to_style_map.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies (HTML, CSS, JavaScript), examples, logical reasoning, potential errors, and debugging clues.

2. **Initial Scan and Keyword Recognition:**  Quickly skim the code, looking for familiar terms and patterns. Keywords like `CSSValue`, `StyleResolverState`, `ComputedStyle`, `FillLayer`, `Animation`, `Transition`, and the `Map...` function names immediately stand out. The file path `blink/renderer/core/css/resolver/` also provides a crucial context: this file is part of the CSS resolution process.

3. **Identify the Core Functionality:** The `Map...` prefix in many function names strongly suggests that this file is responsible for *mapping* CSS property values (represented as `CSSValue` objects) to internal style representations used by the rendering engine (often stored within `ComputedStyle` or related structures like `FillLayer`).

4. **Categorize the Mappings:**  Observe that the functions are grouped by the CSS properties they handle. Examples include `MapFillAttachment`, `MapFillClip`, `MapAnimationDelayStart`, `MapAnimationDirection`, and `MapNinePieceImage`. This suggests a one-to-one (or sometimes one-to-many for shorthands) relationship between CSS properties and these mapping functions.

5. **Infer the Role of `StyleResolverState`:** The `StyleResolverState& state` parameter is present in many functions. This hints that this object holds contextual information needed during the CSS resolution process, such as the current element being styled and potentially access to the computed style.

6. **Connect to Web Technologies:**
    * **CSS:**  The file directly deals with `CSSValue` objects and maps them to internal representations. This is the most obvious connection. The function names often directly correspond to CSS property names.
    * **HTML:** The CSS styles being resolved are ultimately applied to HTML elements. The mapping process is triggered when the browser needs to determine the final styles of an HTML element.
    * **JavaScript:** JavaScript can manipulate CSS styles in several ways (e.g., through `element.style`, setting classes, or using the CSSOM). These manipulations eventually lead to the CSS resolution process, which involves this file. Animations and transitions, often controlled by JavaScript, are explicitly handled in this file.

7. **Provide Concrete Examples:**  For each web technology, provide a simple, illustrative example.
    * **HTML:** A basic `<div>` with inline styles.
    * **CSS:**  Demonstrate how a CSS rule sets a property that this file would handle.
    * **JavaScript:** Show how JavaScript can change a style, triggering the resolution process.

8. **Reason about Input and Output:** Select a representative function (e.g., `MapFillAttachment`). Describe what the input (`CSSValue`) and the expected output (modification of the `FillLayer`) would be for different CSS values. This demonstrates the mapping logic.

9. **Identify Potential User/Programming Errors:** Think about common mistakes developers make when working with CSS that could lead to this code being executed, potentially with unexpected results. Examples include invalid CSS values, typos, or misunderstandings of CSS property behavior.

10. **Outline the User Journey (Debugging Clues):**  Trace the steps a user might take in a browser that would eventually lead to this code being executed. Start with the user loading a page, the browser parsing the HTML and CSS, and then the style resolution process occurring. Emphasize how developer tools can be used to inspect styles and potentially trigger re-resolutions.

11. **Structure and Refine:** Organize the information logically with clear headings and bullet points. Ensure that the explanations are concise and easy to understand. Review the generated response to make sure it accurately reflects the functionality of the file. For example, initially, I might focus too much on individual functions. The refinement would involve emphasizing the overall *mapping* purpose and how it fits into the broader CSS resolution process. Also, ensure the examples are clear and directly related to the function of the file. For example, demonstrating how an invalid CSS value leads to a default value being used by the `Map` function.

12. **Self-Correction/Refinement Example:**  Initially, I might focus heavily on the low-level C++ code. However, the request also asks about the relationship to HTML, CSS, and JavaScript. So, a refinement would be to explicitly connect the C++ functions to their corresponding CSS properties and how those properties are used in web development. Similarly, ensure the debugging clues are practical and relate to how a developer might actually investigate style issues.
这个文件 `blink/renderer/core/css/resolver/css_to_style_map.cc` 的主要功能是将 CSS 属性值 (以 `CSSValue` 对象表示) 映射到 Blink 渲染引擎内部的样式表示形式，这些内部表示形式通常存储在 `ComputedStyle` 对象或其相关的子对象中。  它位于 CSS 解析和样式计算的关键路径上。

下面详细列举其功能，并结合 JavaScript、HTML 和 CSS 进行说明：

**核心功能：CSS 属性值到内部样式表示的映射**

* **将 `CSSValue` 转换为内部类型:**  该文件包含大量的 `Map...` 函数，每个函数负责处理一个或多个相关的 CSS 属性。这些函数接收一个 `CSSValue` 对象 (代表 CSS 规则中属性的值) 并将其转换为引擎内部使用的类型，例如枚举值、长度值、颜色值等。
* **设置 `ComputedStyle` 的属性:** 转换后的值最终会被用来设置 `ComputedStyle` 对象或其子对象（例如 `FillLayer`，用于处理背景和遮罩等）。`ComputedStyle` 是浏览器用于存储元素最终计算后样式的核心数据结构。
* **处理不同类型的 `CSSValue`:**  `CSSValue` 有多种类型，例如 `CSSIdentifierValue` (关键字，如 `fixed`, `scroll`)、`CSSPrimitiveValue` (具体数值，如 `10px`, `50%`)、`CSSColorValue` (颜色值)、`CSSImageValue` (图像值) 等。`css_to_style_map.cc` 中的函数会根据 `CSSValue` 的类型进行相应的转换。

**与 JavaScript、HTML、CSS 的关系及举例说明：**

1. **CSS:** 这是该文件最直接关联的部分。
    * **功能举例:**  当 CSS 规则 `background-color: red;` 应用到一个 HTML 元素时，CSS 解析器会创建一个表示该规则的结构，其中 `background-color` 对应一个属性 ID，`red` 对应一个 `CSSIdentifierValue` 对象。`CSSToStyleMap::MapFillImage` (或者类似的函数，取决于具体的属性) 会被调用，接收到 `red` 的 `CSSIdentifierValue`，并将其转换为引擎内部表示颜色的类型，最终设置到 `ComputedStyle` 对象的背景颜色属性上。
    * **逻辑推理:**
        * **假设输入 (CSS):** `border-width: 5px;`
        * **假设输出 (内部样式):**  `ComputedStyle` 对象的 `border_top_.width()`, `border_right_.width()`, `border_bottom_.width()`, `border_left_.width()` 等会被设置为表示 5 像素的内部长度值。

2. **HTML:**  HTML 元素是 CSS 样式应用的目标。
    * **功能举例:** HTML 元素 `<div style="font-size: 16px;">Hello</div>` 中的内联样式 `font-size: 16px;` 会被解析，`16px` 会被表示为一个 `CSSPrimitiveValue`。`CSSToStyleMap` 中负责处理 `font-size` 的函数 (可能涉及到单位转换) 会被调用，并将 `16px` 转换为内部的字体大小表示，最终影响该 `<div>` 元素在页面上的渲染大小。

3. **JavaScript:** JavaScript 可以动态修改元素的样式，这些修改最终也会通过类似的映射过程生效。
    * **功能举例:** 当 JavaScript 代码 `element.style.marginLeft = '20px';` 执行时，浏览器会将字符串 `'20px'` 解析为一个 `CSSPrimitiveValue`。然后，与 `margin-left` 相关的 `CSSToStyleMap` 函数会被调用，将 `20px` 转换为内部长度值并更新元素的样式。
    * **功能举例 (动画):** 当 JavaScript 使用 CSS 动画或过渡时，例如：
      ```javascript
      element.style.transition = 'opacity 1s ease-in-out';
      element.style.opacity = 0.5;
      ```
      `CSSToStyleMap` 中处理 `transition` 属性的函数 (`MapAnimationTimingFunction` 等) 会被调用，将 `ease-in-out` 转换为内部的 timing function 对象，供动画引擎使用。

**逻辑推理的假设输入与输出:**

* **假设输入 (CSS):** `background-repeat: repeat-x no-repeat;`
* **假设输出 (内部样式):** `FillLayer` 对象的 `repeat_x` 会被设置为表示 `repeat` 的枚举值，`repeat_y` 会被设置为表示 `no-repeat` 的枚举值。 (`MapFillRepeat` 函数会处理这种情况)

**用户或编程常见的使用错误及举例说明:**

* **拼写错误或使用了不存在的 CSS 关键字:**
    * **错误示例 (CSS):** `background-color: rd;` (拼写错误) 或 `display: table-row-grouping;` (不存在的关键字)。
    * **结果:**  `CSSToStyleMap` 中处理 `background-color` 的函数接收到 `rd` 后，由于无法识别，通常会使用属性的初始值或者忽略该值。开发者可能在页面上看不到预期的红色背景。
* **使用了错误的单位:**
    * **错误示例 (CSS):** `width: 10percent;` (正确的单位是 `%`)。
    * **结果:**  `CSSToStyleMap` 中处理 `width` 的函数无法识别 `percent` 单位，可能会将其视为无效值并使用默认值，导致元素宽度不是预期的百分比。
* **类型不匹配的 CSS 值:**
    * **错误示例 (CSS):** `font-size: bold;` (`font-size` 期望的是长度值，而不是关键字 `bold`)。
    * **结果:** `CSSToStyleMap` 中处理 `font-size` 的函数会发现 `bold` 不是一个有效的长度值，通常会忽略该值，使用默认的字体大小。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中加载网页:** 这是所有渲染过程的起点。
2. **浏览器接收到 HTML、CSS 和 JavaScript 代码:**  这些资源可能来自网络、本地文件或缓存。
3. **HTML 解析器构建 DOM 树:** 浏览器解析 HTML 代码，构建文档对象模型 (DOM) 树，表示页面的结构。
4. **CSS 解析器解析 CSS 规则:** 浏览器解析 CSS 代码（包括外部样式表、`<style>` 标签内的样式和内联样式），构建 CSSOM (CSS Object Model)。
5. **样式计算 (Style Calculation):**  对于 DOM 树中的每个元素，浏览器需要确定其最终的样式。这个过程包括：
    * **匹配 CSS 规则:** 找出哪些 CSS 规则适用于当前元素（根据选择器）。
    * **计算优先级和层叠:**  当多个规则影响同一个属性时，根据 CSS 的层叠规则 (specificity, origin, etc.) 确定最终应用的属性值。
    * **解析和转换 CSS 值:**  对于每个最终应用的 CSS 属性值，`css_to_style_map.cc` 中的函数会被调用，将 `CSSValue` 对象转换为引擎内部的表示。
6. **布局 (Layout):**  基于计算出的样式，浏览器计算每个元素的大小和位置。
7. **绘制 (Paint):**  浏览器将元素绘制到屏幕上。

**调试线索:**

* **开发者工具 (DevTools):** 浏览器开发者工具的 "Elements" 面板中的 "Styles" 或 "Computed" 标签是调试 CSS 的关键。
    * **查看计算后的样式:**  "Computed" 标签显示了元素最终应用的样式，这反映了 `ComputedStyle` 对象的内容，可以帮助确认 `css_to_style_map.cc` 的转换是否按预期工作。
    * **查看应用的 CSS 规则:** "Styles" 标签显示了哪些 CSS 规则影响了元素，以及它们的优先级，有助于理解哪些 `CSSValue` 被传递给了 `css_to_style_map.cc`。
* **断点调试 (C++):**  对于 Blink 引擎的开发者，可以在 `css_to_style_map.cc` 的相关函数中设置断点，查看 `CSSValue` 的内容以及转换后的内部值，从而深入了解样式计算的过程。
* **性能分析工具:**  在性能分析中，样式计算通常是一个重要的环节。如果页面渲染性能不佳，可以关注样式计算的时间，并进一步分析 `css_to_style_map.cc` 中哪些操作耗时较多。

总而言之，`blink/renderer/core/css/resolver/css_to_style_map.cc` 是 Blink 渲染引擎中一个至关重要的组件，它负责将抽象的 CSS 属性值转化为引擎可以理解和使用的内部样式表示，是实现网页样式效果的基础。 理解其功能有助于我们更好地理解浏览器的工作原理，并能更有效地调试 CSS 相关的问题。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/css_to_style_map.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc. All
 * rights reserved.
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

#include "third_party/blink/renderer/core/css/resolver/css_to_style_map.h"

#include "third_party/blink/renderer/core/animation/css/css_animation_data.h"
#include "third_party/blink/renderer/core/animation/effect_model.h"
#include "third_party/blink/renderer/core/css/css_border_image_slice_value.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_quad_value.h"
#include "third_party/blink/renderer/core/css/css_repeat_style_value.h"
#include "third_party/blink/renderer/core/css/css_scroll_value.h"
#include "third_party/blink/renderer/core/css/css_timing_function_value.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/css_view_value.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/style/border_image_length_box.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/fill_layer.h"
#include "third_party/blink/renderer/platform/animation/timing_function.h"

namespace blink {

void CSSToStyleMap::MapFillAttachment(StyleResolverState&,
                                      FillLayer* layer,
                                      const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetAttachment(FillLayer::InitialFillAttachment(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return;
  }

  switch (identifier_value->GetValueID()) {
    case CSSValueID::kFixed:
      layer->SetAttachment(EFillAttachment::kFixed);
      break;
    case CSSValueID::kScroll:
      layer->SetAttachment(EFillAttachment::kScroll);
      break;
    case CSSValueID::kLocal:
      layer->SetAttachment(EFillAttachment::kLocal);
      break;
    default:
      return;
  }
}

void CSSToStyleMap::MapFillClip(StyleResolverState&,
                                FillLayer* layer,
                                const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetClip(FillLayer::InitialFillClip(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return;
  }

  layer->SetClip(identifier_value->ConvertTo<EFillBox>());
}

void CSSToStyleMap::MapFillCompositingOperator(StyleResolverState&,
                                               FillLayer* layer,
                                               const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetCompositingOperator(
        FillLayer::InitialFillCompositingOperator(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return;
  }

  layer->SetCompositingOperator(
      identifier_value->ConvertTo<CompositingOperator>());
}

void CSSToStyleMap::MapFillBlendMode(StyleResolverState&,
                                     FillLayer* layer,
                                     const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetBlendMode(FillLayer::InitialFillBlendMode(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return;
  }

  layer->SetBlendMode(identifier_value->ConvertTo<BlendMode>());
}

void CSSToStyleMap::MapFillOrigin(StyleResolverState&,
                                  FillLayer* layer,
                                  const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetOrigin(FillLayer::InitialFillOrigin(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return;
  }

  layer->SetOrigin(identifier_value->ConvertTo<EFillBox>());
}

void CSSToStyleMap::MapFillImage(StyleResolverState& state,
                                 FillLayer* layer,
                                 const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetImage(FillLayer::InitialFillImage(layer->GetType()));
    return;
  }

  CSSPropertyID property = layer->GetType() == EFillLayerType::kBackground
                               ? CSSPropertyID::kBackgroundImage
                               : CSSPropertyID::kMaskImage;
  layer->SetImage(
      state.GetStyleImage(property, state.ResolveLightDarkPair(value)));
}

void CSSToStyleMap::MapFillRepeat(StyleResolverState&,
                                  FillLayer* layer,
                                  const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetRepeat(FillLayer::InitialFillRepeat(layer->GetType()));
    return;
  }

  if (const auto* repeat = DynamicTo<CSSRepeatStyleValue>(value)) {
    layer->SetRepeat({repeat->x()->ConvertTo<EFillRepeat>(),
                      repeat->y()->ConvertTo<EFillRepeat>()});
  }
}

void CSSToStyleMap::MapFillMaskMode(StyleResolverState&,
                                    FillLayer* layer,
                                    const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetMaskMode(FillLayer::InitialFillMaskMode(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return;
  }

  layer->SetMaskMode(identifier_value->ConvertTo<EFillMaskMode>());
}

void CSSToStyleMap::MapFillSize(StyleResolverState& state,
                                FillLayer* layer,
                                const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetSizeType(FillLayer::InitialFillSizeType(layer->GetType()));
    layer->SetSizeLength(FillLayer::InitialFillSizeLength(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value && !value.IsPrimitiveValue() && !value.IsValuePair()) {
    return;
  }

  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kContain) {
    layer->SetSizeType(EFillSizeType::kContain);
  } else if (identifier_value &&
             identifier_value->GetValueID() == CSSValueID::kCover) {
    layer->SetSizeType(EFillSizeType::kCover);
  } else {
    layer->SetSizeType(EFillSizeType::kSizeLength);
  }

  LengthSize b = FillLayer::InitialFillSizeLength(layer->GetType());

  if (identifier_value &&
      (identifier_value->GetValueID() == CSSValueID::kContain ||
       identifier_value->GetValueID() == CSSValueID::kCover)) {
    layer->SetSizeLength(b);
    return;
  }

  Length first_length;
  Length second_length;

  if (const auto* pair = DynamicTo<CSSValuePair>(value)) {
    first_length =
        StyleBuilderConverter::ConvertLengthOrAuto(state, pair->First());
    second_length =
        StyleBuilderConverter::ConvertLengthOrAuto(state, pair->Second());
  } else {
    DCHECK(value.IsPrimitiveValue() || value.IsIdentifierValue());
    first_length = StyleBuilderConverter::ConvertLengthOrAuto(state, value);
    second_length = Length();
  }

  b.SetWidth(first_length);
  b.SetHeight(second_length);
  layer->SetSizeLength(b);
}

void CSSToStyleMap::MapFillPositionX(StyleResolverState& state,
                                     FillLayer* layer,
                                     const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetPositionX(FillLayer::InitialFillPositionX(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value && !value.IsPrimitiveValue() && !value.IsValuePair()) {
    return;
  }

  Length length;
  auto* pair = DynamicTo<CSSValuePair>(value);
  if (pair) {
    length = To<CSSPrimitiveValue>(pair->Second())
                 .ConvertToLength(state.CssToLengthConversionData());
  } else {
    length = StyleBuilderConverter::ConvertPositionLength<CSSValueID::kLeft,
                                                          CSSValueID::kRight>(
        state, value);
  }

  layer->SetPositionX(length);
  if (pair) {
    layer->SetBackgroundXOrigin(To<CSSIdentifierValue>(pair->First())
                                    .ConvertTo<BackgroundEdgeOrigin>());
  }
}

void CSSToStyleMap::MapFillPositionY(StyleResolverState& state,
                                     FillLayer* layer,
                                     const CSSValue& value) {
  if (value.IsInitialValue()) {
    layer->SetPositionY(FillLayer::InitialFillPositionY(layer->GetType()));
    return;
  }

  const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value && !value.IsPrimitiveValue() && !value.IsValuePair()) {
    return;
  }

  Length length;
  auto* pair = DynamicTo<CSSValuePair>(value);
  if (pair) {
    length = To<CSSPrimitiveValue>(pair->Second())
                 .ConvertToLength(state.CssToLengthConversionData());
  } else {
    length = StyleBuilderConverter::ConvertPositionLength<CSSValueID::kTop,
                                                          CSSValueID::kBottom>(
        state, value);
  }

  layer->SetPositionY(length);
  if (pair) {
    layer->SetBackgroundYOrigin(To<CSSIdentifierValue>(pair->First())
                                    .ConvertTo<BackgroundEdgeOrigin>());
  }
}

namespace {

Timing::Delay MapAnimationTimingDelay(const CSSLengthResolver& length_resolver,
                                      const CSSValue& value) {
  if (const auto* primitive = DynamicTo<CSSPrimitiveValue>(value)) {
    return Timing::Delay(
        AnimationTimeDelta(primitive->ComputeSeconds(length_resolver)));
  }

  return Timing::Delay();
}

}  // namespace

Timing::Delay CSSToStyleMap::MapAnimationDelayStart(StyleResolverState& state,
                                                    const CSSValue& value) {
  return MapAnimationTimingDelay(state.CssToLengthConversionData(), value);
}

Timing::Delay CSSToStyleMap::MapAnimationDelayEnd(const CSSValue& value) {
  // Note: using default length resolver here, as this function is only
  // called from the serialization code.
  return MapAnimationTimingDelay(CSSToLengthConversionData(/*element=*/nullptr),
                                 value);
}

Timing::Delay CSSToStyleMap::MapAnimationDelayEnd(StyleResolverState& state,
                                                  const CSSValue& value) {
  return MapAnimationTimingDelay(state.CssToLengthConversionData(), value);
}

Timing::PlaybackDirection CSSToStyleMap::MapAnimationDirection(
    StyleResolverState& state,
    const CSSValue& value) {
  switch (To<CSSIdentifierValue>(value).GetValueID()) {
    case CSSValueID::kNormal:
      return Timing::PlaybackDirection::NORMAL;
    case CSSValueID::kAlternate:
      return Timing::PlaybackDirection::ALTERNATE_NORMAL;
    case CSSValueID::kReverse:
      return Timing::PlaybackDirection::REVERSE;
    case CSSValueID::kAlternateReverse:
      return Timing::PlaybackDirection::ALTERNATE_REVERSE;
    default:
      NOTREACHED();
  }
}

std::optional<double> CSSToStyleMap::MapAnimationDuration(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* identifier = DynamicTo<CSSIdentifierValue>(value);
      identifier && identifier->GetValueID() == CSSValueID::kAuto) {
    return std::nullopt;
  }
  return To<CSSPrimitiveValue>(value).ComputeSeconds();
}

Timing::FillMode CSSToStyleMap::MapAnimationFillMode(StyleResolverState& state,
                                                     const CSSValue& value) {
  switch (To<CSSIdentifierValue>(value).GetValueID()) {
    case CSSValueID::kNone:
      return Timing::FillMode::NONE;
    case CSSValueID::kForwards:
      return Timing::FillMode::FORWARDS;
    case CSSValueID::kBackwards:
      return Timing::FillMode::BACKWARDS;
    case CSSValueID::kBoth:
      return Timing::FillMode::BOTH;
    default:
      NOTREACHED();
  }
}

double CSSToStyleMap::MapAnimationIterationCount(StyleResolverState& state,
                                                 const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kInfinite) {
    return std::numeric_limits<double>::infinity();
  }
  return To<CSSPrimitiveValue>(value).GetFloatValue();
}

AtomicString CSSToStyleMap::MapAnimationName(StyleResolverState& state,
                                             const CSSValue& value) {
  if (auto* custom_ident_value = DynamicTo<CSSCustomIdentValue>(value)) {
    return AtomicString(custom_ident_value->Value());
  }
  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kNone);
  return CSSAnimationData::InitialName();
}

CSSTransitionData::TransitionBehavior CSSToStyleMap::MapAnimationBehavior(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* ident_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (ident_value->GetValueID()) {
      case CSSValueID::kNormal:
        return CSSTransitionData::TransitionBehavior::kNormal;
      case CSSValueID::kAllowDiscrete:
        return CSSTransitionData::TransitionBehavior::kAllowDiscrete;
      default:
        break;
    }
  }
  return CSSTransitionData::InitialBehavior();
}

StyleTimeline CSSToStyleMap::MapAnimationTimeline(StyleResolverState& state,
                                                  const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK(ident->GetValueID() == CSSValueID::kAuto ||
           ident->GetValueID() == CSSValueID::kNone);
    return StyleTimeline(ident->GetValueID());
  }
  if (auto* custom_ident = DynamicTo<CSSCustomIdentValue>(value)) {
    return StyleTimeline(MakeGarbageCollected<ScopedCSSName>(
        custom_ident->Value(), custom_ident->GetTreeScope()));
  }
  if (value.IsViewValue()) {
    const auto& view_value = To<cssvalue::CSSViewValue>(value);
    const auto* axis_value = DynamicTo<CSSIdentifierValue>(view_value.Axis());
    TimelineAxis axis = axis_value ? axis_value->ConvertTo<TimelineAxis>()
                                   : StyleTimeline::ViewData::DefaultAxis();
    const auto* inset_value = view_value.Inset();
    TimelineInset inset =
        inset_value ? StyleBuilderConverter::ConvertSingleTimelineInset(
                          state, *inset_value)
                    : TimelineInset();
    return StyleTimeline(StyleTimeline::ViewData(axis, inset));
  }

  DCHECK(value.IsScrollValue());
  const auto& scroll_value = To<cssvalue::CSSScrollValue>(value);
  const auto* axis_value = DynamicTo<CSSIdentifierValue>(scroll_value.Axis());
  const auto* scroller_value =
      DynamicTo<CSSIdentifierValue>(scroll_value.Scroller());

  TimelineAxis axis = axis_value ? axis_value->ConvertTo<TimelineAxis>()
                                 : StyleTimeline::ScrollData::DefaultAxis();
  TimelineScroller scroller =
      scroller_value ? scroller_value->ConvertTo<TimelineScroller>()
                     : StyleTimeline::ScrollData::DefaultScroller();

  return StyleTimeline(StyleTimeline::ScrollData(axis, scroller));
}

EAnimPlayState CSSToStyleMap::MapAnimationPlayState(StyleResolverState& state,
                                                    const CSSValue& value) {
  if (To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kPaused) {
    return EAnimPlayState::kPaused;
  }
  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kRunning);
  return EAnimPlayState::kPlaying;
}

namespace {

std::optional<TimelineOffset> MapAnimationRange(StyleResolverState& state,
                                                const CSSValue& value,
                                                double default_percent) {
  if (auto* ident = DynamicTo<CSSIdentifierValue>(value);
      ident && ident->GetValueID() == CSSValueID::kNormal) {
    return std::nullopt;
  }
  const auto& list = To<CSSValueList>(value);
  DCHECK_GE(list.length(), 1u);
  DCHECK_LE(list.length(), 2u);
  TimelineOffset::NamedRange range_name = TimelineOffset::NamedRange::kNone;
  Length offset = Length::Percent(default_percent);
  if (list.Item(0).IsIdentifierValue()) {
    range_name = To<CSSIdentifierValue>(list.Item(0))
                     .ConvertTo<TimelineOffset::NamedRange>();
    if (list.length() == 2u) {
      offset = StyleBuilderConverter::ConvertLength(state, list.Item(1));
    }
  } else {
    offset = StyleBuilderConverter::ConvertLength(state, list.Item(0));
  }

  return TimelineOffset(range_name, offset);
}

}  // namespace

std::optional<TimelineOffset> CSSToStyleMap::MapAnimationRangeStart(
    StyleResolverState& state,
    const CSSValue& value) {
  return MapAnimationRange(state, value, 0);
}

std::optional<TimelineOffset> CSSToStyleMap::MapAnimationRangeEnd(
    StyleResolverState& state,
    const CSSValue& value) {
  return MapAnimationRange(state, value, 100);
}

EffectModel::CompositeOperation CSSToStyleMap::MapAnimationComposition(
    StyleResolverState& state,
    const CSSValue& value) {
  switch (To<CSSIdentifierValue>(value).GetValueID()) {
    case CSSValueID::kAdd:
      return EffectModel::kCompositeAdd;
    case CSSValueID::kAccumulate:
      return EffectModel::kCompositeAccumulate;
    case CSSValueID::kReplace:
    default:
      return EffectModel::kCompositeReplace;
  }
}

CSSTransitionData::TransitionProperty CSSToStyleMap::MapAnimationProperty(
    StyleResolverState& state,
    const CSSValue& value) {
  if (const auto* custom_ident_value = DynamicTo<CSSCustomIdentValue>(value)) {
    if (custom_ident_value->IsKnownPropertyID()) {
      return CSSTransitionData::TransitionProperty(
          custom_ident_value->ValueAsPropertyID());
    }
    return CSSTransitionData::TransitionProperty(custom_ident_value->Value());
  }
  if (To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kAll) {
    return CSSTransitionData::InitialProperty();
  }
  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kNone);
  return CSSTransitionData::TransitionProperty(
      CSSTransitionData::kTransitionNone);
}

scoped_refptr<TimingFunction> CSSToStyleMap::MapAnimationTimingFunction(
    const CSSValue& value) {
  // FIXME: We should probably only call into this function with a valid
  // single timing function value which isn't initial or inherit. We can
  // currently get into here with initial since the parser expands unset
  // properties in shorthands to initial.

  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kLinear:
        return LinearTimingFunction::Shared();
      case CSSValueID::kEase:
        return CubicBezierTimingFunction::Preset(
            CubicBezierTimingFunction::EaseType::EASE);
      case CSSValueID::kEaseIn:
        return CubicBezierTimingFunction::Preset(
            CubicBezierTimingFunction::EaseType::EASE_IN);
      case CSSValueID::kEaseOut:
        return CubicBezierTimingFunction::Preset(
            CubicBezierTimingFunction::EaseType::EASE_OUT);
      case CSSValueID::kEaseInOut:
        return CubicBezierTimingFunction::Preset(
            CubicBezierTimingFunction::EaseType::EASE_IN_OUT);
      case CSSValueID::kStepStart:
        return StepsTimingFunction::Preset(
            StepsTimingFunction::StepPosition::START);
      case CSSValueID::kStepEnd:
        return StepsTimingFunction::Preset(
            StepsTimingFunction::StepPosition::END);
      default:
        NOTREACHED();
    }
  }

  if (const auto* linear_timing_function =
          DynamicTo<cssvalue::CSSLinearTimingFunctionValue>(value)) {
    return LinearTimingFunction::Create(linear_timing_function->Points());
  }

  if (const auto* cubic_timing_function =
          DynamicTo<cssvalue::CSSCubicBezierTimingFunctionValue>(value)) {
    return CubicBezierTimingFunction::Create(
        cubic_timing_function->X1(), cubic_timing_function->Y1(),
        cubic_timing_function->X2(), cubic_timing_function->Y2());
  }

  const auto& steps_timing_function =
      To<cssvalue::CSSStepsTimingFunctionValue>(value);
  return StepsTimingFunction::Create(steps_timing_function.NumberOfSteps(),
                                     steps_timing_function.GetStepPosition());
}

scoped_refptr<TimingFunction> CSSToStyleMap::MapAnimationTimingFunction(
    StyleResolverState& state,
    const CSSValue& value) {
  return MapAnimationTimingFunction(value);
}

void CSSToStyleMap::MapNinePieceImage(StyleResolverState& state,
                                      CSSPropertyID property,
                                      const CSSValue& value,
                                      NinePieceImage& image) {
  // Retrieve the border image value.
  const auto* border_image = DynamicTo<CSSValueList>(value);

  // If we're not a value list, then we are "none" and don't need to alter the
  // empty image at all.
  if (!border_image) {
    return;
  }

  // Set the image (this kicks off the load).
  CSSPropertyID image_property;
  if (property == CSSPropertyID::kWebkitBorderImage) {
    image_property = CSSPropertyID::kBorderImageSource;
  } else if (property == CSSPropertyID::kWebkitMaskBoxImage) {
    image_property = CSSPropertyID::kWebkitMaskBoxImageSource;
  } else {
    image_property = property;
  }

  for (unsigned i = 0; i < border_image->length(); ++i) {
    const CSSValue& current = border_image->Item(i);

    if (current.IsImageValue() || current.IsImageGeneratorValue() ||
        current.IsImageSetValue()) {
      image.SetImage(state.GetStyleImage(image_property, current));
    } else if (current.IsBorderImageSliceValue()) {
      MapNinePieceImageSlice(state, current, image);
    } else if (const auto* slash_list = DynamicTo<CSSValueList>(current)) {
      size_t length = slash_list->length();
      // Map in the image slices.
      if (length && slash_list->Item(0).IsBorderImageSliceValue()) {
        MapNinePieceImageSlice(state, slash_list->Item(0), image);
      }

      // Map in the border slices.
      if (length > 1) {
        image.SetBorderSlices(
            MapNinePieceImageQuad(state, slash_list->Item(1)));
      }

      // Map in the outset.
      if (length > 2) {
        image.SetOutset(MapNinePieceImageQuad(state, slash_list->Item(2)));
      }
    } else if (current.IsPrimitiveValue() || current.IsValuePair()) {
      // Set the appropriate rules for stretch/round/repeat of the slices.
      MapNinePieceImageRepeat(state, current, image);
    }
  }

  if (property == CSSPropertyID::kWebkitBorderImage) {
    ComputedStyleBuilder& builder = state.StyleBuilder();
    // We have to preserve the legacy behavior of -webkit-border-image and make
    // the border slices also set the border widths. We don't need to worry
    // about percentages, since we don't even support those on real borders yet.
    if (image.BorderSlices().Top().IsLength() &&
        image.BorderSlices().Top().length().IsFixed()) {
      builder.SetBorderTopWidth(image.BorderSlices().Top().length().Pixels());
    }
    if (image.BorderSlices().Right().IsLength() &&
        image.BorderSlices().Right().length().IsFixed()) {
      builder.SetBorderRightWidth(
          image.BorderSlices().Right().length().Pixels());
    }
    if (image.BorderSlices().Bottom().IsLength() &&
        image.BorderSlices().Bottom().length().IsFixed()) {
      builder.SetBorderBottomWidth(
          image.BorderSlices().Bottom().length().Pixels());
    }
    if (image.BorderSlices().Left().IsLength() &&
        image.BorderSlices().Left().length().IsFixed()) {
      builder.SetBorderLeftWidth(image.BorderSlices().Left().length().Pixels());
    }
  }
}

static Length ConvertBorderImageSliceSide(
    const CSSLengthResolver& length_resolver,
    const CSSPrimitiveValue& value) {
  if (value.IsPercentage()) {
    return Length::Percent(value.ComputePercentage(length_resolver));
  }
  return Length::Fixed(round(value.ComputeNumber(length_resolver)));
}

void CSSToStyleMap::MapNinePieceImageSlice(StyleResolverState& state,
                                           const CSSValue& value,
                                           NinePieceImage& image) {
  if (!IsA<cssvalue::CSSBorderImageSliceValue>(value)) {
    return;
  }

  // Retrieve the border image value.
  const auto& border_image_slice =
      To<cssvalue::CSSBorderImageSliceValue>(value);

  // Set up a length box to represent our image slices.
  LengthBox box;
  const CSSQuadValue& slices = border_image_slice.Slices();
  box.top_ = ConvertBorderImageSliceSide(state.CssToLengthConversionData(),
                                         To<CSSPrimitiveValue>(*slices.Top()));
  box.bottom_ =
      ConvertBorderImageSliceSide(state.CssToLengthConversionData(),
                                  To<CSSPrimitiveValue>(*slices.Bottom()));
  box.left_ = ConvertBorderImageSliceSide(
      state.CssToLengthConversionData(), To<CSSPrimitiveValue>(*slices.Left()));
  box.right_ =
      ConvertBorderImageSliceSide(state.CssToLengthConversionData(),
                                  To<CSSPrimitiveValue>(*slices.Right()));
  image.SetImageSlices(box);

  // Set our fill mode.
  image.SetFill(border_image_slice.Fill());
}

static BorderImageLength ToBorderImageLength(const StyleResolverState& state,
                                             const CSSValue& value) {
  if (const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    if (primitive_value->IsNumber()) {
      return primitive_value->ComputeNumber(state.CssToLengthConversionData());
    }
  }
  return StyleBuilderConverter::ConvertLengthOrAuto(state, value);
}

BorderImageLengthBox CSSToStyleMap::MapNinePieceImageQuad(
    StyleResolverState& state,
    const CSSValue& value) {
  const auto* slices = DynamicTo<CSSQuadValue>(value);
  if (!slices) {
    return BorderImageLengthBox(Length::Auto());
  }

  // Set up a border image length box to represent our image slices.
  return BorderImageLengthBox(ToBorderImageLength(state, *slices->Top()),
                              ToBorderImageLength(state, *slices->Right()),
                              ToBorderImageLength(state, *slices->Bottom()),
                              ToBorderImageLength(state, *slices->Left()));
}

void CSSToStyleMap::MapNinePieceImageRepeat(StyleResolverState&,
                                            const CSSValue& value,
                                            NinePieceImage& image) {
  CSSValueID first_identifier;
  CSSValueID second_identifier;

  const auto* pair = DynamicTo<CSSValuePair>(value);
  if (pair != nullptr) {
    first_identifier = To<CSSIdentifierValue>(pair->First()).GetValueID();
    second_identifier = To<CSSIdentifierValue>(pair->Second()).GetValueID();
  } else {
    first_identifier = second_identifier =
        To<CSSIdentifierValue>(value).GetValueID();
  }

  ENinePieceImageRule horizontal_rule;
  switch (first_identifier) {
    case CSSValueID::kStretch:
      horizontal_rule = kStretchImageRule;
      break;
    case CSSValueID::kRound:
      horizontal_rule = kRoundImageRule;
      break;
    case CSSValueID::kSpace:
      horizontal_rule = kSpaceImageRule;
      break;
    default:  // CSSValueID::kRepeat
      horizontal_rule = kRepeatImageRule;
      break;
  }
  image.SetHorizontalRule(horizontal_rule);

  ENinePieceImageRule vertical_rule;
  switch (second_identifier) {
    case CSSValueID::kStretch:
      vertical_rule = kStretchImageRule;
      break;
    case CSSValueID::kRound:
      vertical_rule = kRoundImageRule;
      break;
    case CSSValueID::kSpace:
      vertical_rule = kSpaceImageRule;
      break;
    default:  // CSSValueID::kRepeat
      vertical_rule = kRepeatImageRule;
      break;
  }
  image.SetVerticalRule(vertical_rule);
}

}  // namespace blink
```