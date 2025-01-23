Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This code is part of the Blink rendering engine, specifically dealing with CSS property handling. I need to analyze each function in the snippet and identify its purpose.

Here's a breakdown of my thought process:

1. **Identify the core purpose:** The filename `longhands_custom.cc` suggests this file defines the behavior of specific, individual CSS properties (longhand properties).

2. **Analyze each function individually:** I'll go through each function and determine what CSS property it handles and what action it performs. The function names generally follow a pattern: `[PropertyName]::[Action]`. Common actions include `ParseSingleValue` (parsing CSS values from a stream) and `CSSValueFromComputedStyleInternal` (converting computed style values to CSSValue objects). There are also some specific color-related functions like `ColorIncludingFallback`.

3. **Relate to CSS concepts:**  For each property, I need to explain what it does in CSS. This involves understanding how the property affects the visual presentation of web pages.

4. **Identify JavaScript, HTML, and CSS relationships:**  I need to explain how each property interacts with these web technologies. For example, CSS properties are set in CSS stylesheets, and JavaScript can read and modify these styles. HTML elements are styled using CSS.

5. **Infer logic and provide examples:** Where parsing is involved, I can infer the expected input (CSS syntax) and output (internal representation).

6. **Identify potential user errors:**  Based on the parsing logic, I can consider common mistakes users might make when writing CSS for these properties.

7. **Trace user interaction:** I need to explain the user's actions that would lead to this code being executed, focusing on the browser's rendering pipeline.

8. **Synthesize a concise summary:**  Finally, I'll summarize the overall function of the code snippet.

**Detailed analysis of each function:**

* **`roundColor::ColorIncludingFallback`**: Handles the `background-color` property. Determines the final color, considering forced colors mode and potential `currentcolor` usage.
* **`BackgroundColor::CSSValueFromComputedStyleInternal`**:  Handles `background-color`. Converts the computed background color to a CSSValue. Handles `visited` link colors and forced colors.
* **`BackgroundImage::ParseSingleValue`**: Handles `background-image`. Parses comma-separated image URLs or `none`.
* **`BackgroundImage::CSSValueFromComputedStyleInternal`**: Handles `background-image`. Retrieves the computed background image layers.
* **`BackgroundOrigin::ParseSingleValue`**: Handles `background-origin`. Parses keywords like `padding-box`, `border-box`, `content-box`.
* **`BackgroundOrigin::CSSValueFromComputedStyleInternal`**: Handles `background-origin`. Retrieves the computed origin for each background layer.
* **`BackgroundPositionX::ParseSingleValue`**: Handles `background-position-x`. Parses horizontal positioning values (keywords or percentages/lengths).
* **`BackgroundPositionX::CSSValueFromComputedStyleInternal`**: Handles `background-position-x`. Retrieves the computed horizontal position for each background layer.
* **`BackgroundPositionY::ParseSingleValue`**: Handles `background-position-y`. Parses vertical positioning values (keywords or percentages/lengths).
* **`BackgroundPositionY::CSSValueFromComputedStyleInternal`**: Handles `background-position-y`. Retrieves the computed vertical position for each background layer.
* **`BackgroundSize::ParseSingleValue`**: Handles `background-size`. Parses sizing keywords (`auto`, `cover`, `contain`) or explicit sizes.
* **`BackgroundSize::CSSValueFromComputedStyleInternal`**: Handles `background-size`. Retrieves the computed size for each background layer.
* **`BackgroundRepeat::ParseSingleValue`**: Handles `background-repeat`. Parses repeat keywords like `repeat-x`, `repeat-y`, `no-repeat`, `repeat`, `space`, `round`.
* **`BackgroundRepeat::CSSValueFromComputedStyleInternal`**: Handles `background-repeat`. Retrieves the computed repeat style for the background.
* **`BaselineSource::CSSValueFromComputedStyleInternal`**: Handles `baseline-source`. Returns the computed baseline source.
* **`BaselineShift::ParseSingleValue`**: Handles `baseline-shift`. Parses keywords (`baseline`, `sub`, `super`) or lengths/percentages.
* **`BaselineShift::CSSValueFromComputedStyleInternal`**: Handles `baseline-shift`. Returns the computed baseline shift value.
* **`BaselineShift::ApplyInherit`**: Handles inheritance for `baseline-shift`.
* **`BaselineShift::ApplyValue`**: Applies parsed values to the style builder for `baseline-shift`.
* **`BlockSize::ParseSingleValue`**: Handles `block-size`. Parses width or height values.
* **`BlockSize::IsLayoutDependent`**: Checks if `block-size` affects layout.
* **Border properties (`BorderBlockEndColor`, `BorderBlockEndWidth`, etc.)**:  Handles individual border properties for logical borders. These functions parse color and width values.
* **Border corner radius properties (`BorderBottomLeftRadius`, `BorderBottomRightRadius`, etc.)**: Handles parsing and retrieving computed values for border radii.
* **Border style properties (`BorderBottomStyle`, `BorderLeftStyle`, etc.)**: Handles parsing and retrieving computed values for border styles (solid, dashed, etc.).
* **Border width properties (`BorderBottomWidth`, `BorderLeftWidth`, etc.)**: Handles parsing and retrieving computed values for border widths.
* **`BorderCollapse::CSSValueFromComputedStyleInternal`**: Handles `border-collapse`. Returns whether borders are collapsed or separate.
* **Border image properties (`BorderImageOutset`, `BorderImageRepeat`, `BorderImageSlice`, `BorderImageSource`, `BorderImageWidth`)**: Handles parsing and retrieving computed values for border images.
* **Border color properties (`BorderBottomColor`, `BorderLeftColor`, etc.)**: Handles parsing and retrieving computed values for border colors, including logic for forced colors and visited links.
* **`Bottom::ParseSingleValue`**: Handles the `bottom` property. Parses margin or offset values.
* **`Bottom::IsLayoutDependent`**: Checks if the `bottom` property affects layout.
* **`Bottom::CSSValueFromComputedStyleInternal`**: Handles the `bottom` property. Returns the computed bottom offset.
* **`BoxDecorationBreak::CSSValueFromComputedStyleInternal`**: Handles `box-decoration-break`. Returns whether box decorations are sliced or cloned across fragments.
* **`BoxShadow::ParseSingleValue`**: Handles `box-shadow`. Parses shadow values (offsets, blur, spread, color, inset).
* **`BoxShadow::CSSValueFromComputedStyleInternal`**: Handles `box-shadow`. Retrieves the computed shadow values.
* **`BoxSizing::CSSValueFromComputedStyleInternal`**: Handles `box-sizing`. Returns whether the box model is `content-box` or `border-box`.
* **`BreakAfter::CSSValueFromComputedStyleInternal`**: Handles `break-after`.

By systematically analyzing each function, I can build a comprehensive understanding of the code's functionality and its relation to web technologies. This will enable me to provide a detailed and accurate summary.
```
longhands_custom.cc
```

这是Chromium Blink引擎中处理各种CSS长属性的源代码文件的一部分。它定义了如何解析和计算各种独立CSS属性的值，例如颜色、背景、边框、定位、阴影和盒子模型相关的属性。

**核心功能归纳：**

这个代码片段的主要功能是为一系列CSS长属性提供以下能力：

1. **解析 (Parsing):**  将CSS文本形式的值（例如 "red", "10px", "url(...)") 转换为Blink内部表示的 `CSSValue` 对象。这通过 `ParseSingleValue` 函数实现。
2. **计算 (Computed Style):**  根据元素的当前样式，包括继承、层叠等因素，计算出最终生效的属性值。这通过 `CSSValueFromComputedStyleInternal` 函数实现。
3. **颜色处理 (Color Handling):** 对于颜色相关的属性（例如 `background-color`, `border-color`），提供特殊处理，包括处理 `currentcolor` 关键字、强制颜色模式以及 `:visited` 伪类的颜色。这体现在 `ColorIncludingFallback` 函数中。
4. **布局依赖性判断 (Layout Dependency):**  判断某些属性的改变是否会影响元素的布局。这通过 `IsLayoutDependent` 函数实现。
5. **继承和应用值 (Inheritance and Applying Values):** 对于某些属性（例如 `baseline-shift`），提供处理继承和将解析后的值应用到样式构建器的逻辑。这体现在 `ApplyInherit` 和 `ApplyValue` 函数中。

**与 JavaScript, HTML, CSS 的关系和举例说明：**

* **CSS:** 这个文件直接处理各种CSS属性。每个函数都对应一个或多个CSS属性。
    * **例子:** `BackgroundColor::ParseSingleValue` 负责解析 CSS 中 `background-color` 属性的值，例如 `#ff0000` (红色), `rgba(0, 0, 0, 0.5)` (半透明黑色) 或 `currentcolor`。
    * **例子:** `BorderBottomWidth::CSSValueFromComputedStyleInternal`  负责根据元素的样式计算出 `border-bottom-width` 的最终像素值。

* **HTML:** HTML 元素通过 CSS 样式进行渲染。这个文件中的代码最终决定了 HTML 元素在屏幕上的视觉呈现。
    * **例子:**  如果一个 HTML `<div>` 元素的 CSS 样式中设置了 `background-color: blue;`，那么 `BackgroundColor::ParseSingleValue` 将解析 `"blue"`，而 `BackgroundColor::CSSValueFromComputedStyleInternal` 将计算出最终的蓝色值，从而让该 `<div>` 显示为蓝色。

* **JavaScript:** JavaScript 可以读取和修改元素的 CSS 样式。当 JavaScript 修改样式时，可能会触发这个文件中的解析和计算逻辑。
    * **例子:**  JavaScript 代码 `element.style.backgroundColor = 'green';` 会导致 Blink 引擎重新解析 `background-color` 属性，`BackgroundColor::ParseSingleValue` 会解析 `"green"`。
    * **例子:**  JavaScript 代码 `getComputedStyle(element).borderBottomWidth` 会触发 `BorderBottomWidth::CSSValueFromComputedStyleInternal` 来获取计算后的边框宽度。

**逻辑推理、假设输入与输出：**

**假设输入 (对于 `BackgroundColor::ParseSingleValue`)：**

```css
.my-element {
  background-color: rgb(255, 165, 0);
}
```

**输出：**

`BackgroundColor::ParseSingleValue` 函数会解析 `"rgb(255, 165, 0)"` 这个字符串，并创建一个 `CSSValue` 对象，该对象内部会存储颜色的红、绿、蓝分量 (255, 165, 0)。具体的 `CSSValue` 类型可能是 `CSSRGBColor`。

**假设输入 (对于 `BorderTopWidth::CSSValueFromComputedStyleInternal`)：**

假设一个元素的样式中设置了：

```css
.my-element {
  border-top-width: 2px;
  zoom: 2; /* 假设有缩放 */
}
```

**输出：**

`BorderTopWidth::CSSValueFromComputedStyleInternal` 会考虑 `zoom` 属性，将 `2px` 转换为实际的像素值。如果缩放为 2，则输出的 `CSSValue` 对象会表示 `4px`。

**用户或编程常见的使用错误举例：**

1. **拼写错误或无效的 CSS 值:** 用户在 CSS 中可能会输入错误的属性名或无效的值。
    * **例子:** 将 `background-color` 拼写成 `backgroud-color` 会导致解析失败。
    * **例子:** 为 `border-width` 输入非法的单位，例如 `border-width: abc;`，`BorderBottomWidth::ParseSingleValue` 会返回一个错误或空值。

2. **类型不匹配:**  JavaScript 代码尝试设置不兼容类型的值。
    * **例子:**  `element.style.borderBottomWidth = 'red';`  `BorderBottomWidth::ParseSingleValue` 期望解析的是长度值，而不是颜色值，这会导致解析错误。

3. **忘记单位:** 对于需要单位的属性，忘记添加单位。
    * **例子:** `element.style.borderBottomWidth = 10;`  `BorderBottomWidth::ParseSingleValue` 可能会将其解释为像素值，但更严谨的做法是加上单位 `px`。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户编写 HTML 和 CSS 代码:** 用户创建一个包含 HTML 元素和相应 CSS 样式的网页。
2. **浏览器加载和解析 HTML:**  浏览器开始加载 HTML 文件，构建 DOM 树。
3. **浏览器解析 CSS:** 浏览器解析 CSS 文件或 `<style>` 标签中的 CSS 规则。对于每个 CSS 属性，相应的 `ParseSingleValue` 函数（例如，来自 `longhands_custom.cc`）会被调用来将 CSS 文本值转换为内部表示。
4. **样式计算:** 浏览器根据 CSS 规则、继承和层叠等规则，计算出每个元素的最终样式（ComputedStyle）。在这个阶段，`CSSValueFromComputedStyleInternal` 函数会被调用来生成 `CSSValue` 对象。
5. **布局和渲染:** 浏览器使用计算出的样式信息来布局元素并在屏幕上绘制它们。
6. **用户交互或 JavaScript 操作:** 用户与网页进行交互（例如，鼠标悬停、点击），或者 JavaScript 代码修改元素的样式。这些操作可能导致样式的重新计算，再次触发 `longhands_custom.cc` 中的代码。

**调试线索:** 如果在调试过程中发现某个 CSS 属性没有按预期工作，可以考虑以下线索：

* **检查 CSS 语法:** 确保 CSS 属性名和值是正确的。
* **查看 Computed Style:**  使用浏览器的开发者工具查看元素的 "Computed" 样式，了解浏览器最终计算出的属性值。这可以帮助确定是在解析阶段还是计算阶段出现了问题。
* **断点调试:** 在 `longhands_custom.cc` 中相关的 `ParseSingleValue` 或 `CSSValueFromComputedStyleInternal` 函数中设置断点，查看代码执行流程和变量值，从而找出解析或计算错误的原因。

**这是第2部分，共13部分，请归纳一下它的功能：**

作为 `longhands_custom.cc` 的一部分，这个代码片段的核心功能是 **处理特定CSS长属性的解析和计算**。 它定义了如何将CSS文本值转换为内部表示，以及如何根据元素的当前样式计算出这些属性的最终生效值。  这个部分特别涵盖了 **背景颜色、背景图片、背景原点、背景位置、背景尺寸、背景重复、基线偏移、块大小、各种边框属性（颜色、宽度、样式、圆角）、边框图片属性、以及盒模型相关的 `bottom`、`box-decoration-break`、`box-shadow` 和 `box-sizing` 属性** 的处理逻辑。

### 提示词
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
roundColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& background_color = style.BackgroundColor();
  if (!style.InForcedColorsMode() && !background_color.HasColorKeyword() &&
      !background_color.IsUnresolvedColorFunction()) {
    // Fast path.
    if (is_current_color) {
      *is_current_color = false;
    }
    return background_color.GetColor();
  } else {
    if (style.ShouldForceColor(background_color)) {
      return GetCSSPropertyInternalForcedBackgroundColor()
          .ColorIncludingFallback(false, style, is_current_color);
    }
    return background_color.Resolve(style.GetCurrentColor(),
                                    style.UsedColorScheme(), is_current_color);
  }
}

const CSSValue* BackgroundColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (allow_visited_style) {
    return cssvalue::CSSColor::Create(style.VisitedDependentColor(*this));
  }

  const StyleColor& background_color = style.BackgroundColor();
  if (value_phase == CSSValuePhase::kResolvedValue &&
      style.ShouldForceColor(background_color)) {
    return GetCSSPropertyInternalForcedBackgroundColor()
        .CSSValueFromComputedStyle(style, nullptr, allow_visited_style,
                                   value_phase);
  }
  return ComputedStyleUtils::CurrentColorOrValidColor(style, background_color,
                                                      value_phase);
}

const CSSValue* BackgroundImage::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeImageOrNone, stream, context);
}

const CSSValue* BackgroundImage::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const FillLayer& fill_layer = style.BackgroundLayers();
  return ComputedStyleUtils::BackgroundImageOrMaskImage(
      style, allow_visited_style, fill_layer, value_phase);
}

const CSSValue* BackgroundOrigin::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBackgroundBox(
      stream, local_context, css_parsing_utils::AllowTextValue::kForbid);
}

const CSSValue* BackgroundOrigin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &style.BackgroundLayers();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    EFillBox box = curr_layer->Origin();
    list->Append(*CSSIdentifierValue::Create(box));
  }
  return list;
}

const CSSValue* BackgroundPositionX::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumePositionLonghand<CSSValueID::kLeft,
                                                 CSSValueID::kRight>,
      stream, context);
}

const CSSValue* BackgroundPositionX::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const FillLayer* curr_layer = &style.BackgroundLayers();
  return ComputedStyleUtils::BackgroundPositionXOrWebkitMaskPositionX(
      style, curr_layer);
}

const CSSValue* BackgroundPositionY::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumePositionLonghand<CSSValueID::kTop,
                                                 CSSValueID::kBottom>,
      stream, context);
}

const CSSValue* BackgroundPositionY::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const FillLayer* curr_layer = &style.BackgroundLayers();
  return ComputedStyleUtils::BackgroundPositionYOrWebkitMaskPositionY(
      style, curr_layer);
}

const CSSValue* BackgroundSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBackgroundSize(
      stream, context, local_context, WebFeature::kNegativeBackgroundSize);
}

const CSSValue* BackgroundSize::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const FillLayer& fill_layer = style.BackgroundLayers();
  return ComputedStyleUtils::BackgroundImageOrMaskSize(style, fill_layer);
}

const CSSValue* BackgroundRepeat::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseRepeatStyle(stream);
}

const CSSValue* BackgroundRepeat::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::RepeatStyle(&style.BackgroundLayers());
}

const CSSValue* BaselineSource::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BaselineSource());
}

const CSSValue* BaselineShift::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kBaseline || id == CSSValueID::kSub ||
      id == CSSValueID::kSuper) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  CSSParserContext::ParserModeOverridingScope scope(context, kSVGAttributeMode);
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* BaselineShift::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  switch (style.BaselineShiftType()) {
    case EBaselineShiftType::kSuper:
      return CSSIdentifierValue::Create(CSSValueID::kSuper);
    case EBaselineShiftType::kSub:
      return CSSIdentifierValue::Create(CSSValueID::kSub);
    case EBaselineShiftType::kLength:
      return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
          style.BaselineShift(), style);
  }
  NOTREACHED();
}

void BaselineShift::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetBaselineShiftType(state.ParentStyle()->BaselineShiftType());
  builder.SetBaselineShift(state.ParentStyle()->BaselineShift());
}

void BaselineShift::ApplyValue(StyleResolverState& state,
                               const CSSValue& value,
                               ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    EBaselineShiftType baseline_shift_type = EBaselineShiftType::kLength;
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kBaseline:
        baseline_shift_type = EBaselineShiftType::kLength;
        break;
      case CSSValueID::kSub:
        baseline_shift_type = EBaselineShiftType::kSub;
        break;
      case CSSValueID::kSuper:
        baseline_shift_type = EBaselineShiftType::kSuper;
        break;
      default:
        NOTREACHED();
    }
    builder.SetBaselineShiftType(baseline_shift_type);
    builder.SetBaselineShift(Length::Fixed());
  } else {
    builder.SetBaselineShiftType(EBaselineShiftType::kLength);
    builder.SetBaselineShift(StyleBuilderConverter::ConvertLength(
        state, To<CSSPrimitiveValue>(value)));
  }
}

const CSSValue* BlockSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWidthOrHeight(stream, context);
}

bool BlockSize::IsLayoutDependent(const ComputedStyle* style,
                                  LayoutObject* layout_object) const {
  return layout_object && (layout_object->IsBox() || layout_object->IsSVG());
}

const CSSValue* BorderBlockEndColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const CSSValue* BorderBlockEndWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderWidth(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* BorderBlockStartColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const CSSValue* BorderBlockStartWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderWidth(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* BorderBottomColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const blink::Color BorderBottomColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& border_bottom_color = style.BorderBottomColor();
  if (style.ShouldForceColor(border_bottom_color)) {
    return GetCSSPropertyInternalForcedBorderColor().ColorIncludingFallback(
        false, style, is_current_color);
  }
  return ComputedStyleUtils::BorderSideColor(style, border_bottom_color,
                                             style.BorderBottomStyle(),
                                             visited_link, is_current_color);
}

const CSSValue* BorderBottomColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleColor& border_bottom_color = style.BorderBottomColor();
  if (value_phase == CSSValuePhase::kResolvedValue &&
      style.ShouldForceColor(border_bottom_color)) {
    return GetCSSPropertyInternalForcedBorderColor().CSSValueFromComputedStyle(
        style, nullptr, allow_visited_style, value_phase);
  }
  return allow_visited_style
             ? cssvalue::CSSColor::Create(style.VisitedDependentColor(*this))
             : ComputedStyleUtils::CurrentColorOrValidColor(
                   style, border_bottom_color, value_phase);
}

const CSSValue* BorderBottomLeftRadius::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseBorderRadiusCorner(stream, context);
}

const CSSValue* BorderBottomLeftRadius::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForBorderRadiusCorner(
      style.BorderBottomLeftRadius(), style);
}

const CSSValue* BorderBottomRightRadius::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseBorderRadiusCorner(stream, context);
}

const CSSValue* BorderBottomRightRadius::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForBorderRadiusCorner(
      style.BorderBottomRightRadius(), style);
}

const CSSValue* BorderBottomStyle::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBorderStyleSide(stream, context);
}

const CSSValue* BorderBottomStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BorderBottomStyle());
}

const CSSValue* BorderBottomWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBorderWidthSide(stream, context,
                                                 local_context);
}

const CSSValue* BorderBottomWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.BorderBottomWidth(), style);
}

const CSSValue* BorderCollapse::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.BorderCollapse() == EBorderCollapse::kCollapse) {
    return CSSIdentifierValue::Create(CSSValueID::kCollapse);
  }
  return CSSIdentifierValue::Create(CSSValueID::kSeparate);
}

const CSSValue* BorderEndEndRadius::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseBorderRadiusCorner(stream, context);
}

const CSSValue* BorderEndStartRadius::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseBorderRadiusCorner(stream, context);
}

const CSSValue* BorderImageOutset::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderImageOutset(stream, context);
}

const CSSValue* BorderImageOutset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImageQuad(
      style.BorderImage().Outset(), style);
}

const CSSValue* BorderImageOutset::InitialValue() const {
  DEFINE_STATIC_LOCAL(const Persistent<CSSQuadValue>, value,
                      (MakeGarbageCollected<CSSQuadValue>(
                          CSSNumericLiteralValue::Create(
                              0, CSSPrimitiveValue::UnitType::kInteger),
                          CSSQuadValue::kSerializeAsQuad)));
  return value;
}

const CSSValue* BorderImageRepeat::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderImageRepeat(stream);
}

const CSSValue* BorderImageRepeat::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImageRepeat(style.BorderImage());
}

const CSSValue* BorderImageRepeat::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kStretch);
}

const CSSValue* BorderImageSlice::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderImageSlice(
      stream, context, css_parsing_utils::DefaultFill::kNoFill);
}

const CSSValue* BorderImageSlice::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImageSlice(style.BorderImage());
}

const CSSValue* BorderImageSlice::InitialValue() const {
  DEFINE_STATIC_LOCAL(
      const Persistent<cssvalue::CSSBorderImageSliceValue>, value,
      (MakeGarbageCollected<cssvalue::CSSBorderImageSliceValue>(
          MakeGarbageCollected<CSSQuadValue>(
              CSSNumericLiteralValue::Create(
                  100, CSSPrimitiveValue::UnitType::kPercentage),
              CSSQuadValue::kSerializeAsQuad),
          /* fill */ false)));
  return value;
}

const CSSValue* BorderImageSource::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeImageOrNone(stream, context);
}

const CSSValue* BorderImageSource::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.BorderImageSource()) {
    return style.BorderImageSource()->ComputedCSSValue(
        style, allow_visited_style, value_phase);
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* BorderImageSource::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

void BorderImageSource::ApplyValue(StyleResolverState& state,
                                   const CSSValue& value,
                                   ValueMode) const {
  state.StyleBuilder().SetBorderImageSource(
      state.GetStyleImage(CSSPropertyID::kBorderImageSource, value));
}

const CSSValue* BorderImageWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderImageWidth(stream, context);
}

const CSSValue* BorderImageWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImageQuad(
      style.BorderImage().BorderSlices(), style);
}

const CSSValue* BorderImageWidth::InitialValue() const {
  DEFINE_STATIC_LOCAL(const Persistent<CSSQuadValue>, value,
                      (MakeGarbageCollected<CSSQuadValue>(
                          CSSNumericLiteralValue::Create(
                              1, CSSPrimitiveValue::UnitType::kInteger),
                          CSSQuadValue::kSerializeAsQuad)));
  return value;
}

const CSSValue* BorderInlineEndColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const CSSValue* BorderInlineEndWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderWidth(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* BorderInlineStartColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const CSSValue* BorderInlineStartWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderWidth(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* BorderLeftColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const blink::Color BorderLeftColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& border_left_color = style.BorderLeftColor();
  if (style.ShouldForceColor(border_left_color)) {
    return GetCSSPropertyInternalForcedBorderColor().ColorIncludingFallback(
        false, style, is_current_color);
  }
  return ComputedStyleUtils::BorderSideColor(style, border_left_color,
                                             style.BorderLeftStyle(),
                                             visited_link, is_current_color);
}

const CSSValue* BorderLeftColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleColor& border_left_color = style.BorderLeftColor();
  if (value_phase == CSSValuePhase::kResolvedValue &&
      style.ShouldForceColor(border_left_color)) {
    return GetCSSPropertyInternalForcedBorderColor().CSSValueFromComputedStyle(
        style, nullptr, allow_visited_style, value_phase);
  }
  return allow_visited_style
             ? cssvalue::CSSColor::Create(style.VisitedDependentColor(*this))
             : ComputedStyleUtils::CurrentColorOrValidColor(
                   style, border_left_color, value_phase);
}

const CSSValue* BorderLeftStyle::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBorderStyleSide(stream, context);
}

const CSSValue* BorderLeftStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BorderLeftStyle());
}

const CSSValue* BorderLeftWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBorderWidthSide(stream, context,
                                                 local_context);
}

const CSSValue* BorderLeftWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.BorderLeftWidth(), style);
}

const CSSValue* BorderRightColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const blink::Color BorderRightColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& border_right_color = style.BorderRightColor();
  if (style.ShouldForceColor(border_right_color)) {
    return GetCSSPropertyInternalForcedBorderColor().ColorIncludingFallback(
        false, style, is_current_color);
  }
  return ComputedStyleUtils::BorderSideColor(style, border_right_color,
                                             style.BorderRightStyle(), false,
                                             is_current_color);
}

const CSSValue* BorderRightColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleColor& border_right_color = style.BorderRightColor();
  if (value_phase == CSSValuePhase::kResolvedValue &&
      style.ShouldForceColor(border_right_color)) {
    return GetCSSPropertyInternalForcedBorderColor().CSSValueFromComputedStyle(
        style, nullptr, allow_visited_style, value_phase);
  }
  return allow_visited_style
             ? cssvalue::CSSColor::Create(style.VisitedDependentColor(*this))
             : ComputedStyleUtils::CurrentColorOrValidColor(
                   style, border_right_color, value_phase);
}

const CSSValue* BorderRightStyle::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBorderStyleSide(stream, context);
}

const CSSValue* BorderRightStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BorderRightStyle());
}

const CSSValue* BorderRightWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBorderWidthSide(stream, context,
                                                 local_context);
}

const CSSValue* BorderRightWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.BorderRightWidth(), style);
}

const CSSValue* BorderStartStartRadius::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseBorderRadiusCorner(stream, context);
}

const CSSValue* BorderStartEndRadius::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseBorderRadiusCorner(stream, context);
}

const CSSValue* BorderTopColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const blink::Color BorderTopColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& border_top_color = style.BorderTopColor();
  if (style.ShouldForceColor(border_top_color)) {
    return GetCSSPropertyInternalForcedBorderColor().ColorIncludingFallback(
        false, style, is_current_color);
  }
  return ComputedStyleUtils::BorderSideColor(style, border_top_color,
                                             style.BorderTopStyle(),
                                             visited_link, is_current_color);
}

const CSSValue* BorderTopColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleColor& border_top_color = style.BorderTopColor();
  if (value_phase == CSSValuePhase::kResolvedValue &&
      style.ShouldForceColor(border_top_color)) {
    return GetCSSPropertyInternalForcedBorderColor().CSSValueFromComputedStyle(
        style, nullptr, allow_visited_style, value_phase);
  }
  return allow_visited_style
             ? cssvalue::CSSColor::Create(style.VisitedDependentColor(*this))
             : ComputedStyleUtils::ComputedStyleUtils::CurrentColorOrValidColor(
                   style, border_top_color, value_phase);
}

const CSSValue* BorderTopLeftRadius::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseBorderRadiusCorner(stream, context);
}

const CSSValue* BorderTopLeftRadius::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForBorderRadiusCorner(
      style.BorderTopLeftRadius(), style);
}

const CSSValue* BorderTopRightRadius::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseBorderRadiusCorner(stream, context);
}

const CSSValue* BorderTopRightRadius::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForBorderRadiusCorner(
      style.BorderTopRightRadius(), style);
}

const CSSValue* BorderTopStyle::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBorderStyleSide(stream, context);
}

const CSSValue* BorderTopStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BorderTopStyle());
}

const CSSValue* BorderTopWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseBorderWidthSide(stream, context,
                                                 local_context);
}

const CSSValue* BorderTopWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.BorderTopWidth(), style);
}

const CSSValue* Bottom::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? kCSSAnchorQueryTypesAll
          : static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchor);
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context,
      css_parsing_utils::UnitlessUnlessShorthand(local_context), anchor_types);
}

bool Bottom::IsLayoutDependent(const ComputedStyle* style,
                               LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* Bottom::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPositionOffset(style, *this,
                                                    layout_object);
}

const CSSValue* BoxDecorationBreak::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.BoxDecorationBreak() == EBoxDecorationBreak::kSlice) {
    return CSSIdentifierValue::Create(CSSValueID::kSlice);
  }
  return CSSIdentifierValue::Create(CSSValueID::kClone);
}

const CSSValue* BoxShadow::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeShadow(
      stream, context, css_parsing_utils::AllowInsetAndSpread::kAllow);
}

const CSSValue* BoxShadow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForShadowList(style.BoxShadow(), style, true,
                                                value_phase);
}

const CSSValue* BoxSizing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.BoxSizing() == EBoxSizing::kContentBox) {
    return CSSIdentifierValue::Create(CSSValueID::kContentBox);
  }
  return CSSIdentifierValue::Create(CSSValueID::kBorderBox);
}

const CSSValue* BreakAfter::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const
```