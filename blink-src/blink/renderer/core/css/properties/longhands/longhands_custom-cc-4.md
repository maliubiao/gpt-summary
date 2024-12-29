Response:
The user wants to understand the functionality of the `longhands_custom.cc` file in the Chromium Blink rendering engine.

Here's a breakdown of the request and a plan to address each point:

1. **List its functions:**  I need to go through the provided code and identify all the classes and their methods defined within the file. These classes seem to be related to CSS properties.
2. **Relationship with JavaScript, HTML, CSS:** I need to explain how the code interacts with these web technologies. This involves understanding how CSS properties defined here influence the rendering of HTML elements, potentially triggered or manipulated by JavaScript.
3. **Examples for JavaScript, HTML, CSS:**  Concrete examples will be helpful to illustrate the relationships mentioned above.
4. **Logical inference with input/output:**  For some functions, especially parsing or conversion functions, I can provide hypothetical input (e.g., a CSS value) and predict the output (e.g., a CSSValue object).
5. **Common usage errors:**  Based on the code, I can identify potential pitfalls or incorrect ways developers might use the related CSS properties.
6. **User operation leading to this code:** I need to describe the typical user actions that would eventually cause this code to be executed during web page rendering. This relates to the CSS parsing and styling process.
7. **Summarize the function:**  Provide a concise overview of the file's purpose.
8. **Part 5 of 13:** Acknowledge this information but it doesn't directly affect the functional analysis.

**Plan:**

*   Iterate through the code, identify each class and its methods. The classes seem to correspond to individual CSS properties (e.g., `EmptyCells`, `Fill`, `Filter`). The methods are likely related to parsing CSS values, converting between internal representations, and applying styles.
*   For each class/property:
    *   Describe its core function in CSS.
    *   Explain how it affects the visual presentation of HTML elements.
    *   Provide CSS examples.
    *   If applicable, illustrate how JavaScript might interact with this property (e.g., using `element.style.propertyName`).
    *   For parsing functions, provide example CSS input and the expected internal representation.
    *   Identify common errors developers might make when using this property in CSS.
*   Outline the general flow of how a user's action (loading a web page with CSS) triggers the parsing and application of these CSS properties.
*   Concisely summarize the role of this file within the Blink rendering engine.
这是目录为 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 的 Chromium Blink 引擎源代码文件，它定义了**自定义的 CSS 长属性 (longhand properties) 的处理逻辑**。

**功能归纳:**

该文件的核心功能是为一系列特定的 CSS 长属性提供自定义的解析、计算和应用样式值的逻辑。  这些属性并非简单的数值或枚举值，而是需要更复杂的处理。它定义了如何将 CSS 文本表示的值转换为 Blink 内部使用的 `CSSValue` 对象，以及如何从 `ComputedStyle` 对象中提取并生成 `CSSValue` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件直接参与了 CSS 的解析和应用，从而影响 HTML 元素的最终渲染。JavaScript 可以通过 DOM API (如 `element.style.propertyName`)  读取或设置这些 CSS 属性，最终会触发这里定义的逻辑。

以下是一些具体的属性及其与 HTML、CSS、JavaScript 的关系：

*   **`DynamicRangeLimitMix`**:
    *   **CSS:**  定义了视频或图像的动态范围限制的混合方式。例如：`dynamic-range-limit-mix: standard 50%, high 50%;`
    *   **HTML:**  应用于 `<video>` 或 `<img>` 标签等媒体元素。
    *   **JavaScript:**  可以通过 `element.style.dynamicRangeLimitMix` 获取或设置。
*   **`EmptyCells`**:
    *   **CSS:**  控制表格中空单元格边框和背景的显示方式。例如：`empty-cells: show;` 或 `empty-cells: hide;`
    *   **HTML:**  应用于 `<table>` 元素。
    *   **JavaScript:**  可以通过 `element.style.emptyCells` 获取或设置。
*   **`Fill`**:
    *   **CSS:**  用于填充 SVG 图形。例如：`fill: red;` 或 `fill: url(#gradient);`
    *   **HTML:**  应用于 `<svg>` 元素及其内部形状元素（如 `<rect>`, `<circle>`）。
    *   **JavaScript:**  可以通过 `element.style.fill` 获取或设置。
*   **`FillOpacity`**:
    *   **CSS:**  设置 SVG 填充的透明度。例如：`fill-opacity: 0.5;`
    *   **HTML:**  应用于 `<svg>` 元素及其内部形状元素。
    *   **JavaScript:**  可以通过 `element.style.fillOpacity` 获取或设置。
*   **`FillRule`**:
    *   **CSS:**  定义如何判断 SVG 路径的内部和外部区域，影响填充效果。例如：`fill-rule: nonzero;` 或 `fill-rule: evenodd;`
    *   **HTML:**  应用于 `<svg>` 元素及其内部路径元素（如 `<path>`）。
    *   **JavaScript:**  可以通过 `element.style.fillRule` 获取或设置。
*   **`Filter`**:
    *   **CSS:**  为元素添加图形效果，如模糊、对比度调整等。例如：`filter: blur(5px) contrast(150%);`
    *   **HTML:**  应用于任何 HTML 元素。
    *   **JavaScript:**  可以通过 `element.style.filter` 获取或设置。
*   **`FlexBasis`**, **`FlexDirection`**, **`FlexGrow`**, **`FlexShrink`**, **`FlexWrap`**:
    *   **CSS:**  定义 Flexbox 布局中弹性项目的尺寸和行为。 例如：`flex-basis: 50%;`, `flex-direction: row;`, `flex-grow: 1;`, `flex-wrap: wrap;`
    *   **HTML:**  应用于设置了 `display: flex;` 或 `display: inline-flex;` 的父元素。
    *   **JavaScript:**  可以通过 `element.style.flexBasis`, `element.style.flexDirection` 等获取或设置。
*   **`Float`**:
    *   **CSS:**  控制元素的浮动行为。例如：`float: left;` 或 `float: right;`
    *   **HTML:**  应用于任何 HTML 元素。
    *   **JavaScript:**  可以通过 `element.style.float` 获取或设置。
*   **`FloodColor`**, **`FloodOpacity`**:
    *   **CSS:**  用于 SVG 滤镜效果，定义泛洪滤镜的颜色和透明度。 例如：`flood-color: blue;`, `flood-opacity: 0.8;`
    *   **HTML:**  通常与 `<feFlood>` 滤镜原语一起使用在 `<svg>` 元素中。
    *   **JavaScript:**  可以通过 `element.style.floodColor`, `element.style.floodOpacity` 获取或设置。
*   **`FontFamily`**, **`FontFeatureSettings`**, **`FontKerning`**, **`FontOpticalSizing`**, **`FontPalette`**, **`FontSizeAdjust`**, **`FontSize`**, **`FontStretch`**, **`FontStyle`**, **`FontVariantCaps`**, **`FontVariantEastAsian`**, **`FontVariantLigatures`**, **`FontVariantNumeric`**, **`FontVariantAlternates`**, **`FontVariationSettings`**, **`FontWeight`**, **`FontSynthesisWeight`**, **`FontSynthesisStyle`**, **`FontSynthesisSmallCaps`**, **`FontVariantPosition`**, **`FontVariantEmoji`**:
    *   **CSS:**  各种字体相关的属性，控制字体族、 OpenType 特性、字距调整、大小、样式、变体等。 例如：`font-family: "Arial", sans-serif;`, `font-size: 16px;`, `font-weight: bold;`, `font-variant-ligatures: common-ligatures;`
    *   **HTML:**  应用于任何可以显示文本的 HTML 元素。
    *   **JavaScript:**  可以通过 `element.style.fontFamily`, `element.style.fontSize` 等获取或设置。
*   **`ForcedColorAdjust`**:
    *   **CSS:**  控制浏览器是否应该调整元素颜色以适应用户选择的高对比度主题。 例如：`forced-color-adjust: auto;` 或 `forced-color-adjust: none;`
    *   **HTML:**  应用于任何 HTML 元素。
    *   **JavaScript:**  可以通过 `element.style.forcedColorAdjust` 获取或设置。
*   **`FieldSizing`**:
    *   **CSS:**  控制表单控件的尺寸调整行为（实验性特性）。
    *   **HTML:**  应用于表单元素，如 `<input>`, `<textarea>`, `<select>`.
    *   **JavaScript:**  可以通过 `element.style.fieldSizing` 获取或设置。
*   **`InternalVisitedColor`**:
    *   **内部使用:**  处理 `:visited` 伪类的颜色，为了防止信息泄露，其行为与普通 `color` 属性不同。
*   **`GridAutoColumns`**, **`GridAutoFlow`**, **`GridAutoRows`**, **`GridColumnEnd`**, **`GridColumnStart`**, **`GridRowEnd`**, **`GridRowStart`**, **`GridTemplateAreas`**:
    *   **CSS:**  定义 CSS Grid 布局中隐式网格轨道的大小和放置规则。 例如：`grid-auto-columns: 100px;`, `grid-auto-flow: row dense;`, `grid-column-start: 2;`, `grid-template-areas: "header header" "nav main" "footer footer";`
    *   **HTML:**  应用于设置了 `display: grid;` 或 `display: inline-grid;` 的父元素及其子元素。
    *   **JavaScript:**  可以通过 `element.style.gridAutoColumns`, `element.style.gridColumnStart` 等获取或设置。

**逻辑推理的假设输入与输出 (示例):**

*   **假设输入 (对于 `Fill::ParseSingleValue`)**: CSS 文本 " `red` "
    *   **输出**: 一个 `CSSIdentifierValue` 对象，其 `GetValueID()` 为 `CSSValueID::kRed`。
*   **假设输入 (对于 `FlexGrow::ParseSingleValue`)**: CSS 文本 " `2.5` "
    *   **输出**: 一个 `CSSNumericLiteralValue` 对象，其值为 `2.5`，单位类型为 `CSSPrimitiveValue::UnitType::kNumber`。
*   **假设输入 (对于 `GridAutoFlow::ParseSingleValue`)**: CSS 文本 " `column dense` "
    *   **输出**: 一个 `CSSValueList` 对象，包含两个 `CSSIdentifierValue` 对象，分别为 `CSSValueID::kColumn` 和 `CSSValueID::kDense`。

**涉及用户或编程常见的使用错误 (示例):**

*   **`Fill`**: 用户可能为非 SVG 元素设置 `fill` 属性，但它不会产生任何视觉效果。
*   **`FlexBasis`**:  开发者可能会混淆 `flex-basis: 0` 和 `flex-basis: auto` 的区别。 `0` 会使项目在分配剩余空间时忽略其内容大小，而 `auto` 则会考虑内容大小。
*   **`FontFamily`**:  拼写错误的字体名称会导致浏览器回退到默认字体。
*   **`GridColumnStart`/`GridColumnEnd`**:  设置了冲突的网格线值可能导致元素重叠或渲染异常。
*   **`FontVariationSettings`**:  提供格式错误的 tag 或 value 会导致解析失败，属性被忽略。例如，tag 必须是 4 个字符的字符串，value 必须是数字。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载一个网页。**
2. **浏览器开始解析 HTML 代码，构建 DOM 树。**
3. **浏览器解析 CSS 代码（外部样式表、`<style>` 标签、或内联样式）。**
4. **当 CSS 解析器遇到一个 CSS 属性，例如 `fill: blue;` 时，**
5. **对于 `fill` 属性，解析器会查找对应的 `CSSProperty` 对象 (可能是 `Fill::ParseSingleValue`)。**
6. **`Fill::ParseSingleValue` 函数会被调用，使用 `CSSParserTokenStream` 来读取 "blue" 这个 token。**
7. **`css_parsing_utils::ConsumeSVGPaint` 函数会被调用，将 "blue" 解析为 `CSSValueID::kBlue`。**
8. **创建一个 `CSSIdentifierValue` 对象来表示这个颜色值。**
9. **在样式计算阶段，当需要计算元素的最终样式时，会用到 `Fill::CSSValueFromComputedStyleInternal` 来获取计算后的 `CSSValue`。**
10. **在应用样式阶段，`Fill::ApplyValue` 会被调用，将 `CSSValue` 转换为 Blink 内部表示的 SVG 填充信息，最终影响元素的渲染。**

在调试过程中，如果发现某个 CSS 属性没有按预期工作，可以设置断点在这个文件中的相关函数（例如 `ParseSingleValue` 或 `CSSValueFromComputedStyleInternal`），来查看 CSS 值的解析和计算过程。

**总结其功能 (第 5 部分):**

作为 13 个部分中的第 5 部分，这个文件 (`longhands_custom.cc`) 专注于处理那些需要自定义逻辑的 CSS 长属性。它定义了如何解析这些属性的 CSS 文本值，如何从计算样式中生成相应的 CSS 值，以及如何在样式应用阶段将这些值传递给渲染引擎。 它的作用是桥接 CSS 语法和 Blink 内部的样式表示，确保浏览器能够正确理解和应用这些复杂的 CSS 属性。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共13部分，请归纳一下它的功能

"""
e::Create(CSSValueID::kConstrainedHigh);
  }
  float high_mix = 1.f - limit.standard_mix - limit.constrained_high_mix;
  if (high_mix == 1.f) {
    return CSSIdentifierValue::Create(CSSValueID::kHigh);
  }
  HeapVector<Member<const CSSValue>> limits;
  HeapVector<Member<const CSSPrimitiveValue>> percentages;
  if (limit.standard_mix != 0.f) {
    limits.push_back(CSSIdentifierValue::Create(CSSValueID::kStandard));
    percentages.push_back(CSSNumericLiteralValue::Create(
        100 * limit.standard_mix, CSSPrimitiveValue::UnitType::kPercentage));
  }
  if (limit.constrained_high_mix != 0.f) {
    limits.push_back(CSSIdentifierValue::Create(CSSValueID::kConstrainedHigh));
    percentages.push_back(CSSNumericLiteralValue::Create(
        100 * limit.constrained_high_mix,
        CSSPrimitiveValue::UnitType::kPercentage));
  }
  if (high_mix != 0.f) {
    limits.push_back(CSSIdentifierValue::Create(CSSValueID::kHigh));
    percentages.push_back(CSSNumericLiteralValue::Create(
        100 * high_mix, CSSPrimitiveValue::UnitType::kPercentage));
  }
  return MakeGarbageCollected<cssvalue::CSSDynamicRangeLimitMixValue>(
      std::move(limits), std::move(percentages));
}

const CSSValue* EmptyCells::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.EmptyCells());
}

const CSSValue* Fill::ParseSingleValue(CSSParserTokenStream& stream,
                                       const CSSParserContext& context,
                                       const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSVGPaint(stream, context);
}

const CSSValue* Fill::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForSVGPaint(style.FillPaint(), style);
}

const blink::Color Fill::ColorIncludingFallback(bool visited_link,
                                                const ComputedStyle& style,
                                                bool* is_current_color) const {
  DCHECK(!visited_link);
  DCHECK(style.FillPaint().HasColor());
  const StyleColor& fill_color = style.FillPaint().GetColor();
  if (style.ShouldForceColor(fill_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return fill_color.Resolve(style.GetCurrentColor(), style.UsedColorScheme(),
                            is_current_color);
}

void Fill::ApplyValue(StyleResolverState& state,
                      const CSSValue& value,
                      ValueMode) const {
  state.StyleBuilder().SetFillPaint(StyleBuilderConverter::ConvertSVGPaint(
      state, value, false, PropertyID()));
}

const CSSValue* FillOpacity::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* FillOpacity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.FillOpacity(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* FillRule::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.FillRule());
}

const CSSValue* Filter::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFilterFunctionList(stream, context);
}

const CSSValue* Filter::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFilter(style, style.Filter());
}

void Filter::ApplyValue(StyleResolverState& state,
                        const CSSValue& value,
                        ValueMode) const {
  state.StyleBuilder().SetFilter(StyleBuilderConverter::ConvertFilterOperations(
      state, value, PropertyID()));
}

const CSSValue* FlexBasis::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // TODO(https://crbug.com/353538495): This should really use
  // css_parsing_utils::ValidWidthOrHeightKeyword.
  if (css_parsing_utils::IdentMatches<
          CSSValueID::kAuto, CSSValueID::kContent, CSSValueID::kMinContent,
          CSSValueID::kMaxContent, CSSValueID::kFitContent>(
          stream.Peek().Id())) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  if (RuntimeEnabledFeatures::LayoutStretchEnabled() &&
      CSSValueID::kStretch == stream.Peek().Id()) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kForbid, kCSSAnchorQueryTypesNone,
      css_parsing_utils::AllowCalcSize::kAllowWithAutoAndContent);
}

const CSSValue* FlexBasis::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.FlexBasis(),
                                                             style);
}

const CSSValue* FlexDirection::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.FlexDirection());
}

const CSSValue* FlexDirection::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kRow);
}

const CSSValue* FlexGrow::ParseSingleValue(CSSParserTokenStream& stream,
                                           const CSSParserContext& context,
                                           const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* FlexGrow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.FlexGrow(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* FlexShrink::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* FlexShrink::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.FlexShrink(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* FlexWrap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.FlexWrap());
}

const CSSValue* FlexWrap::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNowrap);
}

const CSSValue* Float::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.HasOutOfFlowPosition()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return CSSIdentifierValue::Create(style.Floating());
}

const CSSValue* FloodColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color FloodColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  const StyleColor& flood_color = style.FloodColor();
  if (style.ShouldForceColor(flood_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return style.ResolvedColor(flood_color, is_current_color);
}

const CSSValue* FloodColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(style, style.FloodColor(),
                                                      value_phase);
}

const CSSValue* FloodOpacity::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* FloodOpacity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.FloodOpacity(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* FontFamily::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFontFamily(stream);
}

const CSSValue* FontFamily::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontFamily(style);
}

void FontFamily::ApplyInitial(StyleResolverState& state) const {
  state.GetFontBuilder().SetFamilyDescription(
      FontBuilder::InitialFamilyDescription());
  state.GetFontBuilder().SetFamilyTreeScope(nullptr);
}

void FontFamily::ApplyInherit(StyleResolverState& state) const {
  state.GetFontBuilder().SetFamilyDescription(
      state.ParentFontDescription().GetFamilyDescription());
  CSSFontSelector* selector = static_cast<CSSFontSelector*>(
      state.ParentStyle()->GetFont().GetFontSelector());
  const TreeScope* tree_scope = selector ? selector->GetTreeScope() : nullptr;
  state.GetFontBuilder().SetFamilyTreeScope(tree_scope);
}

const CSSValue* FontFeatureSettings::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFontFeatureSettings(stream, context);
}

const CSSValue* FontFeatureSettings::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontFeatureSettings(style);
}

const CSSValue* FontKerning::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontKerning(style);
}

const CSSValue* FontOpticalSizing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontOpticalSizing(style);
}

const CSSValue* FontPalette::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontPalette(style);
}

const CSSValue* FontPalette::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFontPalette(stream, context);
}

const CSSValue* FontSizeAdjust::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  DCHECK(RuntimeEnabledFeatures::CSSFontSizeAdjustEnabled());
  return css_parsing_utils::ConsumeFontSizeAdjust(stream, context);
}

const CSSValue* FontSizeAdjust::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontSizeAdjust(style);
}

const CSSValue* FontSize::ParseSingleValue(CSSParserTokenStream& stream,
                                           const CSSParserContext& context,
                                           const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFontSize(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow);
}

const CSSValue* FontSize::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontSize(style);
}

const CSSValue* FontStretch::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFontStretch(stream, context);
}

const CSSValue* FontStretch::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontStretch(style);
}

const CSSValue* FontStyle::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFontStyle(stream, context);
}

const CSSValue* FontStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontStyle(style);
}

const CSSValue* FontVariantCaps::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIdent<
      CSSValueID::kNormal, CSSValueID::kSmallCaps, CSSValueID::kAllSmallCaps,
      CSSValueID::kPetiteCaps, CSSValueID::kAllPetiteCaps, CSSValueID::kUnicase,
      CSSValueID::kTitlingCaps>(stream);
}

const CSSValue* FontVariantCaps::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontVariantCaps(style);
}

const CSSValue* FontVariantEastAsian::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  bool found_any = false;

  FontVariantEastAsianParser east_asian_parser;
  do {
    if (east_asian_parser.ConsumeEastAsian(stream) !=
        FontVariantEastAsianParser::ParseResult::kConsumedValue) {
      break;
    }
    found_any = true;
  } while (!stream.AtEnd());

  if (!found_any) {
    return nullptr;
  }

  return east_asian_parser.FinalizeValue();
}

const CSSValue* FontVariantEastAsian::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontVariantEastAsian(style);
}

const CSSValue* FontVariantLigatures::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNormal ||
      stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  bool found_any = false;

  FontVariantLigaturesParser ligatures_parser;
  do {
    if (ligatures_parser.ConsumeLigature(stream) !=
        FontVariantLigaturesParser::ParseResult::kConsumedValue) {
      break;
    }
    found_any = true;
  } while (!stream.AtEnd());

  if (!found_any) {
    return nullptr;
  }

  return ligatures_parser.FinalizeValue();
}

const CSSValue* FontVariantLigatures::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontVariantLigatures(style);
}

const CSSValue* FontVariantNumeric::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  bool found_any = false;

  FontVariantNumericParser numeric_parser;
  do {
    if (numeric_parser.ConsumeNumeric(stream) !=
        FontVariantNumericParser::ParseResult::kConsumedValue) {
      break;
    }
    found_any = true;
  } while (!stream.AtEnd());

  if (!found_any) {
    return nullptr;
  }

  return numeric_parser.FinalizeValue();
}

const CSSValue* FontVariantNumeric::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontVariantNumeric(style);
}

const CSSValue* FontVariantAlternates::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  bool found_any = false;

  FontVariantAlternatesParser alternates_parser;
  do {
    if (alternates_parser.ConsumeAlternates(stream, context) !=
        FontVariantAlternatesParser::ParseResult::kConsumedValue) {
      break;
    }
    found_any = true;
  } while (!stream.AtEnd());

  if (!found_any) {
    return nullptr;
  }

  return alternates_parser.FinalizeValue();
}

const CSSValue* FontVariantAlternates::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontVariantAlternates(style);
}

namespace {

cssvalue::CSSFontVariationValue* ConsumeFontVariationTag(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  // Feature tag name consists of 4-letter characters.
  static const wtf_size_t kTagNameLength = 4;

  const CSSParserToken& token = stream.Peek();
  // Feature tag name comes first
  if (token.GetType() != kStringToken) {
    return nullptr;
  }
  if (token.Value().length() != kTagNameLength) {
    return nullptr;
  }
  AtomicString tag = token.Value().ToAtomicString();
  stream.ConsumeIncludingWhitespace();
  for (wtf_size_t i = 0; i < kTagNameLength; ++i) {
    // Limits the range of characters to 0x20-0x7E, following the tag name
    // rules defined in the OpenType specification.
    UChar character = tag[i];
    if (character < 0x20 || character > 0x7E) {
      return nullptr;
    }
  }

  double tag_value = 0;
  if (!css_parsing_utils::ConsumeNumberRaw(stream, context, tag_value)) {
    return nullptr;
  }
  return MakeGarbageCollected<cssvalue::CSSFontVariationValue>(
      tag, ClampTo<float>(tag_value));
}

}  // namespace

const CSSValue* FontVariationSettings::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  CSSValueList* variation_settings = CSSValueList::CreateCommaSeparated();
  do {
    cssvalue::CSSFontVariationValue* font_variation_value =
        ConsumeFontVariationTag(stream, context);
    if (!font_variation_value) {
      return nullptr;
    }
    variation_settings->Append(*font_variation_value);
  } while (css_parsing_utils::ConsumeCommaIncludingWhitespace(stream));
  return variation_settings;
}

const CSSValue* FontVariationSettings::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontVariationSettings(style);
}

const CSSValue* FontWeight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFontWeight(stream, context);
}

const CSSValue* FontWeight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontWeight(style);
}

const CSSValue* FontSynthesisWeight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(
      style.GetFontDescription().GetFontSynthesisWeight());
}

const CSSValue* FontSynthesisStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(
      style.GetFontDescription().GetFontSynthesisStyle());
}

const CSSValue* FontSynthesisSmallCaps::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(
      style.GetFontDescription().GetFontSynthesisSmallCaps());
}

const CSSValue* FontVariantPosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFontVariantPosition(style);
}

const CSSValue* FontVariantEmoji::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  DCHECK(RuntimeEnabledFeatures::FontVariantEmojiEnabled());
  return CSSIdentifierValue::Create(style.GetFontDescription().VariantEmoji());
}

const CSSValue* ForcedColorAdjust::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ForcedColorAdjust());
}

const CSSValue* FieldSizing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.FieldSizing());
}

void InternalVisitedColor::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetInternalVisitedColor(builder.InitialColorForColorScheme());
  builder.SetInternalVisitedColorIsCurrentColor(false);
}

void InternalVisitedColor::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (builder.ShouldPreserveParentColor()) {
    builder.SetInternalVisitedColor(StyleColor(
        state.ParentStyle()->VisitedDependentColor(GetCSSPropertyColor())));
  } else {
    builder.SetInternalVisitedColor(state.ParentStyle()->Color());
  }
  builder.SetInternalVisitedColorIsCurrentColor(
      state.ParentStyle()->InternalVisitedColorIsCurrentColor());
}

void InternalVisitedColor::ApplyValue(StyleResolverState& state,
                                      const CSSValue& value,
                                      ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kCurrentcolor) {
    ApplyInherit(state);
    builder.SetInternalVisitedColorIsCurrentColor(true);
    if (state.UsesHighlightPseudoInheritance() &&
        state.OriginatingElementStyle()) {
      builder.SetInternalVisitedColor(
          state.OriginatingElementStyle()->InternalVisitedColor());
    }
    return;
  }
  if (value.IsInitialColorValue()) {
    DCHECK_EQ(state.GetElement(), state.GetDocument().documentElement());
    builder.SetInternalVisitedColor(builder.InitialColorForColorScheme());
  } else {
    // Unresolved color functions are a special case for this property.
    // See Color::ApplyValue.
    // Using Color instead of InternalVisitedColor here, see
    // https://bugs.chromium.org/p/chromium/issues/detail?id=1236297#c5.
    StyleColor color =
        StyleBuilderConverter::ConvertStyleColor(state, value, true);
    if (color.IsUnresolvedColorFunction()) {
      color = StyleColor(color.Resolve(state.ParentStyle()->Color().GetColor(),
                                       mojom::blink::ColorScheme::kLight));
    }
    builder.SetInternalVisitedColor(color);
  }
  builder.SetInternalVisitedColorIsCurrentColor(false);
}

const blink::Color InternalVisitedColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  if (style.ShouldForceColor(style.InternalVisitedColor())) {
    return GetCSSPropertyInternalForcedVisitedColor().ColorIncludingFallback(
        true, style, is_current_color);
  }
  return style.GetInternalVisitedCurrentColor(is_current_color);
}

const CSSValue* InternalVisitedColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

const CSSValue* GridAutoColumns::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridTrackList(
      stream, context, css_parsing_utils::TrackListType::kGridAuto);
}

// Specs mention that getComputedStyle() should return the used value of the
// property instead of the computed one for grid-template-{rows|columns} but
// not for the grid-auto-{rows|columns} as things like grid-auto-columns:
// 2fr; cannot be resolved to a value in pixels as the '2fr' means very
// different things depending on the size of the explicit grid or the number
// of implicit tracks added to the grid. See
// http://lists.w3.org/Archives/Public/www-style/2013Nov/0014.html
const CSSValue* GridAutoColumns::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridAutoTrackList(kForColumns,
                                                       layout_object, style);
}

const CSSValue* GridAutoColumns::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kAuto);
}

const CSSValue* GridAutoFlow::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSIdentifierValue* row_or_column_value =
      css_parsing_utils::ConsumeIdent<CSSValueID::kRow, CSSValueID::kColumn>(
          stream);
  CSSIdentifierValue* dense_algorithm =
      css_parsing_utils::ConsumeIdent<CSSValueID::kDense>(stream);
  if (!row_or_column_value) {
    row_or_column_value =
        css_parsing_utils::ConsumeIdent<CSSValueID::kRow, CSSValueID::kColumn>(
            stream);
    if (!row_or_column_value && !dense_algorithm) {
      return nullptr;
    }
  }
  CSSValueList* parsed_values = CSSValueList::CreateSpaceSeparated();
  if (row_or_column_value) {
    CSSValueID value = row_or_column_value->GetValueID();
    if (value == CSSValueID::kColumn ||
        (value == CSSValueID::kRow && !dense_algorithm)) {
      parsed_values->Append(*row_or_column_value);
    }
  }
  if (dense_algorithm) {
    parsed_values->Append(*dense_algorithm);
  }
  return parsed_values;
}

const CSSValue* GridAutoFlow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  switch (style.GetGridAutoFlow()) {
    case kAutoFlowRow:
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kRow));
      break;
    case kAutoFlowColumn:
    case kAutoFlowColumnDense:
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kColumn));
      break;
    default:
      // Do nothing.
      break;
  }

  switch (style.GetGridAutoFlow()) {
    case kAutoFlowRowDense:
    case kAutoFlowColumnDense:
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kDense));
      break;
    default:
      // Do nothing.
      break;
  }

  return list;
}

const CSSValue* GridAutoFlow::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kRow);
}

const CSSValue* GridAutoRows::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridTrackList(
      stream, context, css_parsing_utils::TrackListType::kGridAuto);
}

const CSSValue* GridAutoRows::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridAutoTrackList(kForRows, layout_object,
                                                       style);
}

const CSSValue* GridAutoRows::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kAuto);
}

const CSSValue* GridColumnEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridLine(stream, context);
}

const CSSValue* GridColumnEnd::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridPosition(style.GridColumnEnd());
}

const CSSValue* GridColumnStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridLine(stream, context);
}

const CSSValue* GridColumnStart::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridPosition(style.GridColumnStart());
}

const CSSValue* GridRowEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridLine(stream, context);
}

const CSSValue* GridRowEnd::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridPosition(style.GridRowEnd());
}

const CSSValue* GridRowStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridLine(stream, context);
}

const CSSValue* GridRowStart::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridPosition(style.GridRowStart());
}

const CSSValue* GridTemplateAreas::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  NamedGridAreaMap grid_area_map;
  wtf_size_t row_count = 0;
  wtf_size_t column_count = 0;

  while (stream.Peek().GetType() == kStringToken) {
    if (!css_parsing_utils::ParseGridTemplateAreasRow(
            stream.ConsumeIncludingWhitespace().Value().ToString(),
            grid_area_map, row_count, column_count)) {
      return nullp
"""


```