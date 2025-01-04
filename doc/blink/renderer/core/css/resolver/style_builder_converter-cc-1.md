Response:
Let's break down the thought process for analyzing this code snippet and generating the detailed explanation.

**1. Initial Skim and Keyword Spotting:**

The first step is to quickly scan the code, looking for recognizable keywords and patterns. Things that jump out are:

* **`StyleBuilderConverter` and `StyleBuilderConverterBase`:** This strongly suggests a class or set of classes responsible for converting CSS values into internal Blink representations used for styling.
* **`Convert...` functions:**  There are numerous functions with names like `ConvertFontSize`, `ConvertFontWeight`, `ConvertGridTrackSize`, etc. This confirms the conversion purpose.
* **`CSSValue`:** This type appears frequently, indicating it's the input format (representing parsed CSS).
* **`FontDescription` , `FontSizeAdjust`, `FontSelectionValue`, `Grid...` types:** These suggest the *output* format – internal structures representing specific style properties.
* **`StyleResolverState`:** This parameter is common, hinting at a context object containing information needed for resolution (like parent styles, document data).
* **`DCHECK` and `NOTREACHED`:** These are assertion macros, useful for understanding assumptions and potential error conditions within the code.
* **Specific CSS property names (font-size, font-weight, grid-template-areas, etc.):**  These immediately connect the code to concrete CSS features.

**2. Inferring the Core Functionality:**

Based on the keywords, it's clear this code handles the conversion of CSS property values into their corresponding internal Blink representations. This conversion is a crucial step in the CSS styling process.

**3. Analyzing Individual `Convert...` Functions:**

The next step is to examine a few representative `Convert...` functions in more detail. For example:

* **`ConvertFontSize`:**  The code checks for `math` keywords, calculates sizes based on parent styles, and handles different CSS units (like percentages and `rems`). This reveals its responsibility for handling various ways `font-size` can be specified.
* **`ConvertFontWeight`:**  It handles numeric weights, keywords like `bold` and `normal`, and relative keywords like `bolder` and `lighter`. This highlights its logic for different weight specifications.
* **`ConvertGridTemplateAreas`:** This function explicitly deals with parsing the `grid-template-areas` CSS property and creating a `ComputedGridTemplateAreas` object. This illustrates the code's role in handling complex layout properties.
* **`ConvertGridTrackSize` and related functions:** These are more involved, demonstrating how the code parses the intricate syntax of grid track sizing, including `fr` units, `minmax()`, and `fit-content()`.

**4. Identifying Relationships with HTML, CSS, and JavaScript:**

With an understanding of the conversion process, the relationships become clear:

* **CSS:** The primary purpose is to interpret and process CSS values. Examples are straightforward – the functions directly map to CSS properties.
* **HTML:** While not directly manipulating HTML, this code is essential for rendering HTML elements according to their styles. The CSS being converted is applied to HTML elements.
* **JavaScript:**  JavaScript can manipulate styles through the DOM. When JavaScript sets a style, Blink needs to parse and convert those values using code like this. Also, JavaScript can interact with layout and rendering, which depends on the correct interpretation of CSS.

**5. Considering Logic and Examples:**

For each function, try to imagine a simple CSS input and the expected output in terms of the internal Blink structures. This helps solidify understanding. For instance:

* **`font-size: 16px`:**  Should convert to a `FontDescription::Size` with the correct pixel value and `is_absolute` set to true.
* **`font-weight: bold`:** Should convert to `kBoldWeightValue`.
* **`grid-template-columns: 1fr 2fr`:** Should result in a `NGGridTrackList` representing two flexible tracks.

**6. Thinking About Common Errors and Debugging:**

Consider what could go wrong:

* **Invalid CSS syntax:** The parser might choke on incorrect values. The `DCHECK` statements indicate where certain assumptions are made.
* **Unexpected input:**  The "FIXME" comments in the code itself point to potential issues or areas needing more investigation.
* **Incorrect interpretation of CSS specifications:**  A bug in this code could lead to elements being styled incorrectly.

To understand how to reach this code during debugging, trace the styling pipeline:

1. **User action or page load triggers layout/rendering.**
2. **Blink needs to determine the styles for an element.**
3. **The CSS parser processes the stylesheets.**
4. **The style resolver uses `StyleBuilderConverter` to convert CSS values into internal representations.**
5. **These internal representations are used for layout and painting.**

**7. Structuring the Explanation:**

Organize the findings logically:

* Start with a high-level overview of the file's purpose.
* Explain the relationships with HTML, CSS, and JavaScript with concrete examples.
* Provide examples of input and output for key functions.
* Discuss potential user errors and debugging approaches.
* Summarize the overall functionality concisely.

**8. Refinement and Review:**

Read through the explanation, ensuring clarity, accuracy, and completeness. Check for any ambiguities or areas where more detail might be helpful. For example, initially, I might just say "converts CSS," but refining it to "converts CSS property values into internal Blink representations" is more precise.

By following these steps, we can systematically analyze the provided code snippet and generate a comprehensive explanation of its functionality within the Chromium Blink rendering engine.
这是 `blink/renderer/core/css/resolver/style_builder_converter.cc` 文件的第二部分，主要负责将 CSS 属性值转换为 Blink 内部使用的 C++ 对象，以便进行后续的样式计算和应用。  它属于样式解析器 (style resolver) 的一部分。

**整体功能归纳：**

这部分 `StyleBuilderConverter` 类的核心功能是提供一系列静态方法，用于将各种 CSS 属性值（通常是 `CSSValue` 类型的对象）转换为更具体的、Blink 内部使用的类型，例如 `FontDescription::Size`，`FontSelectionValue`，`GridTrackSize` 等。  这些转换方法通常会考虑继承的样式、计算相对值、处理关键字等。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**  这是文件最直接相关的部分。`StyleBuilderConverter` 的输入几乎都是 `CSSValue` 对象，这些对象是 CSS 解析器解析 CSS 规则后生成的。
    * **例子:**  CSS 规则 `font-size: 16px;` 会被解析成一个 `CSSPrimitiveValue` 对象，然后 `ConvertFontSize` 方法会将其转换为一个 `FontDescription::Size` 对象，其中包含了像素值 16 和 `is_absolute` 为 true 的信息。
    * **例子:**  CSS 规则 `font-weight: bold;` 会被解析成一个 `CSSIdentifierValue` 对象，然后 `ConvertFontWeight` 方法会将其转换为一个 `FontSelectionValue` 枚举值，代表粗体。
    * **例子:**  CSS 规则 `grid-template-columns: 1fr 2fr;`  会被解析成一个 `CSSValueList`，然后 `ConvertGridTrackList` 和 `ConvertGridTrackSize` 会将其转换为 `NGGridTrackList` 对象，表示网格列的尺寸。

* **HTML:** `StyleBuilderConverter` 处理的 CSS 最终会应用于 HTML 元素。
    * **例子:**  HTML 中一个 `<div>` 元素的 `style` 属性设置为 `font-size: 1.2em;`，浏览器会解析这个 CSS，然后 `ConvertFontSize` 方法在处理这个值时，会需要父元素的 `font-size` 信息（通过 `state.ParentFontDescription().GetSize()` 获取）来计算出最终的像素值。

* **JavaScript:**  JavaScript 可以通过 DOM API 操作元素的样式，例如 `element.style.fontSize = '20px';`。  当 JavaScript 改变样式时，Blink 的样式系统会重新计算样式，并会使用到 `StyleBuilderConverter` 来转换 JavaScript 设置的 CSS 值。
    * **例子:**  当 JavaScript 设置 `element.style.fontWeight = 'bold';` 时，Blink 内部会生成一个表示 `bold` 的 `CSSValue`，然后 `ConvertFontWeight` 方法会将其转换为 `FontSelectionValue`。

**逻辑推理的假设输入与输出举例：**

* **假设输入 (ConvertFontSize):**
    * `primitive_value`:  一个表示 `150%` 的 `CSSPrimitiveValue` 对象 (百分比值)。
    * `parent_size`: 一个 `FontDescription::Size` 对象，值为 `16px`，`is_absolute` 为 true。
    * `conversion_data`: 包含转换所需信息的对象。
* **输出 (ConvertFontSize):**
    * 一个 `FontDescription::Size` 对象，值为 `24px` (16 * 1.5)，`is_absolute` 为 true。
    * **推理:**  由于输入是百分比，`ComputePercentage` 会返回 150。然后乘以父级大小 16，得到 24。 `is_absolute` 继承自父级。

* **假设输入 (ConvertFontWeight):**
    * `value`: 一个表示 `bolder` 的 `CSSIdentifierValue` 对象。
    * `parent_weight`: 一个 `FontSelectionValue` 对象，值为 `400` (normal)。
* **输出 (ConvertFontWeight):**
    * 一个 `FontSelectionValue` 对象，值可能为 `700` (bold)，具体取决于字体族的定义。
    * **推理:** `ConvertFontWeight` 识别到 `bolder` 关键字，并根据父级的 `font-weight` 增加权重。

**用户或编程常见的使用错误举例：**

* **CSS 语法错误:**  如果在 CSS 中使用了不合法的 `font-size` 值（例如 `font-size: abc;`），CSS 解析器会生成一个错误或者一个特殊类型的 `CSSValue`，`StyleBuilderConverter` 可能会直接返回初始值或者抛出异常，具体取决于 Blink 的错误处理策略。
* **错误的单位:**  在某些情况下，使用错误的单位可能会导致非预期的结果。例如，将 `font-size` 设置为相对单位（如 `em` 或 `%`）时，如果没有正确的父级样式信息，可能会导致计算错误。
* **覆盖默认值时理解不足:**  开发者可能不清楚某些 CSS 属性的初始值或继承规则，导致在设置样式时出现错误。例如，错误地认为 `font-size-adjust` 的默认值是 0，而实际上是 `none`。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器中加载一个包含 CSS 样式的 HTML 页面。**
2. **Blink 的 HTML 解析器解析 HTML 结构，构建 DOM 树。**
3. **Blink 的 CSS 解析器解析页面中引用的 CSS 文件或 `<style>` 标签中的 CSS 规则，构建 CSSOM 树。**
4. **样式层叠 (Cascading):** Blink 的样式系统根据 CSS 的层叠规则（优先级、来源等）确定每个 HTML 元素最终应用的 CSS 属性值。
5. **样式解析 (Style Resolution):**  对于每个需要计算样式的元素，样式解析器会遍历其匹配的 CSS 规则，并使用 `StyleBuilderConverter` 将 CSS 属性值转换为内部表示。
6. **布局 (Layout):**  计算出的样式信息会被用于布局引擎，确定元素在页面上的位置和大小。
7. **绘制 (Painting):** 最终的样式信息还会被用于绘制引擎，将元素渲染到屏幕上。

**调试线索:**  如果在调试样式问题时，发现某个元素的样式计算不正确，可以设置断点在 `StyleBuilderConverter` 的相关方法中（例如 `ConvertFontSize`，`ConvertFontWeight` 等），查看传入的 `CSSValue` 对象和 `StyleResolverState` 对象，以及转换后的输出值，从而追踪 CSS 值的转换过程，找出问题所在。例如，如果怀疑 `font-size` 计算错误，可以断点在 `ConvertFontSize`，查看父级的 `font-size` 是否正确传递，以及百分比值的计算是否符合预期。

总而言之，`blink/renderer/core/css/resolver/style_builder_converter.cc` 的第二部分是 Blink 样式系统中一个至关重要的组件，它负责将 CSS 的抽象表示转换为可供 Blink 内部使用的具体数据结构，是连接 CSS 解析和样式应用的关键桥梁。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_builder_converter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
 return FontDescription::Size(
        /*keyword=*/0,
        (primitive_value.ComputePercentage(conversion_data) *
         parent_size.value / 100.0f),
        parent_size.is_absolute);
  }

  // TODO(crbug.com/979895): This is the result of a refactoring, which might
  // have revealed an existing bug with calculated lengths. Investigate.
  const bool is_absolute =
      parent_size.is_absolute || primitive_value.IsMathFunctionValue() ||
      !To<CSSNumericLiteralValue>(primitive_value).IsFontRelativeLength() ||
      To<CSSNumericLiteralValue>(primitive_value).GetType() ==
          CSSPrimitiveValue::UnitType::kRems;
  return FontDescription::Size(
      /*keyword=*/0,
      ComputeFontSize(conversion_data, primitive_value, parent_size),
      is_absolute);
}

FontDescription::Size StyleBuilderConverter::ConvertFontSize(
    StyleResolverState& state,
    const CSSValue& value) {
  // FIXME: Find out when parentStyle could be 0?
  auto parent_size = state.ParentStyle()
                         ? state.ParentFontDescription().GetSize()
                         : FontDescription::Size(0, 0.0f, false);

  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kMath) {
    auto scale_factor = MathScriptScaleFactor(state);
    state.StyleBuilder().SetHasGlyphRelativeUnits();
    return FontDescription::Size(0, (scale_factor * parent_size.value),
                                 parent_size.is_absolute);
  }

  return StyleBuilderConverterBase::ConvertFontSize(
      value, state.FontSizeConversionData(), parent_size, &state.GetDocument());
}

FontSizeAdjust StyleBuilderConverterBase::ConvertFontSizeAdjust(
    const StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kNone) {
    return FontBuilder::InitialSizeAdjust();
  }

  if (value.IsPendingSystemFontValue()) {
    return FontBuilder::InitialSizeAdjust();
  }

  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kFromFont) {
    return FontSizeAdjust(FontSizeAdjust::kFontSizeAdjustNone,
                          FontSizeAdjust::ValueType::kFromFont);
  }

  if (value.IsPrimitiveValue()) {
    const auto& primitive_value = To<CSSPrimitiveValue>(value);
    DCHECK(primitive_value.IsNumber());
    return FontSizeAdjust(
        primitive_value.ComputeNumber(state.CssToLengthConversionData()));
  }

  DCHECK(value.IsValuePair());
  const auto& pair = To<CSSValuePair>(value);
  auto metric =
      To<CSSIdentifierValue>(pair.First()).ConvertTo<FontSizeAdjust::Metric>();

  if (pair.Second().IsPrimitiveValue()) {
    const auto& primitive_value = To<CSSPrimitiveValue>(pair.Second());
    DCHECK(primitive_value.IsNumber());
    return FontSizeAdjust(
        primitive_value.ComputeNumber(state.CssToLengthConversionData()),
        metric);
  }

  DCHECK(To<CSSIdentifierValue>(pair.Second()).GetValueID() ==
         CSSValueID::kFromFont);
  return FontSizeAdjust(FontSizeAdjust::kFontSizeAdjustNone, metric,
                        FontSizeAdjust::ValueType::kFromFont);
}

FontSizeAdjust StyleBuilderConverter::ConvertFontSizeAdjust(
    StyleResolverState& state,
    const CSSValue& value) {
  return StyleBuilderConverterBase::ConvertFontSizeAdjust(state, value);
}

std::optional<FontSelectionValue>
StyleBuilderConverter::ConvertFontStretchKeyword(const CSSValue& value) {
  // TODO(drott) crbug.com/750014: Consider not parsing them as IdentifierValue
  // any more?
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kUltraCondensed:
        return kUltraCondensedWidthValue;
      case CSSValueID::kExtraCondensed:
        return kExtraCondensedWidthValue;
      case CSSValueID::kCondensed:
        return kCondensedWidthValue;
      case CSSValueID::kSemiCondensed:
        return kSemiCondensedWidthValue;
      case CSSValueID::kNormal:
        return kNormalWidthValue;
      case CSSValueID::kSemiExpanded:
        return kSemiExpandedWidthValue;
      case CSSValueID::kExpanded:
        return kExpandedWidthValue;
      case CSSValueID::kExtraExpanded:
        return kExtraExpandedWidthValue;
      case CSSValueID::kUltraExpanded:
        return kUltraExpandedWidthValue;
      default:
        break;
    }
  }
  return {};
}

FontSelectionValue StyleBuilderConverterBase::ConvertFontStretch(
    const CSSLengthResolver& length_resolver,
    const blink::CSSValue& value) {
  if (const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    if (primitive_value->IsPercentage()) {
      return ClampTo<FontSelectionValue>(
          primitive_value->ComputePercentage(length_resolver));
    }
  }

  if (std::optional<FontSelectionValue> keyword =
          StyleBuilderConverter::ConvertFontStretchKeyword(value);
      keyword.has_value()) {
    return keyword.value();
  }

  if (value.IsPendingSystemFontValue()) {
    return kNormalWidthValue;
  }

  NOTREACHED();
}

FontSelectionValue StyleBuilderConverter::ConvertFontStretch(
    blink::StyleResolverState& state,
    const blink::CSSValue& value) {
  return StyleBuilderConverterBase::ConvertFontStretch(
      state.CssToLengthConversionData(), value);
}

FontSelectionValue StyleBuilderConverterBase::ConvertFontStyle(
    const CSSLengthResolver& length_resolver,
    const CSSValue& value) {
  DCHECK(!value.IsPrimitiveValue());

  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kItalic:
      case CSSValueID::kOblique:
        return kItalicSlopeValue;
      case CSSValueID::kNormal:
        return kNormalSlopeValue;
      default:
        NOTREACHED();
    }
  } else if (IsA<cssvalue::CSSPendingSystemFontValue>(value)) {
    return kNormalSlopeValue;
  } else if (const auto* style_range_value =
                 DynamicTo<cssvalue::CSSFontStyleRangeValue>(value)) {
    const CSSValueList* values = style_range_value->GetObliqueValues();
    CHECK_LT(values->length(), 2u);
    if (values->length()) {
      return FontSelectionValue(To<CSSPrimitiveValue>(values->Item(0))
                                    .ComputeDegrees(length_resolver));
    } else {
      identifier_value = style_range_value->GetFontStyleValue();
      if (identifier_value->GetValueID() == CSSValueID::kNormal) {
        return kNormalSlopeValue;
      }
      if (identifier_value->GetValueID() == CSSValueID::kItalic ||
          identifier_value->GetValueID() == CSSValueID::kOblique) {
        return kItalicSlopeValue;
      }
    }
  }

  NOTREACHED();
}

FontSelectionValue StyleBuilderConverter::ConvertFontStyle(
    StyleResolverState& state,
    const CSSValue& value) {
  return StyleBuilderConverterBase::ConvertFontStyle(
      state.CssToLengthConversionData(), value);
}

FontSelectionValue StyleBuilderConverterBase::ConvertFontWeight(
    const CSSValue& value,
    FontSelectionValue parent_weight) {
  if (const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    if (primitive_value->IsNumber()) {
      return ClampTo<FontSelectionValue>(primitive_value->GetFloatValue());
    }
  }

  if (IsA<cssvalue::CSSPendingSystemFontValue>(value)) {
    return kNormalWeightValue;
  }

  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kNormal:
        return kNormalWeightValue;
      case CSSValueID::kBold:
        return kBoldWeightValue;
      case CSSValueID::kBolder:
        return FontDescription::BolderWeight(parent_weight);
      case CSSValueID::kLighter:
        return FontDescription::LighterWeight(parent_weight);
      default:
        NOTREACHED();
    }
  }
  NOTREACHED();
}

FontSelectionValue StyleBuilderConverter::ConvertFontWeight(
    StyleResolverState& state,
    const CSSValue& value) {
  return StyleBuilderConverterBase::ConvertFontWeight(
      value, state.ParentStyle()->GetFontDescription().Weight());
}

FontDescription::FontVariantCaps
StyleBuilderConverterBase::ConvertFontVariantCaps(const CSSValue& value) {
  if (value.IsPendingSystemFontValue()) {
    return FontDescription::kCapsNormal;
  }

  CSSValueID value_id = To<CSSIdentifierValue>(value).GetValueID();
  switch (value_id) {
    case CSSValueID::kNormal:
      return FontDescription::kCapsNormal;
    case CSSValueID::kSmallCaps:
      return FontDescription::kSmallCaps;
    case CSSValueID::kAllSmallCaps:
      return FontDescription::kAllSmallCaps;
    case CSSValueID::kPetiteCaps:
      return FontDescription::kPetiteCaps;
    case CSSValueID::kAllPetiteCaps:
      return FontDescription::kAllPetiteCaps;
    case CSSValueID::kUnicase:
      return FontDescription::kUnicase;
    case CSSValueID::kTitlingCaps:
      return FontDescription::kTitlingCaps;
    default:
      return FontDescription::kCapsNormal;
  }
}

FontDescription::FontVariantCaps StyleBuilderConverter::ConvertFontVariantCaps(
    StyleResolverState&,
    const CSSValue& value) {
  return StyleBuilderConverterBase::ConvertFontVariantCaps(value);
}

FontDescription::VariantLigatures
StyleBuilderConverter::ConvertFontVariantLigatures(StyleResolverState&,
                                                   const CSSValue& value) {
  if (const auto* value_list = DynamicTo<CSSValueList>(value)) {
    FontDescription::VariantLigatures ligatures;
    for (wtf_size_t i = 0; i < value_list->length(); ++i) {
      const CSSValue& item = value_list->Item(i);
      switch (To<CSSIdentifierValue>(item).GetValueID()) {
        case CSSValueID::kNoCommonLigatures:
          ligatures.common = FontDescription::kDisabledLigaturesState;
          break;
        case CSSValueID::kCommonLigatures:
          ligatures.common = FontDescription::kEnabledLigaturesState;
          break;
        case CSSValueID::kNoDiscretionaryLigatures:
          ligatures.discretionary = FontDescription::kDisabledLigaturesState;
          break;
        case CSSValueID::kDiscretionaryLigatures:
          ligatures.discretionary = FontDescription::kEnabledLigaturesState;
          break;
        case CSSValueID::kNoHistoricalLigatures:
          ligatures.historical = FontDescription::kDisabledLigaturesState;
          break;
        case CSSValueID::kHistoricalLigatures:
          ligatures.historical = FontDescription::kEnabledLigaturesState;
          break;
        case CSSValueID::kNoContextual:
          ligatures.contextual = FontDescription::kDisabledLigaturesState;
          break;
        case CSSValueID::kContextual:
          ligatures.contextual = FontDescription::kEnabledLigaturesState;
          break;
        default:
          NOTREACHED();
      }
    }
    return ligatures;
  }

  if (value.IsPendingSystemFontValue()) {
    return FontDescription::VariantLigatures();
  }

  if (To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kNone) {
    return FontDescription::VariantLigatures(
        FontDescription::kDisabledLigaturesState);
  }

  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kNormal);
  return FontDescription::VariantLigatures();
}

FontVariantNumeric StyleBuilderConverter::ConvertFontVariantNumeric(
    StyleResolverState&,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNormal);
    return FontVariantNumeric();
  }

  if (value.IsPendingSystemFontValue()) {
    return FontVariantNumeric();
  }

  FontVariantNumeric variant_numeric;
  for (const CSSValue* feature : To<CSSValueList>(value)) {
    switch (To<CSSIdentifierValue>(feature)->GetValueID()) {
      case CSSValueID::kLiningNums:
        variant_numeric.SetNumericFigure(FontVariantNumeric::kLiningNums);
        break;
      case CSSValueID::kOldstyleNums:
        variant_numeric.SetNumericFigure(FontVariantNumeric::kOldstyleNums);
        break;
      case CSSValueID::kProportionalNums:
        variant_numeric.SetNumericSpacing(
            FontVariantNumeric::kProportionalNums);
        break;
      case CSSValueID::kTabularNums:
        variant_numeric.SetNumericSpacing(FontVariantNumeric::kTabularNums);
        break;
      case CSSValueID::kDiagonalFractions:
        variant_numeric.SetNumericFraction(
            FontVariantNumeric::kDiagonalFractions);
        break;
      case CSSValueID::kStackedFractions:
        variant_numeric.SetNumericFraction(
            FontVariantNumeric::kStackedFractions);
        break;
      case CSSValueID::kOrdinal:
        variant_numeric.SetOrdinal(FontVariantNumeric::kOrdinalOn);
        break;
      case CSSValueID::kSlashedZero:
        variant_numeric.SetSlashedZero(FontVariantNumeric::kSlashedZeroOn);
        break;
      default:
        NOTREACHED();
    }
  }
  return variant_numeric;
}

scoped_refptr<FontVariantAlternates>
StyleBuilderConverter::ConvertFontVariantAlternates(StyleResolverState&,
                                                    const CSSValue& value) {
  scoped_refptr<FontVariantAlternates> alternates =
      FontVariantAlternates::Create();
  // See FontVariantAlternates::ParseSingleValue - we either receive the normal
  // identifier or a list of 1 or more elements if it's non normal.
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNormal);
    return nullptr;
  }

  if (value.IsPendingSystemFontValue()) {
    return nullptr;
  }

  // If it's not the single normal identifier, it has to be a list.
  for (const CSSValue* alternate : To<CSSValueList>(value)) {
    const cssvalue::CSSAlternateValue* alternate_value =
        DynamicTo<cssvalue::CSSAlternateValue>(alternate);
    if (alternate_value) {
      switch (alternate_value->Function().FunctionType()) {
        case CSSValueID::kStylistic:
          alternates->SetStylistic(
              FirstEntryAsAtomicString(alternate_value->Aliases()));
          break;
        case CSSValueID::kSwash:
          alternates->SetSwash(
              FirstEntryAsAtomicString(alternate_value->Aliases()));
          break;
        case CSSValueID::kOrnaments:
          alternates->SetOrnaments(
              FirstEntryAsAtomicString(alternate_value->Aliases()));
          break;
        case CSSValueID::kAnnotation:
          alternates->SetAnnotation(
              FirstEntryAsAtomicString(alternate_value->Aliases()));
          break;
        case CSSValueID::kStyleset:
          alternates->SetStyleset(
              ValueListToAtomicStringVector(alternate_value->Aliases()));
          break;
        case CSSValueID::kCharacterVariant:
          alternates->SetCharacterVariant(
              ValueListToAtomicStringVector(alternate_value->Aliases()));
          break;
        default:
          NOTREACHED();
      }
    }
    const CSSIdentifierValue* alternate_value_ident =
        DynamicTo<CSSIdentifierValue>(alternate);
    if (alternate_value_ident) {
      DCHECK_EQ(alternate_value_ident->GetValueID(),
                CSSValueID::kHistoricalForms);
      alternates->SetHistoricalForms();
    }
  }

  if (alternates->IsNormal()) {
    return nullptr;
  }

  return alternates;
}

FontVariantEastAsian StyleBuilderConverter::ConvertFontVariantEastAsian(
    StyleResolverState&,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNormal);
    return FontVariantEastAsian();
  }

  if (value.IsPendingSystemFontValue()) {
    return FontVariantEastAsian();
  }

  FontVariantEastAsian variant_east_asian;
  for (const CSSValue* feature : To<CSSValueList>(value)) {
    switch (To<CSSIdentifierValue>(feature)->GetValueID()) {
      case CSSValueID::kJis78:
        variant_east_asian.SetForm(FontVariantEastAsian::kJis78);
        break;
      case CSSValueID::kJis83:
        variant_east_asian.SetForm(FontVariantEastAsian::kJis83);
        break;
      case CSSValueID::kJis90:
        variant_east_asian.SetForm(FontVariantEastAsian::kJis90);
        break;
      case CSSValueID::kJis04:
        variant_east_asian.SetForm(FontVariantEastAsian::kJis04);
        break;
      case CSSValueID::kSimplified:
        variant_east_asian.SetForm(FontVariantEastAsian::kSimplified);
        break;
      case CSSValueID::kTraditional:
        variant_east_asian.SetForm(FontVariantEastAsian::kTraditional);
        break;
      case CSSValueID::kFullWidth:
        variant_east_asian.SetWidth(FontVariantEastAsian::kFullWidth);
        break;
      case CSSValueID::kProportionalWidth:
        variant_east_asian.SetWidth(FontVariantEastAsian::kProportionalWidth);
        break;
      case CSSValueID::kRuby:
        variant_east_asian.SetRuby(true);
        break;
      default:
        NOTREACHED();
    }
  }
  return variant_east_asian;
}

StyleSelfAlignmentData StyleBuilderConverter::ConvertSelfOrDefaultAlignmentData(
    StyleResolverState&,
    const CSSValue& value) {
  StyleSelfAlignmentData alignment_data =
      ComputedStyleInitialValues::InitialAlignSelf();
  if (const auto* pair = DynamicTo<CSSValuePair>(value)) {
    if (To<CSSIdentifierValue>(pair->First()).GetValueID() ==
        CSSValueID::kLegacy) {
      alignment_data.SetPositionType(ItemPositionType::kLegacy);
      alignment_data.SetPosition(
          To<CSSIdentifierValue>(pair->Second()).ConvertTo<ItemPosition>());
    } else if (To<CSSIdentifierValue>(pair->First()).GetValueID() ==
               CSSValueID::kFirst) {
      alignment_data.SetPosition(ItemPosition::kBaseline);
    } else if (To<CSSIdentifierValue>(pair->First()).GetValueID() ==
               CSSValueID::kLast) {
      alignment_data.SetPosition(ItemPosition::kLastBaseline);
    } else {
      alignment_data.SetOverflow(
          To<CSSIdentifierValue>(pair->First()).ConvertTo<OverflowAlignment>());
      alignment_data.SetPosition(
          To<CSSIdentifierValue>(pair->Second()).ConvertTo<ItemPosition>());
    }
  } else {
    alignment_data.SetPosition(
        To<CSSIdentifierValue>(value).ConvertTo<ItemPosition>());
  }
  return alignment_data;
}

StyleContentAlignmentData StyleBuilderConverter::ConvertContentAlignmentData(
    StyleResolverState&,
    const CSSValue& value) {
  StyleContentAlignmentData alignment_data =
      ComputedStyleInitialValues::InitialContentAlignment();
  const cssvalue::CSSContentDistributionValue& content_value =
      To<cssvalue::CSSContentDistributionValue>(value);
  if (IsValidCSSValueID(content_value.Distribution())) {
    alignment_data.SetDistribution(
        CSSIdentifierValue::Create(content_value.Distribution())
            ->ConvertTo<ContentDistributionType>());
  }
  if (IsValidCSSValueID(content_value.Position())) {
    alignment_data.SetPosition(
        CSSIdentifierValue::Create(content_value.Position())
            ->ConvertTo<ContentPosition>());
  }
  if (IsValidCSSValueID(content_value.Overflow())) {
    alignment_data.SetOverflow(
        CSSIdentifierValue::Create(content_value.Overflow())
            ->ConvertTo<OverflowAlignment>());
  }

  return alignment_data;
}

GridAutoFlow StyleBuilderConverter::ConvertGridAutoFlow(StyleResolverState&,
                                                        const CSSValue& value) {
  const auto* list = DynamicTo<CSSValueList>(&value);
  if (list) {
    DCHECK_GE(list->length(), 1u);
  } else {
    DCHECK(value.IsIdentifierValue());
  }

  const CSSIdentifierValue& first =
      To<CSSIdentifierValue>(list ? list->Item(0) : value);
  const CSSIdentifierValue* second =
      list && list->length() == 2 ? &To<CSSIdentifierValue>(list->Item(1))
                                  : nullptr;

  switch (first.GetValueID()) {
    case CSSValueID::kRow:
      if (second && second->GetValueID() == CSSValueID::kDense) {
        return kAutoFlowRowDense;
      }
      return kAutoFlowRow;
    case CSSValueID::kColumn:
      if (second && second->GetValueID() == CSSValueID::kDense) {
        return kAutoFlowColumnDense;
      }
      return kAutoFlowColumn;
    case CSSValueID::kDense:
      if (second && second->GetValueID() == CSSValueID::kColumn) {
        return kAutoFlowColumnDense;
      }
      return kAutoFlowRowDense;
    default:
      NOTREACHED();
  }
}

GridPosition StyleBuilderConverter::ConvertGridPosition(
    StyleResolverState& state,
    const CSSValue& value) {
  // We accept the specification's grammar:
  // 'auto' | [ <integer> || <custom-ident> ] |
  // [ span && [ <integer> || <custom-ident> ] ] | <custom-ident>

  GridPosition position;

  if (auto* ident_value = DynamicTo<CSSCustomIdentValue>(value)) {
    position.SetNamedGridArea(ident_value->Value());
    return position;
  }

  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kAuto);
    return position;
  }

  const auto& values = To<CSSValueList>(value);
  DCHECK(values.length());

  bool is_span_position = false;
  // The specification makes the <integer> optional, in which case it default to
  // '1'.
  int grid_line_number = 1;
  AtomicString grid_line_name;

  auto it = values.begin();
  const CSSValue* current_value = it->Get();
  auto* current_identifier_value = DynamicTo<CSSIdentifierValue>(current_value);
  if (current_identifier_value &&
      current_identifier_value->GetValueID() == CSSValueID::kSpan) {
    is_span_position = true;
    ++it;
    current_value = it != values.end() ? it->Get() : nullptr;
  }

  auto* current_primitive_value = DynamicTo<CSSPrimitiveValue>(current_value);
  if (current_primitive_value && current_primitive_value->IsNumber()) {
    grid_line_number = current_primitive_value->ComputeInteger(
        state.CssToLengthConversionData());
    ++it;
    current_value = it != values.end() ? it->Get() : nullptr;
  }

  auto* current_ident_value = DynamicTo<CSSCustomIdentValue>(current_value);
  if (current_ident_value) {
    grid_line_name = current_ident_value->Value();
    ++it;
  }

  DCHECK_EQ(it, values.end());
  if (is_span_position) {
    position.SetSpanPosition(grid_line_number, grid_line_name);
  } else {
    position.SetExplicitPosition(grid_line_number, grid_line_name);
  }

  return position;
}

// static
ComputedGridTemplateAreas* StyleBuilderConverter::ConvertGridTemplateAreas(
    StyleResolverState&,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }

  const auto& grid_template_areas_value =
      To<cssvalue::CSSGridTemplateAreasValue>(value);
  return MakeGarbageCollected<ComputedGridTemplateAreas>(
      grid_template_areas_value.GridAreaMap(),
      grid_template_areas_value.RowCount(),
      grid_template_areas_value.ColumnCount());
}

GridTrackSize StyleBuilderConverter::ConvertGridTrackSize(
    StyleResolverState& state,
    const CSSValue& value) {
  if (value.IsPrimitiveValue() || value.IsIdentifierValue()) {
    return GridTrackSize(ConvertGridTrackBreadth(state, value));
  }

  auto& function = To<CSSFunctionValue>(value);
  if (function.FunctionType() == CSSValueID::kFitContent) {
    SECURITY_DCHECK(function.length() == 1);
    return GridTrackSize(ConvertGridTrackBreadth(state, function.Item(0)),
                         kFitContentTrackSizing);
  }

  SECURITY_DCHECK(function.length() == 2);
  return GridTrackSize(ConvertGridTrackBreadth(state, function.Item(0)),
                       ConvertGridTrackBreadth(state, function.Item(1)));
}

static void ConvertGridLineNamesList(
    const CSSValue& value,
    wtf_size_t current_named_grid_line,
    NamedGridLinesMap& named_grid_lines,
    OrderedNamedGridLines& ordered_named_grid_lines,
    bool is_in_repeat = false,
    bool is_first_repeat = false) {
  DCHECK(value.IsGridLineNamesValue());

  for (auto& named_grid_line_value : To<CSSValueList>(value)) {
    AtomicString named_grid_line =
        To<CSSCustomIdentValue>(*named_grid_line_value).Value();
    NamedGridLinesMap::AddResult result =
        named_grid_lines.insert(named_grid_line, Vector<wtf_size_t>());
    result.stored_value->value.push_back(current_named_grid_line);
    OrderedNamedGridLines::AddResult ordered_insertion_result =
        ordered_named_grid_lines.insert(current_named_grid_line,
                                        Vector<NamedGridLine>());
    ordered_insertion_result.stored_value->value.push_back(
        NamedGridLine(named_grid_line, is_in_repeat, is_first_repeat));
  }
}

NGGridTrackList StyleBuilderConverter::ConvertGridTrackSizeList(
    StyleResolverState& state,
    const CSSValue& value) {
  const CSSValueList* list = DynamicTo<CSSValueList>(value);
  if (!list) {
    const auto& ident = To<CSSIdentifierValue>(value);
    DCHECK_EQ(ident.GetValueID(), CSSValueID::kAuto);
    return NGGridTrackList(GridTrackSize(Length::Auto()));
  }

  Vector<GridTrackSize, 1> track_sizes;
  for (auto& curr_value : To<CSSValueList>(value)) {
    DCHECK(!curr_value->IsGridLineNamesValue());
    DCHECK(!curr_value->IsGridRepeatValue());
    track_sizes.push_back(ConvertGridTrackSize(state, *curr_value));
  }

  NGGridTrackList track_list;
  track_list.AddRepeater(track_sizes);
  return track_list;
}

void StyleBuilderConverter::ConvertGridTrackList(
    const CSSValue& value,
    ComputedGridTrackList& computed_grid_track_list,
    StyleResolverState& state) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return;
  }

  NGGridTrackList& track_list = computed_grid_track_list.track_list;

  wtf_size_t current_named_grid_line = 0;
  auto ConvertLineNameOrTrackSize =
      [&](const CSSValue& curr_value, bool is_in_repeat = false,
          bool is_first_repeat = false) -> wtf_size_t {
    wtf_size_t line_name_indices_count = 0;
    if (curr_value.IsGridLineNamesValue()) {
      ++line_name_indices_count;
      ConvertGridLineNamesList(
          curr_value, current_named_grid_line,
          computed_grid_track_list.named_grid_lines,
          computed_grid_track_list.ordered_named_grid_lines, is_in_repeat,
          is_first_repeat);
      if (computed_grid_track_list.IsSubgriddedAxis()) {
        ++current_named_grid_line;
        track_list.IncrementNonAutoRepeatLineCount();
      }
    } else {
      DCHECK_EQ(computed_grid_track_list.axis_type,
                GridAxisType::kStandaloneAxis);
      ++current_named_grid_line;
    }
    return line_name_indices_count;
  };

  const auto& values = To<CSSValueList>(value);
  auto curr_value = values.begin();
  bool is_subgrid = false;

  auto* identifier_value = DynamicTo<CSSIdentifierValue>(curr_value->Get());
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kSubgrid) {
    state.GetDocument().CountUse(WebFeature::kCSSSubgridLayout);
    computed_grid_track_list.axis_type = GridAxisType::kSubgriddedAxis;
    track_list.SetAxisType(GridAxisType::kSubgriddedAxis);
    is_subgrid = true;
    ++curr_value;
  }

  for (; curr_value != values.end(); ++curr_value) {
    if (auto* grid_auto_repeat_value =
            DynamicTo<cssvalue::CSSGridAutoRepeatValue>(curr_value->Get())) {
      Vector<GridTrackSize, 1> repeated_track_sizes;
      wtf_size_t auto_repeat_index = 0;
      wtf_size_t line_name_indices_count = 0;
      CSSValueID auto_repeat_id = grid_auto_repeat_value->AutoRepeatID();
      DCHECK(auto_repeat_id == CSSValueID::kAutoFill ||
             auto_repeat_id == CSSValueID::kAutoFit);
      computed_grid_track_list.auto_repeat_type =
          (auto_repeat_id == CSSValueID::kAutoFill) ? AutoRepeatType::kAutoFill
                                                    : AutoRepeatType::kAutoFit;
      for (const CSSValue* auto_repeat_value : To<CSSValueList>(**curr_value)) {
        if (auto_repeat_value->IsGridLineNamesValue()) {
          ++line_name_indices_count;
          ConvertGridLineNamesList(
              *auto_repeat_value, auto_repeat_index,
              computed_grid_track_list.auto_repeat_named_grid_lines,
              computed_grid_track_list.auto_repeat_ordered_named_grid_lines);
          if (computed_grid_track_list.IsSubgriddedAxis()) {
            ++auto_repeat_index;
          }
          continue;
        }
        ++auto_repeat_index;
        repeated_track_sizes.push_back(
            ConvertGridTrackSize(state, *auto_repeat_value));
      }
      track_list.AddRepeater(repeated_track_sizes,
                             static_cast<NGGridTrackRepeater::RepeatType>(
                                 computed_grid_track_list.auto_repeat_type),
                             /* repeat_count */ 1,
                             /* repeat_number_of_lines */ auto_repeat_index,
                             line_name_indices_count);
      computed_grid_track_list.auto_repeat_insertion_point =
          current_named_grid_line++;
      continue;
    }

    if (auto* grid_integer_repeat_value =
            DynamicTo<cssvalue::CSSGridIntegerRepeatValue>(curr_value->Get())) {
      const wtf_size_t repetitions = grid_integer_repeat_value->Repetitions();
      wtf_size_t line_name_indices_count = 0;

      for (wtf_size_t i = 0; i < repetitions; ++i) {
        const bool is_first_repeat = i == 0;
        for (auto integer_repeat_value : *grid_integer_repeat_value) {
          wtf_size_t current_line_name_indices_count =
              ConvertLineNameOrTrackSize(*integer_repeat_value,
                                         /* is_inside_repeat */ true,
                                         is_first_repeat);
          // Only add to `line_name_indices_count` on the first iteration so it
          // doesn't need to be divided by `repetitions`.
          if (is_first_repeat) {
            line_name_indices_count += current_line_name_indices_count;
          }
        }
      }

      Vector<GridTrackSize, 1> repeater_track_sizes;
      if (computed_grid_track_list.axis_type == GridAxisType::kStandaloneAxis) {
        for (auto integer_repeat_value : *grid_integer_repeat_value) {
          if (!integer_repeat_value->IsGridLineNamesValue()) {
            repeater_track_sizes.push_back(
                ConvertGridTrackSize(state, *integer_repeat_value));
          }
        }
      }
      track_list.AddRepeater(repeater_track_sizes,
                             NGGridTrackRepeater::RepeatType::kInteger,
                             repetitions, /* repeat_number_of_lines */ 1u,
                             line_name_indices_count);
      continue;
    }

    wtf_size_t line_name_indices_count =
        ConvertLineNameOrTrackSize(**curr_value);
    if (!curr_value->Get()->IsGridLineNamesValue()) {
      track_list.AddRepeater({ConvertGridTrackSize(state, **curr_value)});
    } else if (is_subgrid) {
      track_list.AddRepeater(/* repeater_track_sizes */ {},
                             NGGridTrackRepeater::RepeatType::kNoRepeat,
                             /* repeat_count */ 1,
                             /* repeat_number_of_lines */ 1u,
                             line_name_indices_count);
    }
  }

  // Unless the axis is subgridded, the parser should have rejected any
  // <track-list> without any <track-size> as this is not conformant to
  // the syntax.
  DCHECK(track_list.RepeaterCount() ||
         computed_grid_track_list.IsSubgriddedAxis());
}

std::optional<Length> StyleBuilderConverter::ConvertMasonrySlack(
    const StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kNormal) {
    return std::nullopt;
  }

  return ConvertLength(state, value);
}

StyleHyphenateLimitChars StyleBuilderConverter::ConvertHyphenateLimitChars(
    StyleResolverState& state,
    const CSSValue& value) {
  if (const auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(ident->GetValueID(), CSSValueID::kAuto);
    return StyleHyphenateLimitChars();
  }
  const auto& list = To<CSSValueList>(value);
  DCHECK_GE(list.length(), 1u);
  DCHECK_LE(list.length(), 3u);
  Vector<unsigned, 3> values;
  for (const Member<const CSSValue>& item : list) {
    if (const auto* primitive = DynamicTo<CSSPrimitiveValue>(item.Get())) {
      DCHECK(primitive->IsInteger());
      DCHECK_GE(primitive->ComputeInteger(state.CssToLengthConversionData()),
                1);
      values.push_back(
          primitive->Comput
"""


```