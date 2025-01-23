Response:
The user wants a summary of the functionality of the provided C++ code snippet from `computed_style_utils.cc`. I need to identify the key functions and their purpose. Since the user also asked about relationships with JavaScript, HTML, and CSS, I should look for any code that interacts with or represents CSS properties and values. The request also includes asking for examples of logic, user errors, and debugging, so I need to consider how the code might be used and what could go wrong. Finally, since this is part 2 of 6, I need to focus on the functions present in this specific snippet.

Here's a breakdown of the functions and their apparent purposes:

*   `ValueForPositionT()`:  Deals with calculating and returning CSS values for properties like `top`, `right`, `bottom`, `left`. It handles percentages, `auto`, and different positioning contexts (relative, sticky).
*   `ValueForItemPositionWithOverflowAlignment()`: Handles CSS values for item alignment properties like `justify-items` and `align-items`, considering legacy syntax and overflow alignment.
*   `ValueForContentPositionAndDistributionWithOverflowAlignment()`: Handles CSS values for content alignment properties like `justify-content` and `align-content`, considering distribution and overflow alignment.
*   Font-related functions (`ValueForLineHeight`, `ComputedValueForLineHeight`, `IdentifierForFamily`, `ValueForFamily`, `ValueForFontFamily`, `ValueForFontSize`, `ValueForFontSizeAdjust`, `ValueForFontStretch`, `ValueForFontStyle`, `ValueForFontWeight`, `ValueForFontVariantCaps`, `ValueForFontVariantLigatures`, `ValueForFontVariantNumeric`, `ValueForFontVariantAlternates`, `ValueForFontVariantPosition`, `ValueForFontKerning`, `ValueForFontOpticalSizing`, `ValueForFontStretchAsKeyword`, `ValueForFontVariantEastAsian`, `ValueForFontFeatureSettings`, `ValueForFontVariationSettings`, `ValueForFontPalette`, `ValueForFont`):  A large set of functions responsible for converting internal representations of font properties into their corresponding CSS value representations.
*   `SpecifiedValueForGridTrackSize()`:  Handles the conversion of internal grid track size representations to CSS values for properties like `grid-template-columns` and `grid-template-rows`.
*   `OrderedNamedLinesCollector`:  A class (though incomplete in the snippet) likely used for collecting and organizing named grid lines.

Based on this, the core function of this code snippet appears to be taking internal representations of computed styles (specifically related to positioning, alignment, and fonts) and converting them into their corresponding CSS value representations.
这是 `blink/renderer/core/css/properties/computed_style_utils.cc` 文件的一部分，主要功能是**将计算后的样式值（ComputedStyle）转换为 CSS 属性的 CSSValue 对象**。 这部分代码主要集中在处理定位属性、对齐属性以及各种字体相关的属性。

**功能归纳:**

1. **处理定位属性:**  `ValueForPositionT` 函数负责将计算后的 `top`, `right`, `bottom`, `left` 等定位属性值转换为 `CSSValue` 对象。它会处理像素值、百分比值、`auto` 值以及相对定位和粘性定位的情况。
2. **处理项目对齐属性:** `ValueForItemPositionWithOverflowAlignment` 函数将计算后的 `justify-items` 和 `align-items` 等属性值转换为 `CSSValue` 对象，考虑了旧的 `legacy` 值以及溢出对齐方式。
3. **处理内容对齐属性:** `ValueForContentPositionAndDistributionWithOverflowAlignment` 函数将计算后的 `justify-content` 和 `align-content` 等属性值转换为 `CSSValue` 对象，包括分布方式和溢出对齐。
4. **处理行高属性:** `ValueForLineHeight` 和 `ComputedValueForLineHeight` 函数将计算后的 `line-height` 属性值转换为 `CSSValue` 对象，处理 `auto` 值和数值。
5. **处理字体族属性:** `IdentifierForFamily` 和 `ValueForFamily` 函数将字体族名称转换为 `CSSValueID` 或 `CSSFontFamilyValue` 对象。 `ValueForFontFamily` 函数处理包含多个字体族的情况。
6. **处理字号属性:** `ValueForFontSize` 函数将计算后的字号转换为像素值的 `CSSPrimitiveValue` 对象。
7. **处理 `font-size-adjust` 属性:** `ValueForFontSizeAdjust` 函数将计算后的 `font-size-adjust` 属性值转换为 `CSSValue` 对象，处理 `none` 值和数值。
8. **处理 `font-stretch` 属性:** `ValueForFontStretch` 函数将计算后的 `font-stretch` 属性值转换为百分比的 `CSSPrimitiveValue` 对象， `ValueForFontStretchAsKeyword` 则尝试将其转换为关键字。
9. **处理 `font-style` 属性:** `ValueForFontStyle` 函数将计算后的 `font-style` 属性值转换为 `CSSValue` 对象，处理 `normal`, `italic` 和 `oblique` 值。
10. **处理 `font-weight` 属性:** `ValueForFontWeight` 函数将计算后的 `font-weight` 属性值转换为数值的 `CSSNumericLiteralValue` 对象。
11. **处理 `font-variant-caps` 属性:** `ValueForFontVariantCaps` 函数将计算后的 `font-variant-caps` 属性值转换为 `CSSIdentifierValue` 对象。
12. **处理 `font-variant-ligatures` 属性:** `ValueForFontVariantLigatures` 函数将计算后的 `font-variant-ligatures` 属性值转换为 `CSSValue` 对象，处理 `normal` 和 `none` 值以及各种连字类型。
13. **处理 `font-variant-numeric` 属性:** `ValueForFontVariantNumeric` 函数将计算后的 `font-variant-numeric` 属性值转换为 `CSSValue` 对象，处理数字相关的变体。
14. **处理 `font-variant-alternates` 属性:** `ValueForFontVariantAlternates` 函数将计算后的 `font-variant-alternates` 属性值转换为 `CSSValue` 对象，处理各种替代字形。
15. **处理 `font-variant-position` 属性:** `ValueForFontVariantPosition` 函数将计算后的 `font-variant-position` 属性值转换为 `CSSIdentifierValue` 对象，例如 `sub` 或 `super`。
16. **处理 `font-kerning` 属性:** `ValueForFontKerning` 函数将计算后的 `font-kerning` 属性值转换为 `CSSIdentifierValue` 对象，例如 `auto`, `normal`, `none`。
17. **处理 `font-optical-sizing` 属性:** `ValueForFontOpticalSizing` 函数将计算后的 `font-optical-sizing` 属性值转换为 `CSSIdentifierValue` 对象，例如 `auto`, `none`。
18. **处理 `font-variant-east-asian` 属性:** `ValueForFontVariantEastAsian` 函数将计算后的 `font-variant-east-asian` 属性值转换为 `CSSValue` 对象，处理东亚字体的变体。
19. **处理 `font-feature-settings` 属性:** `ValueForFontFeatureSettings` 函数将计算后的 `font-feature-settings` 属性值转换为 `CSSValue` 对象，包含 OpenType 特性标签。
20. **处理 `font-variation-settings` 属性:** `ValueForFontVariationSettings` 函数将计算后的 `font-variation-settings` 属性值转换为 `CSSValue` 对象，包含可变字体轴。
21. **处理 `font-palette` 属性:** `ValueForFontPalette` 函数将计算后的 `font-palette` 属性值转换为 `CSSValue` 对象。
22. **处理简写 `font` 属性:** `ValueForFont` 函数尝试将多个独立的字体属性组合成一个 `font` 简写属性的 `CSSValue` 对象。如果某些子属性的值与简写属性的序列化方式冲突，则返回 `nullptr`。
23. **处理 Grid 轨道尺寸:** `SpecifiedValueForGridTrackSize` 函数将 `GridTrackSize` 对象转换为 `CSSValue` 对象，用于 `grid-template-columns` 和 `grid-template-rows` 等属性。
24. **处理命名的 Grid 线:**  `OrderedNamedLinesCollector` 类用于收集和组织命名的 Grid 线。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **CSS 属性值的表示:**  这些函数的核心作用是将内部表示的 CSS 属性值转换为浏览器可以理解和序列化的 `CSSValue` 对象。例如，当 JavaScript 通过 `getComputedStyle()` 获取元素的 `line-height` 时，Blink 引擎会调用 `ValueForLineHeight` 这样的函数来生成对应的 CSS 值字符串。
    ```javascript
    const element = document.getElementById('myElement');
    const computedStyle = window.getComputedStyle(element);
    const lineHeight = computedStyle.lineHeight; // 这里获取到的值是由 C++ 代码生成的
    console.log(lineHeight); // 例如: "16px" 或 "normal"
    ```
*   **HTML 元素的样式计算:**  当浏览器渲染 HTML 元素时，需要计算元素的最终样式。这个过程中会涉及到读取 CSS 样式表中的规则，应用层叠和继承，最终得到每个属性的计算值。这些 `ComputedStyleUtils` 中的函数就是在计算完成后，将这些计算值转换为可用的 CSS 值表示。
*   **CSS 属性与内部表示的映射:** 这些函数体现了 CSS 属性和 Blink 引擎内部数据结构之间的映射关系。例如，CSS 的 `font-weight: bold;` 会在内部被表示为一个数值（如 700），而 `ValueForFontWeight` 函数则负责将其转换回 CSS 的数值表示。

**逻辑推理的假设输入与输出:**

**假设输入 (ValueForPositionT):**

*   `property_id`: `CSSPropertyID::kLeft`
*   `offset`:  一个表示 `10%` 的 `Length` 对象
*   `style`:  一个 `ComputedStyle` 对象
*   `layout_object`: 一个表示设置了 `position: relative` 的 `LayoutBox` 对象，其包含块宽度为 `200px`。
*   `box`: 同 `layout_object`
*   `opposite`:  一个表示 `auto` 的 `Length` 对象
*   `is_horizontal_property`: `true`

**输出:**

*   一个 `CSSPrimitiveValue` 对象，表示 `20px` (200px 的 10%)，单位为像素。

**假设输入 (ValueForLineHeight):**

*   `style`: 一个 `ComputedStyle` 对象，其 `LineHeight()` 返回一个表示 `1.5` 的无单位 `Length` 对象。
*   `style.GetFontDescription().ComputedSize()`: `16px`

**输出:**

*   一个 `CSSPrimitiveValue` 对象，表示 `24px` (1.5 * 16px)。

**用户或编程常见的使用错误举例说明:**

*   **在 `font` 简写属性中遗漏必要信息:**  用户可能在 CSS 中设置了 `font-style` 和 `font-weight`，但尝试通过 JavaScript 获取 `font` 属性时，由于 `ValueForFont` 函数检测到非初始值，可能会返回 `nullptr`，导致 JavaScript 代码无法获取到预期的简写值。
    ```css
    #myElement {
      font-style: italic;
      font-weight: bold;
    }
    ```
    ```javascript
    const element = document.getElementById('myElement');
    const computedStyle = window.getComputedStyle(element);
    const font = computedStyle.font; // font 可能为 null 或空字符串，取决于浏览器实现细节
    ```
*   **不理解 `auto` 值的计算方式:**  对于定位属性，用户可能认为 `left: auto;` 会保持元素在包含块的左侧，但实际上，如果 `right` 属性有非 `auto` 的值，`left` 的计算值会是 `-right`。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在 HTML 文件中添加了一个设置了样式的元素。**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        #myElement {
          position: relative;
          left: 10%;
          font-size: 16px;
          line-height: 1.5;
        }
      </style>
    </head>
    <body>
      <div id="myElement">Hello</div>
    </body>
    </html>
    ```
2. **用户使用浏览器加载该 HTML 文件。**
3. **浏览器解析 HTML 和 CSS，构建 DOM 树和 CSSOM 树。**
4. **浏览器进行布局计算，确定元素的位置和大小。** 在计算 `#myElement` 的 `left` 和 `line-height` 时，会使用到 `ComputedStyle` 对象。
5. **如果用户在浏览器的开发者工具中查看元素的 "Computed" 样式，或者使用 JavaScript 的 `getComputedStyle()` 方法，浏览器会调用 Blink 引擎的相关代码来获取这些计算后的样式值。**
6. **当需要将 `ComputedStyle` 对象中的 `left` 属性值转换为 CSS 可以理解的字符串时，`ValueForPositionT` 函数会被调用。同样，当需要获取 `line-height` 的值时，`ValueForLineHeight` 函数会被调用。**
7. **调试时，如果怀疑计算后的样式值有问题，可以设置断点在这些 `ValueFor...` 函数中，查看输入参数（如 `offset`, `style`）的值，以及函数的输出，从而追踪样式计算的流程。**

总而言之，这部分 `computed_style_utils.cc` 代码是 Blink 引擎中负责将内部表示的计算样式值转换为外部（例如 JavaScript 或开发者工具）可访问的 CSS 值表示的关键部分，涉及到多种 CSS 属性的处理。

### 提示词
```
这是目录为blink/renderer/core/css/properties/computed_style_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
inset = insets.right;
        break;
      case CSSPropertyID::kBottom:
        inset = insets.bottom;
        break;
      default:
        NOTREACHED();
    }
    return ZoomAdjustedPixelValue(inset, style);
  }

  if ((offset.IsPercent() || offset.IsCalculated()) && box &&
      box->IsPositioned()) {
    LayoutUnit containing_block_size;
    if (box->IsStickyPositioned()) {
      const LayoutBox* scroll_container = box->ContainingScrollContainer();
      DCHECK(scroll_container);
      bool use_inline_size =
          is_horizontal_property == scroll_container->IsHorizontalWritingMode();
      containing_block_size = use_inline_size
                                  ? scroll_container->ContentLogicalWidth()
                                  : scroll_container->ContentLogicalHeight();
      UseCounter::Count(box->GetDocument(),
                        WebFeature::kPercentOrCalcStickyUsedOffset);
    } else {
      DCHECK(box->IsRelPositioned());
      containing_block_size =
          is_horizontal_property ==
                  box->ContainingBlock()->IsHorizontalWritingMode()
              ? box->ContainingBlockLogicalWidthForContent()
              : box->ContainingBlockLogicalHeightForRelPositioned();
      UseCounter::Count(box->GetDocument(),
                        WebFeature::kPercentOrCalcRelativeUsedOffset);
    }

    return ZoomAdjustedPixelValue(ValueForLength(offset, containing_block_size),
                                  style);
  }

  if (offset.IsAuto() && layout_object && layout_object->IsRelPositioned()) {
    UseCounter::Count(layout_object->GetDocument(),
                      WebFeature::kAutoRelativeUsedOffset);
    // If e.g. left is auto and right is not auto, then left's computed value
    // is negative right. So we get the opposite length unit and see if it is
    // auto.
    if (opposite.IsAuto()) {
      return CSSNumericLiteralValue::Create(
          0, CSSPrimitiveValue::UnitType::kPixels);
    }

    if (opposite.IsPercent() || opposite.IsCalculated()) {
      if (box) {
        LayoutUnit containing_block_size =
            is_horizontal_property ==
                    layout_object->ContainingBlock()->IsHorizontalWritingMode()
                ? box->ContainingBlockLogicalWidthForContent()
                : box->ContainingBlockLogicalHeightForRelPositioned();
        return ZoomAdjustedPixelValue(
            -FloatValueForLength(opposite, containing_block_size), style);
      }
      // FIXME:  fall back to auto for position:relative, display:inline
      return CSSIdentifierValue::Create(CSSValueID::kAuto);
    }

    Length negated_opposite = Negate(opposite);
    return ZoomAdjustedPixelValueForLength(negated_opposite, style);
  }

  if (offset.IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  // Fixed lengths must have been handled by previous branches.
  CHECK(!offset.IsFixed());
  return ZoomAdjustedPixelValueForLength(offset, style);
}

CSSValue* ComputedStyleUtils::ValueForItemPositionWithOverflowAlignment(
    const StyleSelfAlignmentData& data) {
  if (data.PositionType() == ItemPositionType::kLegacy) {
    // Legacy is only for justify-items and may only be created with the
    // positions "left", "right", or "center". See
    // JustifyItems::ParseSingleValue.
    DCHECK(data.GetPosition() == ItemPosition::kLeft ||
           data.GetPosition() == ItemPosition::kRight ||
           data.GetPosition() == ItemPosition::kCenter)
        << "Unexpected position: " << (unsigned)data.GetPosition();
    DCHECK_EQ(data.Overflow(), OverflowAlignment::kDefault);
    return MakeGarbageCollected<CSSValuePair>(
        CSSIdentifierValue::Create(CSSValueID::kLegacy),
        CSSIdentifierValue::Create(data.GetPosition()),
        CSSValuePair::kDropIdenticalValues);
  }

  if (data.GetPosition() == ItemPosition::kBaseline) {
    return CSSIdentifierValue::Create(CSSValueID::kBaseline);
  } else if (data.GetPosition() == ItemPosition::kLastBaseline) {
    return MakeGarbageCollected<CSSValuePair>(
        CSSIdentifierValue::Create(CSSValueID::kLast),
        CSSIdentifierValue::Create(CSSValueID::kBaseline),
        CSSValuePair::kDropIdenticalValues);
  } else {
    auto* position = data.GetPosition() == ItemPosition::kLegacy
                         ? CSSIdentifierValue::Create(CSSValueID::kNormal)
                         : CSSIdentifierValue::Create(data.GetPosition());
    if (data.GetPosition() >= ItemPosition::kCenter &&
        data.Overflow() != OverflowAlignment::kDefault) {
      return MakeGarbageCollected<CSSValuePair>(
          CSSIdentifierValue::Create(data.Overflow()), position,
          CSSValuePair::kDropIdenticalValues);
    }
    return position;
  }
}

cssvalue::CSSContentDistributionValue*
ComputedStyleUtils::ValueForContentPositionAndDistributionWithOverflowAlignment(
    const StyleContentAlignmentData& data) {
  CSSValueID distribution = CSSValueID::kInvalid;
  CSSValueID position = CSSValueID::kInvalid;
  CSSValueID overflow = CSSValueID::kInvalid;

  // Handle content-distribution values
  if (data.Distribution() != ContentDistributionType::kDefault) {
    distribution = CSSIdentifierValue(data.Distribution()).GetValueID();
  }

  // Handle content-position values (either as fallback or actual value)
  switch (data.GetPosition()) {
    case ContentPosition::kNormal:
      // Handle 'normal' value, not valid as content-distribution fallback.
      if (data.Distribution() == ContentDistributionType::kDefault) {
        position = CSSValueID::kNormal;
      }
      break;
    case ContentPosition::kLastBaseline:
      position = CSSValueID::kLastBaseline;
      break;
    default:
      // Handle overflow-alignment (only allowed for content-position values)
      if ((data.GetPosition() >= ContentPosition::kCenter ||
           data.Distribution() != ContentDistributionType::kDefault) &&
          data.Overflow() != OverflowAlignment::kDefault) {
        overflow = CSSIdentifierValue::Create(data.Overflow())->GetValueID();
      }
      position = CSSIdentifierValue::Create(data.GetPosition())->GetValueID();
  }

  return MakeGarbageCollected<cssvalue::CSSContentDistributionValue>(
      distribution, position, overflow);
}

CSSValue* ComputedStyleUtils::ValueForLineHeight(const ComputedStyle& style) {
  const Length& length = style.LineHeight();
  if (length.IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  return ZoomAdjustedPixelValue(
      FloatValueForLength(length, style.GetFontDescription().ComputedSize()),
      style);
}

CSSValue* ComputedStyleUtils::ComputedValueForLineHeight(
    const ComputedStyle& style) {
  const Length& length = style.LineHeight();
  if (length.IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  if (length.IsPercent()) {
    return CSSNumericLiteralValue::Create(length.GetFloatValue() / 100.0,
                                          CSSPrimitiveValue::UnitType::kNumber);
  } else {
    return ZoomAdjustedPixelValue(
        FloatValueForLength(length, style.GetFontDescription().ComputedSize()),
        style);
  }
}

CSSValueID IdentifierForFamily(const AtomicString& family) {
  if (family == font_family_names::kCursive) {
    return CSSValueID::kCursive;
  }
  if (family == font_family_names::kFantasy) {
    return CSSValueID::kFantasy;
  }
  if (family == font_family_names::kMonospace) {
    return CSSValueID::kMonospace;
  }
  if (family == font_family_names::kSansSerif) {
    return CSSValueID::kSansSerif;
  }
  if (family == font_family_names::kSerif) {
    return CSSValueID::kSerif;
  }
  if (family == font_family_names::kSystemUi) {
    return CSSValueID::kSystemUi;
  }
  if (family == font_family_names::kMath) {
    return CSSValueID::kMath;
  }
  // If family does not correspond to any of the above, then it was actually
  // converted from -webkit-body by FontBuilder, so put this value back.
  // TODO(crbug.com/1065468): This trick does not work if
  // FontBuilder::StandardFontFamilyName() actually returned one of the generic
  // family above.
  return CSSValueID::kWebkitBody;
}

CSSValue* ValueForFamily(const FontFamily& family) {
  if (family.FamilyIsGeneric()) {
    return CSSIdentifierValue::Create(IdentifierForFamily(family.FamilyName()));
  }
  return CSSFontFamilyValue::Create(family.FamilyName());
}

CSSValueList* ComputedStyleUtils::ValueForFontFamily(
    const FontFamily& font_family) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const FontFamily* family = &font_family; family;
       family = family->Next()) {
    list->Append(*ValueForFamily(*family));
  }
  return list;
}

CSSValueList* ComputedStyleUtils::ValueForFontFamily(
    const ComputedStyle& style) {
  return ComputedStyleUtils::ValueForFontFamily(
      style.GetFontDescription().Family());
}

CSSPrimitiveValue* ComputedStyleUtils::ValueForFontSize(
    const ComputedStyle& style) {
  return ZoomAdjustedPixelValue(style.GetFontDescription().ComputedSize(),
                                style);
}

CSSValue* ComputedStyleUtils::ValueForFontSizeAdjust(
    const ComputedStyle& style) {
  if (!style.HasFontSizeAdjust() ||
      style.FontSizeAdjust().Value() == FontSizeAdjust::kFontSizeAdjustNone) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  // A resolved value is to be returned. Compare CSS WG discussion.
  // https://github.com/w3c/csswg-drafts/issues/9050
  FontSizeAdjust font_size_adjust = style.FontSizeAdjust();
  if (font_size_adjust.GetMetric() == FontSizeAdjust::Metric::kExHeight) {
    return CSSNumericLiteralValue::Create(style.FontSizeAdjust().Value(),
                                          CSSPrimitiveValue::UnitType::kNumber);
  }

  return MakeGarbageCollected<CSSValuePair>(
      CSSIdentifierValue::Create(font_size_adjust.GetMetric()),
      CSSNumericLiteralValue::Create(style.FontSizeAdjust().Value(),
                                     CSSPrimitiveValue::UnitType::kNumber),
      CSSValuePair::kKeepIdenticalValues);
}

CSSPrimitiveValue* ComputedStyleUtils::ValueForFontStretch(
    const ComputedStyle& style) {
  return CSSNumericLiteralValue::Create(
      style.GetFontDescription().Stretch(),
      CSSPrimitiveValue::UnitType::kPercentage);
}

CSSValue* ComputedStyleUtils::ValueForFontStyle(const ComputedStyle& style) {
  FontSelectionValue angle = style.GetFontDescription().Style();
  if (angle == kNormalSlopeValue) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  if (angle == kItalicSlopeValue) {
    return CSSIdentifierValue::Create(CSSValueID::kItalic);
  }

  // The spec says: 'The lack of a number represents an angle of
  // "20deg"', but since we compute that to 'italic' (handled above),
  // we don't perform any special treatment of that value here.
  CSSValueList* oblique_values = CSSValueList::CreateSpaceSeparated();
  oblique_values->Append(*CSSNumericLiteralValue::Create(
      angle, CSSPrimitiveValue::UnitType::kDegrees));
  return MakeGarbageCollected<cssvalue::CSSFontStyleRangeValue>(
      *CSSIdentifierValue::Create(CSSValueID::kOblique), *oblique_values);
}

CSSNumericLiteralValue* ComputedStyleUtils::ValueForFontWeight(
    const ComputedStyle& style) {
  return CSSNumericLiteralValue::Create(style.GetFontDescription().Weight(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

CSSIdentifierValue* ComputedStyleUtils::ValueForFontVariantCaps(
    const ComputedStyle& style) {
  FontDescription::FontVariantCaps variant_caps =
      style.GetFontDescription().VariantCaps();
  switch (variant_caps) {
    case FontDescription::kCapsNormal:
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    case FontDescription::kSmallCaps:
      return CSSIdentifierValue::Create(CSSValueID::kSmallCaps);
    case FontDescription::kAllSmallCaps:
      return CSSIdentifierValue::Create(CSSValueID::kAllSmallCaps);
    case FontDescription::kPetiteCaps:
      return CSSIdentifierValue::Create(CSSValueID::kPetiteCaps);
    case FontDescription::kAllPetiteCaps:
      return CSSIdentifierValue::Create(CSSValueID::kAllPetiteCaps);
    case FontDescription::kUnicase:
      return CSSIdentifierValue::Create(CSSValueID::kUnicase);
    case FontDescription::kTitlingCaps:
      return CSSIdentifierValue::Create(CSSValueID::kTitlingCaps);
    default:
      NOTREACHED();
  }
}

CSSValue* ComputedStyleUtils::ValueForFontVariantLigatures(
    const ComputedStyle& style) {
  FontDescription::LigaturesState common_ligatures_state =
      style.GetFontDescription().CommonLigaturesState();
  FontDescription::LigaturesState discretionary_ligatures_state =
      style.GetFontDescription().DiscretionaryLigaturesState();
  FontDescription::LigaturesState historical_ligatures_state =
      style.GetFontDescription().HistoricalLigaturesState();
  FontDescription::LigaturesState contextual_ligatures_state =
      style.GetFontDescription().ContextualLigaturesState();
  if (common_ligatures_state == FontDescription::kNormalLigaturesState &&
      discretionary_ligatures_state == FontDescription::kNormalLigaturesState &&
      historical_ligatures_state == FontDescription::kNormalLigaturesState &&
      contextual_ligatures_state == FontDescription::kNormalLigaturesState) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  if (common_ligatures_state == FontDescription::kDisabledLigaturesState &&
      discretionary_ligatures_state ==
          FontDescription::kDisabledLigaturesState &&
      historical_ligatures_state == FontDescription::kDisabledLigaturesState &&
      contextual_ligatures_state == FontDescription::kDisabledLigaturesState) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* value_list = CSSValueList::CreateSpaceSeparated();
  if (common_ligatures_state != FontDescription::kNormalLigaturesState) {
    value_list->Append(*CSSIdentifierValue::Create(
        common_ligatures_state == FontDescription::kDisabledLigaturesState
            ? CSSValueID::kNoCommonLigatures
            : CSSValueID::kCommonLigatures));
  }
  if (discretionary_ligatures_state != FontDescription::kNormalLigaturesState) {
    value_list->Append(*CSSIdentifierValue::Create(
        discretionary_ligatures_state ==
                FontDescription::kDisabledLigaturesState
            ? CSSValueID::kNoDiscretionaryLigatures
            : CSSValueID::kDiscretionaryLigatures));
  }
  if (historical_ligatures_state != FontDescription::kNormalLigaturesState) {
    value_list->Append(*CSSIdentifierValue::Create(
        historical_ligatures_state == FontDescription::kDisabledLigaturesState
            ? CSSValueID::kNoHistoricalLigatures
            : CSSValueID::kHistoricalLigatures));
  }
  if (contextual_ligatures_state != FontDescription::kNormalLigaturesState) {
    value_list->Append(*CSSIdentifierValue::Create(
        contextual_ligatures_state == FontDescription::kDisabledLigaturesState
            ? CSSValueID::kNoContextual
            : CSSValueID::kContextual));
  }
  return value_list;
}

CSSValue* ComputedStyleUtils::ValueForFontVariantNumeric(
    const ComputedStyle& style) {
  FontVariantNumeric variant_numeric =
      style.GetFontDescription().VariantNumeric();
  if (variant_numeric.IsAllNormal()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  CSSValueList* value_list = CSSValueList::CreateSpaceSeparated();
  if (variant_numeric.NumericFigureValue() !=
      FontVariantNumeric::kNormalFigure) {
    value_list->Append(*CSSIdentifierValue::Create(
        variant_numeric.NumericFigureValue() == FontVariantNumeric::kLiningNums
            ? CSSValueID::kLiningNums
            : CSSValueID::kOldstyleNums));
  }
  if (variant_numeric.NumericSpacingValue() !=
      FontVariantNumeric::kNormalSpacing) {
    value_list->Append(*CSSIdentifierValue::Create(
        variant_numeric.NumericSpacingValue() ==
                FontVariantNumeric::kProportionalNums
            ? CSSValueID::kProportionalNums
            : CSSValueID::kTabularNums));
  }
  if (variant_numeric.NumericFractionValue() !=
      FontVariantNumeric::kNormalFraction) {
    value_list->Append(*CSSIdentifierValue::Create(
        variant_numeric.NumericFractionValue() ==
                FontVariantNumeric::kDiagonalFractions
            ? CSSValueID::kDiagonalFractions
            : CSSValueID::kStackedFractions));
  }
  if (variant_numeric.OrdinalValue() == FontVariantNumeric::kOrdinalOn) {
    value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kOrdinal));
  }
  if (variant_numeric.SlashedZeroValue() ==
      FontVariantNumeric::kSlashedZeroOn) {
    value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kSlashedZero));
  }

  return value_list;
}

CSSValue* ComputedStyleUtils::ValueForFontVariantAlternates(
    const ComputedStyle& style) {
  const FontVariantAlternates* variant_alternates =
      style.GetFontDescription().GetFontVariantAlternates();
  if (!variant_alternates || variant_alternates->IsNormal()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  auto make_single_ident_list = [](const AtomicString& alias) {
    CSSValueList* aliases_list = CSSValueList::CreateCommaSeparated();
    aliases_list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(alias));
    return aliases_list;
  };

  CSSValueList* value_list = CSSValueList::CreateSpaceSeparated();
  if (const AtomicString* opt_stylistic = variant_alternates->Stylistic()) {
    value_list->Append(*MakeGarbageCollected<cssvalue::CSSAlternateValue>(
        *MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kStylistic),
        *make_single_ident_list(*opt_stylistic)));
  }
  if (variant_alternates->HistoricalForms()) {
    value_list->Append(
        *CSSIdentifierValue::Create(CSSValueID::kHistoricalForms));
  }
  if (const AtomicString* opt_swash = variant_alternates->Swash()) {
    value_list->Append(*MakeGarbageCollected<cssvalue::CSSAlternateValue>(
        *MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kSwash),
        *make_single_ident_list(*opt_swash)));
  }
  if (const AtomicString* opt_ornaments = variant_alternates->Ornaments()) {
    value_list->Append(*MakeGarbageCollected<cssvalue::CSSAlternateValue>(
        *MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kOrnaments),
        *make_single_ident_list(*opt_ornaments)));
  }
  if (const AtomicString* opt_annotation = variant_alternates->Annotation()) {
    value_list->Append(*MakeGarbageCollected<cssvalue::CSSAlternateValue>(
        *MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kAnnotation),
        *make_single_ident_list(*opt_annotation)));
  }

  if (!variant_alternates->Styleset().empty()) {
    CSSValueList* aliases_list = CSSValueList::CreateCommaSeparated();
    for (auto alias : variant_alternates->Styleset()) {
      aliases_list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(alias));
    }
    value_list->Append(*MakeGarbageCollected<cssvalue::CSSAlternateValue>(
        *MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kStyleset),
        *aliases_list));
  }
  if (!variant_alternates->CharacterVariant().empty()) {
    CSSValueList* aliases_list = CSSValueList::CreateCommaSeparated();
    for (auto alias : variant_alternates->CharacterVariant()) {
      aliases_list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(alias));
    }
    value_list->Append(*MakeGarbageCollected<cssvalue::CSSAlternateValue>(
        *MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kCharacterVariant),
        *aliases_list));
  }

  DCHECK(value_list->length());
  return value_list;
}

CSSIdentifierValue* ComputedStyleUtils::ValueForFontVariantPosition(
    const ComputedStyle& style) {
  FontDescription::FontVariantPosition variant_position =
      style.GetFontDescription().VariantPosition();
  switch (variant_position) {
    case FontDescription::kNormalVariantPosition:
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    case FontDescription::kSubVariantPosition:
      return CSSIdentifierValue::Create(CSSValueID::kSub);
    case FontDescription::kSuperVariantPosition:
      return CSSIdentifierValue::Create(CSSValueID::kSuper);
    default:
      NOTREACHED();
  }
}

CSSIdentifierValue* ComputedStyleUtils::ValueForFontKerning(
    const ComputedStyle& style) {
  FontDescription::Kerning kerning = style.GetFontDescription().GetKerning();
  switch (kerning) {
    case FontDescription::kAutoKerning:
      return CSSIdentifierValue::Create(CSSValueID::kAuto);
    case FontDescription::kNormalKerning:
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    case FontDescription::kNoneKerning:
      return CSSIdentifierValue::Create(CSSValueID::kNone);
    default:
      NOTREACHED();
  }
}

CSSIdentifierValue* ComputedStyleUtils::ValueForFontOpticalSizing(
    const ComputedStyle& style) {
  OpticalSizing optical_sizing = style.GetFontDescription().FontOpticalSizing();
  switch (optical_sizing) {
    case kAutoOpticalSizing:
      return CSSIdentifierValue::Create(CSSValueID::kAuto);
    case kNoneOpticalSizing:
      return CSSIdentifierValue::Create(CSSValueID::kNone);
    default:
      return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
}

CSSIdentifierValue* ValueForFontStretchAsKeyword(const ComputedStyle& style) {
  FontSelectionValue stretch_value = style.GetFontDescription().Stretch();
  CSSValueID value_id = CSSValueID::kInvalid;
  if (stretch_value == kUltraCondensedWidthValue) {
    value_id = CSSValueID::kUltraCondensed;
  }
  if (stretch_value == kUltraCondensedWidthValue) {
    value_id = CSSValueID::kUltraCondensed;
  }
  if (stretch_value == kExtraCondensedWidthValue) {
    value_id = CSSValueID::kExtraCondensed;
  }
  if (stretch_value == kCondensedWidthValue) {
    value_id = CSSValueID::kCondensed;
  }
  if (stretch_value == kSemiCondensedWidthValue) {
    value_id = CSSValueID::kSemiCondensed;
  }
  if (stretch_value == kNormalWidthValue) {
    value_id = CSSValueID::kNormal;
  }
  if (stretch_value == kSemiExpandedWidthValue) {
    value_id = CSSValueID::kSemiExpanded;
  }
  if (stretch_value == kExpandedWidthValue) {
    value_id = CSSValueID::kExpanded;
  }
  if (stretch_value == kExtraExpandedWidthValue) {
    value_id = CSSValueID::kExtraExpanded;
  }
  if (stretch_value == kUltraExpandedWidthValue) {
    value_id = CSSValueID::kUltraExpanded;
  }

  if (IsValidCSSValueID(value_id)) {
    return CSSIdentifierValue::Create(value_id);
  }
  return nullptr;
}

CSSValue* ComputedStyleUtils::ValueForFontVariantEastAsian(
    const ComputedStyle& style) {
  FontVariantEastAsian east_asian =
      style.GetFontDescription().VariantEastAsian();
  if (east_asian.IsAllNormal()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  CSSValueList* value_list = CSSValueList::CreateSpaceSeparated();
  switch (east_asian.Form()) {
    case FontVariantEastAsian::kNormalForm:
      break;
    case FontVariantEastAsian::kJis78:
      value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kJis78));
      break;
    case FontVariantEastAsian::kJis83:
      value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kJis83));
      break;
    case FontVariantEastAsian::kJis90:
      value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kJis90));
      break;
    case FontVariantEastAsian::kJis04:
      value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kJis04));
      break;
    case FontVariantEastAsian::kSimplified:
      value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kSimplified));
      break;
    case FontVariantEastAsian::kTraditional:
      value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kTraditional));
      break;
    default:
      NOTREACHED();
  }
  switch (east_asian.Width()) {
    case FontVariantEastAsian::kNormalWidth:
      break;
    case FontVariantEastAsian::kFullWidth:
      value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kFullWidth));
      break;
    case FontVariantEastAsian::kProportionalWidth:
      value_list->Append(
          *CSSIdentifierValue::Create(CSSValueID::kProportionalWidth));
      break;
    default:
      NOTREACHED();
  }
  if (east_asian.Ruby()) {
    value_list->Append(*CSSIdentifierValue::Create(CSSValueID::kRuby));
  }
  return value_list;
}

CSSValue* ComputedStyleUtils::ValueForFontFeatureSettings(
    const ComputedStyle& style) {
  const blink::FontFeatureSettings* feature_settings =
      style.GetFontDescription().FeatureSettings();
  if (!feature_settings || !feature_settings->size()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (wtf_size_t i = 0; i < feature_settings->size(); ++i) {
    const FontFeature& feature = feature_settings->at(i);
    auto* feature_value = MakeGarbageCollected<cssvalue::CSSFontFeatureValue>(
        feature.TagString(), feature.Value());
    list->Append(*feature_value);
  }
  return list;
}

CSSValue* ComputedStyleUtils::ValueForFontVariationSettings(
    const ComputedStyle& style) {
  const blink::FontVariationSettings* variation_settings =
      style.GetFontDescription().VariationSettings();
  if (!variation_settings || !variation_settings->size()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (wtf_size_t i = 0; i < variation_settings->size(); ++i) {
    const FontVariationAxis& variation_axis = variation_settings->at(i);
    cssvalue::CSSFontVariationValue* variation_value =
        MakeGarbageCollected<cssvalue::CSSFontVariationValue>(
            variation_axis.TagString(), variation_axis.Value());
    list->Append(*variation_value);
  }
  return list;
}

CSSValue* ComputedStyleUtils::ValueForFontPalette(const ComputedStyle& style) {
  const blink::FontPalette* palette =
      style.GetFontDescription().GetFontPalette();

  if (!palette) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  return ConvertFontPaletteToCSSValue(palette);
}

CSSValue* ComputedStyleUtils::ValueForFont(const ComputedStyle& style) {
  auto AppendIfNotNormal = [](CSSValueList* list, const CSSValue& value) {
    auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
    if (identifier_value &&
        identifier_value->GetValueID() == CSSValueID::kNormal) {
      return;
    }

    list->Append(value);
  };

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();

  AppendIfNotNormal(list, *ValueForFontStyle(style));

  // Check that non-initial font-variant subproperties are not conflicting with
  // this serialization.
  CSSValue* ligatures_value = ValueForFontVariantLigatures(style);
  CSSValue* numeric_value = ValueForFontVariantNumeric(style);
  CSSValue* east_asian_value = ValueForFontVariantEastAsian(style);
  CSSValue* feature_settings = ValueForFontFeatureSettings(style);
  CSSValue* variation_settings = ValueForFontVariationSettings(style);
  CSSValue* variant_alternative = ValueForFontVariantAlternates(style);
  // FIXME: Use DataEquivalent<CSSValue>(...) once http://crbug.com/729447 is
  // resolved.
  if (!base::ValuesEquivalent(ligatures_value,
                              static_cast<CSSValue*>(CSSIdentifierValue::Create(
                                  CSSValueID::kNormal))) ||
      !base::ValuesEquivalent(numeric_value,
                              static_cast<CSSValue*>(CSSIdentifierValue::Create(
                                  CSSValueID::kNormal))) ||
      !base::ValuesEquivalent(east_asian_value,
                              static_cast<CSSValue*>(CSSIdentifierValue::Create(
                                  CSSValueID::kNormal))) ||
      !base::ValuesEquivalent(feature_settings,
                              static_cast<CSSValue*>(CSSIdentifierValue::Create(
                                  CSSValueID::kNormal))) ||
      !base::ValuesEquivalent(variation_settings,
                              static_cast<CSSValue*>(CSSIdentifierValue::Create(
                                  CSSValueID::kNormal))) ||
      !base::ValuesEquivalent(variant_alternative,
                              static_cast<CSSValue*>(CSSIdentifierValue::Create(
                                  CSSValueID::kNormal)))) {
    return nullptr;
  }

  FontDescription::Kerning kerning = style.GetFontDescription().GetKerning();
  FontDescription::FontVariantPosition variant_position =
      style.GetFontDescription().VariantPosition();
  FontVariantEmoji variant_emoji = style.GetFontDescription().VariantEmoji();
  OpticalSizing optical_sizing = style.GetFontDescription().FontOpticalSizing();

  if (kerning != FontDescription::kAutoKerning ||
      optical_sizing != kAutoOpticalSizing ||
      (RuntimeEnabledFeatures::CSSFontSizeAdjustEnabled() &&
       style.GetFontDescription().HasSizeAdjust()) ||
      variant_position != FontDescription::kNormalVariantPosition ||
      (RuntimeEnabledFeatures::FontVariantEmojiEnabled() &&
       variant_emoji != kNormalVariantEmoji)) {
    return nullptr;
  }

  if (!ValueForFontStretchAsKeyword(style)) {
    return nullptr;
  }

  CSSIdentifierValue* caps_value = ValueForFontVariantCaps(style);
  if (caps_value->GetValueID() != CSSValueID::kNormal &&
      caps_value->GetValueID() != CSSValueID::kSmallCaps) {
    return nullptr;
  }
  AppendIfNotNormal(list, *caps_value);

  {
    CSSNumericLiteralValue* font_weight = ValueForFontWeight(style);
    if (font_weight->DoubleValue() != kNormalWeightValue) {
      list->Append(*font_weight);
    }
  }

  AppendIfNotNormal(list, *ValueForFontStretchAsKeyword(style));

  {
    CSSValue* line_height = ValueForLineHeight(style);
    auto* identifier_line_height = DynamicTo<CSSIdentifierValue>(line_height);
    if (identifier_line_height &&
        identifier_line_height->GetValueID() == CSSValueID::kNormal) {
      list->Append(*ValueForFontSize(style));
    } else {
      // Add a slash between size and line-height.
      CSSValueList* size_and_line_height = CSSValueList::CreateSlashSeparated();
      size_and_line_height->Append(*ValueForFontSize(style));
      size_and_line_height->Append(*line_height);

      list->Append(*size_and_line_height);
    }
  }

  list->Append(*ValueForFontFamily(style));

  return list;
}

CSSValue* ComputedStyleUtils::SpecifiedValueForGridTrackSize(
    const GridTrackSize& track_size,
    const ComputedStyle& style) {
  switch (track_size.GetType()) {
    case kLengthTrackSizing:
      return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
          track_size.MinTrackBreadth(), style);
    case kMinMaxTrackSizing: {
      if (track_size.MinTrackBreadth().IsAuto() &&
          track_size.MaxTrackBreadth().IsFlex()) {
        return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
            track_size.MaxTrackBreadth(), style);
      }

      auto* min_max_track_breadths =
          MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kMinmax);
      min_max_track_breadths->Append(
          *ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
              track_size.MinTrackBreadth(), style));
      min_max_track_breadths->Append(
          *ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
              track_size.MaxTrackBreadth(), style));
      return min_max_track_breadths;
    }
    case kFitContentTrackSizing: {
      auto* fit_content_track_breadth =
          MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kFitContent);
      fit_content_track_breadth->Append(
          *ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
              track_size.FitContentTrackBreadth(), style));
      return fit_content_track_breadth;
    }
  }
  NOTREACHED();
}

enum class NamedLinesType { kNamedLines, kAutoRepeatNamedLines };
class OrderedNamedLinesCollector {
  STACK_ALLOCATED();

 public:
  OrderedNamedLinesCollector(
      const OrderedNamedGridLines& ordered_named_grid_lines,
      const OrderedNamedGridLines& ordered_named_auto_repeat_grid_lines,
      bool is_subgridded_track,
      bool is_layout_grid)
      : ordered_named_grid_lines_(ordered_named_grid_lines),
        ordered_named_auto_repeat_grid_lines_(
            ordered_named_auto_repeat_grid_lines),
        is_subgridded_axis_(is_subgridded_track),
        is_layout_grid_(is_layout_grid) {}
  OrderedNamedLinesCollector(const OrderedNamedLinesCollector&) = delete;
  OrderedNamedLinesCollector& operator=(const OrderedNamedLinesCollector&) =
      delete;
  virtual ~OrderedNamedLinesCollector() = default;

  bool IsEmpty() const {
    return ordered_named_grid_lines_.empty() &&
           ordered_named_auto_repeat_grid_lines_.empty();
  }
  bool IsSubgriddedAxis() const { return is_subgridded_axis_; }
  wtf_size_t
```