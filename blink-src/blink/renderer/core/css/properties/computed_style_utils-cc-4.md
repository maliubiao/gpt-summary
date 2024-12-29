Response:
My goal is to analyze the provided C++ code snippet and provide a comprehensive explanation of its functionality, its relationship with web technologies (JavaScript, HTML, CSS), potential use cases, debugging information, and a summary.

Here's a breakdown of my thought process:

1. **Identify the Core Purpose:** The filename `computed_style_utils.cc` and the function names like `ValueFor...` immediately suggest that this code is responsible for generating CSS values based on the computed style of an element. It seems to be converting internal representations of style properties into their corresponding CSS value representations.

2. **Examine Individual Functions:** I'll go through each function, trying to understand what specific CSS property or feature it handles.

    * **`ValueForBasicShape`:**  This looks like it handles the `clip-path` CSS property when using basic shapes. It takes a `ComputedStyle` and a `BasicShape` object and returns a `CSSValueList`. It also handles the optional `box` value.

    * **`ValueForBorderRadiusShorthand`:**  This clearly deals with the `border-radius` shorthand property. It breaks down the individual corner radii and combines them into the correct shorthand representation, handling cases where some radii are the same. The `show_horizontal_*` and `show_vertical_*` flags are key to understanding the logic for omitting redundant values.

    * **`StrokeDashArrayToCSSValueList`:** This converts an internal `SVGDashArray` (likely used for SVG `stroke-dasharray`) into a `CSSValueList` of lengths.

    * **`ValueForSVGPaint`:** This function handles SVG paint attributes like `fill` and `stroke`. It supports colors, `none`, `url`, `context-fill`, and `context-stroke`.

    * **`ValueForSVGResource`:** This seems to handle referencing SVG resources via URLs.

    * **`GetGapDecorationPropertyValue` and related functions:** These functions appear to be related to CSS grid and flexbox `gap` properties (specifically the `column-rule-*` equivalents initially and the newer `gap` syntax). The template usage suggests handling different types of gap values (like colors and lengths). The `RuntimeEnabledFeatures::CSSGapDecorationEnabled()` check is important for understanding feature rollout.

    * **`ValueForShadowData` and `ValueForShadowList`:** These handle `box-shadow` and `text-shadow`. They take `ShadowData` objects and convert them to `CSSShadowValue` objects, including handling the `inset` keyword and spread radius.

    * **`ValueForFilter`:** This function is responsible for generating CSS `filter` values. It iterates through `FilterOperations` and creates the corresponding CSS function values (like `grayscale`, `blur`, `drop-shadow`, etc.).

    * **`ValueForScrollSnapType` and `ValueForScrollSnapAlign`:** These handle the `scroll-snap-type` and `scroll-snap-align` CSS properties.

    * **`ValueForPageBreakBetween`, `ValueForWebkitColumnBreakBetween`, `ValueForPageBreakInside`, `ValueForWebkitColumnBreakInside`:** These handle the different flavors of page and column break properties, translating the more general `break-*` properties into their specific counterparts.

    * **`WidthOrHeightShouldReturnUsedValue`:** This function determines whether the *used* value (the actual rendered value) or the *computed* value should be returned for `width` and `height`. This highlights the distinction between these two value types in CSS.

    * **`ValuesForShorthandProperty` and other `ValuesFor...Shorthand` functions:** These are crucial for handling CSS shorthand properties. They take a `StylePropertyShorthand` object and extract the values of the constituent longhand properties to construct the shorthand value. Each shorthand function implements the specific logic for combining the longhand values (e.g., `border-radius`, `margin`, `padding`, `grid`, `grid-area`, `grid-line`, `grid-template`, `place-items`, `font-variant`). The logic often involves checking for identical values to shorten the output.

    * **`ValuesForFontVariantProperty`:** This is a more complex shorthand handler due to the nature of `font-variant`. It checks for the special "none" case and concatenates non-normal values.

3. **Identify Relationships with Web Technologies:**

    * **CSS:** The entire file is fundamentally about representing CSS values. The function names and the types of `CSSValue` objects being created directly link to CSS properties and their syntax.

    * **HTML:**  The computed style is associated with HTML elements. The functions operate on the `ComputedStyle` of an element, which is derived from the CSS applied to that element in the context of the HTML document.

    * **JavaScript:** While this specific code is C++, JavaScript interacts with these computed styles through the browser's DOM API (e.g., `getComputedStyle`). When JavaScript requests the computed style of an element, the browser internally uses logic similar to this code to format the CSS values.

4. **Infer Logical Reasoning (Hypothetical Inputs and Outputs):** For many functions, I can create simple examples:

    * **`ValueForBorderRadiusShorthand`:**
        * *Input:* `style.BorderTopLeftRadius() = (10px, 5px)`, `style.BorderTopRightRadius() = (20px, 5px)`, `style.BorderBottomRightRadius() = (20px, 10px)`, `style.BorderBottomLeftRadius() = (10px, 10px)`
        * *Output:* `10px 20px / 5px 10px`

    * **`ValueForShadowData`:**
        * *Input:* `shadow.X() = 5px`, `shadow.Y() = 5px`, `shadow.Blur() = 10px`, `shadow.Spread() = 2px`, `shadow.Style() = kNormal`, `shadow.GetColor() = red`
        * *Output:* `5px 5px 10px 2px red`

    * **`ValueForFilter`:**
        * *Input:* A `FilterOperations` object containing a grayscale operation with amount 0.5 and a blur operation with radius 3px.
        * *Output:* `grayscale(0.5) blur(3px)`

5. **Consider User/Programming Errors:**

    * **Incorrect CSS Syntax:** If the CSS used to style an element has syntax errors, the computed style might not be what the user expects, and these utility functions would reflect that (e.g., a misspelled property might default to its initial value).

    * **Overriding Styles:** Understanding CSS specificity and the cascade is crucial. A common error is expecting a style to apply when it's being overridden by a more specific rule. This code reflects the *computed* style after the cascade has been applied.

    * **JavaScript Interaction:** If JavaScript manipulates styles directly, it can lead to unexpected computed styles if the JavaScript logic is flawed.

6. **Trace User Operations (Debugging):**

    * A developer might be inspecting an element in the browser's DevTools and looking at the "Computed" tab to see the final styles applied to an element.
    * They might be using JavaScript with `getComputedStyle()` to retrieve style information for programmatic manipulation or analysis.
    * When a layout or rendering issue occurs, developers might step through the Blink rendering engine's code in a debugger, and this file could be part of the call stack when examining how computed styles are being determined and used.

7. **Synthesize the Summary:**  Combine the key findings into a concise description of the file's overall purpose.

By following these steps, I can systematically analyze the code and generate a comprehensive and informative response. The process involves code comprehension, understanding the underlying web technologies, inferring behavior, and considering practical usage and debugging scenarios.
这是第 5 部分，共 6 部分，我们来归纳一下 `blink/renderer/core/css/properties/computed_style_utils.cc` 的功能。

**总而言之，`computed_style_utils.cc` 的核心功能是提供一系列实用工具函数，用于将 `ComputedStyle` 对象中存储的各种 CSS 属性值转换为可以被浏览器或开发者理解和使用的 `CSSValue` 对象。**

**具体来说，它负责以下关键方面：**

* **将内部表示转换为 CSS 语法:** 它将 `ComputedStyle` 中以 C++ 数据结构表示的属性值（例如，长度、颜色、枚举值、形状数据等）转换成对应的 CSS 语法表示，即 `CSSValue` 及其子类的对象（例如 `CSSPrimitiveValue`, `CSSIdentifierValue`, `CSSValueList` 等）。

* **处理不同类型的 CSS 属性:**  它包含了针对各种不同类型 CSS 属性的转换逻辑，包括：
    * **基本类型:** 长度、颜色、数字、标识符等。
    * **复杂类型:**  边框半径、阴影、滤镜、变换、形状、渐变、网格轨道列表等。
    * **简写属性:**  将简写属性拆解并组合成长写属性的值，并以正确的 CSS 语法表示。

* **考虑上下文和依赖关系:** 在转换过程中，它会考虑某些属性之间的依赖关系以及渲染上下文，例如：
    * 缩放调整 (`ZoomAdjustedPixelValue`)。
    * 是否需要展示简写属性的所有组成部分。
    * 网格布局中不同属性之间的依赖关系。

* **生成用于显示的 CSS 值:** 生成的 `CSSValue` 对象可以用于：
    * **开发者工具显示:**  在浏览器的开发者工具中展示元素的计算样式。
    * **JavaScript API (getComputedStyle):**  通过 JavaScript 获取元素的计算样式。
    * **渲染引擎内部使用:**  供渲染引擎的其他部分使用，例如布局和绘制阶段。

**作为第 5 部分，我们可以推断出之前的部分可能涵盖了以下内容：**

* **第 1-4 部分:**  可能已经介绍了 `computed_style_utils.cc` 中一部分功能的实现，例如：
    * 针对基本类型属性的转换函数。
    * 针对特定复杂属性（如颜色、长度等）的转换函数。
    * 一些简单的简写属性的处理。

**而接下来的第 6 部分可能包含：**

* **剩余的简写属性处理:** 可能会涵盖更复杂的简写属性，或者是一些尚未涉及到的属性类型。
* **一些辅助或工具函数:** 可能会有一些通用的辅助函数，用于创建或操作 `CSSValue` 对象。
* **与性能或优化的相关内容:** 虽然这个代码片段本身没有明显的性能优化，但后续部分可能会涉及相关内容。

**总结来说，`computed_style_utils.cc` 是 Blink 渲染引擎中一个至关重要的组成部分，它充当了内部样式表示和外部 CSS 语法之间的桥梁，使得浏览器能够正确地展示和开发者能够方便地理解元素的样式信息。**

Prompt: 
```
这是目录为blink/renderer/core/css/properties/computed_style_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
:kShape);

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*ValueForBasicShape(style, shape_value->Shape()));
  if (shape_value->CssBox() != CSSBoxType::kMissing) {
    list->Append(*CSSIdentifierValue::Create(shape_value->CssBox()));
  }
  return list;
}

CSSValueList* ComputedStyleUtils::ValueForBorderRadiusShorthand(
    const ComputedStyle& style) {
  CSSValueList* list = CSSValueList::CreateSlashSeparated();

  bool show_horizontal_bottom_left = style.BorderTopRightRadius().Width() !=
                                     style.BorderBottomLeftRadius().Width();
  bool show_horizontal_bottom_right =
      show_horizontal_bottom_left || (style.BorderBottomRightRadius().Width() !=
                                      style.BorderTopLeftRadius().Width());
  bool show_horizontal_top_right =
      show_horizontal_bottom_right || (style.BorderTopRightRadius().Width() !=
                                       style.BorderTopLeftRadius().Width());

  bool show_vertical_bottom_left = style.BorderTopRightRadius().Height() !=
                                   style.BorderBottomLeftRadius().Height();
  bool show_vertical_bottom_right =
      show_vertical_bottom_left || (style.BorderBottomRightRadius().Height() !=
                                    style.BorderTopLeftRadius().Height());
  bool show_vertical_top_right =
      show_vertical_bottom_right || (style.BorderTopRightRadius().Height() !=
                                     style.BorderTopLeftRadius().Height());

  CSSValueList* top_left_radius =
      ValuesForBorderRadiusCorner(style.BorderTopLeftRadius(), style);
  CSSValueList* top_right_radius =
      ValuesForBorderRadiusCorner(style.BorderTopRightRadius(), style);
  CSSValueList* bottom_right_radius =
      ValuesForBorderRadiusCorner(style.BorderBottomRightRadius(), style);
  CSSValueList* bottom_left_radius =
      ValuesForBorderRadiusCorner(style.BorderBottomLeftRadius(), style);

  CSSValueList* horizontal_radii = CSSValueList::CreateSpaceSeparated();
  horizontal_radii->Append(top_left_radius->Item(0));
  if (show_horizontal_top_right) {
    horizontal_radii->Append(top_right_radius->Item(0));
  }
  if (show_horizontal_bottom_right) {
    horizontal_radii->Append(bottom_right_radius->Item(0));
  }
  if (show_horizontal_bottom_left) {
    horizontal_radii->Append(bottom_left_radius->Item(0));
  }

  list->Append(*horizontal_radii);

  CSSValueList* vertical_radii = CSSValueList::CreateSpaceSeparated();
  vertical_radii->Append(top_left_radius->Item(1));
  if (show_vertical_top_right) {
    vertical_radii->Append(top_right_radius->Item(1));
  }
  if (show_vertical_bottom_right) {
    vertical_radii->Append(bottom_right_radius->Item(1));
  }
  if (show_vertical_bottom_left) {
    vertical_radii->Append(bottom_left_radius->Item(1));
  }

  if (!vertical_radii->Equals(To<CSSValueList>(list->Item(0)))) {
    list->Append(*vertical_radii);
  }

  return list;
}

CSSValue* ComputedStyleUtils::StrokeDashArrayToCSSValueList(
    const SVGDashArray& dashes,
    const ComputedStyle& style) {
  if (dashes.data.empty()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const Length& dash_length : dashes.data) {
    list->Append(*ZoomAdjustedPixelValueForLength(dash_length, style));
  }

  return list;
}

const CSSValue* ComputedStyleUtils::ValueForSVGPaint(
    const SVGPaint& paint,
    const ComputedStyle& style) {
  switch (paint.type) {
    case SVGPaintType::kColor:
      return CurrentColorOrValidColor(style, paint.GetColor(),
                                      CSSValuePhase::kComputedValue);
    case SVGPaintType::kNone:
      return CSSIdentifierValue::Create(CSSValueID::kNone);
    case SVGPaintType::kUriNone:
    case SVGPaintType::kUriColor: {
      CSSValueList* values = CSSValueList::CreateSpaceSeparated();
      values->Append(*MakeGarbageCollected<cssvalue::CSSURIValue>(
          CSSUrlData(paint.GetUrl())));
      values->Append(
          paint.type == SVGPaintType::kUriNone
              ? *CSSIdentifierValue::Create(CSSValueID::kNone)
              : *CurrentColorOrValidColor(style, paint.GetColor(),
                                          CSSValuePhase::kComputedValue));
      return values;
    }
    case SVGPaintType::kUri:
      return MakeGarbageCollected<cssvalue::CSSURIValue>(
          CSSUrlData(paint.GetUrl()));
    case SVGPaintType::kContextFill:
      return CSSIdentifierValue::Create(CSSValueID::kContextFill);
    case SVGPaintType::kContextStroke:
      return CSSIdentifierValue::Create(CSSValueID::kContextStroke);
  }
}

CSSValue* ComputedStyleUtils::ValueForSVGResource(
    const StyleSVGResource* resource) {
  if (resource) {
    return MakeGarbageCollected<cssvalue::CSSURIValue>(
        CSSUrlData(resource->Url()));
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

namespace {

template <typename T>
const CSSValue* GetGapDecorationPropertyValue(const T& value,
                                              const ComputedStyle& style,
                                              CSSValuePhase value_phase);

template <>
const CSSValue* GetGapDecorationPropertyValue(const StyleColor& value,
                                              const ComputedStyle& style,
                                              CSSValuePhase value_phase) {
  return ComputedStyleUtils::CurrentColorOrValidColor(style, value,
                                                      value_phase);
}

template <>
const CSSValue* GetGapDecorationPropertyValue(const int& value,
                                              const ComputedStyle& style,
                                              CSSValuePhase value_phase) {
  return ZoomAdjustedPixelValue(value, style);
}

template <typename T>
void PopulateNonRepeaterGapData(CSSValueList* list,
                                const GapData<T>& gap_data,
                                const ComputedStyle& style,
                                CSSValuePhase value_phase) {
  const CSSValue* value =
      GetGapDecorationPropertyValue(gap_data.GetValue(), style, value_phase);
  list->Append(*value);
}

template <typename T>
void PopulateRepeaterGapData(CSSValueList* list,
                             const GapData<T>& gap_data,
                             const ComputedStyle& style,
                             CSSValuePhase value_phase) {
  CSSPrimitiveValue* repetitions = nullptr;

  if (!gap_data.GetValueRepeater()->IsAutoRepeater()) {
    repetitions = CSSNumericLiteralValue::Create(
        gap_data.GetValueRepeater()->RepeatCount(),
        CSSPrimitiveValue::UnitType::kNumber);
  }

  CSSValueList* repeated_values = CSSValueList::CreateSpaceSeparated();

  for (const auto& value : gap_data.GetValueRepeater()->RepeatedValues()) {
    const CSSValue* css_value =
        GetGapDecorationPropertyValue(value, style, value_phase);
    repeated_values->Append(*css_value);
  }

  CSSValue* repeater_value = MakeGarbageCollected<cssvalue::CSSRepeatValue>(
      repetitions, *repeated_values);

  list->Append(*repeater_value);
}

template <typename T>
const CSSValue* ValueForGapDecorationPropertyDataList(
    const GapDataList<T>& gap_color_list,
    const ComputedStyle& style,
    CSSValuePhase value_phase) {
  // The CSS Gap Decorations API [1] can take more than one value. When
  // that feature is enabled, create a space separated list to hold the
  // values. Otherwise, return a single value, as is supported in
  // the legacy `column-rule-*` property.
  // [1]: https://chromestatus.com/feature/5157805733183488
  if (!RuntimeEnabledFeatures::CSSGapDecorationEnabled()) {
    return GetGapDecorationPropertyValue(gap_color_list.GetLegacyValue(), style,
                                         value_phase);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();

  for (const auto& gap_data : gap_color_list.GetGapDataList()) {
    if (gap_data.IsRepeaterData()) {
      PopulateRepeaterGapData(list, gap_data, style, value_phase);
    } else {
      PopulateNonRepeaterGapData(list, gap_data, style, value_phase);
    }
  }
  return list;
}
}  // namespace

const CSSValue* ComputedStyleUtils::ValueForGapDecorationColorDataList(
    const GapDataList<StyleColor>& gap_color_list,
    const ComputedStyle& style,
    CSSValuePhase value_phase) {
  return ValueForGapDecorationPropertyDataList(gap_color_list, style,
                                               value_phase);
}

const CSSValue* ComputedStyleUtils::ValueForGapDecorationWidthDataList(
    const GapDataList<int>& gap_width_list,
    const ComputedStyle& style,
    CSSValuePhase value_phase) {
  return ValueForGapDecorationPropertyDataList(gap_width_list, style,
                                               value_phase);
}

CSSValue* ComputedStyleUtils::ValueForShadowData(const ShadowData& shadow,
                                                 const ComputedStyle& style,
                                                 bool use_spread,
                                                 CSSValuePhase value_phase) {
  CSSPrimitiveValue* x = ZoomAdjustedPixelValue(shadow.X(), style);
  CSSPrimitiveValue* y = ZoomAdjustedPixelValue(shadow.Y(), style);
  CSSPrimitiveValue* blur = ZoomAdjustedPixelValue(shadow.Blur(), style);
  CSSPrimitiveValue* spread =
      use_spread ? ZoomAdjustedPixelValue(shadow.Spread(), style) : nullptr;
  CSSIdentifierValue* shadow_style =
      shadow.Style() == ShadowStyle::kNormal
          ? nullptr
          : CSSIdentifierValue::Create(CSSValueID::kInset);
  const CSSValue* color =
      CurrentColorOrValidColor(style, shadow.GetColor(), value_phase);
  return MakeGarbageCollected<CSSShadowValue>(x, y, blur, spread, shadow_style,
                                              color);
}

CSSValue* ComputedStyleUtils::ValueForShadowList(const ShadowList* shadow_list,
                                                 const ComputedStyle& style,
                                                 bool use_spread,
                                                 CSSValuePhase value_phase) {
  if (!shadow_list) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  wtf_size_t shadow_count = shadow_list->Shadows().size();
  for (wtf_size_t i = 0; i < shadow_count; ++i) {
    list->Append(*ValueForShadowData(shadow_list->Shadows()[i], style,
                                     use_spread, value_phase));
  }
  return list;
}

CSSValue* ComputedStyleUtils::ValueForFilter(
    const ComputedStyle& style,
    const FilterOperations& filter_operations) {
  if (filter_operations.Operations().empty()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();

  CSSFunctionValue* filter_value = nullptr;

  for (const auto& operation : filter_operations.Operations()) {
    FilterOperation* filter_operation = operation.Get();
    switch (filter_operation->GetType()) {
      case FilterOperation::OperationType::kReference:
        list->Append(*MakeGarbageCollected<cssvalue::CSSURIValue>(
            CSSUrlData(AtomicString(
                To<ReferenceFilterOperation>(filter_operation)->Url()))));
        continue;
      case FilterOperation::OperationType::kGrayscale:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kGrayscale);
        filter_value->Append(*CSSNumericLiteralValue::Create(
            To<BasicColorMatrixFilterOperation>(filter_operation)->Amount(),
            CSSPrimitiveValue::UnitType::kNumber));
        break;
      case FilterOperation::OperationType::kSepia:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kSepia);
        filter_value->Append(*CSSNumericLiteralValue::Create(
            To<BasicColorMatrixFilterOperation>(filter_operation)->Amount(),
            CSSPrimitiveValue::UnitType::kNumber));
        break;
      case FilterOperation::OperationType::kSaturate:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kSaturate);
        filter_value->Append(*CSSNumericLiteralValue::Create(
            To<BasicColorMatrixFilterOperation>(filter_operation)->Amount(),
            CSSPrimitiveValue::UnitType::kNumber));
        break;
      case FilterOperation::OperationType::kHueRotate:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kHueRotate);
        filter_value->Append(*CSSNumericLiteralValue::Create(
            To<BasicColorMatrixFilterOperation>(filter_operation)->Amount(),
            CSSPrimitiveValue::UnitType::kDegrees));
        break;
      case FilterOperation::OperationType::kInvert:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kInvert);
        filter_value->Append(*CSSNumericLiteralValue::Create(
            To<BasicComponentTransferFilterOperation>(filter_operation)
                ->Amount(),
            CSSPrimitiveValue::UnitType::kNumber));
        break;
      case FilterOperation::OperationType::kOpacity:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kOpacity);
        filter_value->Append(*CSSNumericLiteralValue::Create(
            To<BasicComponentTransferFilterOperation>(filter_operation)
                ->Amount(),
            CSSPrimitiveValue::UnitType::kNumber));
        break;
      case FilterOperation::OperationType::kBrightness:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kBrightness);
        filter_value->Append(*CSSNumericLiteralValue::Create(
            To<BasicComponentTransferFilterOperation>(filter_operation)
                ->Amount(),
            CSSPrimitiveValue::UnitType::kNumber));
        break;
      case FilterOperation::OperationType::kContrast:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kContrast);
        filter_value->Append(*CSSNumericLiteralValue::Create(
            To<BasicComponentTransferFilterOperation>(filter_operation)
                ->Amount(),
            CSSPrimitiveValue::UnitType::kNumber));
        break;
      case FilterOperation::OperationType::kBlur:
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kBlur);
        filter_value->Append(*ZoomAdjustedPixelValue(
            To<BlurFilterOperation>(filter_operation)->StdDeviation().Value(),
            style));
        break;
      case FilterOperation::OperationType::kDropShadow: {
        const auto& drop_shadow_operation =
            To<DropShadowFilterOperation>(*filter_operation);
        filter_value =
            MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kDropShadow);
        // We want our computed style to look like that of a text shadow (has
        // neither spread nor inset style).
        filter_value->Append(
            *ValueForShadowData(drop_shadow_operation.Shadow(), style, false,
                                CSSValuePhase::kComputedValue));
        break;
      }
      default:
        NOTREACHED();
    }
    list->Append(*filter_value);
  }

  return list;
}

CSSValue* ComputedStyleUtils::ValueForScrollSnapType(
    const cc::ScrollSnapType& type,
    const ComputedStyle& style) {
  if (!type.is_none) {
    if (type.strictness == cc::SnapStrictness::kProximity) {
      return CSSIdentifierValue::Create(type.axis);
    }
    return MakeGarbageCollected<CSSValuePair>(
        CSSIdentifierValue::Create(type.axis),
        CSSIdentifierValue::Create(type.strictness),
        CSSValuePair::kDropIdenticalValues);
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

CSSValue* ComputedStyleUtils::ValueForScrollSnapAlign(
    const cc::ScrollSnapAlign& align,
    const ComputedStyle& style) {
  return MakeGarbageCollected<CSSValuePair>(
      CSSIdentifierValue::Create(align.alignment_block),
      CSSIdentifierValue::Create(align.alignment_inline),
      CSSValuePair::kDropIdenticalValues);
}

// Returns a suitable value for the page-break-(before|after) property, given
// the computed value of the more general break-(before|after) property.
CSSValue* ComputedStyleUtils::ValueForPageBreakBetween(
    EBreakBetween break_value) {
  switch (break_value) {
    case EBreakBetween::kAvoidColumn:
    case EBreakBetween::kColumn:
    case EBreakBetween::kRecto:
    case EBreakBetween::kVerso:
    case EBreakBetween::kAvoidPage:
      return nullptr;
    case EBreakBetween::kPage:
      return CSSIdentifierValue::Create(CSSValueID::kAlways);
    default:
      return CSSIdentifierValue::Create(break_value);
  }
}

// Returns a suitable value for the -webkit-column-break-(before|after)
// property, given the computed value of the more general break-(before|after)
// property.
CSSValue* ComputedStyleUtils::ValueForWebkitColumnBreakBetween(
    EBreakBetween break_value) {
  switch (break_value) {
    case EBreakBetween::kAvoidPage:
    case EBreakBetween::kLeft:
    case EBreakBetween::kPage:
    case EBreakBetween::kRecto:
    case EBreakBetween::kRight:
    case EBreakBetween::kVerso:
      return nullptr;
    case EBreakBetween::kColumn:
      return CSSIdentifierValue::Create(CSSValueID::kAlways);
    case EBreakBetween::kAvoidColumn:
      return CSSIdentifierValue::Create(CSSValueID::kAvoid);
    default:
      return CSSIdentifierValue::Create(break_value);
  }
}

// Returns a suitable value for the page-break-inside property, given the
// computed value of the more general break-inside property.
CSSValue* ComputedStyleUtils::ValueForPageBreakInside(
    EBreakInside break_value) {
  switch (break_value) {
    case EBreakInside::kAvoidColumn:
      return nullptr;
    case EBreakInside::kAvoidPage:
      return CSSIdentifierValue::Create(CSSValueID::kAvoid);
    default:
      return CSSIdentifierValue::Create(break_value);
  }
}

// Returns a suitable value for the -webkit-column-break-inside property, given
// the computed value of the more general break-inside property.
CSSValue* ComputedStyleUtils::ValueForWebkitColumnBreakInside(
    EBreakInside break_value) {
  switch (break_value) {
    case EBreakInside::kAvoidPage:
      return nullptr;
    case EBreakInside::kAvoidColumn:
      return CSSIdentifierValue::Create(CSSValueID::kAvoid);
    default:
      return CSSIdentifierValue::Create(break_value);
  }
}

// https://drafts.csswg.org/cssom/#resolved-value
//
// For 'width' and 'height':
//
// If the property applies to the element or pseudo-element and the resolved
// value of the display property is not none or contents, then the resolved
// value is the used value. Otherwise the resolved value is the computed value
// (https://drafts.csswg.org/css-cascade-4/#computed-value).
//
// (Note that the computed value exists even when the property does not apply.)
bool ComputedStyleUtils::WidthOrHeightShouldReturnUsedValue(
    const LayoutObject* object) {
  // The display property is 'none'.
  if (!object) {
    return false;
  }
  // Non-root SVG objects return the resolved value except <image>,
  // <rect> and <foreignObject> which return the used value.
  if (object->IsSVGChild()) {
    return IsSVGObjectWithWidthAndHeight(*object);
  }
  // According to
  // http://www.w3.org/TR/CSS2/visudet.html#the-width-property and
  // http://www.w3.org/TR/CSS2/visudet.html#the-height-property, the "width" or
  // "height" property does not apply to non-atomic inline elements.
  return object->IsAtomicInlineLevel() || !object->IsInline();
}

CSSValueList* ComputedStyleUtils::ValuesForShorthandProperty(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  for (const CSSProperty* const longhand : shorthand.properties()) {
    const CSSValue* value = longhand->CSSValueFromComputedStyle(
        style, layout_object, allow_visited_style, value_phase);
    DCHECK(value);
    list->Append(*value);
  }
  return list;
}

CSSValuePair* ComputedStyleUtils::ValuesForGapShorthand(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  const CSSValue* row_gap_value =
      shorthand.properties()[0]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* column_gap_value =
      shorthand.properties()[1]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);

  return MakeGarbageCollected<CSSValuePair>(row_gap_value, column_gap_value,
                                            CSSValuePair::kDropIdenticalValues);
}

CSSValueList* ComputedStyleUtils::ValuesForGridShorthand(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  // Trailing non-initial values should be dropped.
  unsigned last_index = shorthand.length();
  // Work backwards to determine the final non-initial index. For grid
  // shorthands, we can drop all trailing `none` and `auto` values.
  for (; last_index > 1; --last_index) {
    const CSSValue* value =
        shorthand.properties()[last_index - 1]->CSSValueFromComputedStyle(
            style, layout_object, allow_visited_style, value_phase);
    if ((!IsA<CSSIdentifierValue>(value) ||
         (To<CSSIdentifierValue>(value)->GetValueID() != CSSValueID::kNone))) {
      break;
    }
  }

  CSSValueList* list = CSSValueList::CreateSlashSeparated();
  for (unsigned i = 0; i < last_index; ++i) {
    const CSSValue* value =
        shorthand.properties()[i]->CSSValueFromComputedStyle(
            style, layout_object, allow_visited_style, value_phase);
    DCHECK(value);
    list->Append(*value);
  }
  return list;
}

CSSValueList* ComputedStyleUtils::ValuesForGridAreaShorthand(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  DCHECK_EQ(shorthand.length(), 4u);

  const CSSValue* grid_row_start =
      shorthand.properties()[0]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* grid_column_start =
      shorthand.properties()[1]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* grid_row_end =
      shorthand.properties()[2]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* grid_column_end =
      shorthand.properties()[3]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);

  // `grid-row-end` depends on `grid-row-start`, and `grid-column-end` depends
  // on on `grid-column-start`, but what's not consistent is that
  // `grid-column-start` has a dependency on `grid-row-start`. For more details,
  // see https://www.w3.org/TR/css-grid-2/#placement-shorthands
  const bool include_column_start =
      CSSOMUtils::IncludeDependentGridLineEndValue(grid_row_start,
                                                   grid_column_start);
  const bool include_row_end = CSSOMUtils::IncludeDependentGridLineEndValue(
      grid_row_start, grid_row_end);
  const bool include_column_end = CSSOMUtils::IncludeDependentGridLineEndValue(
      grid_column_start, grid_column_end);

  CSSValueList* list = CSSValueList::CreateSlashSeparated();

  // `grid-row-start` is always included.
  list->Append(*grid_row_start);

  // If `IncludeDependentGridLineEndValue` returns true for a property,
  // all preceding values must be included.
  if (include_column_start || include_row_end || include_column_end) {
    list->Append(*grid_column_start);
  }
  if (include_row_end || include_column_end) {
    list->Append(*grid_row_end);
  }
  if (include_column_end) {
    list->Append(*grid_column_end);
  }

  return list;
}

CSSValueList* ComputedStyleUtils::ValuesForGridLineShorthand(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  DCHECK_EQ(shorthand.length(), 2u);

  const CSSValue* line_start =
      shorthand.properties()[0]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* line_end =
      shorthand.properties()[1]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  CSSValueList* list = CSSValueList::CreateSlashSeparated();

  // `grid-line-start` is always included.
  list->Append(*line_start);
  if (CSSOMUtils::IncludeDependentGridLineEndValue(line_start, line_end)) {
    list->Append(*line_end);
  }

  return list;
}

CSSValueList* ComputedStyleUtils::ValuesForGridTemplateShorthand(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  DCHECK_EQ(shorthand.length(), 3u);

  // "Note: In general, resolved values are the computed values, except for a
  // small list of legacy 2.1 properties. However, compatibility with early
  // implementations of this module requires us to define grid-template-rows and
  // grid-template-columns as returning used values."
  //
  // https://www.w3.org/TR/css-grid-2/#resolved-track-list-standalone
  //
  // For `grid-template`, this doesn't apply, so we shouldn't be returning used
  // values. The following method mostly mirrors
  // `StylePropertySerializer::GetShorthandValueForGridTemplate`, except it
  // produces a `CSSValueList` instead of a String.
  const CSSValue* template_rows_computed =
      ValueForGridTrackList(kForRows, layout_object, style,
                            /* force_computed_values */ true);
  const CSSValue* template_columns_computed =
      ValueForGridTrackList(kForColumns, layout_object, style,
                            /* force_computed_values */ true);

  const CSSValue* template_row_values =
      shorthand.properties()[0]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* template_column_values =
      shorthand.properties()[1]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* template_area_values =
      shorthand.properties()[2]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);

  // Implicit tracks will generate an empty list from `ValueForGridTrackList`,
  // as they don't create repeaters. In this case, they will already be
  // equivalent to the expected computed value (since implicit tracks don't
  // generate repeaters and are always fixed sizes). So in that case, we can
  // simply use the values directly from the shorthand.
  return CSSOMUtils::ComputedValueForGridTemplateShorthand(
      CSSOMUtils::IsEmptyValueList(template_rows_computed)
          ? template_row_values
          : template_rows_computed,
      CSSOMUtils::IsEmptyValueList(template_columns_computed)
          ? template_column_values
          : template_columns_computed,
      template_area_values);
}

CSSValueList* ComputedStyleUtils::ValuesForSidesShorthand(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  // Assume the properties are in the usual order top, right, bottom, left.
  const CSSValue* top_value =
      shorthand.properties()[0]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* right_value =
      shorthand.properties()[1]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* bottom_value =
      shorthand.properties()[2]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* left_value =
      shorthand.properties()[3]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);

  // All 4 properties must be specified.
  if (!top_value || !right_value || !bottom_value || !left_value) {
    return nullptr;
  }

  bool show_left = !base::ValuesEquivalent(right_value, left_value);
  bool show_bottom =
      !base::ValuesEquivalent(top_value, bottom_value) || show_left;
  bool show_right =
      !base::ValuesEquivalent(top_value, right_value) || show_bottom;

  list->Append(*top_value);
  if (show_right) {
    list->Append(*right_value);
  }
  if (show_bottom) {
    list->Append(*bottom_value);
  }
  if (show_left) {
    list->Append(*left_value);
  }

  return list;
}

CSSValuePair* ComputedStyleUtils::ValuesForInlineBlockShorthand(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  const CSSValue* start_value =
      shorthand.properties()[0]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* end_value =
      shorthand.properties()[1]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  // Both properties must be specified.
  if (!start_value || !end_value) {
    return nullptr;
  }

  auto* pair = MakeGarbageCollected<CSSValuePair>(
      start_value, end_value, CSSValuePair::kDropIdenticalValues);
  return pair;
}

CSSValuePair* ComputedStyleUtils::ValuesForPlaceShorthand(
    const StylePropertyShorthand& shorthand,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  const CSSValue* align_value =
      shorthand.properties()[0]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* justify_value =
      shorthand.properties()[1]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);

  return MakeGarbageCollected<CSSValuePair>(align_value, justify_value,
                                            CSSValuePair::kDropIdenticalValues);
}

static CSSValue* ExpandNoneLigaturesValue() {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kNoCommonLigatures));
  list->Append(
      *CSSIdentifierValue::Create(CSSValueID::kNoDiscretionaryLigatures));
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kNoHistoricalLigatures));
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kNoContextual));
  return list;
}

CSSValue* ComputedStyleUtils::ValuesForFontVariantProperty(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  enum VariantShorthandCases {
    kAllNormal,
    kNoneLigatures,
    kConcatenateNonNormal,
    kEmptyString
  };
  StylePropertyShorthand shorthand = fontVariantShorthand();
  VariantShorthandCases shorthand_case = kAllNormal;
  for (const CSSProperty* const longhand : shorthand.properties()) {
    const CSSValue* value = longhand->CSSValueFromComputedStyle(
        style, layout_object, allow_visited_style, value_phase);

    auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
    if (shorthand_case == kAllNormal && identifier_value &&
        identifier_value->GetValueID() == CSSValueID::kNone &&
        longhand->IDEquals(CSSPropertyID::kFontVariantLigatures)) {
      shorthand_case = kNoneLigatures;
    } else if (!(identifier_value &&
                 identifier_value->GetValueID() == CSSValueID::kNormal)) {
      shorthand_case = shorthand_case == kNoneLigatures ? kEmptyString
                                                        : kConcatenateNonNormal;
      break;
    }
  }

  switch (shorthand_case) {
    case kAllNormal:
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    case kNoneLigatures:
      return CSSIdentifierValue::Create(CSSValueID::kNone);
    case kConcatenateNonNormal: {
      CSSValueList* list = CSSValueList::CreateSpaceSeparated();
      for (const CSSProperty* const longhand : shorthand.properties()) {
        const CSSValue* value = longhand
"""


```