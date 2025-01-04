Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This file seems to be responsible for handling the parsing and computation of various CSS properties.

Here's a breakdown of the thought process to analyze the code and answer the user's request:

1. **Identify the core purpose:** The file name `longhands_custom.cc` and the surrounding context (parsing and computation of CSS values) strongly suggest this file defines how specific CSS longhand properties are handled within the Blink rendering engine.

2. **Analyze individual CSS properties:** Go through each CSS property defined in the code snippet. For each property, observe the following:
    * **`ParseSingleValue` function:** This function is responsible for taking the raw CSS token stream and converting it into a `CSSValue` object. It handles the syntax and allowed values for that property.
    * **`CSSValueFromComputedStyleInternal` function:** This function takes the computed style of an element and extracts the relevant CSS value for the property. It handles how the browser determines the final value of the property after applying all CSS rules.
    * **Helper functions:** Note any calls to functions like `css_parsing_utils::Consume...`, `ComputedStyleUtils::...`, and `ZoomAdjustedPixelValue...`. These point to shared utility functions for parsing and calculating CSS values.
    * **Special cases:** Look for conditional logic within the functions, especially for keywords like `auto`, `none`, and handling of different value types (lengths, percentages, identifiers).

3. **Relate to web technologies (HTML, CSS, JavaScript):**
    * **CSS:** The core purpose is directly related to CSS. The file deals with specific CSS properties.
    * **HTML:** These CSS properties are applied to HTML elements. The code uses `LayoutObject` which represents elements in the rendering tree.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, the resulting styles computed here affect how JavaScript interacts with the DOM (e.g., getting element styles).

4. **Provide examples:** For each property, think about how it's used in CSS and how it affects the rendered HTML. Illustrate with simple HTML and CSS snippets.

5. **Address logical reasoning (input/output):** For the parsing functions, consider different valid and invalid CSS values as input and what the expected output (a `CSSValue` object or `nullptr`) would be. For the computed style functions, the input is a `ComputedStyle` object, and the output is the specific `CSSValue` for the property.

6. **Identify common user errors:**  Think about mistakes developers might make when using these CSS properties in their stylesheets. Examples include incorrect units, invalid keywords, or misunderstanding how certain properties interact.

7. **Explain the debugging process:** Describe how a developer might end up examining this specific code. This usually involves inspecting element styles in the browser's developer tools and tracing the rendering process.

8. **Synthesize the functionality:**  Based on the analysis of individual properties, summarize the overall purpose of the file.

9. **Address the "part 8 of 13" instruction:**  Since this is part of a larger sequence, the final summary should focus on the specific properties handled in this segment and how they contribute to the overall CSS processing.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the C++ implementation details.
* **Correction:** Shift focus to the *purpose* of the code in the context of CSS and web development. Explain what each function *does* rather than *how* it does it (unless the "how" is crucial for understanding).
* **Initial thought:** Treat each property completely independently.
* **Correction:** Look for patterns and commonalities in the code (e.g., the use of `css_parsing_utils`). This helps in writing a more concise and organized explanation.
* **Initial thought:**  Overlook the connection to the rendering process.
* **Correction:** Explicitly mention how these properties influence the layout and rendering of HTML elements. The use of `LayoutObject` is a key indicator of this.

By following this structured approach, combining code analysis with knowledge of web technologies, and incorporating self-correction, it's possible to generate a comprehensive and helpful answer to the user's request.
这是 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 文件的第 8 部分，共 13 部分。从这段代码来看，它主要负责 **定义和实现了一系列 CSS 长属性 (longhand properties) 的解析和计算逻辑**。

具体来说，这段代码定义了多个 `CSSProperty` 类的子类，每个子类对应一个特定的 CSS 属性，例如 `MaxHeight`, `MaxWidth`, `MinHeight`, `MinWidth`, `MixBlendMode`, `ObjectFit`, `ObjectPosition`, `ObjectViewBox`, `OffsetAnchor`, `OffsetDistance`, `OffsetPath`, `OffsetPosition`, `OffsetRotate`, `Opacity`, `Order`, `OriginTrialTestProperty`, `Orphans`, `OutlineColor`, `AccentColor`, `OutlineOffset`, `OutlineStyle`, `OutlineWidth`, `OverflowAnchor`, `OverflowClipMargin`, `OverflowWrap`, `OverflowX`, `OverflowY`, `OverscrollBehaviorX`, `OverscrollBehaviorY`, `PaddingBlockEnd`, `PaddingBlockStart`, `PaddingBottom`, `PaddingInlineEnd`, `PaddingInlineStart`, `PaddingLeft`, `PaddingRight`, `PaddingTop`, `Page`, `ViewTransitionName` 等。

对于每个 CSS 属性，这段代码主要实现了以下功能：

1. **`ParseSingleValue`**:  负责解析 CSS 样式表中的属性值。它接收一个 `CSSParserTokenStream` (CSS 词法单元流) 和解析上下文，然后尝试将流中的 token 解析成该属性对应的 `CSSValue` 对象。
2. **`CSSValueFromComputedStyleInternal`**: 负责从 `ComputedStyle` 对象中提取该属性的计算值。`ComputedStyle` 包含了元素最终应用的样式信息。这个函数将计算后的值转换为相应的 `CSSValue` 对象。
3. **其他辅助函数**: 例如 `ColorIncludingFallback` (针对 `OutlineColor`)，以及 `ApplyInitial`, `ApplyInherit`, `ApplyValue` (针对 `OutlineStyle`, `OverflowX`, `OverflowY`) 等，用于处理属性的初始值、继承以及应用。
4. **`IsLayoutDependent`**:  部分属性（例如 `PaddingBottom`, `PaddingLeft`, `PaddingRight`, `PaddingTop`, `PaddingBlockEnd`, `PaddingBlockStart`, `PaddingInlineEnd`, `PaddingInlineStart`) 具有 `IsLayoutDependent` 函数，表示这些属性的值可能依赖于元素的布局信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这段代码直接对应于 CSS 语言中的各种属性。它定义了浏览器如何理解和处理这些 CSS 属性。
    * **例子:**  对于 `MaxWidth` 属性，`ParseSingleValue` 会解析像 `max-width: 100px;` 或 `max-width: 50%;` 这样的 CSS 声明。`CSSValueFromComputedStyleInternal` 则会在元素经过样式计算后，返回最终的 `max-width` 值，例如 `100px`。
* **HTML:**  这些 CSS 属性最终会应用到 HTML 元素上，控制元素的样式和布局。
    * **例子:**  HTML 中有一个 `<div>` 元素，应用了 CSS 规则 `max-height: 200px; overflow: auto;`。 当渲染这个 `<div>` 时，这段 C++ 代码会处理 `max-height` 属性的解析和计算，确保 `<div>` 的最大高度不超过 200px，并且当内容超出时显示滚动条（由 `overflow: auto;` 控制）。
* **JavaScript:**  JavaScript 可以通过 DOM API 获取和修改元素的样式。浏览器内部会使用这里定义的逻辑来计算和返回这些样式值。
    * **例子:**  JavaScript 代码 `element.style.maxWidth = '300px';` 会触发 Blink 引擎的 CSS 解析逻辑，其中就包括这段代码中 `MaxWidth::ParseSingleValue` 的调用。  而 `window.getComputedStyle(element).maxWidth` 则会调用 `MaxWidth::CSSValueFromComputedStyleInternal` 来获取计算后的 `max-width` 值。

**逻辑推理及假设输入与输出:**

假设用户设置了以下 CSS 样式：

```css
.container {
  max-height: none;
  min-width: auto;
  object-fit: cover;
  opacity: 0.5;
}
```

对于这段 CSS，相关属性的 `ParseSingleValue` 和 `CSSValueFromComputedStyleInternal` 的行为如下：

* **`MaxHeight::ParseSingleValue`:**
    * **假设输入:**  CSS token 流中包含 `none` 这个标识符。
    * **输出:**  返回一个表示 `none` 的 `CSSIdentifierValue` 对象。
* **`MaxHeight::CSSValueFromComputedStyleInternal`:**
    * **假设输入:**  `ComputedStyle` 对象中 `MaxHeight()` 返回一个 `Length` 对象，其 `IsNone()` 返回 true。
    * **输出:**  返回一个表示 `none` 的 `CSSIdentifierValue` 对象。
* **`MinWidth::ParseSingleValue`:**
    * **假设输入:**  CSS token 流中包含 `auto` 这个标识符。
    * **输出:**  返回一个表示 `auto` 的 `CSSIdentifierValue` 对象。
* **`MinWidth::CSSValueFromComputedStyleInternal`:**
    * **假设输入:**  `ComputedStyle` 对象中 `MinWidth()` 返回一个 `Length` 对象，其 `IsAuto()` 返回 true，并且 `value_phase` 是 `CSSValuePhase::kComputedValue`。
    * **输出:**  返回一个表示 `auto` 的 `CSSIdentifierValue` 对象。
* **`ObjectFit::CSSValueFromComputedStyleInternal`:**
    * **假设输入:** `ComputedStyle` 对象中 `GetObjectFit()` 返回 `EObjectFit::kCover`。
    * **输出:** 返回一个表示 `cover` 的 `CSSIdentifierValue` 对象。
* **`Opacity::ParseSingleValue`:**
    * **假设输入:** CSS token 流中包含 `0.5` 这个数字。
    * **输出:** 返回一个值为 0.5 的 `CSSNumericLiteralValue` 对象。
* **`Opacity::CSSValueFromComputedStyleInternal`:**
    * **假设输入:** `ComputedStyle` 对象中 `Opacity()` 返回 0.5。
    * **输出:** 返回一个值为 0.5 的 `CSSNumericLiteralValue` 对象。

**用户或编程常见的使用错误举例:**

* **单位错误:**  例如，将 `max-height` 设置为 `200` 而不是 `200px`，可能会导致解析失败或被浏览器忽略（取决于属性是否允许无单位的值）。 对应的 `ParseSingleValue` 函数可能会返回 `nullptr`。
* **拼写错误:**  将属性名拼写错误，例如 `max-heigt`，会导致浏览器无法识别该属性，这段代码中的任何函数都不会被调用处理这个错误的属性。
* **类型错误:**  为需要特定类型值的属性设置了错误类型的值，例如将 `opacity` 设置为 `solid`。 `Opacity::ParseSingleValue` 会尝试解析为一个表示透明度的数字，如果遇到 `solid` 这样的非数字值，会返回 `nullptr`。
* **理解 `auto` 的含义:** 误解 `min-width: auto;` 的作用。开发者可能认为 `auto` 会使元素宽度为 0，但实际上 `auto` 的含义取决于上下文。`MinWidth::CSSValueFromComputedStyleInternal` 会根据不同的 `value_phase` 返回不同的值，体现了 `auto` 的复杂性。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **开发者遇到一个与特定 CSS 属性相关的渲染或样式计算问题。** 例如，一个元素的 `max-height` 没有按预期工作。
2. **开发者使用浏览器开发者工具检查元素的 Computed Styles (计算样式)。**  他们可能会看到 `max-height` 的值不正确，或者根本没有应用。
3. **开发者怀疑是 CSS 规则解析或计算出了问题。**
4. **开发者可能会尝试在浏览器源代码中搜索与该 CSS 属性相关的代码。**  例如，搜索 "MaxHeight::ParseSingleValue" 或 "CSSValueFromComputedStyleInternal max-height"。
5. **通过搜索，开发者可能会定位到 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 文件，并找到处理 `MaxHeight` 属性的代码。**
6. **开发者可以仔细阅读 `ParseSingleValue` 函数，查看它是如何解析 CSS 值的，以及 `CSSValueFromComputedStyleInternal` 函数，了解计算值的来源和转换过程。**
7. **开发者可以设置断点或添加日志，来跟踪代码的执行流程，查看在解析和计算过程中，`CSSParserTokenStream` 的内容和 `ComputedStyle` 的状态。**  这有助于确定问题是出在 CSS 解析阶段还是样式计算阶段。

**功能归纳 (针对第 8 部分):**

这部分代码 (第 8 部分) 的主要功能是 **定义了大量与尺寸、视觉效果、定位、以及内外边距相关的 CSS 长属性的解析和计算逻辑**。它负责将 CSS 样式表中的声明转换为内部表示，并从计算后的样式信息中提取这些属性的最终值，为浏览器的渲染引擎提供必要的样式信息。 这部分涵盖了布局相关的属性 (例如 `max-height`, `min-width`, `padding`) 以及视觉效果属性 (例如 `opacity`, `object-fit`)，在元素的最终呈现中扮演着重要的角色。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共13部分，请归纳一下它的功能

"""
 LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Length& max_height = style.MaxHeight();
  if (max_height.IsNone()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(max_height, style);
}

const CSSValue* MaxInlineSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeMaxWidthOrHeight(stream, context);
}

const CSSValue* MaxWidth::ParseSingleValue(CSSParserTokenStream& stream,
                                           const CSSParserContext& context,
                                           const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeMaxWidthOrHeight(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow);
}

const CSSValue* MaxWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Length& max_width = style.MaxWidth();
  if (max_width.IsNone()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(max_width, style);
}

const CSSValue* MinBlockSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWidthOrHeight(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* MinHeight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWidthOrHeight(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow);
}

const CSSValue* MinHeight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.MinHeight().IsAuto()) {
    if (value_phase == CSSValuePhase::kComputedValue) {
      return CSSIdentifierValue::Create(CSSValueID::kAuto);
    }
    return ComputedStyleUtils::MinWidthOrMinHeightAuto(style);
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.MinHeight(),
                                                             style);
}

const CSSValue* MinInlineSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWidthOrHeight(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* MinWidth::ParseSingleValue(CSSParserTokenStream& stream,
                                           const CSSParserContext& context,
                                           const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWidthOrHeight(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow);
}

const CSSValue* MinWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.MinWidth().IsAuto()) {
    if (value_phase == CSSValuePhase::kComputedValue) {
      return CSSIdentifierValue::Create(CSSValueID::kAuto);
    }
    return ComputedStyleUtils::MinWidthOrMinHeightAuto(style);
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.MinWidth(),
                                                             style);
}

const CSSValue* MixBlendMode::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetBlendMode());
}

const CSSValue* ObjectFit::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetObjectFit());
}

const CSSValue* ObjectPosition::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumePosition(stream, context,
                         css_parsing_utils::UnitlessQuirk::kForbid,
                         std::optional<WebFeature>());
}

const CSSValue* ObjectPosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return MakeGarbageCollected<CSSValuePair>(
      ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
          style.ObjectPosition().X(), style),
      ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
          style.ObjectPosition().Y(), style),
      CSSValuePair::kKeepIdenticalValues);
}

const CSSValue* ObjectViewBox::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  auto* css_value = css_parsing_utils::ConsumeBasicShape(
      stream, context, css_parsing_utils::AllowPathValue::kForbid);

  if (!css_value || css_value->IsBasicShapeInsetValue() ||
      css_value->IsBasicShapeRectValue() ||
      css_value->IsBasicShapeXYWHValue()) {
    return css_value;
  }

  return nullptr;
}

const CSSValue* ObjectViewBox::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (auto* basic_shape = style.ObjectViewBox()) {
    return ValueForBasicShape(style, basic_shape);
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* OffsetAnchor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumePosition(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid,
      std::optional<WebFeature>());
}

const CSSValue* OffsetAnchor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPosition(style.OffsetAnchor(), style);
}

const CSSValue* OffsetDistance::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* OffsetDistance::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.OffsetDistance(), style);
}

const CSSValue* OffsetPath::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeOffsetPath(stream, context);
}

const CSSValue* OffsetPath::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const OffsetPathOperation* operation = style.OffsetPath();
  if (operation) {
    if (const auto* shape_operation =
            DynamicTo<ShapeOffsetPathOperation>(operation)) {
      CSSValueList* list = CSSValueList::CreateSpaceSeparated();
      CSSValue* shape =
          ValueForBasicShape(style, &shape_operation->GetBasicShape());
      list->Append(*shape);
      CoordBox coord_box = shape_operation->GetCoordBox();
      if (coord_box != CoordBox::kBorderBox) {
        list->Append(*CSSIdentifierValue::Create(coord_box));
      }
      return list;
    }
    if (const auto* coord_box_operation =
            DynamicTo<CoordBoxOffsetPathOperation>(operation)) {
      CSSValueList* list = CSSValueList::CreateSpaceSeparated();
      CoordBox coord_box = coord_box_operation->GetCoordBox();
      list->Append(*CSSIdentifierValue::Create(coord_box));
      return list;
    }
    const auto& reference_operation =
        To<ReferenceOffsetPathOperation>(*operation);
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    AtomicString url = reference_operation.Url();
    list->Append(*MakeGarbageCollected<cssvalue::CSSURIValue>(CSSUrlData(url)));
    CoordBox coord_box = reference_operation.GetCoordBox();
    if (coord_box != CoordBox::kBorderBox) {
      list->Append(*CSSIdentifierValue::Create(coord_box));
    }
    return list;
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* OffsetPosition::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  if (id == CSSValueID::kNormal) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  CSSValue* value = css_parsing_utils::ConsumePosition(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid,
      std::optional<WebFeature>());

  // Count when we receive a valid position other than 'auto'.
  if (value && value->IsValuePair()) {
    context.Count(WebFeature::kCSSOffsetInEffect);
  }
  return value;
}

const CSSValue* OffsetPosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPosition(style.OffsetPosition(), style);
}

const CSSValue* OffsetRotate::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeOffsetRotate(stream, context);
}

const CSSValue* OffsetRotate::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (style.OffsetRotate().type == OffsetRotationType::kAuto) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kAuto));
  }
  list->Append(*CSSNumericLiteralValue::Create(
      style.OffsetRotate().angle, CSSPrimitiveValue::UnitType::kDegrees));
  return list;
}

const CSSValue* Opacity::ParseSingleValue(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeAlphaValue(stream, context);
}

const CSSValue* Opacity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.Opacity(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* Order::ParseSingleValue(CSSParserTokenStream& stream,
                                        const CSSParserContext& context,
                                        const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeInteger(stream, context);
}

const CSSValue* Order::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.Order(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* OriginTrialTestProperty::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.OriginTrialTestProperty());
  ;
}

const CSSValue* Orphans::ParseSingleValue(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePositiveInteger(stream, context);
}

const CSSValue* Orphans::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.Orphans(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* OutlineColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // Allow the special focus color even in HTML Standard parsing mode.
  if (stream.Peek().Id() == CSSValueID::kWebkitFocusRingColor) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeColor(stream, context);
}

const CSSValue* AccentColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeColor(stream, context);
}

const CSSValue* AccentColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleAutoColor& auto_color = style.AccentColor();
  if (auto_color.IsAutoColor()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  return ComputedStyleUtils::ValueForStyleAutoColor(style, style.AccentColor(),
                                                    value_phase);
}

const blink::Color OutlineColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& outline_color = style.OutlineColor();
  if (style.ShouldForceColor(outline_color)) {
    return GetCSSPropertyInternalForcedOutlineColor().ColorIncludingFallback(
        false, style, is_current_color);
  }
  return outline_color.Resolve(style.GetCurrentColor(), style.UsedColorScheme(),
                               is_current_color);
}

const CSSValue* OutlineColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleColor& outline_color = style.OutlineColor();
  if (value_phase == CSSValuePhase::kResolvedValue &&
      style.ShouldForceColor(outline_color)) {
    return GetCSSPropertyInternalForcedOutlineColor().CSSValueFromComputedStyle(
        style, nullptr, allow_visited_style, value_phase);
  }
  return allow_visited_style
             ? cssvalue::CSSColor::Create(style.VisitedDependentColor(*this))
             : ComputedStyleUtils::CurrentColorOrValidColor(
                   style, outline_color, value_phase);
}

const CSSValue* OutlineOffset::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLength(stream, context,
                                          CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* OutlineOffset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.OutlineOffset(), style);
}

const CSSValue* OutlineStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.OutlineStyleIsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return CSSIdentifierValue::Create(style.OutlineStyle());
}

void OutlineStyle::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetOutlineStyleIsAuto(
      ComputedStyleInitialValues::InitialOutlineStyleIsAuto());
  builder.SetOutlineStyle(EBorderStyle::kNone);
}

void OutlineStyle::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetOutlineStyleIsAuto(state.ParentStyle()->OutlineStyleIsAuto());
  builder.SetOutlineStyle(state.ParentStyle()->OutlineStyle());
}

void OutlineStyle::ApplyValue(StyleResolverState& state,
                              const CSSValue& value,
                              ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  const auto& identifier_value = To<CSSIdentifierValue>(value);
  builder.SetOutlineStyleIsAuto(
      static_cast<bool>(identifier_value.ConvertTo<OutlineIsAuto>()));
  builder.SetOutlineStyle(identifier_value.ConvertTo<EBorderStyle>());
}

const CSSValue* OutlineWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLineWidth(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* OutlineWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.OutlineWidth(), style);
}

const CSSValue* OverflowAnchor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.OverflowAnchor());
}

const CSSValue* OverflowClipMargin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  auto* css_value_list = CSSValueList::CreateSpaceSeparated();

  if (!style.OverflowClipMargin()) {
    css_value_list->Append(
        *CSSPrimitiveValue::CreateFromLength(Length::Fixed(0), 1.f));
    return css_value_list;
  }

  if (style.OverflowClipMargin()->GetReferenceBox() ==
          StyleOverflowClipMargin::ReferenceBox::kPaddingBox &&
      style.OverflowClipMargin()->GetMargin() == LayoutUnit()) {
    css_value_list->Append(
        *CSSPrimitiveValue::CreateFromLength(Length::Fixed(0), 1.f));
    return css_value_list;
  }

  CSSValueID reference_box;
  switch (style.OverflowClipMargin()->GetReferenceBox()) {
    case StyleOverflowClipMargin::ReferenceBox::kBorderBox:
      reference_box = CSSValueID::kBorderBox;
      break;
    case StyleOverflowClipMargin::ReferenceBox::kContentBox:
      reference_box = CSSValueID::kContentBox;
      break;
    case StyleOverflowClipMargin::ReferenceBox::kPaddingBox:
      reference_box = CSSValueID::kPaddingBox;
      break;
  }

  if (reference_box != CSSValueID::kPaddingBox) {
    css_value_list->Append(*CSSIdentifierValue::Create(reference_box));
  }
  if (style.OverflowClipMargin()->GetMargin() != LayoutUnit()) {
    css_value_list->Append(*ZoomAdjustedPixelValue(
        style.OverflowClipMargin()->GetMargin(), style));
  }

  DCHECK_GT(css_value_list->length(), 0u);
  return css_value_list;
}

const CSSValue* OverflowClipMargin::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSPrimitiveValue* length;
  CSSIdentifierValue* reference_box;

  if (stream.Peek().GetType() != kIdentToken &&
      stream.Peek().GetType() != kDimensionToken) {
    return nullptr;
  }

  if (stream.Peek().GetType() == kIdentToken) {
    reference_box = css_parsing_utils::ConsumeVisualBox(stream);
    length = css_parsing_utils::ConsumeLength(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  } else {
    length = css_parsing_utils::ConsumeLength(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    reference_box = css_parsing_utils::ConsumeVisualBox(stream);
  }

  // At least one of |reference_box| and |length| must be provided.
  if (!reference_box && !length) {
    return nullptr;
  }

  if (reference_box && reference_box->GetValueID() == CSSValueID::kPaddingBox) {
    reference_box = nullptr;
    if (!length) {
      length = CSSPrimitiveValue::CreateFromLength(Length::Fixed(0), 1.f);
    }
  } else if (reference_box && length &&
             length->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue) {
    length = nullptr;
  }

  auto* css_value_list = CSSValueList::CreateSpaceSeparated();
  if (reference_box) {
    css_value_list->Append(*reference_box);
  }
  if (length) {
    css_value_list->Append(*length);
  }
  return css_value_list;
}

const CSSValue* OverflowWrap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.OverflowWrap());
}

const CSSValue* OverflowX::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.OverflowX());
}

void OverflowX::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetOverflowX(ComputedStyleInitialValues::InitialOverflowX());

  DCHECK_EQ(builder.OverflowX(), EOverflow::kVisible);
  builder.SetHasExplicitOverflowXVisible();
}

void OverflowX::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  auto parent_value = state.ParentStyle()->OverflowX();
  builder.SetOverflowX(parent_value);

  if (parent_value == EOverflow::kVisible) {
    builder.SetHasExplicitOverflowXVisible();
  }
}

void OverflowX::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  auto converted_value =
      To<CSSIdentifierValue>(value).ConvertTo<blink::EOverflow>();
  builder.SetOverflowX(converted_value);

  if (converted_value == EOverflow::kVisible) {
    builder.SetHasExplicitOverflowXVisible();
  }
}

const CSSValue* OverflowY::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.OverflowY());
}

void OverflowY::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetOverflowY(ComputedStyleInitialValues::InitialOverflowY());

  DCHECK_EQ(builder.OverflowY(), EOverflow::kVisible);
  builder.SetHasExplicitOverflowYVisible();
}

void OverflowY::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  auto parent_value = state.ParentStyle()->OverflowY();
  builder.SetOverflowY(parent_value);

  if (parent_value == EOverflow::kVisible) {
    builder.SetHasExplicitOverflowYVisible();
  }
}

void OverflowY::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  auto converted_value =
      To<CSSIdentifierValue>(value).ConvertTo<blink::EOverflow>();
  builder.SetOverflowY(converted_value);

  if (converted_value == EOverflow::kVisible) {
    builder.SetHasExplicitOverflowYVisible();
  }
}

const CSSValue* OverscrollBehaviorX::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.OverscrollBehaviorX());
}

const CSSValue* OverscrollBehaviorY::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.OverscrollBehaviorY());
}

bool PaddingBlockEnd::IsLayoutDependent(const ComputedStyle* style,
                                        LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* PaddingBlockEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative,
                                css_parsing_utils::UnitlessQuirk::kForbid);
}

bool PaddingBlockStart::IsLayoutDependent(const ComputedStyle* style,
                                          LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* PaddingBlockStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative,
                                css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* PaddingBottom::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kAllow, kCSSAnchorQueryTypesNone,
      css_parsing_utils::AllowCalcSize::kForbid);
}

bool PaddingBottom::IsLayoutDependent(const ComputedStyle* style,
                                      LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->PaddingBottom().IsFixed());
}

const CSSValue* PaddingBottom::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Length& padding_bottom = style.PaddingBottom();
  if (padding_bottom.IsFixed() || !layout_object || !layout_object->IsBox()) {
    return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(padding_bottom,
                                                               style);
  }
  return ZoomAdjustedPixelValue(
      To<LayoutBox>(layout_object)->ComputedCSSPaddingBottom(), style);
}

bool PaddingInlineEnd::IsLayoutDependent(const ComputedStyle* style,
                                         LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* PaddingInlineEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative,
                                css_parsing_utils::UnitlessQuirk::kForbid);
}

bool PaddingInlineStart::IsLayoutDependent(const ComputedStyle* style,
                                           LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* PaddingInlineStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative,
                                css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* PaddingLeft::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kAllow, kCSSAnchorQueryTypesNone,
      css_parsing_utils::AllowCalcSize::kForbid);
}

bool PaddingLeft::IsLayoutDependent(const ComputedStyle* style,
                                    LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->PaddingLeft().IsFixed());
}

const CSSValue* PaddingLeft::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Length& padding_left = style.PaddingLeft();
  if (padding_left.IsFixed() || !layout_object || !layout_object->IsBox()) {
    return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(padding_left,
                                                               style);
  }
  return ZoomAdjustedPixelValue(
      To<LayoutBox>(layout_object)->ComputedCSSPaddingLeft(), style);
}

const CSSValue* PaddingRight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kAllow, kCSSAnchorQueryTypesNone,
      css_parsing_utils::AllowCalcSize::kForbid);
}

bool PaddingRight::IsLayoutDependent(const ComputedStyle* style,
                                     LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->PaddingRight().IsFixed());
}

const CSSValue* PaddingRight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Length& padding_right = style.PaddingRight();
  if (padding_right.IsFixed() || !layout_object || !layout_object->IsBox()) {
    return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(padding_right,
                                                               style);
  }
  return ZoomAdjustedPixelValue(
      To<LayoutBox>(layout_object)->ComputedCSSPaddingRight(), style);
}

const CSSValue* PaddingTop::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kAllow, kCSSAnchorQueryTypesNone,
      css_parsing_utils::AllowCalcSize::kForbid);
}

bool PaddingTop::IsLayoutDependent(const ComputedStyle* style,
                                   LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->PaddingTop().IsFixed());
}

const CSSValue* PaddingTop::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Length& padding_top = style.PaddingTop();
  if (padding_top.IsFixed() || !layout_object || !layout_object->IsBox()) {
    return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(padding_top,
                                                               style);
  }
  return ZoomAdjustedPixelValue(
      To<LayoutBox>(layout_object)->ComputedCSSPaddingTop(), style);
}

const CSSValue* Page::ParseSingleValue(CSSParserTokenStream& stream,
                                       const CSSParserContext& context,
                                       const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeCustomIdent(stream, context);
}

const CSSValue* Page::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.Page().IsNull()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return MakeGarbageCollected<CSSCustomIdentValue>(style.Page());
}

const CSSValue* ViewTransitionName::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID:
"""


```