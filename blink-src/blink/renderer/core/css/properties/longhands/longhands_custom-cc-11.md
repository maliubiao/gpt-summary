Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a description of the functionality of a specific Chromium source code file (`longhands_custom.cc`), its relationship to web technologies (JavaScript, HTML, CSS), examples of its usage, potential errors, debugging hints, and a summary of its function, considering it's part 12 of 13.

2. **High-Level Overview of the File:** I recognize that `longhands_custom.cc` is likely responsible for handling the parsing and computation of CSS *longhand* properties that don't fit into the standard, automatically generated property handling. The "custom" part suggests it deals with non-standard or vendor-prefixed properties.

3. **Break Down the Code by Function:** I will iterate through the provided code, examining each function definition. I'll pay attention to the function names and the operations performed within each.

4. **Identify Key Functionalities:**  Based on the function names and code, I can identify these core responsibilities:
    * **Parsing CSS Values:** Functions like `ParseSingleValue` clearly take a `CSSParserTokenStream` and attempt to convert it into a `CSSValue`. This is about interpreting the text of the CSS.
    * **Converting Computed Styles to CSS Values:** Functions like `CSSValueFromComputedStyleInternal` take a `ComputedStyle` object (the final, resolved style of an element) and generate a `CSSValue` representing that style. This is the reverse of parsing, going from internal representation to CSS syntax.
    * **Applying CSS Values to Styles:** Functions like `ApplyValue` (though less frequent in this snippet) take a parsed `CSSValue` and update the internal `StyleBuilder` state. This is the mechanism to set the style based on parsed input.
    * **Handling Specific CSS Properties:**  The class names (e.g., `Appearance`, `WebkitBorderImage`, `MaskClip`) directly correspond to CSS properties, either standard or vendor-prefixed.

5. **Relate to Web Technologies:**
    * **CSS:** This file is fundamentally about CSS. It deals with the syntax, interpretation, and application of CSS properties.
    * **HTML:** The CSS properties managed here are ultimately applied to HTML elements. The parsing and computation determine how those elements are rendered.
    * **JavaScript:** While this specific file doesn't directly involve JavaScript *execution*, JavaScript can *interact* with the styles defined by these properties. For example, JavaScript can get and set CSS properties using the DOM `style` interface or `getComputedStyle`.

6. **Provide Examples:** For each identified CSS property, I'll think of a simple HTML/CSS snippet that demonstrates its use. This will make the abstract code more concrete.

7. **Infer Logic and Provide Input/Output Examples:**  For `ParseSingleValue` functions, I can hypothesize CSS input and the expected `CSSValue` output. For `CSSValueFromComputedStyleInternal`, I can imagine a `ComputedStyle` and the corresponding CSS value.

8. **Identify Common Errors:** Based on the parsing logic (e.g., expecting specific types, ranges, or keywords), I can anticipate common user errors, such as incorrect syntax, invalid values, or using non-existent keywords.

9. **Outline Debugging Steps:** I'll consider how a developer might end up looking at this code. The typical scenario is investigating why a CSS property isn't working as expected. Tracing the parsing and application flow is key.

10. **Synthesize the Summary (Part 12 of 13):** Knowing this is near the end of a series, I'll emphasize that this file contributes to the *final stages* of CSS property handling, focusing on the conversion to and from computed styles, and likely complements other files dealing with parsing and initial value setup.

11. **Structure the Answer:**  I'll organize my thoughts into logical sections, addressing each part of the request clearly and concisely. Using headings and bullet points will improve readability.

12. **Refine and Review:** I will reread my answer to ensure accuracy, clarity, and completeness, making sure I've addressed all aspects of the prompt. I'll check for consistency and correct any technical inaccuracies. For instance, ensuring I clearly distinguish between parsing and converting from computed styles.

By following these steps, I can effectively analyze the provided code snippet and generate a comprehensive and informative answer that addresses all parts of the user's request.
好的，让我们来详细分析一下 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 这个文件的功能。

**文件功能概览**

这个文件 `longhands_custom.cc` 是 Chromium Blink 渲染引擎中处理 CSS **长属性 (longhand properties)** 的一部分。它的主要职责是为那些不能通过通用方法处理的**自定义的或特殊的 CSS 长属性**提供 **解析 (parsing)**、**计算值获取 (CSSValueFromComputedStyleInternal)** 和 **应用 (applying)** 的逻辑。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件直接参与了 CSS 的处理流程，因此与 HTML 和 JavaScript 都有着密切的关系：

* **CSS:**  这是最直接的关系。该文件中的代码负责解析和处理特定的 CSS 属性。例如，`WebkitBorderImage` 属性的解析逻辑就在这里定义。
    * **例子:**  假设你的 CSS 中有如下代码：
      ```css
      .my-element {
        -webkit-border-image: url(border.png) 15% round;
      }
      ```
      当浏览器解析这段 CSS 时，`WebkitBorderImage::ParseSingleValue` 函数会被调用，它会读取 `url(border.png) 15% round` 这个值，并将其转换为 Blink 内部表示的 `CSSValue` 对象。

* **HTML:** CSS 属性最终会应用到 HTML 元素上，以控制它们的样式和布局。
    * **例子:** 上面的 CSS 代码会影响所有 class 为 `my-element` 的 HTML 元素的边框样式。`WebkitBorderImage::ApplyValue` 函数会将解析后的 `CSSValue` 应用到与该 HTML 元素关联的样式对象上。

* **JavaScript:** JavaScript 可以通过 DOM API 来读取和修改 CSS 属性。
    * **例子:**  JavaScript 可以使用 `element.style.webkitBorderImage = 'url(new_border.png) 20% stretch';` 来修改元素的 `-webkit-border-image` 属性。当 JavaScript 设置这个属性时，Blink 引擎会再次调用相应的解析函数（如 `WebkitBorderImage::ParseSingleValue`）来处理新的值。
    * **例子:** JavaScript 可以使用 `window.getComputedStyle(element).webkitBorderImage` 来获取元素最终计算出的 `-webkit-border-image` 值。 这将触发 `WebkitBorderImage::CSSValueFromComputedStyleInternal` 函数，将内部表示的样式值转换为 CSS 文本形式。

**逻辑推理、假设输入与输出**

我们以 `WebkitBorderHorizontalSpacing::ParseSingleValue` 为例进行逻辑推理：

* **假设输入 (CSS):**  `5px`
* **逻辑:** `WebkitBorderHorizontalSpacing::ParseSingleValue` 函数会调用 `css_parsing_utils::ConsumeLength`，期望从输入流中解析出一个长度值。 它指定了 `CSSPrimitiveValue::ValueRange::kNonNegative`，表示这个长度值必须是非负数。
* **预期输出 (CSSValue):**  一个 `CSSPrimitiveValue` 对象，其值为 5，单位为像素 (px)。

再以 `WebkitBoxAlign::CSSValueFromComputedStyleInternal` 为例：

* **假设输入 (ComputedStyle):** 一个 `ComputedStyle` 对象，其 `BoxAlign()` 的值为 `STRETCH`。
* **逻辑:** `WebkitBoxAlign::CSSValueFromComputedStyleInternal` 函数会调用 `style.BoxAlign()` 获取计算后的 `BoxAlign` 值，并使用 `CSSIdentifierValue::Create()` 创建一个对应的 CSS 标识符值。
* **预期输出 (CSSValue):** 一个 `CSSIdentifierValue` 对象，其值为 `stretch`。

**用户或编程常见的使用错误举例**

* **`WebkitBorderHorizontalSpacing` 和 `WebkitBorderVerticalSpacing`:** 用户可能会尝试设置负值，例如 `-3px`。由于 `ParseSingleValue` 中指定了 `kNonNegative`，解析会失败，该属性会被视为无效值。
* **`WebkitBoxFlex` 和 `WebkitBoxOrdinalGroup`:**  用户可能会提供非数字值或者负数（对于 `WebkitBoxOrdinalGroup`）。解析函数会进行类型检查和范围检查，如果输入不符合要求，解析会失败。
* **`WebkitLineClamp`:** 用户可能会设置 `0` 作为行数。虽然 CSS 规范允许，但此处的实现会将 `0` 转换为 `none`。这可能导致用户困惑，因为他们预期的行为可能是不显示任何行，而实际效果是该属性被禁用。
* **`WebkitMaskBoxImageOutset`, `WebkitMaskBoxImageSlice`, `WebkitMaskBoxImageWidth`:** 这些属性涉及到图像边框的切割和偏移，如果用户提供的值不符合 `border-image` 相关的语法规则（例如，百分比相对于什么计算不明确，或者 `fill` 关键字使用错误），解析会出错。
* **`MaskClip` 和 `MaskOrigin`:**  用户可能会混淆不同的 box 值（例如，`content-box`, `padding-box`, `border-box`)，导致遮罩效果不符合预期。

**用户操作如何一步步到达这里 (调试线索)**

当开发者在编写或调试网页时遇到与上述 CSS 属性相关的问题时，可能会逐步追踪到这个文件：

1. **开发者编写 HTML 和 CSS 代码:**  在 CSS 中使用了例如 `-webkit-border-image` 或 `mask-clip` 等属性，并赋予了特定的值。
2. **浏览器加载和解析 HTML 和 CSS:**  Blink 引擎开始解析 CSS 文件。
3. **CSS 解析器遇到特定的长属性:** 当解析器遇到像 `-webkit-border-image` 这样的属性时，它会查找对应的处理函数。
4. **定位到 `longhands_custom.cc`:** 由于这些属性是自定义或特殊的，它们的解析逻辑很可能定义在 `longhands_custom.cc` 文件中。
5. **执行相应的解析函数:**  例如，对于 `-webkit-border-image: url(image.png) ...`,  `WebkitBorderImage::ParseSingleValue` 函数会被调用。
6. **计算样式:**  解析成功后，这些属性的值会被存储在元素的样式对象中。在布局和渲染阶段，会计算出这些属性的最终效果，可能会调用 `CSSValueFromComputedStyleInternal` 获取计算值。
7. **开发者发现问题并开始调试:**
    * 样式没有按预期生效。
    * 使用浏览器的开发者工具检查元素的计算样式，发现属性值不正确或被覆盖。
    * 可能设置断点在 CSS 解析相关的代码中，或者在 `longhands_custom.cc` 中与特定属性相关的函数上。
    * 逐步执行代码，查看 CSS 值的解析过程和应用过程。

**第 12 部分，共 13 部分，功能归纳**

考虑到这是 13 部分中的第 12 部分，可以推断 `longhands_custom.cc` 的功能集中在 **CSS 属性处理流程的后期阶段**，特别是：

* **处理那些不适合通用解析和计算逻辑的 CSS 长属性。** 这包括带有 `-webkit-` 前缀的实验性属性，以及行为比较特殊的标准属性。
* **提供从 CSS 语法到 Blink 内部 `CSSValue` 对象的转换逻辑 (解析)。**
* **提供从 Blink 内部计算后的样式 (`ComputedStyle`) 到 `CSSValue` 对象的转换逻辑，用于例如 `getComputedStyle` 的实现。**
* **提供将解析后的 `CSSValue` 应用到元素样式的逻辑。**

在整个 CSS 属性处理流程中，可能还存在其他文件负责：

* 定义 CSS 属性的 ID 和元数据。
* 处理通用的 CSS 属性解析逻辑。
* 管理样式的继承和层叠。
* 将最终的样式应用到渲染对象。

`longhands_custom.cc` 作为接近尾声的一部分，专注于那些需要特殊处理的属性，确保它们能够被正确地解析、计算和应用，最终影响页面的渲染效果。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共13部分，请归纳一下它的功能

"""
rn nullptr;
}

const CSSValue* Appearance::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Appearance());
}

const CSSValue* WebkitBorderHorizontalSpacing::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue*
WebkitBorderHorizontalSpacing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.HorizontalBorderSpacing(), style);
}

const CSSValue* WebkitBorderImage::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWebkitBorderImage(stream, context);
}

const CSSValue* WebkitBorderImage::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImage(
      style.BorderImage(), style, allow_visited_style, value_phase);
}

void WebkitBorderImage::ApplyValue(StyleResolverState& state,
                                   const CSSValue& value,
                                   ValueMode) const {
  NinePieceImage image;
  CSSToStyleMap::MapNinePieceImage(state, CSSPropertyID::kWebkitBorderImage,
                                   value, image);
  state.StyleBuilder().SetBorderImage(image);
}

const CSSValue* WebkitBorderVerticalSpacing::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* WebkitBorderVerticalSpacing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.VerticalBorderSpacing(), style);
}

const CSSValue* WebkitBoxAlign::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BoxAlign());
}

const CSSValue* WebkitBoxDecorationBreak::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return GetCSSPropertyBoxDecorationBreak().CSSValueFromComputedStyleInternal(
      style, layout_object, allow_visited_style, value_phase);
}

const CSSValue* WebkitBoxDirection::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BoxDirection());
}

const CSSValue* WebkitBoxFlex::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeNumber(stream, context,
                                          CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* WebkitBoxFlex::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.BoxFlex(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* WebkitBoxOrdinalGroup::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePositiveInteger(stream, context);
}

const CSSValue* WebkitBoxOrdinalGroup::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.BoxOrdinalGroup(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* WebkitBoxOrient::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BoxOrient());
}

const CSSValue* WebkitBoxPack::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BoxPack());
}

namespace {

CSSValue* ConsumeReflect(CSSParserTokenStream& stream,
                         const CSSParserContext& context) {
  CSSIdentifierValue* direction =
      css_parsing_utils::ConsumeIdent<CSSValueID::kAbove, CSSValueID::kBelow,
                                      CSSValueID::kLeft, CSSValueID::kRight>(
          stream);
  if (!direction) {
    return nullptr;
  }

  CSSPrimitiveValue* offset = ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll,
      css_parsing_utils::UnitlessQuirk::kForbid);
  if (!offset) {
    // End of stream or parse error; in the latter case,
    // the caller will clean up since we're not at the end.
    offset =
        CSSNumericLiteralValue::Create(0, CSSPrimitiveValue::UnitType::kPixels);
    return MakeGarbageCollected<cssvalue::CSSReflectValue>(direction, offset,
                                                           /*mask=*/nullptr);
  }

  CSSValue* mask_or_null =
      css_parsing_utils::ConsumeWebkitBorderImage(stream, context);
  return MakeGarbageCollected<cssvalue::CSSReflectValue>(direction, offset,
                                                         mask_or_null);
}

}  // namespace

const CSSValue* WebkitBoxReflect::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeReflect(stream, context);
}

const CSSValue* WebkitBoxReflect::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForReflection(
      style.BoxReflect(), style, allow_visited_style, value_phase);
}

const CSSValue* InternalFontSizeDelta::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kAll,
      css_parsing_utils::UnitlessQuirk::kAllow);
}

const CSSValue* WebkitFontSmoothing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetFontDescription().FontSmoothing());
}

const CSSValue* HyphenateCharacter::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeString(stream);
}

const CSSValue* HyphenateCharacter::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.HyphenationString().IsNull()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return MakeGarbageCollected<CSSStringValue>(style.HyphenationString());
}

const CSSValue* WebkitLineBreak::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetLineBreak());
}

const CSSValue* WebkitLineClamp::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  } else {
    // When specifying number of lines, don't allow 0 as a valid value.
    return css_parsing_utils::ConsumePositiveInteger(stream, context);
  }
}

const CSSValue* WebkitLineClamp::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.WebkitLineClamp() == 0) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return CSSNumericLiteralValue::Create(style.WebkitLineClamp(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* WebkitLocale::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeString(stream);
}

const CSSValue* WebkitLocale::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.Locale().IsNull()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return MakeGarbageCollected<CSSStringValue>(style.Locale());
}

void WebkitLocale::ApplyValue(StyleResolverState& state,
                              const CSSValue& value,
                              ValueMode) const {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kAuto);
    state.GetFontBuilder().SetLocale(nullptr);
  } else {
    state.GetFontBuilder().SetLocale(
        LayoutLocale::Get(AtomicString(To<CSSStringValue>(value).Value())));
  }
}

const CSSValue* WebkitMaskBoxImageOutset::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderImageOutset(stream, context);
}

const CSSValue* WebkitMaskBoxImageOutset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImageQuad(
      style.MaskBoxImage().Outset(), style);
}

const CSSValue* WebkitMaskBoxImageRepeat::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderImageRepeat(stream);
}

const CSSValue* WebkitMaskBoxImageRepeat::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImageRepeat(style.MaskBoxImage());
}

const CSSValue* WebkitMaskBoxImageSlice::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderImageSlice(
      stream, context, css_parsing_utils::DefaultFill::kNoFill);
}

const CSSValue* WebkitMaskBoxImageSlice::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImageSlice(style.MaskBoxImage());
}

const CSSValue* WebkitMaskBoxImageSource::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeImageOrNone(stream, context);
}

const CSSValue* WebkitMaskBoxImageSource::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.MaskBoxImageSource()) {
    return style.MaskBoxImageSource()->ComputedCSSValue(
        style, allow_visited_style, value_phase);
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

void WebkitMaskBoxImageSource::ApplyValue(StyleResolverState& state,
                                          const CSSValue& value,
                                          ValueMode) const {
  state.StyleBuilder().SetMaskBoxImageSource(
      state.GetStyleImage(CSSPropertyID::kWebkitMaskBoxImageSource, value));
}

const CSSValue* WebkitMaskBoxImageWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeBorderImageWidth(stream, context);
}

const CSSValue* WebkitMaskBoxImageWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImageQuad(
      style.MaskBoxImage().BorderSlices(), style);
}

const CSSValue* MaskClip::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext& local_context) const {
  if (local_context.UseAliasParsing()) {
    return css_parsing_utils::ConsumeCommaSeparatedList(
        css_parsing_utils::ConsumePrefixedBackgroundBox, stream,
        css_parsing_utils::AllowTextValue::kAllow);
  }
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeCoordBoxOrNoClip, stream);
}

const CSSValue* MaskClip::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &style.MaskLayers();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    EFillBox box = curr_layer->Clip();
    list->Append(*CSSIdentifierValue::Create(box));
  }
  return list;
}

const CSSValue* MaskClip::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kBorderBox);
}

const CSSValue* MaskComposite::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext& local_context) const {
  if (local_context.UseAliasParsing()) {
    return css_parsing_utils::ConsumeCommaSeparatedList(
        css_parsing_utils::ConsumePrefixedMaskComposite, stream);
  }
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeMaskComposite, stream);
}

const CSSValue* MaskComposite::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &style.MaskLayers();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(
        *CSSIdentifierValue::Create(curr_layer->CompositingOperator()));
  }
  return list;
}

const CSSValue* MaskComposite::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kAdd);
}

const CSSValue* MaskImage::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeImageOrNone, stream, context);
}

const CSSValue* MaskImage::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const FillLayer& fill_layer = style.MaskLayers();
  return ComputedStyleUtils::BackgroundImageOrMaskImage(
      style, allow_visited_style, fill_layer, value_phase);
}

const CSSValue* MaskMode::ParseSingleValue(CSSParserTokenStream& stream,
                                           const CSSParserContext&,
                                           const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeMaskMode, stream);
}

const CSSValue* MaskMode::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::MaskMode(&style.MaskLayers());
}

const CSSValue* MaskMode::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kMatchSource);
}

const CSSValue* MaskOrigin::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext& local_context) const {
  if (local_context.UseAliasParsing()) {
    return css_parsing_utils::ConsumeCommaSeparatedList(
        css_parsing_utils::ConsumePrefixedBackgroundBox, stream,
        css_parsing_utils::AllowTextValue::kForbid);
  }
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeCoordBox, stream);
}

const CSSValue* MaskOrigin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &style.MaskLayers();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    EFillBox box = curr_layer->Origin();
    list->Append(*CSSIdentifierValue::Create(box));
  }
  return list;
}

const CSSValue* MaskOrigin::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kBorderBox);
}

const CSSValue* WebkitMaskPositionX::ParseSingleValue(
    CSSParserTokenStream& Stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumePositionLonghand<CSSValueID::kLeft,
                                                 CSSValueID::kRight>,
      Stream, context);
}

const CSSValue* WebkitMaskPositionX::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const FillLayer* curr_layer = &style.MaskLayers();
  return ComputedStyleUtils::BackgroundPositionXOrWebkitMaskPositionX(
      style, curr_layer);
}

const CSSValue* WebkitMaskPositionX::InitialValue() const {
  return CSSNumericLiteralValue::Create(
      0, CSSPrimitiveValue::UnitType::kPercentage);
}

const CSSValue* WebkitMaskPositionY::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumePositionLonghand<CSSValueID::kTop,
                                                 CSSValueID::kBottom>,
      stream, context);
}

const CSSValue* WebkitMaskPositionY::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const FillLayer* curr_layer = &style.MaskLayers();
  return ComputedStyleUtils::BackgroundPositionYOrWebkitMaskPositionY(
      style, curr_layer);
}

const CSSValue* WebkitMaskPositionY::InitialValue() const {
  return CSSNumericLiteralValue::Create(
      0, CSSPrimitiveValue::UnitType::kPercentage);
}

const CSSValue* MaskRepeat::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseRepeatStyle(stream);
}

const CSSValue* MaskRepeat::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::RepeatStyle(&style.MaskLayers());
}

const CSSValue* MaskRepeat::InitialValue() const {
  return MakeGarbageCollected<CSSRepeatStyleValue>(
      CSSIdentifierValue::Create(CSSValueID::kRepeat));
}

const CSSValue* MaskSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ParseMaskSize(stream, context, local_context,
                                          WebFeature::kNegativeMaskSize);
}

const CSSValue* MaskSize::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const FillLayer& fill_layer = style.MaskLayers();
  return ComputedStyleUtils::BackgroundImageOrMaskSize(style, fill_layer);
}

const CSSValue* MaskSize::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kAuto);
}

const CSSValue* WebkitPerspectiveOriginX::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePositionLonghand<CSSValueID::kLeft,
                                                    CSSValueID::kRight>(
      stream, context);
}

void WebkitPerspectiveOriginX::ApplyInherit(StyleResolverState& state) const {
  state.StyleBuilder().SetPerspectiveOriginX(
      state.ParentStyle()->PerspectiveOrigin().X());
}

const CSSValue* WebkitPerspectiveOriginY::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePositionLonghand<CSSValueID::kTop,
                                                    CSSValueID::kBottom>(
      stream, context);
}

void WebkitPerspectiveOriginY::ApplyInherit(StyleResolverState& state) const {
  state.StyleBuilder().SetPerspectiveOriginY(
      state.ParentStyle()->PerspectiveOrigin().Y());
}

const CSSValue* WebkitPrintColorAdjust::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.PrintColorAdjust());
}

const CSSValue* WebkitRtlOrdering::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.RtlOrdering() == EOrder::kVisual
                                        ? CSSValueID::kVisual
                                        : CSSValueID::kLogical);
}

const CSSValue* RubyAlign::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.RubyAlign());
}

const CSSValue* WebkitRubyPosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  switch (style.GetRubyPosition()) {
    case blink::RubyPosition::kOver:
      return CSSIdentifierValue::Create(CSSValueID::kBefore);
    case blink::RubyPosition::kUnder:
      return CSSIdentifierValue::Create(CSSValueID::kAfter);
  }
  NOTREACHED();
}

const CSSValue* RubyPosition::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueID value_id = stream.Peek().Id();
  if (css_parsing_utils::IdentMatches<CSSValueID::kOver, CSSValueID::kUnder>(
          value_id)) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  if (value_id == CSSValueID::kAlternate) {
    context.Count(WebFeature::kRubyPositionAlternate);
  } else if (value_id == CSSValueID::kInterCharacter) {
    context.Count(WebFeature::kRubyPositionInterCharacter);
  }
  return nullptr;
}

const CSSValue* RubyPosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetRubyPosition());
}

const CSSValue* WebkitTapHighlightColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color WebkitTapHighlightColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  const StyleColor& highlight_color = style.TapHighlightColor();
  if (style.ShouldForceColor(highlight_color)) {
    return visited_link
               ? style.GetInternalForcedVisitedCurrentColor(is_current_color)
               : style.GetInternalForcedCurrentColor(is_current_color);
  }
  return style.ResolvedColor(style.TapHighlightColor(), is_current_color);
}

const CSSValue* WebkitTapHighlightColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(
      style, style.TapHighlightColor(), value_phase);
}

const CSSValue* WebkitTextCombine::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.TextCombine() == ETextCombine::kAll) {
    return CSSIdentifierValue::Create(CSSValueID::kHorizontal);
  }
  return CSSIdentifierValue::Create(style.TextCombine());
}

const CSSValue* WebkitTextDecorationsInEffect::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeTextDecorationLine(stream);
}

const CSSValue*
WebkitTextDecorationsInEffect::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::RenderTextDecorationFlagsToCSSValue(
      style.TextDecorationsInEffect());
}

const CSSValue* TextEmphasisColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color TextEmphasisColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& text_emphasis_color = style.TextEmphasisColor();
  if (style.ShouldForceColor(text_emphasis_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return text_emphasis_color.Resolve(style.GetCurrentColor(),
                                     style.UsedColorScheme(), is_current_color);
}

const CSSValue* TextEmphasisColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(
      style, style.TextEmphasisColor(), value_phase);
}

// [ over | under ] && [ right | left ]?
// If [ right | left ] is omitted, it defaults to right.
const CSSValue* TextEmphasisPosition::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSIdentifierValue* values[2] = {
      css_parsing_utils::ConsumeIdent<CSSValueID::kOver, CSSValueID::kUnder,
                                      CSSValueID::kRight, CSSValueID::kLeft>(
          stream),
      nullptr};
  if (!values[0]) {
    return nullptr;
  }
  values[1] =
      css_parsing_utils::ConsumeIdent<CSSValueID::kOver, CSSValueID::kUnder,
                                      CSSValueID::kRight, CSSValueID::kLeft>(
          stream);
  CSSIdentifierValue* over_under = nullptr;
  CSSIdentifierValue* left_right = nullptr;

  for (auto* value : values) {
    if (!value) {
      break;
    }
    switch (value->GetValueID()) {
      case CSSValueID::kOver:
      case CSSValueID::kUnder:
        if (over_under) {
          return nullptr;
        }
        over_under = value;
        break;
      case CSSValueID::kLeft:
      case CSSValueID::kRight:
        if (left_right) {
          return nullptr;
        }
        left_right = value;
        break;
      default:
        NOTREACHED();
    }
  }
  if (!over_under) {
    return nullptr;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*over_under);
  if (left_right) {
    list->Append(*left_right);
  }
  return list;
}

const CSSValue* TextEmphasisPosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  switch (style.GetTextEmphasisPosition()) {
    case blink::TextEmphasisPosition::kOverRight:
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kOver));
      break;
    case blink::TextEmphasisPosition::kOverLeft:
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kOver));
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kLeft));
      break;
    case blink::TextEmphasisPosition::kUnderRight:
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kUnder));
      break;
    case blink::TextEmphasisPosition::kUnderLeft:
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kUnder));
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kLeft));
      break;
  }
  return list;
}

const CSSValue* TextEmphasisStyle::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  if (CSSValue* text_emphasis_style =
          css_parsing_utils::ConsumeString(stream)) {
    return text_emphasis_style;
  }

  CSSIdentifierValue* fill =
      css_parsing_utils::ConsumeIdent<CSSValueID::kFilled, CSSValueID::kOpen>(
          stream);
  CSSIdentifierValue* shape = css_parsing_utils::ConsumeIdent<
      CSSValueID::kDot, CSSValueID::kCircle, CSSValueID::kDoubleCircle,
      CSSValueID::kTriangle, CSSValueID::kSesame>(stream);
  if (!fill) {
    fill =
        css_parsing_utils::ConsumeIdent<CSSValueID::kFilled, CSSValueID::kOpen>(
            stream);
  }
  if (fill && shape) {
    CSSValueList* parsed_values = CSSValueList::CreateSpaceSeparated();
    parsed_values->Append(*fill);
    parsed_values->Append(*shape);
    return parsed_values;
  }
  if (fill) {
    return fill;
  }
  if (shape) {
    return shape;
  }
  return nullptr;
}

const CSSValue* TextEmphasisStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  switch (style.GetTextEmphasisMark()) {
    case TextEmphasisMark::kNone:
      return CSSIdentifierValue::Create(CSSValueID::kNone);
    case TextEmphasisMark::kCustom:
      return MakeGarbageCollected<CSSStringValue>(
          style.TextEmphasisCustomMark());
    case TextEmphasisMark::kAuto:
      NOTREACHED();
    case TextEmphasisMark::kDot:
    case TextEmphasisMark::kCircle:
    case TextEmphasisMark::kDoubleCircle:
    case TextEmphasisMark::kTriangle:
    case TextEmphasisMark::kSesame: {
      CSSValueList* list = CSSValueList::CreateSpaceSeparated();
      if (style.GetTextEmphasisFill() != TextEmphasisFill::kFilled) {
        list->Append(*CSSIdentifierValue::Create(style.GetTextEmphasisFill()));
      }
      list->Append(*CSSIdentifierValue::Create(style.GetTextEmphasisMark()));
      return list;
    }
  }
  NOTREACHED();
}

void TextEmphasisStyle::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetTextEmphasisFill(
      ComputedStyleInitialValues::InitialTextEmphasisFill());
  builder.SetTextEmphasisMark(
      ComputedStyleInitialValues::InitialTextEmphasisMark());
  builder.SetTextEmphasisCustomMark(
      ComputedStyleInitialValues::InitialTextEmphasisCustomMark());
}

void TextEmphasisStyle::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetTextEmphasisFill(state.Par
"""


```