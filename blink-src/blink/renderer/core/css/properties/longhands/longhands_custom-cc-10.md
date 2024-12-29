Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The request is to analyze a specific C++ file within the Chromium Blink rendering engine. The core goal is to understand its functionality, especially its relation to web technologies (JavaScript, HTML, CSS), provide illustrative examples, and discuss potential usage errors and debugging approaches.

2. **Initial Scan and Identification of Key Structures:**  The first step is to quickly read through the code, looking for repeating patterns and identifiable structures. I immediately noticed:
    *  Functions named `ParseSingleValue`: These strongly suggest parsing CSS property values from a stream of tokens.
    *  Functions named `CSSValueFromComputedStyleInternal`:  These seem responsible for converting internal computed style representations into `CSSValue` objects. This is a key part of how the browser's rendering engine exposes style information.
    *  Functions named `ApplyValue`: These likely handle applying parsed CSS values to the internal style representation (`StyleResolverState`).
    *  Constants like `CSSValueID::k...`: These are enumerations representing specific CSS keyword values.
    *  Data structures like `ComputedStyle`, `CSSParserTokenStream`, `CSSParserContext`, `CSSValueList`, `Length`, etc. These are all part of Blink's CSS parsing and styling infrastructure.
    *  Specific CSS property names embedded in the function names (e.g., `TextDecorationStyle`, `TextIndent`, `TextOverflow`). This is the most direct clue to the file's purpose.

3. **Categorize Functionality by CSS Property:**  The most logical way to organize the analysis is by the CSS properties that this file handles. I started listing them as I encountered them: `text-decoration-style`, `text-decoration-thickness`, `text-indent`, `text-orientation`, `text-overflow`, `text-rendering`, `text-shadow`, `text-size-adjust`, `text-spacing-trim`, `text-transform`, `text-underline-position`, `text-underline-offset`, `top`, `touch-action`, `transform-box`, `transform`, `transform-origin`, `transform-style`, `transition-delay`, `transition-duration`, `transition-property`, `transition-behavior`, `transition-timing-function`, `translate`, `unicode-bidi`, `user-select`, `vector-effect`, `vertical-align`, `view-timeline-axis`, `view-timeline-inset`, `view-timeline-name`, `visibility`, `app-region`, `appearance`.

4. **Analyze Each Property's Handling:** For each property, I examined the corresponding functions:
    * **`ParseSingleValue`:**  Focused on how the CSS syntax for that property is parsed. Looked for the expected data types (lengths, percentages, keywords, lists) and the use of helper functions like `css_parsing_utils::Consume...`. This directly relates to CSS syntax.
    * **`CSSValueFromComputedStyleInternal`:**  Determined how the internally stored computed style value is converted back into a `CSSValue`. This often involves mapping internal enums or data structures to specific CSS keywords or values.
    * **`ApplyValue`:**  Identified how the parsed `CSSValue` is applied to the `StyleResolverState`, ultimately influencing the computed style.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **CSS:** The most obvious connection. This file *directly* deals with parsing and managing CSS properties. Examples are straightforward: demonstrating the CSS syntax and how it maps to the code's parsing logic.
    * **HTML:** The parsed CSS styles are applied to HTML elements. The `LayoutObject` parameters in some functions hint at this connection. Examples involve showing how the CSS properties affect the rendering of HTML elements.
    * **JavaScript:**  While this C++ code doesn't directly execute JavaScript, the computed styles it manages are accessible and modifiable via JavaScript's CSSOM (CSS Object Model). Examples show how JavaScript can read or set these styles.

6. **Logical Reasoning (Assumptions and Outputs):**  For functions like `ParseSingleValue`, I could make assumptions about the input CSS token stream and predict the resulting `CSSValue` object. For `CSSValueFromComputedStyleInternal`, I could assume an internal computed style value and predict the corresponding CSS value.

7. **Common Usage Errors:**  I thought about the common mistakes developers make when working with these CSS properties:
    * Incorrect syntax (e.g., missing units, invalid keywords).
    * Understanding initial and inherited values.
    * Misunderstanding the interaction between different properties.

8. **Debugging Clues and User Operations:** I considered how a developer might end up looking at this code during debugging:
    * Inspecting element styles in the browser's developer tools.
    * Observing unexpected rendering behavior related to these properties.
    * Setting breakpoints in the browser's rendering engine (though this is advanced).

9. **Synthesize and Summarize:** Finally, I brought all the information together, summarizing the file's overall purpose and highlighting its role in the CSS parsing and styling pipeline within the Blink engine. The fact that this is part 11 of 13 suggested a need to provide a summary of the functionalities covered in *this specific file*.

**Self-Correction/Refinement during the Process:**

* **Initial Overwhelm:**  The sheer number of properties can be initially overwhelming. Breaking it down property by property was crucial.
* **Focus on Core Functions:**  I realized that the `ParseSingleValue`, `CSSValueFromComputedStyleInternal`, and `ApplyValue` functions are the key to understanding the functionality.
* **Specificity of Examples:** I aimed to make the examples concrete and directly related to the code snippets.
* **Balancing Detail and Conciseness:**  I tried to provide enough detail to be informative but avoid getting bogged down in overly technical implementation details that might not be relevant to the request.
* **Addressing the "Part 11 of 13" Constraint:**  The final summary focused on the specific properties handled in this file, rather than the entire set of CSS properties.
好的，让我们来分析一下 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 这个文件的功能。

**文件功能概览**

这个文件是 Chromium Blink 引擎中负责处理**自定义 CSS 属性（Longhand Properties）** 的一部分。更具体地说，它定义了许多 CSS 属性的 **解析 (Parsing)** 和 **计算样式到 CSS 值的转换 (CSSValueFromComputedStyleInternal)** 逻辑。

**功能细分与举例说明**

这个文件中的每个代码块通常对应一个 CSS 属性，并提供了以下功能：

1. **`ParseSingleValue` 函数:**
   - **功能:**  负责解析 CSS 语法中该属性的单个值。它会从 `CSSParserTokenStream` 中读取 token，并根据 CSS 语法规则将其转换为 Blink 内部的 `CSSValue` 对象。
   - **与 CSS 的关系:** 这是将 CSS 文本转换为浏览器可以理解和使用的内部表示的关键步骤。
   - **举例说明:** 对于 `text-indent` 属性，`ParseSingleValue` 会解析长度 (`<length>`) 或百分比 (`<percentage>`) 值。例如，如果 CSS 中写了 `text-indent: 2em;` 或 `text-indent: 10%;`，这个函数会负责识别 `2em` 或 `10%` 并创建相应的 `CSSValue` 对象。
   - **假设输入与输出 (TextIndent):**
     - **假设输入:**  `CSSParserTokenStream` 中包含 "2em" 这个 token。
     - **输出:**  一个指向 `CSSPrimitiveValue` 对象的指针，该对象表示长度为 2em。

2. **`CSSValueFromComputedStyleInternal` 函数:**
   - **功能:** 负责将元素最终计算出的样式 (存储在 `ComputedStyle` 对象中) 中该属性的值转换为可以用于表示 CSS 值的 `CSSValue` 对象。
   - **与 CSS 的关系:**  这用于获取元素最终生效的样式值，例如在开发者工具中看到的“计算后样式”。
   - **举例说明:** 对于 `text-decoration-style` 属性，`CSSValueFromComputedStyleInternal` 会读取 `ComputedStyle` 中存储的 `ETextDecorationStyle` 枚举值（例如 `kSolid`, `kDotted`），并将其转换为相应的 `CSSIdentifierValue` 对象（例如 `CSSValueID::kSolid`, `CSSValueID::kDotted`）。
   - **假设输入与输出 (TextDecorationStyle):**
     - **假设输入:** `ComputedStyle` 对象的 `TextDecorationStyle()` 返回 `ETextDecorationStyle::kDashed`。
     - **输出:**  一个指向 `CSSIdentifierValue` 对象的指针，该对象的值为 `CSSValueID::kDashed`。

3. **`ApplyValue` 函数 (部分属性有):**
   - **功能:**  负责将已解析的 `CSSValue` 应用到正在构建的元素样式中 (`StyleResolverState`)。
   - **与 CSS 的关系:** 这是将解析后的 CSS 值实际应用到元素样式，影响最终渲染结果的关键步骤。
   - **举例说明:** 对于 `text-indent` 属性，`ApplyValue` 函数会将解析得到的长度或百分比值存储到 `StyleBuilder` 中，以便后续布局阶段使用。

4. **其他辅助函数:**
   - 文件中还包含一些辅助函数，例如 `ApplyInitial` 和 `ApplyInherit`，用于处理属性的初始值和继承。

**与 JavaScript, HTML, CSS 的关系**

* **CSS:**  这个文件是 Blink 引擎处理 CSS 的核心组成部分，负责解析 CSS 语法和管理 CSS 属性值。
* **HTML:** CSS 样式最终会应用到 HTML 元素上。当浏览器解析 HTML 并构建 DOM 树时，会使用这个文件中的逻辑来解析和应用样式规则，从而确定每个 HTML 元素的最终外观。
* **JavaScript:** JavaScript 可以通过 DOM API 操作元素的样式。例如，可以使用 `element.style.textIndent = '20px';` 来设置元素的 `text-indent` 属性。当 JavaScript 设置样式时，Blink 引擎内部也会使用类似的解析和应用逻辑。此外，JavaScript 可以通过 `window.getComputedStyle(element).textIndent` 获取元素的计算后样式，这时会调用 `CSSValueFromComputedStyleInternal` 这类函数来获取 `textIndent` 属性的 `CSSValue` 表示。

**用户或编程常见的使用错误**

* **CSS 语法错误:**  如果用户在 CSS 中写了错误的语法，例如 `text-indent: 20 px;` (缺少单位)，`ParseSingleValue` 函数可能会返回 `nullptr`，导致样式应用失败。
* **不理解属性的初始值和继承:** 开发者可能错误地认为所有属性都会继承，或者不清楚属性的初始值是什么，导致样式设置不符合预期。例如，`text-orientation` 默认值是 `mixed`，如果不显式设置，可能会得到意想不到的文本方向。
* **使用了错误的单位:**  某些属性只接受特定的单位，例如 `text-decoration-thickness` 早期版本只接受长度单位或 `auto` 和 `from-font` 关键字，如果使用了百分比单位可能会被忽略。

**用户操作如何到达这里 (调试线索)**

一个开发者可能会在以下情况下查看这个文件或与这个文件相关的代码：

1. **在开发者工具中检查元素样式:**
   - 用户在浏览器中打开开发者工具 (通常按 F12)。
   - 选择 "Elements" 面板，然后选择一个 HTML 元素。
   - 在 "Styles" 或 "Computed" 面板中查看该元素的样式。如果某个 CSS 属性的值不是预期的，开发者可能会怀疑是 Blink 引擎解析或计算样式时出现了问题。
2. **遇到 CSS 样式问题需要调试:**
   - 页面渲染出现问题，例如文本缩进不正确，下划线样式错误等。
   - 开发者可能会尝试在 Blink 引擎的源代码中查找与这些 CSS 属性相关的代码，例如 `longhands_custom.cc`，以了解其内部实现逻辑，从而找到问题根源。
3. **参与 Blink 引擎的开发或维护:**
   - 开发人员可能需要修改或添加新的 CSS 属性支持，这时就需要修改或添加类似 `ParseSingleValue` 和 `CSSValueFromComputedStyleInternal` 的函数。
4. **阅读 Chromium 源代码学习 CSS 原理:**
   - 一些开发者为了深入理解 CSS 的工作原理，会阅读 Blink 引擎的源代码，`longhands_custom.cc` 是一个很好的入口点，可以了解各种 CSS 属性是如何被解析和处理的。

**假设输入与输出 (TextDecorationThickness):**

* **假设输入 (ParseSingleValue):** `CSSParserTokenStream` 中包含 "from-font" 这个 token。
* **输出 (ParseSingleValue):** 一个指向 `CSSIdentifierValue` 对象的指针，该对象的值为 `CSSValueID::kFromFont`。
* **假设输入 (CSSValueFromComputedStyleInternal):** `ComputedStyle` 对象的 `GetTextDecorationThickness()` 返回一个内部表示 "auto" 的值。
* **输出 (CSSValueFromComputedStyleInternal):** 一个指向 `CSSIdentifierValue` 对象的指针，该对象的值为 `CSSValueID::kAuto`。

**用户或编程常见的使用错误举例:**

* **`text-decoration-thickness: 1.5;` (缺少单位):**  `ParseSingleValue` 会解析失败，因为长度值缺少单位 (例如 `px`, `em`)。浏览器可能会忽略这个样式声明。
* **`text-underline-position: under left top;` (使用了多余的关键字):** `ParseSingleValue` 只期望 `auto` 或者 `[ from-font | under ] || [ left | right ]` 的组合，多余的 `top` 关键字会导致解析失败。

**作为调试线索，说明用户操作是如何一步步的到达这里:**

1. **用户在浏览器中看到一段文字的下划线位置不正确。**
2. **开发者打开开发者工具，选中该文字所在的元素。**
3. **在 "Computed" 面板中，开发者看到 `text-underline-position` 的值是 `auto`，但实际表现不是预期的默认行为。**
4. **开发者怀疑是浏览器解析 `text-underline-position` 属性时出现了问题，或者计算后的值不正确。**
5. **为了进一步调查，开发者可能会查看 Chromium 源代码中 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 文件，找到 `TextUnderlinePosition` 相关的代码。**
6. **开发者可能会分析 `ParseSingleValue` 函数，看是否正确解析了 CSS 中设置的 `text-underline-position` 值。**
7. **开发者也可能会分析 `CSSValueFromComputedStyleInternal` 函数，看计算后的 `TextUnderlinePosition` 值是如何转换为 CSS 值的，以及是否存在计算错误的可能性。**

**第11部分，共13部分，功能归纳:**

作为长hand属性处理文件的第 11 部分（总共 13 部分），`longhands_custom.cc` 文件主要负责以下 CSS 属性的**解析和计算值到 CSS 值的转换**：

* 与文本装饰相关的属性：`text-decoration-style`, `text-decoration-thickness`, `text-underline-position`, `text-underline-offset`
* 文本排版相关的属性：`text-indent`, `text-orientation`, `text-overflow`, `text-rendering`, `text-shadow`, `text-size-adjust`, `text-spacing-trim`, `text-transform`
* 定位属性：`top`
* 触摸交互属性：`touch-action`
* 变换和动画相关的属性：`transform-box`, `transform`, `transform-origin`, `transform-style`, `transition-delay`, `transition-duration`, `transition-property`, `transition-behavior`, `transition-timing-function`, `translate`
* 其他属性：`unicode-bidi`, `user-select`, `vector-effect`, `vertical-align`, `view-timeline-axis`, `view-timeline-inset`, `view-timeline-name`, `visibility`, `app-region`, `appearance`

总而言之，这个文件是 Blink 引擎中处理多种常见和重要的 CSS 属性的关键组成部分，负责将 CSS 文本转化为浏览器内部表示，并提供计算后样式到 CSS 值的转换能力。它是连接 CSS 语法和浏览器渲染引擎的桥梁。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共13部分，请归纳一下它的功能

"""
e* TextDecorationStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForTextDecorationStyle(
      style.TextDecorationStyle());
}

const CSSValue* TextDecorationThickness::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (auto* ident =
          css_parsing_utils::ConsumeIdent<CSSValueID::kFromFont,
                                          CSSValueID::kAuto>(stream)) {
    return ident;
  }
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* TextDecorationThickness::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.GetTextDecorationThickness().IsFromFont()) {
    return CSSIdentifierValue::Create(CSSValueID::kFromFont);
  }

  if (style.GetTextDecorationThickness().IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.GetTextDecorationThickness().Thickness(), style);
}

const CSSValue* TextIndent::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // [ <length> | <percentage> ]
  CSSValue* length_percentage = css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll,
      css_parsing_utils::UnitlessQuirk::kAllow);
  if (!length_percentage) {
    return nullptr;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*length_percentage);

  return list;
}

const CSSValue* TextIndent::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.TextIndent(), style));
  return list;
}

void TextIndent::ApplyValue(StyleResolverState& state,
                            const CSSValue& value,
                            ValueMode) const {
  Length length_or_percentage_value;

  for (auto& list_value : To<CSSValueList>(value)) {
    if (auto* list_primitive_value =
            DynamicTo<CSSPrimitiveValue>(*list_value)) {
      length_or_percentage_value = list_primitive_value->ConvertToLength(
          state.CssToLengthConversionData());
    } else {
      NOTREACHED();
    }
  }

  state.StyleBuilder().SetTextIndent(length_or_percentage_value);
}

const CSSValue* TextOrientation::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetTextOrientation());
}

void TextOrientation::ApplyInitial(StyleResolverState& state) const {
  state.SetTextOrientation(
      ComputedStyleInitialValues::InitialTextOrientation());
}

void TextOrientation::ApplyInherit(StyleResolverState& state) const {
  state.SetTextOrientation(state.ParentStyle()->GetTextOrientation());
}

void TextOrientation::ApplyValue(StyleResolverState& state,
                                 const CSSValue& value,
                                 ValueMode) const {
  state.SetTextOrientation(
      To<CSSIdentifierValue>(value).ConvertTo<ETextOrientation>());
}

const CSSValue* TextOverflow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.TextOverflow() != ETextOverflow::kClip) {
    return CSSIdentifierValue::Create(CSSValueID::kEllipsis);
  }
  return CSSIdentifierValue::Create(CSSValueID::kClip);
}

const CSSValue* TextRendering::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetFontDescription().TextRendering());
}

const CSSValue* TextShadow::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeShadow(
      stream, context, css_parsing_utils::AllowInsetAndSpread::kForbid);
}

const CSSValue* TextShadow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForShadowList(style.TextShadow(), style,
                                                false, value_phase);
}

const CSSValue* TextSizeAdjust::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumePercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* TextSizeAdjust::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.GetTextSizeAdjust().IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return CSSNumericLiteralValue::Create(
      style.GetTextSizeAdjust().Multiplier() * 100,
      CSSPrimitiveValue::UnitType::kPercentage);
}

const CSSValue* TextSpacingTrim::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(
      style.GetFontDescription().GetTextSpacingTrim());
}

const CSSValue* TextTransform::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TextTransform());
}

// https://drafts.csswg.org/css-text-decor-4/#text-underline-position-property
// auto | [ from-font | under ] || [ left | right ] - default: auto
const CSSValue* TextUnderlinePosition::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSIdentifierValue* from_font_or_under_value =
      css_parsing_utils::ConsumeIdent<CSSValueID::kFromFont,
                                      CSSValueID::kUnder>(stream);
  CSSIdentifierValue* left_or_right_value =
      css_parsing_utils::ConsumeIdent<CSSValueID::kLeft, CSSValueID::kRight>(
          stream);
  if (left_or_right_value && !from_font_or_under_value) {
    from_font_or_under_value =
        css_parsing_utils::ConsumeIdent<CSSValueID::kFromFont,
                                        CSSValueID::kUnder>(stream);
  }
  if (!from_font_or_under_value && !left_or_right_value) {
    return nullptr;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (from_font_or_under_value) {
    list->Append(*from_font_or_under_value);
  }
  if (left_or_right_value) {
    list->Append(*left_or_right_value);
  }
  return list;
}

const CSSValue* TextUnderlinePosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  auto text_underline_position = style.GetTextUnderlinePosition();
  if (text_underline_position == blink::TextUnderlinePosition::kAuto) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (text_underline_position == blink::TextUnderlinePosition::kFromFont) {
    return CSSIdentifierValue::Create(CSSValueID::kFromFont);
  }
  if (text_underline_position == blink::TextUnderlinePosition::kUnder) {
    return CSSIdentifierValue::Create(CSSValueID::kUnder);
  }
  if (text_underline_position == blink::TextUnderlinePosition::kLeft) {
    return CSSIdentifierValue::Create(CSSValueID::kLeft);
  }
  if (text_underline_position == blink::TextUnderlinePosition::kRight) {
    return CSSIdentifierValue::Create(CSSValueID::kRight);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (EnumHasFlags(text_underline_position,
                   blink::TextUnderlinePosition::kFromFont)) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kFromFont));
  } else {
    DCHECK(EnumHasFlags(text_underline_position,
                        blink::TextUnderlinePosition::kUnder));
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kUnder));
  }
  if (EnumHasFlags(text_underline_position,
                   blink::TextUnderlinePosition::kLeft)) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kLeft));
  }
  if (EnumHasFlags(text_underline_position,
                   blink::TextUnderlinePosition::kRight)) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kRight));
  }
  DCHECK_EQ(list->length(), 2U);
  return list;
}

const CSSValue* TextUnderlineOffset::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* TextUnderlineOffset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.TextUnderlineOffset(), style);
}

const CSSValue* Top::ParseSingleValue(
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

bool Top::IsLayoutDependent(const ComputedStyle* style,
                            LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* Top::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPositionOffset(style, *this,
                                                    layout_object);
}

namespace {

static bool ConsumePan(CSSParserTokenStream& stream,
                       CSSValue*& pan_x,
                       CSSValue*& pan_y,
                       CSSValue*& pinch_zoom) {
  CSSValueID id = stream.Peek().Id();
  if ((id == CSSValueID::kPanX || id == CSSValueID::kPanRight ||
       id == CSSValueID::kPanLeft) &&
      !pan_x) {
    pan_x = css_parsing_utils::ConsumeIdent(stream);
  } else if ((id == CSSValueID::kPanY || id == CSSValueID::kPanDown ||
              id == CSSValueID::kPanUp) &&
             !pan_y) {
    pan_y = css_parsing_utils::ConsumeIdent(stream);
  } else if (id == CSSValueID::kPinchZoom && !pinch_zoom) {
    pinch_zoom = css_parsing_utils::ConsumeIdent(stream);
  } else {
    return false;
  }
  return true;
}

}  // namespace

const CSSValue* TouchAction::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kAuto || id == CSSValueID::kNone ||
      id == CSSValueID::kManipulation) {
    list->Append(*css_parsing_utils::ConsumeIdent(stream));
    return list;
  }

  CSSValue* pan_x = nullptr;
  CSSValue* pan_y = nullptr;
  CSSValue* pinch_zoom = nullptr;
  if (!ConsumePan(stream, pan_x, pan_y, pinch_zoom)) {
    return nullptr;
  }
  ConsumePan(stream, pan_x, pan_y, pinch_zoom);  // May fail.
  ConsumePan(stream, pan_x, pan_y, pinch_zoom);  // May fail.

  if (pan_x) {
    list->Append(*pan_x);
  }
  if (pan_y) {
    list->Append(*pan_y);
  }
  if (pinch_zoom) {
    list->Append(*pinch_zoom);
  }
  return list;
}

const CSSValue* TouchAction::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::TouchActionFlagsToCSSValue(style.GetTouchAction());
}

const CSSValue* TransformBox::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.TransformBox());
}

const CSSValue* Transform::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeTransformList(stream, context,
                                                 local_context);
}

bool Transform::IsLayoutDependent(const ComputedStyle* style,
                                  LayoutObject* layout_object) const {
  return layout_object &&
         (layout_object->IsBox() || layout_object->IsSVGChild());
}

const CSSValue* Transform::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (value_phase == CSSValuePhase::kComputedValue) {
    return ComputedStyleUtils::ComputedTransformList(style, layout_object);
  }
  return ComputedStyleUtils::ResolvedTransform(layout_object, style);
}

const CSSValue* TransformOrigin::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValue* result_x = nullptr;
  CSSValue* result_y = nullptr;
  if (css_parsing_utils::ConsumeOneOrTwoValuedPosition(
          stream, context, css_parsing_utils::UnitlessQuirk::kForbid, result_x,
          result_y)) {
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    list->Append(*result_x);
    list->Append(*result_y);
    CSSValue* result_z = css_parsing_utils::ConsumeLength(
        stream, context, CSSPrimitiveValue::ValueRange::kAll);
    if (result_z) {
      list->Append(*result_z);
    }
    return list;
  }
  return nullptr;
}

bool TransformOrigin::IsLayoutDependent(const ComputedStyle* style,
                                        LayoutObject* layout_object) const {
  return layout_object &&
         (layout_object->IsBox() || layout_object->IsSVGChild());
}

const CSSValue* TransformOrigin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (layout_object) {
    gfx::RectF reference_box =
        ComputedStyleUtils::ReferenceBoxForTransform(*layout_object);
    gfx::PointF resolved_origin(
        FloatValueForLength(style.GetTransformOrigin().X(),
                            reference_box.width()),
        FloatValueForLength(style.GetTransformOrigin().Y(),
                            reference_box.height()));
    list->Append(*ZoomAdjustedPixelValue(resolved_origin.x(), style));
    list->Append(*ZoomAdjustedPixelValue(resolved_origin.y(), style));
  } else {
    list->Append(*ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
        style.GetTransformOrigin().X(), style));
    list->Append(*ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
        style.GetTransformOrigin().Y(), style));
  }
  if (style.GetTransformOrigin().Z() != 0) {
    list->Append(
        *ZoomAdjustedPixelValue(style.GetTransformOrigin().Z(), style));
  }
  return list;
}

const CSSValue* TransformStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(
      (style.TransformStyle3D() == ETransformStyle3D::kPreserve3d)
          ? CSSValueID::kPreserve3d
          : CSSValueID::kFlat);
}

const CSSValue* TransitionDelay::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      static_cast<CSSPrimitiveValue* (*)(CSSParserTokenStream&,
                                         const CSSParserContext&,
                                         CSSPrimitiveValue::ValueRange)>(
          css_parsing_utils::ConsumeTime),
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* TransitionDelay::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationDelayList(style.Transitions());
}

const CSSValue* TransitionDelay::InitialValue() const {
  DEFINE_STATIC_LOCAL(const Persistent<CSSValue>, value,
                      (ComputedStyleUtils::ValueForAnimationDelay(
                          CSSTimingData::InitialDelayStart())));
  return value;
}

const CSSValue* TransitionDuration::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      static_cast<CSSPrimitiveValue* (*)(CSSParserTokenStream&,
                                         const CSSParserContext&,
                                         CSSPrimitiveValue::ValueRange)>(
          css_parsing_utils::ConsumeTime),
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* TransitionDuration::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationDurationList(style.Transitions());
}

const CSSValue* TransitionDuration::InitialValue() const {
  DEFINE_STATIC_LOCAL(const Persistent<CSSValue>, value,
                      (CSSNumericLiteralValue::Create(
                          CSSTransitionData::InitialDuration().value(),
                          CSSPrimitiveValue::UnitType::kSeconds)));
  return value;
}

const CSSValue* TransitionProperty::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueList* list = css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeTransitionProperty, stream, context);
  if (!list || !css_parsing_utils::IsValidPropertyList(*list)) {
    return nullptr;
  }
  return list;
}

const CSSValue* TransitionProperty::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForTransitionProperty(style.Transitions());
}

const CSSValue* TransitionProperty::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kAll);
}

namespace {
CSSIdentifierValue* ConsumeIdentNoTemplate(CSSParserTokenStream& stream,
                                           const CSSParserContext&) {
  return css_parsing_utils::ConsumeIdent(stream);
}
}  // namespace

const CSSValue* TransitionBehavior::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueList* list = css_parsing_utils::ConsumeCommaSeparatedList(
      ConsumeIdentNoTemplate, stream, context);
  if (!list || !css_parsing_utils::IsValidTransitionBehaviorList(*list)) {
    return nullptr;
  }
  return list;
}

const CSSValue* TransitionBehavior::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForTransitionBehavior(style.Transitions());
}

const CSSValue* TransitionBehavior::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNormal);
}

const CSSValue* TransitionTimingFunction::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeAnimationTimingFunction, stream, context);
}

const CSSValue* TransitionTimingFunction::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationTimingFunctionList(
      style.Transitions());
}

const CSSValue* TransitionTimingFunction::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kEase);
}

const CSSValue* Translate::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValue* translate_x = css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!translate_x) {
    return nullptr;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*translate_x);
  CSSPrimitiveValue* translate_y = css_parsing_utils::ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (translate_y) {
    CSSPrimitiveValue* translate_z = css_parsing_utils::ConsumeLength(
        stream, context, CSSPrimitiveValue::ValueRange::kAll);

    if (translate_z &&
        translate_z->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue) {
      translate_z = nullptr;
    }
    if (translate_y->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue &&
        !translate_y->HasPercentage() && !translate_z) {
      return list;
    }

    list->Append(*translate_y);
    if (translate_z) {
      list->Append(*translate_z);
    }
  }

  return list;
}

bool Translate::IsLayoutDependent(const ComputedStyle* style,
                                  LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* Translate::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.Translate()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  const Length& x = style.Translate()->X();
  const Length& y = style.Translate()->Y();
  double z = style.Translate()->Z();

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*ComputedStyleUtils::ZoomAdjustedPixelValueForLength(x, style));

  if (!y.IsZero() || y.HasPercent() || z != 0) {
    list->Append(
        *ComputedStyleUtils::ZoomAdjustedPixelValueForLength(y, style));
  }

  if (z != 0) {
    list->Append(*ZoomAdjustedPixelValue(z, style));
  }

  return list;
}

const CSSValue* UnicodeBidi::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetUnicodeBidi());
}

const CSSValue* UserSelect::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.UserSelect());
}

const CSSValue* VectorEffect::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.VectorEffect());
}

const CSSValue* VerticalAlign::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSValue* parsed_value = css_parsing_utils::ConsumeIdentRange(
      stream, CSSValueID::kBaseline, CSSValueID::kWebkitBaselineMiddle);
  if (!parsed_value) {
    parsed_value = css_parsing_utils::ConsumeLengthOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kAll,
        css_parsing_utils::UnitlessQuirk::kAllow);
  }
  return parsed_value;
}

const CSSValue* VerticalAlign::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  switch (style.VerticalAlign()) {
    case EVerticalAlign::kBaseline:
      return CSSIdentifierValue::Create(CSSValueID::kBaseline);
    case EVerticalAlign::kMiddle:
      return CSSIdentifierValue::Create(CSSValueID::kMiddle);
    case EVerticalAlign::kSub:
      return CSSIdentifierValue::Create(CSSValueID::kSub);
    case EVerticalAlign::kSuper:
      return CSSIdentifierValue::Create(CSSValueID::kSuper);
    case EVerticalAlign::kTextTop:
      return CSSIdentifierValue::Create(CSSValueID::kTextTop);
    case EVerticalAlign::kTextBottom:
      return CSSIdentifierValue::Create(CSSValueID::kTextBottom);
    case EVerticalAlign::kTop:
      return CSSIdentifierValue::Create(CSSValueID::kTop);
    case EVerticalAlign::kBottom:
      return CSSIdentifierValue::Create(CSSValueID::kBottom);
    case EVerticalAlign::kBaselineMiddle:
      return CSSIdentifierValue::Create(CSSValueID::kWebkitBaselineMiddle);
    case EVerticalAlign::kLength:
      return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
          style.GetVerticalAlignLength(), style);
  }
  NOTREACHED();
}

void VerticalAlign::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  EVerticalAlign vertical_align = state.ParentStyle()->VerticalAlign();
  builder.SetVerticalAlign(vertical_align);
  if (vertical_align == EVerticalAlign::kLength) {
    builder.SetVerticalAlignLength(
        state.ParentStyle()->GetVerticalAlignLength());
  }
}

void VerticalAlign::ApplyValue(StyleResolverState& state,
                               const CSSValue& value,
                               ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    builder.SetVerticalAlign(identifier_value->ConvertTo<EVerticalAlign>());
  } else {
    builder.SetVerticalAlignLength(To<CSSPrimitiveValue>(value).ConvertToLength(
        state.CssToLengthConversionData()));
  }
}

const CSSValue* ViewTimelineAxis::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  using css_parsing_utils::ConsumeCommaSeparatedList;
  using css_parsing_utils::ConsumeSingleTimelineAxis;
  return ConsumeCommaSeparatedList(ConsumeSingleTimelineAxis, stream);
}

const CSSValue* ViewTimelineAxis::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Vector<TimelineAxis>& vector = style.ViewTimelineAxis();
  if (vector.empty()) {
    return InitialValue();
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (TimelineAxis axis : vector) {
    list->Append(*CSSIdentifierValue::Create(axis));
  }
  return list;
}

const CSSValue* ViewTimelineAxis::InitialValue() const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kBlock));
  return list;
}

const CSSValue* ViewTimelineInset::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  using css_parsing_utils::ConsumeCommaSeparatedList;
  using css_parsing_utils::ConsumeSingleTimelineInset;
  return ConsumeCommaSeparatedList(ConsumeSingleTimelineInset, stream, context);
}

const CSSValue* ViewTimelineInset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Vector<TimelineInset>& vector = style.ViewTimelineInset();
  if (vector.empty()) {
    return InitialValue();
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const TimelineInset& inset : vector) {
    list->Append(*ComputedStyleUtils::ValueForTimelineInset(inset, style));
  }
  return list;
}

const CSSValue* ViewTimelineInset::InitialValue() const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kAuto));
  return list;
}

const CSSValue* ViewTimelineName::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  using css_parsing_utils::ConsumeCommaSeparatedList;
  using css_parsing_utils::ConsumeSingleTimelineName;
  return ConsumeCommaSeparatedList(ConsumeSingleTimelineName, stream, context);
}

const CSSValue* ViewTimelineName::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.ViewTimelineName()) {
    return InitialValue();
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const Member<const ScopedCSSName>& name :
       style.ViewTimelineName()->GetNames()) {
    list->Append(*ComputedStyleUtils::ValueForCustomIdentOrNone(name.Get()));
  }
  return list;
}

const CSSValue* ViewTimelineName::InitialValue() const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
  return list;
}

const CSSValue* Visibility::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Visibility());
}

const CSSValue* AppRegion::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.DraggableRegionMode() == EDraggableRegionMode::kNone) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return CSSIdentifierValue::Create(style.DraggableRegionMode() ==
                                            EDraggableRegionMode::kDrag
                                        ? CSSValueID::kDrag
                                        : CSSValueID::kNoDrag);
}

void AppRegion::ApplyInitial(StyleResolverState& state) const {}

void AppRegion::ApplyInherit(StyleResolverState& state) const {}

void AppRegion::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  const auto& identifier_value = To<CSSIdentifierValue>(value);
  state.StyleBuilder().SetDraggableRegionMode(
      identifier_value.GetValueID() == CSSValueID::kDrag
          ? EDraggableRegionMode::kDrag
          : EDraggableRegionMode::kNoDrag);
  state.GetDocument().SetHasDraggableRegions(true);
}

const CSSValue* Appearance::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  CSSValueID id = stream.Peek().Id();
  CSSPropertyID property = CSSPropertyID::kAppearance;
  if (local_context.UseAliasParsing()) {
    property = CSSPropertyID::kAliasWebkitAppearance;
  }
  if (CSSParserFastPaths::IsValidKeywordPropertyAndValue(property, id,
                                                         context.Mode())) {
    css_parsing_utils::CountKeywordOnlyPropertyUsage(property, context, id);
    return css_parsing_utils::ConsumeIdent(stream);
  }
  css_parsing_utils::WarnInvalidKeywordPropertyUsage(property, context, id);
  retu
"""


```