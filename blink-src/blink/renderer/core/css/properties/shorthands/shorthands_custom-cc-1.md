Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This code is part of the CSS parsing logic, specifically dealing with CSS shorthand properties.

Here's a breakdown of the thought process to analyze the code and generate the answer:

1. **Identify the Core Functionality:** The code defines `ParseShorthand` and `CSSValueFromComputedStyleInternal` methods for various CSS shorthand properties like `border-left`, `border-radius`, `border-right`, `border-spacing`, `border-style`, `border-top`, `border-width`, `column-rule`, `columns`, `contain-intrinsic-size`, `container`, `flex`, `flex-flow`, and `font`, `font-variant`. These methods are responsible for:
    * **`ParseShorthand`**:  Taking a stream of CSS tokens and parsing the shorthand property into its individual longhand properties.
    * **`CSSValueFromComputedStyleInternal`**:  Retrieving the computed value of the shorthand property from the `ComputedStyle` object.

2. **Analyze Individual Shorthands:** Examine the implementation of `ParseShorthand` for each property to understand how it breaks down the shorthand into longhands. Look for common patterns and helper functions.

3. **Relate to CSS, HTML, and JavaScript:**
    * **CSS:** The code directly manipulates CSS properties. It parses CSS syntax and sets CSS values.
    * **HTML:**  CSS styles are applied to HTML elements. The parsing process is triggered when the browser encounters CSS rules in stylesheets or inline styles.
    * **JavaScript:** JavaScript can manipulate CSS styles through the DOM API (e.g., `element.style.border`). While this code doesn't directly interact with JavaScript, the parsing it performs is crucial for JavaScript's ability to correctly interpret and modify styles.

4. **Identify Logic and Assumptions:**  Focus on the parsing logic within `ParseShorthand`. Look for conditional statements, loops, and helper functions used for token consumption and value extraction. Note any assumptions made about the input token stream.

5. **Spot Potential User Errors:** Consider how a user might write incorrect CSS that would be processed by this code. Think about common mistakes in shorthand syntax.

6. **Trace User Actions:**  Imagine the steps a user takes that would lead to this code being executed. This usually involves loading a web page with CSS.

7. **Address the "Part 2 of 5" Request:**  Summarize the overall function of the provided code snippet.

8. **Structure the Answer:** Organize the findings into clear sections as requested by the prompt. Use examples where appropriate.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Just list the shorthands and say they parse CSS.
* **Refinement:** Provide more detail about *how* the parsing happens (e.g., using `ConsumeShorthandGreedilyViaLonghands`, `ConsumeRadii`, etc.).
* **Initial thought:** The code only deals with CSS.
* **Refinement:** Explain the indirect relationship with HTML (styling elements) and JavaScript (DOM manipulation of styles).
* **Initial thought:**  Assume valid input for logic examples.
* **Refinement:**  Consider what happens with invalid input and how the parsing might fail.
* **Initial thought:** Focus solely on the code.
* **Refinement:** Think about the user's perspective and how they trigger this code through browser interactions.

By following this process of analyzing the code, identifying its purpose, relating it to web technologies, and considering user interactions and potential errors, we can construct a comprehensive and informative answer.
这是对`blink/renderer/core/css/properties/shorthands/shorthands_custom.cc` 文件中部分代码的分析，主要涉及 CSS 边框、圆角、列布局、弹性布局、容器查询和字体相关的 CSS 简写属性的解析和计算值获取。

**功能归纳 (针对提供的代码片段):**

这段代码主要负责实现以下 CSS 简写属性的解析和计算值获取：

* **边框属性 (Border Properties):**
    * `border-left`: 解析 `border-left-width`, `border-left-style`, `border-left-color`。
    * `border-radius`: 解析四个角的半径值，包括水平和垂直半径。
    * `border-right`: 解析 `border-right-width`, `border-right-style`, `border-right-color`。
    * `border-spacing`: 解析表格单元格边框的水平和垂直间距。
    * `border-style`: 解析四个边框的样式。
    * `border-top`: 解析 `border-top-width`, `border-top-style`, `border-top-color`。
    * `border-width`: 解析四个边框的宽度。
* **列布局属性 (Column Layout Properties):**
    * `column-rule`: 解析 `column-rule-width`, `column-rule-style`, `column-rule-color`。
    * `columns`: 解析 `column-width` 和 `column-count`。
* **内容固有尺寸属性 (Contain Intrinsic Size Property):**
    * `contain-intrinsic-size`: 解析 `contain-intrinsic-width` 和 `contain-intrinsic-height`。
* **容器查询属性 (Container Query Properties):**
    * `container`: 解析 `container-name` 和 `container-type`。
* **弹性布局属性 (Flexbox Properties):**
    * `flex`: 解析 `flex-grow`, `flex-shrink`, `flex-basis`。
    * `flex-flow`: 解析 `flex-direction` 和 `flex-wrap`。
* **字体属性 (Font Properties):**
    * `font`: 解析 `font-style`, `font-variant`, `font-weight`, `font-stretch`, `font-size`, `line-height`, `font-family`。
    * `font-variant`: 解析各种字体变体特征，如 ligatures, caps, numeric, east-asian, alternates, position 和 emoji。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些代码是浏览器引擎处理 CSS 样式规则的核心部分。当浏览器解析 HTML 和 CSS 时，会调用这些函数来理解和应用样式。

* **CSS:**  这段代码直接负责解析 CSS 简写属性的语法。例如，当遇到 CSS 规则 `border-radius: 10px;` 时，`BorderRadius::ParseShorthand` 函数会被调用，将 `10px` 应用于所有四个角的水平和垂直半径。

* **HTML:** HTML 结构定义了网页的内容。CSS 样式通过选择器作用于 HTML 元素。这段代码解析的 CSS 属性会影响最终 HTML 元素的渲染外观。例如，HTML 中一个 `<div>` 元素的样式设置为 `border-left: 1px solid black;`，`BorderLeft::ParseShorthand` 会解析这个规则，从而让 `<div>` 的左边框显示为 1 像素的黑色实线。

* **JavaScript:** JavaScript 可以通过 DOM API (Document Object Model) 操作元素的样式。例如，可以使用 `element.style.borderLeft = '2px dashed red';` 来修改元素的左边框样式。当 JavaScript 设置这些简写属性时，浏览器引擎会再次调用相应的 `ParseShorthand` 函数来解析新的样式值。

**逻辑推理、假设输入与输出举例:**

**假设输入 (CSS 规则):** `border-radius: 5px 10px;`

**`BorderRadius::ParseShorthand` 的逻辑推理:**

1. **读取第一个值 `5px`:**  假设这是一个水平半径值。
2. **读取第二个值 `10px`:** 假设这是一个垂直半径值。
3. **如果只读取到两个值:**
    * 左上角和右下角的水平半径为 `5px`，垂直半径为 `10px`。
    * 右上角和左下角的水平半径为 `10px`，垂直半径为 `5px`。
4. **最终设置：**
   * `border-top-left-radius: 5px 10px;`
   * `border-top-right-radius: 10px 5px;`
   * `border-bottom-right-radius: 5px 10px;`
   * `border-bottom-left-radius: 10px 5px;`

**假设输出 (存储在 `properties` 中):**  会生成四个 `CSSPropertyValue` 对象，分别对应 `border-top-left-radius`, `border-top-right-radius`, `border-bottom-right-radius`, `border-bottom-left-radius`，每个对象都包含一个 `CSSValuePair`，其水平和垂直值分别为 `5px` 和 `10px` 或 `10px` 和 `5px`。

**用户或编程常见的使用错误举例:**

* **`border-radius` 简写顺序错误:** 用户可能会错误地认为 `border-radius: top-left top-right bottom-right bottom-left;`，但实际上其语法更灵活，可以接受 1 到 4 个值，每个值的含义根据值的数量而定。例如，`border-radius: 10px 20px 30px` 是合法的，但其展开方式可能与用户的预期不同。

* **`font` 简写缺少必要属性:** 用户可能只写 `font: 16px;`，这会解析失败，因为 `font-family` 是必需的。正确的写法至少需要包含 `font-size` 和 `font-family`，例如 `font: 16px sans-serif;`。

* **`flex` 简写值的类型错误:** 用户可能错误地将非数字值用于 `flex-grow` 或 `flex-shrink`，例如 `flex: auto 1 0;`，这是不正确的，`flex-grow` 必须是非负数字。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 HTML 文件中编写 CSS 样式:**  这可以是内联样式 (`<div style="border-left: ...">`) 或外部样式表 (`<link rel="stylesheet" href="...">`) 中的规则。
2. **浏览器加载 HTML 文件并开始解析:**  HTML 解析器会遇到 CSS 样式。
3. **CSS 解析器开始解析 CSS 规则:** 当遇到例如 `border-left: 1px solid black;` 这样的规则时，CSS 解析器会识别出 `border-left` 是一个简写属性。
4. **查找对应的 `ParseShorthand` 函数:**  浏览器会查找与 `border-left` 简写属性关联的解析函数，即 `BorderLeft::ParseShorthand`。
5. **`ParseShorthand` 函数被调用:**  CSS 解析器会将 CSS 规则的 token 流传递给 `BorderLeft::ParseShorthand` 函数进行解析。
6. **解析长属性:** `BorderLeft::ParseShorthand` 内部会调用 `css_parsing_utils::ConsumeShorthandGreedilyViaLonghands`，它会尝试解析 `border-left-width`, `border-left-style`, 和 `border-left-color` 的值。
7. **生成 `CSSPropertyValue` 对象:** 解析出的值会被封装到 `CSSPropertyValue` 对象中，存储在 `properties` 容器中。
8. **应用样式:**  这些 `CSSPropertyValue` 对象最终会被用于更新元素的样式，并在渲染树中体现出来。

**作为调试线索:**  当开发者发现元素的样式没有按预期显示时，可以检查浏览器的开发者工具中的 "Styles" 标签，查看应用到元素上的 CSS 规则。如果发现某个简写属性的值不正确，或者某些长属性没有被正确设置，那么可能是 CSS 语法错误，或者与简写属性的解析逻辑有关。开发者可能需要在 Blink 引擎的源代码中查找相关的 `ParseShorthand` 函数，了解其解析逻辑，从而定位问题。例如，如果 `border-radius` 的解析结果不符合预期，开发者可以查看 `BorderRadius::ParseShorthand` 的实现，理解其如何处理不同数量的值。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/shorthands/shorthands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      borderLeftShorthand(), important, context, stream, properties);
}

const CSSValue* BorderLeft::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      borderLeftShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderRadius::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  std::array<CSSValue*, 4> horizontal_radii = {nullptr};
  std::array<CSSValue*, 4> vertical_radii = {nullptr};

  if (!css_parsing_utils::ConsumeRadii(horizontal_radii, vertical_radii, stream,
                                       context,
                                       local_context.UseAliasParsing())) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderTopLeftRadius, CSSPropertyID::kBorderRadius,
      *MakeGarbageCollected<CSSValuePair>(horizontal_radii[0],
                                          vertical_radii[0],
                                          CSSValuePair::kDropIdenticalValues),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderTopRightRadius, CSSPropertyID::kBorderRadius,
      *MakeGarbageCollected<CSSValuePair>(horizontal_radii[1],
                                          vertical_radii[1],
                                          CSSValuePair::kDropIdenticalValues),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderBottomRightRadius, CSSPropertyID::kBorderRadius,
      *MakeGarbageCollected<CSSValuePair>(horizontal_radii[2],
                                          vertical_radii[2],
                                          CSSValuePair::kDropIdenticalValues),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderBottomLeftRadius, CSSPropertyID::kBorderRadius,
      *MakeGarbageCollected<CSSValuePair>(horizontal_radii[3],
                                          vertical_radii[3],
                                          CSSValuePair::kDropIdenticalValues),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  return true;
}

const CSSValue* BorderRadius::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForBorderRadiusShorthand(style);
}

bool BorderRight::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      borderRightShorthand(), important, context, stream, properties);
}

const CSSValue* BorderRight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      borderRightShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderSpacing::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValue* horizontal_spacing = ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kAllow);
  if (!horizontal_spacing) {
    return false;
  }
  CSSValue* vertical_spacing = ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      css_parsing_utils::UnitlessQuirk::kAllow);
  if (!vertical_spacing) {
    vertical_spacing = horizontal_spacing;
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kWebkitBorderHorizontalSpacing,
      CSSPropertyID::kBorderSpacing, *horizontal_spacing, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kWebkitBorderVerticalSpacing,
      CSSPropertyID::kBorderSpacing, *vertical_spacing, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* BorderSpacing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*ZoomAdjustedPixelValue(style.HorizontalBorderSpacing(), style));
  list->Append(*ZoomAdjustedPixelValue(style.VerticalBorderSpacing(), style));
  return list;
}

bool BorderStyle::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      borderStyleShorthand(), important, context, stream, properties);
}

const CSSValue* BorderStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      borderStyleShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderTop::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      borderTopShorthand(), important, context, stream, properties);
}

const CSSValue* BorderTop::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      borderTopShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderWidth::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      borderWidthShorthand(), important, context, stream, properties);
}

const CSSValue* BorderWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      borderWidthShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool ColumnRule::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      columnRuleShorthand(), important, context, stream, properties);
}

const CSSValue* ColumnRule::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      columnRuleShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool Columns::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValue* column_width = nullptr;
  CSSValue* column_count = nullptr;
  if (!css_parsing_utils::ConsumeColumnWidthOrCount(
          stream, context, column_width, column_count)) {
    return false;
  }
  css_parsing_utils::ConsumeColumnWidthOrCount(stream, context, column_width,
                                               column_count);
  if (!column_width) {
    column_width = CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (!column_count) {
    column_count = CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kColumnWidth, CSSPropertyID::kInvalid, *column_width,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kColumnCount, CSSPropertyID::kInvalid, *column_count,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  return true;
}

const CSSValue* Columns::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      columnsShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool ContainIntrinsicSize::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      containIntrinsicSizeShorthand(), important, context, stream, properties);
}

const CSSValue* ContainIntrinsicSize::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StylePropertyShorthand& shorthand = containIntrinsicSizeShorthand();
  const auto& width = style.ContainIntrinsicWidth();
  const auto& height = style.ContainIntrinsicHeight();
  if (width != height) {
    return ComputedStyleUtils::ValuesForShorthandProperty(
        shorthand, style, layout_object, allow_visited_style, value_phase);
  }
  return shorthand.properties()[0]->CSSValueFromComputedStyle(
      style, layout_object, allow_visited_style, value_phase);
}

bool Container::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* name =
      css_parsing_utils::ConsumeContainerName(stream, context);
  if (!name) {
    return false;
  }

  const CSSValue* type = CSSIdentifierValue::Create(CSSValueID::kNormal);
  if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
    if (!(type = css_parsing_utils::ConsumeContainerType(stream))) {
      return false;
    }
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kContainerName, CSSPropertyID::kContainer, *name,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  css_parsing_utils::AddProperty(
      CSSPropertyID::kContainerType, CSSPropertyID::kContainer, *type,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  return true;
}

const CSSValue* Container::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForContainerShorthand(
      style, layout_object, allow_visited_style, value_phase);
}

bool Flex::ParseShorthand(bool important,
                          CSSParserTokenStream& stream,
                          const CSSParserContext& context,
                          const CSSParserLocalContext&,
                          HeapVector<CSSPropertyValue, 64>& properties) const {
  static const double kUnsetValue = -1;
  double flex_grow = kUnsetValue;
  double flex_shrink = kUnsetValue;
  CSSValue* flex_basis = nullptr;

  if (stream.Peek().Id() == CSSValueID::kNone) {
    flex_grow = 0;
    flex_shrink = 0;
    flex_basis = CSSIdentifierValue::Create(CSSValueID::kAuto);
    stream.ConsumeIncludingWhitespace();
  } else {
    for (;;) {
      CSSParserSavePoint savepoint(stream);
      double num;
      if (css_parsing_utils::ConsumeNumberRaw(stream, context, num)) {
        if (num < 0) {
          break;
        }
        if (flex_grow == kUnsetValue) {
          flex_grow = num;
          savepoint.Release();
        } else if (flex_shrink == kUnsetValue) {
          flex_shrink = num;
          savepoint.Release();
        } else if (!num && !flex_basis) {
          // Unitless zero is a valid <'flex-basis'>. All other <length>s
          // must have some unit, and are handled by the other branch.
          flex_basis = CSSNumericLiteralValue::Create(
              0, CSSPrimitiveValue::UnitType::kPixels);
          savepoint.Release();
        } else {
          break;
        }
      } else if (!flex_basis) {
        if (css_parsing_utils::IdentMatches<
                CSSValueID::kAuto, CSSValueID::kContent,
                CSSValueID::kMinContent, CSSValueID::kMaxContent,
                CSSValueID::kFitContent>(stream.Peek().Id())) {
          flex_basis = css_parsing_utils::ConsumeIdent(stream);
        }
        if (RuntimeEnabledFeatures::LayoutStretchEnabled() &&
            CSSValueID::kStretch == stream.Peek().Id()) {
          flex_basis = css_parsing_utils::ConsumeIdent(stream);
        }

        if (!flex_basis) {
          flex_basis = css_parsing_utils::ConsumeLengthOrPercent(
              stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
        }
        if (flex_basis) {
          // <'flex-basis'> may not appear between <'flex-grow'> and
          // <'flex-shrink'>. We therefore ensure that grow and shrink are
          // either both set, or both unset, once <'flex-basis'> is seen.
          if (flex_grow != kUnsetValue && flex_shrink == kUnsetValue) {
            flex_shrink = 1;
          }
          DCHECK_EQ(flex_grow == kUnsetValue, flex_shrink == kUnsetValue);
          savepoint.Release();
        } else {
          break;
        }
      } else {
        break;
      }
    }
    if (flex_grow == kUnsetValue && flex_shrink == kUnsetValue && !flex_basis) {
      return false;
    }
    if (flex_grow == kUnsetValue) {
      flex_grow = 1;
    }
    if (flex_shrink == kUnsetValue) {
      flex_shrink = 1;
    }
    if (!flex_basis) {
      flex_basis = CSSNumericLiteralValue::Create(
          0, CSSPrimitiveValue::UnitType::kPercentage);
    }
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFlexGrow, CSSPropertyID::kFlex,
      *CSSNumericLiteralValue::Create(ClampTo<float>(flex_grow),
                                      CSSPrimitiveValue::UnitType::kNumber),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFlexShrink, CSSPropertyID::kFlex,
      *CSSNumericLiteralValue::Create(ClampTo<float>(flex_shrink),
                                      CSSPrimitiveValue::UnitType::kNumber),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFlexBasis, CSSPropertyID::kFlex, *flex_basis, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* Flex::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      flexShorthand(), style, layout_object, allow_visited_style, value_phase);
}

bool FlexFlow::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      flexFlowShorthand(), important, context, stream, properties,
      /* use_initial_value_function */ true);
}

const CSSValue* FlexFlow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      flexFlowShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}
namespace {

bool ConsumeSystemFont(bool important,
                       CSSParserTokenStream& stream,
                       HeapVector<CSSPropertyValue, 64>& properties) {
  CSSValueID system_font_id = stream.ConsumeIncludingWhitespace().Id();
  DCHECK(CSSParserFastPaths::IsValidSystemFont(system_font_id));

  css_parsing_utils::AddExpandedPropertyForValue(
      CSSPropertyID::kFont,
      *cssvalue::CSSPendingSystemFontValue::Create(system_font_id), important,
      properties);
  return true;
}

bool ConsumeFont(bool important,
                 CSSParserTokenStream& stream,
                 const CSSParserContext& context,
                 HeapVector<CSSPropertyValue, 64>& properties) {
  // Optional font-style, font-variant, font-stretch and font-weight.
  // Each may be normal.
  CSSValue* font_style = nullptr;
  CSSIdentifierValue* font_variant_caps = nullptr;
  CSSValue* font_weight = nullptr;
  CSSValue* font_stretch = nullptr;
  const int kNumReorderableFontProperties = 4;
  for (int i = 0; i < kNumReorderableFontProperties && !stream.AtEnd(); ++i) {
    CSSValueID id = stream.Peek().Id();
    if (id == CSSValueID::kNormal) {
      css_parsing_utils::ConsumeIdent(stream);
      continue;
    }
    if (!font_style &&
        (id == CSSValueID::kItalic || id == CSSValueID::kOblique)) {
      font_style = css_parsing_utils::ConsumeFontStyle(stream, context);
      if (!font_style) {
        // NOTE: Strictly speaking, perhaps we should rewind the stream here
        // and return true instead, but given that this rule exists solely
        // for accepting !important, we can just as well give a parse error.
        return false;
      }
      continue;
    }
    if (!font_variant_caps && id == CSSValueID::kSmallCaps) {
      // Font variant in the shorthand is particular, it only accepts normal
      // or small-caps. See https://drafts.csswg.org/css-fonts/#propdef-font
      font_variant_caps = css_parsing_utils::ConsumeFontVariantCSS21(stream);
      if (font_variant_caps) {
        continue;
      }
    }
    if (!font_weight) {
      font_weight = css_parsing_utils::ConsumeFontWeight(stream, context);
      if (font_weight) {
        continue;
      }
    }
    // Stretch in the font shorthand can only take the CSS Fonts Level 3
    // keywords, not arbitrary values, compare
    // https://drafts.csswg.org/css-fonts-4/#font-prop
    // Bail out if the last possible property of the set in this loop could
    // not be parsed, this closes the first block of optional values of the
    // font shorthand, compare: [ [ <‘font-style’> || <font-variant-css21> ||
    // <‘font-weight’> || <font-stretch-css3> ]?
    if (font_stretch ||
        !(font_stretch = css_parsing_utils::ConsumeFontStretchKeywordOnly(
              stream, context))) {
      break;
    }
  }

  if (stream.AtEnd()) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontStyle, CSSPropertyID::kFont,
      font_style ? *font_style
                 : *CSSIdentifierValue::Create(CSSValueID::kNormal),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantCaps, CSSPropertyID::kFont,
      font_variant_caps ? *font_variant_caps
                        : *CSSIdentifierValue::Create(CSSValueID::kNormal),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  // All subproperties of the font, i.e. font-size-adjust, font-kerning, all
  // subproperties of font-variant, font-feature-settings,
  // font-language-override, font-optical-sizing and font-variation-settings
  // property should be reset to their initial values, compare
  // https://drafts.csswg.org/css-fonts-4/#font-prop
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantLigatures, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantNumeric, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantEastAsian, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantAlternates, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  if (RuntimeEnabledFeatures::CSSFontSizeAdjustEnabled()) {
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontSizeAdjust, CSSPropertyID::kFont,
        *CSSIdentifierValue::Create(CSSValueID::kNone), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontKerning, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kAuto), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontOpticalSizing, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kAuto), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontFeatureSettings, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariationSettings, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantPosition, CSSPropertyID::kFont,
      *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  if (RuntimeEnabledFeatures::FontVariantEmojiEnabled()) {
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantEmoji, CSSPropertyID::kFont,
        *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontWeight, CSSPropertyID::kFont,
      font_weight ? *font_weight
                  : *CSSIdentifierValue::Create(CSSValueID::kNormal),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontStretch, CSSPropertyID::kFont,
      font_stretch ? *font_stretch
                   : *CSSIdentifierValue::Create(CSSValueID::kNormal),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  // Now a font size _must_ come.
  CSSValue* font_size = css_parsing_utils::ConsumeFontSize(stream, context);
  if (!font_size || stream.AtEnd()) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontSize, CSSPropertyID::kFont, *font_size, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
    CSSValue* line_height =
        css_parsing_utils::ConsumeLineHeight(stream, context);
    if (!line_height) {
      return false;
    }
    css_parsing_utils::AddProperty(
        CSSPropertyID::kLineHeight, CSSPropertyID::kFont, *line_height,
        important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
        properties);
  } else {
    css_parsing_utils::AddProperty(
        CSSPropertyID::kLineHeight, CSSPropertyID::kFont,
        *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  }

  // Font family must come now.
  CSSValue* parsed_family_value = css_parsing_utils::ConsumeFontFamily(stream);
  if (!parsed_family_value) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontFamily, CSSPropertyID::kFont, *parsed_family_value,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  return true;
}

}  // namespace

bool Font::ParseShorthand(bool important,
                          CSSParserTokenStream& stream,
                          const CSSParserContext& context,
                          const CSSParserLocalContext&,
                          HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSParserToken& token = stream.Peek();
  if (CSSParserFastPaths::IsValidSystemFont(token.Id())) {
    return ConsumeSystemFont(important, stream, properties);
  }
  return ConsumeFont(important, stream, context, properties);
}

const CSSValue* Font::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFont(style);
}

bool FontVariant::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  if (css_parsing_utils::IdentMatches<CSSValueID::kNormal, CSSValueID::kNone>(
          stream.Peek().Id())) {
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantLigatures, CSSPropertyID::kFontVariant,
        *css_parsing_utils::ConsumeIdent(stream), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantCaps, CSSPropertyID::kFontVariant,
        *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantNumeric, CSSPropertyID::kFontVariant,
        *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantEastAsian, CSSPropertyID::kFontVariant,
        *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantAlternates, CSSPropertyID::kFontVariant,
        *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantPosition, CSSPropertyID::kFontVariant,
        *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    if (RuntimeEnabledFeatures::FontVariantEmojiEnabled()) {
      css_parsing_utils::AddProperty(
          CSSPropertyID::kFontVariantEmoji, CSSPropertyID::kFontVariant,
          *CSSIdentifierValue::Create(CSSValueID::kNormal), important,
          css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    }
    return true;
  }

  CSSIdentifierValue* caps_value = nullptr;
  FontVariantLigaturesParser ligatures_parser;
  FontVariantNumericParser numeric_parser;
  FontVariantEastAsianParser east_asian_parser;
  FontVariantAlternatesParser alternates_parser;
  CSSIdentifierValue* position_value = nullptr;
  CSSIdentifierValue* emoji_value = nullptr;
  bool first_value = true;
  do {
    FontVariantLigaturesParser::ParseResult ligatures_parse_result =
        ligatures_parser.ConsumeLigature(stream);
    FontVariantNumericParser::ParseResult numeric_parse_result =
        numeric_parser.ConsumeNumeric(stream);
    FontVariantEastAsianParser::ParseResult east_asian_parse_result =
        east_asian_parser.ConsumeEastAsian(stream);
    FontVariantAlternatesParser::ParseResult alternates_parse_result =
        alternates_parser.ConsumeAlternates(stream, context);
    if (ligatures_parse_result ==
            FontVariantLigaturesParser::ParseResult::kConsumedValue ||
        numeric_parse_result ==
            FontVariantNumericParser::ParseResult::kConsumedValue ||
        east_asian_parse_result ==
            FontVariantEastAsianParser::ParseResult::kConsumedValue ||
        alternates_parse_result ==
            FontVariantAlternatesParser::ParseResult::kConsumedValue) {
      first_value = false;
      continue;
    }

    if (ligatures_parse_result ==
            FontVariantLigaturesParser::ParseResult::kDisallowedValue ||
        numeric_parse_result ==
            FontVariantNumericParser::ParseResult::kDisallowedValue ||
        east_asian_parse_result ==
            FontVariantEastAsianParser::ParseResult::kDisallowedValue ||
        alternates_parse_result ==
            FontVariantAlternatesParser::ParseResult::kDisallowedValue) {
      return false;
    }

    CSSValueID id = stream.Peek().Id();
    bool fail = false;
    switch (id) {
      case CSSValueID::kSmallCaps:
      case CSSValueID::kAllSmallCaps:
      case CSSValueID::kPetiteCaps:
      case CSSValueID::kAllPetiteCaps:
      case CSSValueID::kUnicase:
      case CSSValueID::kTitlingCaps:
        // Only one caps value permitted in font-variant grammar.
        if (caps_value) {
          return false;
        }
        caps_value = css_parsing_utils::ConsumeIdent(stream);
        break;
      case CSSValueID::kSub:
      case CSSValueID::kSuper:
        // Only one position value permitted in font-variant grammar.
        if (position_value) {
          return false;
        }
        position_value = css_parsing_utils::ConsumeIdent(stream);
        break;
      case CSSValueID::kText:
      case CSSValueID::kEmoji:
      case CSSValueID::kUnicode:
        if (!RuntimeEnabledFeatures::FontVariantEmojiEnabled()) {
          return false;
        }
        // Only one emoji value permitted in font-variant grammar.
        if (emoji_value) {
          return false;
        }
        emoji_value = css_parsing_utils::ConsumeIdent(stream);
        break;
      default:
        // Random junk at the end is allowed (could be “!important”,
        // and if it's not, the caller will reject the value for us).
        fail = true;
        break;
    }
    if (fail) {
      if (first_value) {
        // Need at least one good value.
        return false;
      }
      break;
    }
    first_value = false;
  } while (!stream.AtEnd());

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantLigatures, CSSPropertyID::kFontVariant,
      *ligatures_parser.FinalizeValue(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantNumeric, CSSPropertyID::kFontVariant,
      *numeric_parser.FinalizeValue(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantEastAsian, CSSPropertyID::kFontVariant,
      *east_asian_parser.FinalizeValue(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantCaps, CSSPropertyID::kFontVariant,
      caps_value ? *caps_value
                 : *CSSIdentifierValue::Create(CSSValueID::kNormal),
      important, css_parsing_utils::IsImplicitProperty::kNo
"""


```