Response:
The user wants a summary of the provided C++ code snippet, which is part of the Chromium Blink rendering engine. This file (`shorthands_custom.cc`) seems to define how certain CSS shorthand properties are parsed and handled.

Here's a breakdown of the request and how to approach it:

1. **List Functionality:** Identify the core purpose of the code. It's about handling CSS shorthand properties.
2. **Relationship to Web Technologies:** Determine how this code interacts with JavaScript, HTML, and CSS. It directly deals with CSS parsing and how CSS properties are interpreted by the browser.
3. **Logic and Examples:** Analyze the parsing logic for specific shorthand properties and provide concrete examples of CSS input and the resulting internal representation (though this is difficult without deep knowledge of Blink's internal data structures). Focus on how the shorthand is broken down into its longhand components.
4. **Common Errors:** Think about potential mistakes a user or developer could make when using these CSS properties, which would be caught or handled by this code.
5. **User Journey:** Trace back how a user action leads to this code being executed. This is related to the browser's rendering pipeline.
6. **Part 4 Summary:**  Synthesize the information from the previous steps into a concise summary of the file's purpose.

**Mental Sandbox:**

* **Focus on the `ParseShorthand` methods:** These are the primary entry points for processing the CSS.
* **Look for patterns:** Many of these methods follow a similar structure using `css_parsing_utils`.
* **Consider the role of `ComputedStyle`:**  The `CSSValueFromComputedStyleInternal` methods are responsible for converting the internal representation back into CSS values for display.
* **Think about the web development workflow:**  A developer writes CSS, the browser parses it, and then uses the parsed values to render the page. This file is in the parsing stage.

**Constraint Checklist & Confidence Score:**

* List functionality: Yes
* Relationship to JS/HTML/CSS: Yes
* Examples: Yes (with some level of abstraction due to internal data structures)
* Logic/Input/Output: Yes (focused on parsing logic and conceptual output)
* Common Errors: Yes
* User Journey: Yes
* Part 4 Summary: Yes

Confidence Score: 4/5 (Slight uncertainty in providing very precise input/output examples without more internal knowledge).

**Strategizing complete. Proceeding with response generation.**
这是 `blink/renderer/core/css/properties/shorthands/shorthands_custom.cc` 文件的第四部分，该文件是 Chromium Blink 引擎中处理 **自定义 CSS 简写属性** 的代码。根据代码内容，可以归纳出以下功能：

**主要功能： 定义和实现特定 CSS 简写属性的解析和计算值生成逻辑。**

这个文件中的代码主要包含了一系列结构体（例如 `MasonryTrack`, `Offset`, `Outline`, `Overflow` 等），每个结构体对应一个特定的 CSS 简写属性。这些结构体都实现了以下几个核心方法：

* **`ParseShorthand`**:  这个方法负责解析 CSS 样式表中该简写属性的值。它接收 CSS 解析器令牌流 (`CSSParserTokenStream`)，并尝试从流中提取出构成该简写属性的各个组成部分的值。解析成功后，会将这些值分别设置到对应的长写属性中。
* **`CSSValueFromComputedStyleInternal`**: 这个方法负责根据元素的计算样式 (`ComputedStyle`)，生成该简写属性的 CSSValue 对象。这通常涉及到从构成该简写属性的各个长写属性的值中提取信息，并将其组合成一个表示简写属性值的 CSSValue。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接参与了 **CSS 的解析和应用** 过程，是浏览器理解和处理 CSS 样式的关键部分。

* **CSS**:  文件中定义的每个结构体都对应一个或多个 CSS 简写属性。例如，`Offset` 结构体处理 `offset` 简写属性，`Padding` 结构体处理 `padding` 简写属性。这些简写属性方便开发者用更简洁的方式设置多个相关的 CSS 属性。
    * **例子 (CSS):**
        ```css
        .element {
          padding: 10px 20px; /* padding 简写属性 */
          offset: 10px 20px path('M 0 0 L 100 100') rotate(45deg); /* offset 简写属性 */
        }
        ```
* **HTML**:  HTML 结构通过 CSS 样式进行渲染。当浏览器解析 HTML 时，会遇到 `<style>` 标签或外部 CSS 文件链接，然后调用 CSS 解析器来处理这些样式。本文件中的代码就是 CSS 解析器的一部分，负责理解和转换 CSS 样式规则。
    * **例子 (HTML):**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            .box {
              padding: 15px;
              background-color: lightblue;
            }
          </style>
        </head>
        <body>
          <div class="box">This is a box.</div>
        </body>
        </html>
        ```
* **JavaScript**: JavaScript 可以动态地修改元素的 CSS 样式。当 JavaScript 修改元素的样式时，浏览器需要重新解析和应用这些样式。本文件中的代码在浏览器处理这些动态修改的 CSS 时也会被调用。
    * **例子 (JavaScript):**
        ```javascript
        const element = document.querySelector('.box');
        element.style.padding = '20px 30px'; // 修改 padding 简写属性
        ```

**逻辑推理、假设输入与输出：**

以 `Padding` 结构体的 `ParseShorthand` 方法为例：

**假设输入 (CSS 样式字符串):** `padding: 10px 20px 30px 40px;`

**逻辑推理:** `ParseShorthand` 方法会使用 `css_parsing_utils::ConsumeShorthandVia4Longhands` 函数，这个函数会尝试从令牌流中解析出四个长度值。然后，它会将这些值分别设置到 `padding-top`, `padding-right`, `padding-bottom`, `padding-left` 这四个长写属性中。

**假设输出 (内部表示):**  `properties` 向量会包含四个 `CSSPropertyValue` 对象，分别对应：

* `padding-top: 10px`
* `padding-right: 20px`
* `padding-bottom: 30px`
* `padding-left: 40px`

**假设输入 (CSS 样式字符串):** `padding: 10px 20px;`

**逻辑推理:** `ConsumeShorthandVia4Longhands` 会处理少于四个值的情况，根据 CSS 规范，会进行值的复制和补全。

**假设输出 (内部表示):**

* `padding-top: 10px`
* `padding-right: 20px`
* `padding-bottom: 10px`
* `padding-left: 20px`

**涉及用户或编程常见的使用错误：**

* **提供无效的简写属性值:** 例如，`padding: 10px invalid;`，解析器会因为遇到无法识别的 `invalid` 关键字而解析失败。
* **简写属性值的顺序错误:** 虽然 `padding` 属性有一定的灵活性，但某些简写属性对值的顺序有严格要求。例如，`offset-path` 和 `offset-distance` 的顺序不能随意颠倒。
* **忘记提供必要的值:** 某些简写属性可能需要至少提供一个值，如果完全省略，可能会导致解析失败或使用默认值。
* **在不支持的浏览器中使用新的简写属性:**  例如，`masonry-track` 是一个相对较新的属性，在一些旧版本的浏览器中可能无法识别和解析。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在 HTML 文件或外部 CSS 文件中编写 CSS 样式，使用了简写属性。**
2. **浏览器加载并解析 HTML 文件。**
3. **当解析器遇到 CSS 样式规则时，会将其分解成令牌流。**
4. **对于遇到简写属性，例如 `padding: 10px;`，CSS 解析器会查找对应的处理函数，本例中会进入 `Padding::ParseShorthand` 方法。**
5. **`ParseShorthand` 方法会进一步调用 `css_parsing_utils` 中的辅助函数来解析属性值。**
6. **解析成功后，会将解析出的值存储在内部数据结构中，最终影响元素的渲染结果。**
7. **如果解析过程中出现错误，浏览器可能会忽略该样式规则或使用默认值，并在开发者工具中报告错误。**

**归纳一下它的功能 (第 4 部分):**

这部分代码主要负责定义并实现了 **多个 CSS 简写属性** 的解析逻辑和计算值生成方式。它确保了浏览器能够正确理解和应用开发者在 CSS 中使用的这些简写属性，并将它们转换为浏览器内部可以处理的长写属性值。 这些结构体通过 `ParseShorthand` 方法将 CSS 字符串转换为内部表示，并通过 `CSSValueFromComputedStyleInternal` 方法根据计算样式生成最终的 CSS 值，从而连接了 CSS 语法和浏览器的渲染过程。  它涵盖了包括布局相关的 `masonry-track`、定位相关的 `offset`、边框相关的 `outline`、溢出相关的 `overflow` 以及内外边距、滚动相关的多个简写属性的处理。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/shorthands/shorthands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
)) {
    return marker_start;
  }
  return nullptr;
}

bool MasonryTrack::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const auto& shorthand = shorthandForProperty(CSSPropertyID::kMasonryTrack);
  DCHECK_EQ(shorthand.length(), 2u);

  CSSValue *start_value = nullptr, *end_value = nullptr;
  if (!css_parsing_utils::ConsumeGridItemPositionShorthand(
          important, stream, context, start_value, end_value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      shorthand.properties()[0]->PropertyID(), CSSPropertyID::kMasonryTrack,
      *start_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      shorthand.properties()[1]->PropertyID(), CSSPropertyID::kMasonryTrack,
      *end_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* MasonryTrack::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridLineShorthand(
      masonryTrackShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool Offset::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  // TODO(meade): The propertyID parameter isn't used - it can be removed
  // once all of the ParseSingleValue implementations have been moved to the
  // CSSPropertys, and the base CSSProperty::ParseSingleValue contains
  // no functionality.

  const CSSValue* offset_position =
      GetCSSPropertyOffsetPosition().ParseSingleValue(stream, context,
                                                      CSSParserLocalContext());
  const CSSValue* offset_path =
      css_parsing_utils::ConsumeOffsetPath(stream, context);
  const CSSValue* offset_distance = nullptr;
  const CSSValue* offset_rotate = nullptr;
  if (offset_path) {
    offset_distance = css_parsing_utils::ConsumeLengthOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kAll);
    offset_rotate = css_parsing_utils::ConsumeOffsetRotate(stream, context);
    if (offset_rotate && !offset_distance) {
      offset_distance = css_parsing_utils::ConsumeLengthOrPercent(
          stream, context, CSSPrimitiveValue::ValueRange::kAll);
    }
  }
  const CSSValue* offset_anchor = nullptr;
  if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
    offset_anchor = GetCSSPropertyOffsetAnchor().ParseSingleValue(
        stream, context, CSSParserLocalContext());
    if (!offset_anchor) {
      return false;
    }
  }
  if (!offset_position && !offset_path) {
    return false;
  }

  if (!offset_position) {
    offset_position = CSSIdentifierValue::Create(CSSValueID::kNormal);
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kOffsetPosition, CSSPropertyID::kOffset, *offset_position,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  if (!offset_path) {
    offset_path = CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kOffsetPath, CSSPropertyID::kOffset, *offset_path,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  if (!offset_distance) {
    offset_distance =
        CSSNumericLiteralValue::Create(0, CSSPrimitiveValue::UnitType::kPixels);
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kOffsetDistance, CSSPropertyID::kOffset, *offset_distance,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  if (!offset_rotate) {
    offset_rotate = CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kOffsetRotate, CSSPropertyID::kOffset, *offset_rotate,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  if (!offset_anchor) {
    offset_anchor = CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kOffsetAnchor, CSSPropertyID::kOffset, *offset_anchor,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  return true;
}

const CSSValue* Offset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForOffset(style, layout_object,
                                            allow_visited_style, value_phase);
}

bool Outline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      outlineShorthand(), important, context, stream, properties);
}

const CSSValue* Outline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      outlineShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool Overflow::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      overflowShorthand(), important, context, stream, properties);
}

const CSSValue* Overflow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSIdentifierValue::Create(style.OverflowX()));
  if (style.OverflowX() != style.OverflowY()) {
    list->Append(*CSSIdentifierValue::Create(style.OverflowY()));
  }

  return list;
}

bool OverscrollBehavior::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      overscrollBehaviorShorthand(), important, context, stream, properties);
}

const CSSValue* OverscrollBehavior::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSIdentifierValue::Create(style.OverscrollBehaviorX()));
  if (style.OverscrollBehaviorX() != style.OverscrollBehaviorY()) {
    list->Append(*CSSIdentifierValue::Create(style.OverscrollBehaviorY()));
  }

  return list;
}

bool PaddingBlock::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      paddingBlockShorthand(), important, context, stream, properties);
}

const CSSValue* PaddingBlock::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      paddingBlockShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool Padding::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      paddingShorthand(), important, context, stream, properties);
}

bool Padding::IsLayoutDependent(const ComputedStyle* style,
                                LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->PaddingBottom().IsFixed() ||
          !style->PaddingTop().IsFixed() || !style->PaddingLeft().IsFixed() ||
          !style->PaddingRight().IsFixed());
}

const CSSValue* Padding::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      paddingShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool PaddingInline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      paddingInlineShorthand(), important, context, stream, properties);
}

const CSSValue* PaddingInline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      paddingInlineShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool PageBreakAfter::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValueID value;
  if (!css_parsing_utils::ConsumeFromPageBreakBetween(stream, value)) {
    return false;
  }

  DCHECK(IsValidCSSValueID(value));
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBreakAfter, CSSPropertyID::kPageBreakAfter,
      *CSSIdentifierValue::Create(value), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* PageBreakAfter::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPageBreakBetween(style.BreakAfter());
}

bool PageBreakBefore::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValueID value;
  if (!css_parsing_utils::ConsumeFromPageBreakBetween(stream, value)) {
    return false;
  }

  DCHECK(IsValidCSSValueID(value));
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBreakBefore, CSSPropertyID::kPageBreakBefore,
      *CSSIdentifierValue::Create(value), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* PageBreakBefore::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPageBreakBetween(style.BreakBefore());
}

bool PageBreakInside::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValueID value;
  if (!css_parsing_utils::ConsumeFromColumnOrPageBreakInside(stream, value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kBreakInside, CSSPropertyID::kPageBreakInside,
      *CSSIdentifierValue::Create(value), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* PageBreakInside::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPageBreakInside(style.BreakInside());
}

bool PlaceContent::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(shorthandForProperty(CSSPropertyID::kPlaceContent).length(), 2u);

  stream.EnsureLookAhead();

  CSSParserTokenStream::State savepoint = stream.Save();
  bool is_baseline = css_parsing_utils::IsBaselineKeyword(stream.Peek().Id());
  const CSSValue* align_content_value =
      GetCSSPropertyAlignContent().ParseSingleValue(stream, context,
                                                    local_context);
  if (!align_content_value) {
    return false;
  }

  const CSSValue* justify_content_value =
      GetCSSPropertyJustifyContent().ParseSingleValue(stream, context,
                                                      local_context);
  if (!justify_content_value) {
    if (is_baseline) {
      justify_content_value =
          MakeGarbageCollected<cssvalue::CSSContentDistributionValue>(
              CSSValueID::kInvalid, CSSValueID::kStart, CSSValueID::kInvalid);
    } else {
      // Rewind the parser and use the value we just parsed as align-content,
      // as justify-content, too.
      stream.Restore(savepoint);
      justify_content_value = GetCSSPropertyJustifyContent().ParseSingleValue(
          stream, context, local_context);
    }
  }
  if (!justify_content_value) {
    return false;
  }

  DCHECK(align_content_value);
  DCHECK(justify_content_value);

  css_parsing_utils::AddProperty(
      CSSPropertyID::kAlignContent, CSSPropertyID::kPlaceContent,
      *align_content_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kJustifyContent, CSSPropertyID::kPlaceContent,
      *justify_content_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* PlaceContent::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForPlaceShorthand(
      placeContentShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool PlaceItems::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(shorthandForProperty(CSSPropertyID::kPlaceItems).length(), 2u);

  stream.EnsureLookAhead();
  CSSParserTokenStream::State savepoint = stream.Save();
  const CSSValue* align_items_value =
      GetCSSPropertyAlignItems().ParseSingleValue(stream, context,
                                                  local_context);
  if (!align_items_value) {
    return false;
  }

  const CSSValue* justify_items_value =
      GetCSSPropertyJustifyItems().ParseSingleValue(stream, context,
                                                    local_context);
  if (!justify_items_value) {
    // End-of-stream or parse error. If it's the former,
    // we try to to parse what we already parsed as align-items again,
    // just as justify-items. If it's the latter, the caller will
    // clean up for us (as we won't end on end-of-stream).
    wtf_size_t align_items_end = stream.Offset();
    stream.Restore(savepoint);
    justify_items_value = GetCSSPropertyJustifyItems().ParseSingleValue(
        stream, context, local_context);
    if (!justify_items_value || stream.Offset() != align_items_end) {
      return false;
    }
  }

  DCHECK(align_items_value);
  DCHECK(justify_items_value);

  css_parsing_utils::AddProperty(
      CSSPropertyID::kAlignItems, CSSPropertyID::kPlaceItems,
      *align_items_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kJustifyItems, CSSPropertyID::kPlaceItems,
      *justify_items_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* PlaceItems::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForPlaceShorthand(
      placeItemsShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool PlaceSelf::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(shorthandForProperty(CSSPropertyID::kPlaceSelf).length(), 2u);

  stream.EnsureLookAhead();
  CSSParserTokenStream::State savepoint = stream.Save();

  const CSSValue* align_self_value = GetCSSPropertyAlignSelf().ParseSingleValue(
      stream, context, local_context);
  if (!align_self_value) {
    return false;
  }

  const CSSValue* justify_self_value =
      GetCSSPropertyJustifySelf().ParseSingleValue(stream, context,
                                                   local_context);
  if (!justify_self_value) {
    // End-of-stream or parse error. If it's the former,
    // we try to to parse what we already parsed as align-items again,
    // just as justify-items. If it's the latter, the caller will
    // clean up for us (as we won't end on end-of-stream).
    wtf_size_t align_items_end = stream.Offset();
    stream.Restore(savepoint);
    justify_self_value = GetCSSPropertyJustifySelf().ParseSingleValue(
        stream, context, local_context);
    if (!justify_self_value || stream.Offset() != align_items_end) {
      return false;
    }
  }

  DCHECK(align_self_value);
  DCHECK(justify_self_value);

  css_parsing_utils::AddProperty(
      CSSPropertyID::kAlignSelf, CSSPropertyID::kPlaceSelf, *align_self_value,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kJustifySelf, CSSPropertyID::kPlaceSelf,
      *justify_self_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* PlaceSelf::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForPlaceShorthand(
      placeSelfShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

namespace {

bool ParsePositionTryShorthand(const StylePropertyShorthand& shorthand,
                               bool important,
                               CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               const CSSParserLocalContext& local_context,
                               HeapVector<CSSPropertyValue, 64>& properties) {
  CHECK_EQ(shorthand.length(), 2u);
  CHECK_EQ(shorthand.properties()[0], &GetCSSPropertyPositionTryOrder());
  const CSSValue* order = css_parsing_utils::ParseLonghand(
      CSSPropertyID::kPositionTryOrder, CSSPropertyID::kPositionTry, context,
      stream);
  if (!order) {
    order = GetCSSPropertyPositionTryOrder().InitialValue();
  }
  AddProperty(CSSPropertyID::kPositionTryOrder, CSSPropertyID::kPositionTry,
              *order, important,
              css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  CSSPropertyID fallbacks_id = shorthand.properties()[1]->PropertyID();
  if (const CSSValue* fallbacks = css_parsing_utils::ParseLonghand(
          fallbacks_id, CSSPropertyID::kPositionTry, context, stream)) {
    css_parsing_utils::AddProperty(
        fallbacks_id, CSSPropertyID::kPositionTry, *fallbacks, important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    return true;
  }
  return false;
}

}  // namespace

bool PositionTry::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return ParsePositionTryShorthand(positionTryShorthand(), important, stream,
                                   context, local_context, properties);
}

const CSSValue* PositionTry::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (EPositionTryOrder order = style.PositionTryOrder();
      order != ComputedStyleInitialValues::InitialPositionTryOrder()) {
    list->Append(*CSSIdentifierValue::Create(order));
  }
  if (const PositionTryFallbacks* fallbacks = style.GetPositionTryFallbacks()) {
    list->Append(*ComputedStyleUtils::ValueForPositionTryFallbacks(*fallbacks));
  } else {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
  }
  return list;
}

bool ScrollMarginBlock::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      scrollMarginBlockShorthand(), important, context, stream, properties);
}

const CSSValue* ScrollMarginBlock::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      scrollMarginBlockShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool ScrollMargin::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      scrollMarginShorthand(), important, context, stream, properties);
}

const CSSValue* ScrollMargin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      scrollMarginShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool ScrollMarginInline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      scrollMarginInlineShorthand(), important, context, stream, properties);
}

const CSSValue* ScrollMarginInline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      scrollMarginInlineShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool ScrollPaddingBlock::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      scrollPaddingBlockShorthand(), important, context, stream, properties);
}

const CSSValue* ScrollPaddingBlock::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      scrollPaddingBlockShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool ScrollPadding::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      scrollPaddingShorthand(), important, context, stream, properties);
}

const CSSValue* ScrollPadding::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      scrollPaddingShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool ScrollPaddingInline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      scrollPaddingInlineShorthand(), important, context, stream, properties);
}

const CSSValue* ScrollPaddingInline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      scrollPaddingInlineShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

namespace {

// Consume a single name, axis, and optionally inset, then append the result
// to `name_list`, `axis_list`, and `inset_list` respectively.
//
// Insets are only relevant for the view-timeline shorthand, and not for
// the scroll-timeline shorthand, hence `inset_list` may be nullptr.
//
// https://drafts.csswg.org/scroll-animations-1/#view-timeline-shorthand
// https://drafts.csswg.org/scroll-animations-1/#scroll-timeline-shorthand
bool ConsumeTimelineItemInto(CSSParserTokenStream& stream,
                             const CSSParserContext& context,
                             CSSValueList* name_list,
                             CSSValueList* axis_list,
                             CSSValueList* inset_list) {
  using css_parsing_utils::ConsumeSingleTimelineAxis;
  using css_parsing_utils::ConsumeSingleTimelineInset;
  using css_parsing_utils::ConsumeSingleTimelineName;

  CSSValue* name = ConsumeSingleTimelineName(stream, context);

  if (!name) {
    return false;
  }

  CSSValue* axis = nullptr;
  CSSValue* inset = nullptr;

  // [ <'view-timeline-axis'> || <'view-timeline-inset'> ]
  while (true) {
    if (!axis && (axis = ConsumeSingleTimelineAxis(stream))) {
      continue;
    }
    if (inset_list && !inset &&
        (inset = ConsumeSingleTimelineInset(stream, context))) {
      continue;
    }
    break;
  }

  if (!axis) {
    axis = CSSIdentifierValue::Create(CSSValueID::kBlock);
  }
  if (inset_list && !inset) {
    inset = MakeGarbageCollected<CSSValuePair>(
        CSSIdentifierValue::Create(CSSValueID::kAuto),
        CSSIdentifierValue::Create(CSSValueID::kAuto),
        CSSValuePair::kDropIdenticalValues);
  }

  DCHECK(name_list);
  DCHECK(axis_list);
  name_list->Append(*name);
  axis_list->Append(*axis);
  if (inset) {
    DCHECK(inset_list);
    inset_list->Append(*inset);
  }

  return true;
}

bool ParseTimelineShorthand(CSSPropertyID shorthand_id,
                            const StylePropertyShorthand& shorthand,
                            bool important,
                            CSSParserTokenStream& stream,
                            const CSSParserContext& context,
                            const CSSParserLocalContext&,
                            HeapVector<CSSPropertyValue, 64>& properties) {
  using css_parsing_utils::AddProperty;
  using css_parsing_utils::ConsumeCommaIncludingWhitespace;
  using css_parsing_utils::IsImplicitProperty;

  CSSValueList* name_list = CSSValueList::CreateCommaSeparated();
  CSSValueList* axis_list = CSSValueList::CreateCommaSeparated();
  CSSValueList* inset_list =
      shorthand.length() == 3u ? CSSValueList::CreateCommaSeparated() : nullptr;

  do {
    if (!ConsumeTimelineItemInto(stream, context, name_list, axis_list,
                                 inset_list)) {
      return false;
    }
  } while (ConsumeCommaIncludingWhitespace(stream));

  DCHECK(name_list->length());
  DCHECK(axis_list->length());
  DCHECK(!inset_list || inset_list->length());
  DCHECK_EQ(name_list->length(), axis_list->length());
  DCHECK_EQ(inset_list ? name_list->length() : 0,
            inset_list ? inset_list->length() : 0);

  DCHECK_GE(shorthand.length(), 2u);
  DCHECK_LE(shorthand.length(), 3u);
  AddProperty(shorthand.properties()[0]->PropertyID(), shorthand_id, *name_list,
              important, IsImplicitProperty::kNotImplicit, properties);
  AddProperty(shorthand.properties()[1]->PropertyID(), shorthand_id, *axis_list,
              important, IsImplicitProperty::kNotImplicit, properties);
  if (inset_list) {
    DCHECK_EQ(shorthand.length(), 3u);
    AddProperty(shorthand.properties()[2]->PropertyID(), shorthand_id,
                *inset_list, important, IsImplicitProperty::kNotImplicit,
                properties);
  }

  return true;
}

static CSSValue* CSSValueForTimelineShorthand(
    const HeapVector<Member<const ScopedCSSName>>& name_vector,
    const Vector<TimelineAxis>& axis_vector,
    const Vector<TimelineInset>* inset_vector,
    const ComputedStyle& style) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();

  if (name_vector.size() != axis_vector.size()) {
    return list;
  }
  if (inset_vector && name_vector.size() != inset_vector->size()) {
    return list;
  }
  if (name_vector.empty()) {
    list->Append(*ComputedStyleUtils::SingleValueForTimelineShorthand(
        /* name */ nullptr, TimelineAxis::kBlock, /* inset */ std::nullopt,
        style));
    return list;
  }
  for (wtf_size_t i = 0; i < name_vector.size(); ++i) {
    list->Append(*ComputedStyleUtils::SingleValueForTimelineShorthand(
        name_vector[i].Get(), axis_vector[i],
        inset_vector ? std::optional<TimelineInset>((*inset_vector)[i])
                     : std::optional<TimelineInset>(),
        style));
  }

  return list;
}

}  // namespace

bool ScrollStart::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValue* block_value =
      css_parsing_utils::ConsumeScrollStart(stream, context);
  if (!block_value) {
    return false;
  }
  CSSValue* inline_value =
      css_parsing_utils::ConsumeScrollStart(stream, context);
  if (!inline_value) {
    inline_value = CSSIdentifierValue::Create(CSSValueID::kStart);
  }
  AddProperty(scrollStartShorthand().properties()[0]->PropertyID(),
              scrollStartShorthand().id(), *block_value, important,
              css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  AddProperty(scrollStartShorthand().properties()[1]->PropertyID(),
              scrollStartShorthand().id(), *inline_value, important,
              css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* ScrollStart::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const CSSValue* block_value =
      scrollStartShorthand().properties()[0]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* inline_value =
      scrollStartShorthand().properties()[1]->CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  if (const auto* ident_value = DynamicTo<CSSIdentifierValue>(inline_value);
      !ident_value || ident_value->GetValueID() != CSSValueID::kStart) {
    return MakeGarbageCollected<CSSValuePair>(
        block_value, inline_value, CSSValuePair::kDropIdenticalValues);
  }
  return block_value;
}

bool ScrollTimeline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& proper
"""


```