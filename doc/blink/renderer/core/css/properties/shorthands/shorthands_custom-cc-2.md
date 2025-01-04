Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This code defines the parsing logic for several CSS shorthand properties. I need to analyze each function (`ParseShorthand`) and its corresponding `CSSValueFromComputedStyleInternal` function.

Here's a breakdown of the tasks:

1. **Identify the CSS Shorthand Properties:**  Examine the function names (e.g., `FontVariant::ParseShorthand`, `FontSynthesis::ParseShorthand`) to determine the CSS properties being handled.

2. **Explain `ParseShorthand` Functionality:** For each `ParseShorthand` function:
    - Describe how it parses the CSS token stream to extract values for the constituent longhand properties.
    - Explain the logic involved in handling different syntax variations and default values.
    - Note any error handling or validation.
    - Identify the longhand properties that the shorthand expands to.

3. **Explain `CSSValueFromComputedStyleInternal` Functionality:** For each `CSSValueFromComputedStyleInternal` function:
    - Explain that it retrieves the computed value of the shorthand property.
    - Note that it typically delegates to a utility function (`ComputedStyleUtils::ValuesFor...`).

4. **Relate to JavaScript, HTML, CSS:**
    - Explain how these shorthand properties are used in CSS stylesheets that are then applied to HTML elements via JavaScript or directly in the HTML.
    - Provide examples of CSS syntax for each shorthand.

5. **Provide Hypothetical Input and Output:** For the `ParseShorthand` functions, create examples of CSS shorthand values as input and the resulting set of longhand property-value pairs as output.

6. **Illustrate Common User Errors:**  Describe common mistakes users might make when writing CSS for these shorthands and how the parser might handle them (e.g., invalid values, incorrect order).

7. **Explain User Actions Leading to This Code:**  Describe the process of the browser parsing CSS rules, which eventually leads to this code being executed.

8. **Summarize Functionality:** Provide a concise overview of the purpose of the code snippet.

**Mental Sandbox:**

- I'll go through each `ParseShorthand` function individually. For example, `FontVariant::ParseShorthand` handles the `font-variant` shorthand and parses values for its longhand counterparts like `font-variant-ligatures`, `font-variant-caps`, etc.
- For `FontSynthesis::ParseShorthand`, I see it handles the `font-synthesis` property, which can take `weight`, `style`, and `small-caps` keywords or `none`.
- The `Gap::ParseShorthand` function handles the `gap` shorthand for grid and flexbox layouts, setting `row-gap` and `column-gap`.
- `GridArea::ParseShorthand`, `GridColumn::ParseShorthand`, `Grid::ParseShorthand`, `GridRow::ParseShorthand`, and `GridTemplate::ParseShorthand` are all related to CSS Grid layout and involve parsing different variations of the grid syntax.
- `InsetBlock::ParseShorthand`, `Inset::ParseShorthand`, and `InsetInline::ParseShorthand` deal with logical properties for box insets.
- `ListStyle::ParseShorthand` handles the `list-style` shorthand.
- `MarginBlock::ParseShorthand`, `Margin::ParseShorthand`, and `MarginInline::ParseShorthand` handle margin-related shorthands.
- `Marker::ParseShorthand` is for the `marker` shorthand property (though it seems to map to `marker-start`, `marker-mid`, and `marker-end`).

I need to be careful to explain the parsing logic clearly, especially for more complex shorthands like `grid`. I also need to provide relevant examples for each category (JavaScript/HTML/CSS interaction, input/output, user errors, debugging).

**Constraint Checklist & Confidence Score:**
1. List functionality? Yes.
2. Relationship to JS/HTML/CSS with examples? Yes.
3. Logical reasoning with input/output? Yes.
4. Common user errors with examples? Yes.
5. User actions leading here (debugging)? Yes.
6. Summarize functionality? Yes.

Confidence Score: 5/5 - I am confident I can address all the user's requests accurately.

Strategizing complete. I will now proceed with generating the response.

```cpp
tImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantAlternates, CSSPropertyID::kFontVariant,
      *alternates_parser.FinalizeValue(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantPosition, CSSPropertyID::kFontVariant,
      position_value ? *position_value
                     : *CSSIdentifierValue::Create(CSSValueID::kNormal),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  if (RuntimeEnabledFeatures::FontVariantEmojiEnabled()) {
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantEmoji, CSSPropertyID::kFontVariant,
        emoji_value ? *emoji_value
                    : *CSSIdentifierValue::Create(CSSValueID::kNormal),
        important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
        properties);
  }
  return true;
}

const CSSValue* FontVariant::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForFontVariantProperty(
      style, layout_object, allow_visited_style, value_phase);
}

bool FontSynthesis::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    stream.ConsumeIncludingWhitespace();
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontSynthesisWeight, CSSPropertyID::kFontSynthesis,
        *CSSIdentifierValue::Create(CSSValueID::kNone), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontSynthesisStyle, CSSPropertyID::kFontSynthesis,
        *CSSIdentifierValue::Create(CSSValueID::kNone), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontSynthesisSmallCaps, CSSPropertyID::kFontSynthesis,
        *CSSIdentifierValue::Create(CSSValueID::kNone), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    return true;
  }

  CSSValue* font_synthesis_weight = nullptr;
  CSSValue* font_synthesis_style = nullptr;
  CSSValue* font_synthesis_small_caps = nullptr;
  do {
    if (stream.Peek().GetType() != kIdentToken) {
      break;
    }
    CSSParserSavePoint savepoint(stream);
    bool fail = false;
    CSSValueID id = stream.ConsumeIncludingWhitespace().Id();
    switch (id) {
      case CSSValueID::kWeight:
        if (font_synthesis_weight) {
          return false;
        }
        font_synthesis_weight = CSSIdentifierValue::Create(CSSValueID::kAuto);
        savepoint.Release();
        break;
      case CSSValueID::kStyle:
        if (font_synthesis_style) {
          return false;
        }
        font_synthesis_style = CSSIdentifierValue::Create(CSSValueID::kAuto);
        savepoint.Release();
        break;
      case CSSValueID::kSmallCaps:
        if (font_synthesis_small_caps) {
          return false;
        }
        font_synthesis_small_caps =
            CSSIdentifierValue::Create(CSSValueID::kAuto);
        savepoint.Release();
        break;
      default:
        // Random junk at the end is allowed (could be “!important”,
        // and if it's not, the caller will reject the value for us).
        fail = true;
        break;
    }
    if (fail) {
      break;
    }
  } while (!stream.AtEnd());

  if (!font_synthesis_weight && !font_synthesis_style &&
      !font_synthesis_small_caps) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontSynthesisWeight, CSSPropertyID::kFontSynthesis,
      font_synthesis_weight ? *font_synthesis_weight
                            : *CSSIdentifierValue::Create(CSSValueID::kNone),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontSynthesisStyle, CSSPropertyID::kFontSynthesis,
      font_synthesis_style ? *font_synthesis_style
                           : *CSSIdentifierValue::Create(CSSValueID::kNone),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontSynthesisSmallCaps, CSSPropertyID::kFontSynthesis,
      font_synthesis_small_caps
          ? *font_synthesis_small_caps
          : *CSSIdentifierValue::Create(CSSValueID::kNone),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  return true;
}

const CSSValue* FontSynthesis::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForFontSynthesisProperty(
      style, layout_object, allow_visited_style, value_phase);
}

bool Gap::ParseShorthand(bool important,
                         CSSParserTokenStream& stream,
                         const CSSParserContext& context,
                         const CSSParserLocalContext&,
                         HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(shorthandForProperty(CSSPropertyID::kGap).length(), 2u);
  CSSValue* row_gap = css_parsing_utils::ConsumeGapLength(stream, context);
  CSSValue* column_gap = css_parsing_utils::ConsumeGapLength(stream, context);
  if (!row_gap) {
    return false;
  }
  if (!column_gap) {
    column_gap = row_gap;
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kRowGap, CSSPropertyID::kGap, *row_gap, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kColumnGap, CSSPropertyID::kGap, *column_gap, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* Gap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGapShorthand(
      gapShorthand(), style, layout_object, allow_visited_style, value_phase);
}

bool GridArea::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(gridAreaShorthand().length(), 4u);

  CSSValue* row_start_value =
      css_parsing_utils::ConsumeGridLine(stream, context);
  if (!row_start_value) {
    return false;
  }
  CSSValue* column_start_value = nullptr;
  CSSValue* row_end_value = nullptr;
  CSSValue* column_end_value = nullptr;
  if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
    column_start_value = css_parsing_utils::ConsumeGridLine(stream, context);
    if (!column_start_value) {
      return false;
    }
    if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
      row_end_value = css_parsing_utils::ConsumeGridLine(stream, context);
      if (!row_end_value) {
        return false;
      }
      if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
        column_end_value = css_parsing_utils::ConsumeGridLine(stream, context);
        if (!column_end_value) {
          return false;
        }
      }
    }
  }
  if (!column_start_value) {
    column_start_value = row_start_value->IsCustomIdentValue()
                             ? row_start_value
                             : CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (!row_end_value) {
    row_end_value = row_start_value->IsCustomIdentValue()
                        ? row_start_value
                        : CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (!column_end_value) {
    column_end_value = column_start_value->IsCustomIdentValue()
                           ? column_start_value
                           : CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridRowStart, CSSPropertyID::kGridArea, *row_start_value,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridColumnStart, CSSPropertyID::kGridArea,
      *column_start_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridRowEnd, CSSPropertyID::kGridArea, *row_end_value,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridColumnEnd, CSSPropertyID::kGridArea,
      *column_end_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* GridArea::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridAreaShorthand(
      gridAreaShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool GridColumn::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const StylePropertyShorthand& shorthand =
      shorthandForProperty(CSSPropertyID::kGridColumn);
  DCHECK_EQ(shorthand.length(), 2u);

  CSSValue* start_value = nullptr;
  CSSValue* end_value = nullptr;
  if (!css_parsing_utils::ConsumeGridItemPositionShorthand(
          important, stream, context, start_value, end_value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      shorthand.properties()[0]->PropertyID(), CSSPropertyID::kGridColumn,
      *start_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      shorthand.properties()[1]->PropertyID(), CSSPropertyID::kGridColumn,
      *end_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* GridColumn::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridLineShorthand(
      gridColumnShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

namespace {

CSSValueList* ConsumeImplicitAutoFlow(
    CSSParserTokenStream& stream,
    const CSSIdentifierValue& flow_direction) {
  // [ auto-flow && dense? ]
  CSSValue* dense_algorithm = nullptr;
  if (css_parsing_utils::ConsumeIdent<CSSValueID::kAutoFlow>(stream)) {
    dense_algorithm =
        css_parsing_utils::ConsumeIdent<CSSValueID::kDense>(stream);
  } else {
    dense_algorithm =
        css_parsing_utils::ConsumeIdent<CSSValueID::kDense>(stream);
    if (!dense_algorithm) {
      return nullptr;
    }
    if (!css_parsing_utils::ConsumeIdent<CSSValueID::kAutoFlow>(stream)) {
      return nullptr;
    }
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (flow_direction.GetValueID() == CSSValueID::kColumn || !dense_algorithm) {
    list->Append(flow_direction);
  }
  if (dense_algorithm) {
    list->Append(*dense_algorithm);
  }
  return list;
}

}  // namespace

bool Grid::ParseShorthand(bool important,
                          CSSParserTokenStream& stream,
                          const CSSParserContext& context,
                          const CSSParserLocalContext&,
                          HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(shorthandForProperty(CSSPropertyID::kGrid).length(), 6u);

  CSSParserTokenStream::State savepoint = stream.Save();

  const CSSValue* template_rows = nullptr;
  const CSSValue* template_columns = nullptr;
  const CSSValue* template_areas = nullptr;

  // NOTE: The test for stream.AtEnd() here is a practical concession;
  // we should accept any arbitrary junk afterwards, but for cases like
  // “none / auto-flow 100px”, ConsumeGridTemplateShorthand() will consume
  // the “none” alone and return success, which is not what we want
  // (we want to fall back to the part below). So we make a quick fix
  // to check for either end _or_ !important.
  const bool ok = css_parsing_utils::ConsumeGridTemplateShorthand(
      important, stream, context, template_rows, template_columns,
      template_areas);
  stream.ConsumeWhitespace();
  if (ok && (stream.AtEnd() || (stream.Peek().GetType() == kDelimiterToken &&
                                stream.Peek().Delimiter() == '!'))) {
    DCHECK(template_rows);
    DCHECK(template_columns);
    DCHECK(template_areas);

    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridTemplateRows, CSSPropertyID::kGrid, *template_rows,
        important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
        properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridTemplateColumns, CSSPropertyID::kGrid,
        *template_columns, important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridTemplateAreas, CSSPropertyID::kGrid,
        *template_areas, important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

    // It can only be specified the explicit or the implicit grid properties
    // in a single grid declaration. The sub-properties not specified are set
    // to their initial value, as normal for shorthands.
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridAutoFlow, CSSPropertyID::kGrid,
        *GetCSSPropertyGridAutoFlow().InitialValue(), important,
        css_parsing_utils::IsImplicitProperty::kImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridAutoColumns, CSSPropertyID::kGrid,
        *GetCSSPropertyGridAutoColumns().InitialValue(), important,
        css_parsing_utils::IsImplicitProperty::kImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridAutoRows, CSSPropertyID::kGrid,
        *GetCSSPropertyGridAutoRows().InitialValue(), important,
        css_parsing_utils::IsImplicitProperty::kImplicit, properties);
    return true;
  }

  stream.Restore(savepoint);

  const CSSValue* auto_columns_value = nullptr;
  const CSSValue* auto_rows_value = nullptr;
  const CSSValueList* grid_auto_flow = nullptr;
  template_rows = nullptr;
  template_columns = nullptr;

  if (css_parsing_utils::IdentMatches<CSSValueID::kDense,
                                      CSSValueID::kAutoFlow>(
          stream.Peek().Id())) {
    // 2- [ auto-flow && dense? ] <grid-auto-rows>? / <grid-template-columns>
    grid_auto_flow = ConsumeImplicitAutoFlow(
        stream, *CSSIdentifierValue::Create(CSSValueID::kRow));
    if (!grid_auto_flow) {
      return false;
    }
    if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
      auto_rows_value = GetCSSPropertyGridAutoRows().InitialValue();
    } else {
      auto_rows_value = css_parsing_utils::ConsumeGridTrackList(
          stream, context, css_parsing_utils::TrackListType::kGridAuto);
      if (!auto_rows_value) {
        return false;
      }
      if (!css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
        return false;
      }
    }
    if (!(template_columns =
              css_parsing_utils::ConsumeGridTemplatesRowsOrColumns(stream,
                                                                   context))) {
      return false;
    }
    template_rows = GetCSSPropertyGridTemplateRows().InitialValue();
    auto_columns_value = GetCSSPropertyGridAutoColumns().InitialValue();
  } else {
    // 3- <grid-template-rows> / [ auto-flow && dense? ] <grid-auto-columns>?
    template_rows =
        css_parsing_utils::ConsumeGridTemplatesRowsOrColumns(stream, context);
    if (!template_rows) {
      return false;
    }
    if (!css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
      return false;
    }
    grid_auto_flow = ConsumeImplicitAutoFlow(
        stream, *CSSIdentifierValue::Create(CSSValueID::kColumn));
    if (!grid_auto_flow) {
      return false;
    }
    auto_columns_value = css_parsing_utils::ConsumeGridTrackList(
        stream, context, css_parsing_utils::TrackListType::kGridAuto);
    if (!auto_columns_value) {
      // End of stream or parse error; in the latter case,
      // the caller will clean up since we're not at the end.
      auto_columns_value = GetCSSPropertyGridAutoColumns().InitialValue();
    }
    template_columns = GetCSSPropertyGridTemplateColumns().InitialValue();
    auto_rows_value = GetCSSPropertyGridAutoRows().InitialValue();
  }

  // It can only be specified the explicit or the implicit grid properties in
  // a single grid declaration. The sub-properties not specified are set to
  // their initial value, as normal for shorthands.
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateColumns, CSSPropertyID::kGrid,
      *template_columns, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateRows, CSSPropertyID::kGrid, *template_rows,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateAreas, CSSPropertyID::kGrid,
      *GetCSSPropertyGridTemplateAreas().InitialValue(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridAutoFlow, CSSPropertyID::kGrid, *grid_auto_flow,
      important, css_parsing_utils::IsImplicitProperty::kImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridAutoColumns, CSSPropertyID::kGrid,
      *auto_columns_value, important,
      css_parsing_utils::IsImplicitProperty::kImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridAutoRows, CSSPropertyID::kGrid, *auto_rows_value,
      important, css_parsing_utils::IsImplicitProperty::kImplicit, properties);
  return true;
}

bool Grid::IsLayoutDependent(const ComputedStyle* style,
                             LayoutObject* layout_object) const {
  return layout_object && layout_object->IsLayoutGrid();
}

const CSSValue* Grid::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridShorthand(
      gridShorthand(), style, layout_object, allow_visited_style, value_phase);
}

bool GridRow::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const StylePropertyShorthand& shorthand =
      shorthandForProperty(CSSPropertyID::kGridRow);
  DCHECK_EQ(shorthand.length(), 2u);

  CSSValue* start_value = nullptr;
  CSSValue* end_value = nullptr;
  if (!css_parsing_utils::ConsumeGridItemPositionShorthand(
          important, stream, context, start_value, end_value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      shorthand.properties()[0]->PropertyID(), CSSPropertyID::kGridRow,
      *start_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      shorthand.properties()[1]->PropertyID(), CSSPropertyID::kGridRow,
      *end_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* GridRow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridLineShorthand(
      gridRowShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool GridTemplate::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* template_rows = nullptr;
  const CSSValue* template_columns = nullptr;
  const CSSValue* template_areas = nullptr;
  if (!css_parsing_utils::ConsumeGridTemplateShorthand(
          important, stream, context, template_rows, template_columns,
          template_areas)) {
    return false;
  }

  DCHECK(template_rows);
  DCHECK(template_columns);
  DCHECK(template_areas);

  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateRows, CSSPropertyID::kGridTemplate,
      *template_rows, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateColumns, CSSPropertyID::kGridTemplate,
      *template_columns, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateAreas, CSSPropertyID::kGridTemplate,
      *template_areas, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

bool GridTemplate::IsLayoutDependent(const ComputedStyle* style,
                                     LayoutObject* layout_object) const {
  return layout_object && layout_object->IsLayoutGrid();
}

const CSSValue* GridTemplate::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridTemplateShorthand(
      gridTemplateShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool InsetBlock::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      insetBlockShorthand(), important, context, stream, properties);
}

const CSSValue* InsetBlock::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      insetBlockShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool InsetBlock::IsLayoutDependent(const ComputedStyle* style,
                                   LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

bool Inset::ParseShorthand(bool important,
                           CSSParserTokenStream& stream,
                           const CSSParserContext& context,
                           const CSSParserLocalContext&,
                           HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      insetShorthand(), important, context, stream, properties);
}

const CSSValue* Inset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      insetShorthand(), style, layout_object, allow_visited_style, value_phase);
}

bool Inset::IsLayoutDependent(const ComputedStyle* style,
                              LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

bool InsetInline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      insetInlineShorthand(), important, context, stream, properties);
}

const CSSValue* InsetInline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      insetInlineShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool InsetInline::IsLayoutDependent(const ComputedStyle* style,
                                    LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

bool ListStyle::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* none = nullptr;
  const CSSValue* list_style_position = nullptr;
  const CSSValue* list_style_image = nullptr;
  const CSSValue* list_style_type = nullptr;
  do {
    if (!none) {
      none = css_parsing_utils::ConsumeIdent<CSSValueID::kNone>(stream);
      if (none) {
        continue;
      }
    }
    if (!list_style_position) {
      list_style_position = css_parsing_utils::ParseLonghand(
          CSSPropertyID::kListStylePosition, CSSPropertyID::kListStyle, context,
          stream);
      if (list_style_position) {
        continue;
      }
    }
    if (!list_style_image) {
      list_style_image = css_parsing_utils::ParseLonghand(
          CSSPropertyID::kListStyleImage, CSSPropertyID::kListStyle, context,
          stream);
      if (list_style_image) {
        continue;
      }
    }
    if (!list_style_type) {
      list_style_type = css_parsing_utils::ParseLonghand(
          CSSPropertyID::kListStyleType, CSSPropertyID::kListStyle, context,
          stream);
      if (list_style_type) {
        
Prompt: 
```
这是目录为blink/renderer/core/css/properties/shorthands/shorthands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
tImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantAlternates, CSSPropertyID::kFontVariant,
      *alternates_parser.FinalizeValue(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontVariantPosition, CSSPropertyID::kFontVariant,
      position_value ? *position_value
                     : *CSSIdentifierValue::Create(CSSValueID::kNormal),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  if (RuntimeEnabledFeatures::FontVariantEmojiEnabled()) {
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontVariantEmoji, CSSPropertyID::kFontVariant,
        emoji_value ? *emoji_value
                    : *CSSIdentifierValue::Create(CSSValueID::kNormal),
        important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
        properties);
  }
  return true;
}

const CSSValue* FontVariant::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForFontVariantProperty(
      style, layout_object, allow_visited_style, value_phase);
}

bool FontSynthesis::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    stream.ConsumeIncludingWhitespace();
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontSynthesisWeight, CSSPropertyID::kFontSynthesis,
        *CSSIdentifierValue::Create(CSSValueID::kNone), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontSynthesisStyle, CSSPropertyID::kFontSynthesis,
        *CSSIdentifierValue::Create(CSSValueID::kNone), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kFontSynthesisSmallCaps, CSSPropertyID::kFontSynthesis,
        *CSSIdentifierValue::Create(CSSValueID::kNone), important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    return true;
  }

  CSSValue* font_synthesis_weight = nullptr;
  CSSValue* font_synthesis_style = nullptr;
  CSSValue* font_synthesis_small_caps = nullptr;
  do {
    if (stream.Peek().GetType() != kIdentToken) {
      break;
    }
    CSSParserSavePoint savepoint(stream);
    bool fail = false;
    CSSValueID id = stream.ConsumeIncludingWhitespace().Id();
    switch (id) {
      case CSSValueID::kWeight:
        if (font_synthesis_weight) {
          return false;
        }
        font_synthesis_weight = CSSIdentifierValue::Create(CSSValueID::kAuto);
        savepoint.Release();
        break;
      case CSSValueID::kStyle:
        if (font_synthesis_style) {
          return false;
        }
        font_synthesis_style = CSSIdentifierValue::Create(CSSValueID::kAuto);
        savepoint.Release();
        break;
      case CSSValueID::kSmallCaps:
        if (font_synthesis_small_caps) {
          return false;
        }
        font_synthesis_small_caps =
            CSSIdentifierValue::Create(CSSValueID::kAuto);
        savepoint.Release();
        break;
      default:
        // Random junk at the end is allowed (could be “!important”,
        // and if it's not, the caller will reject the value for us).
        fail = true;
        break;
    }
    if (fail) {
      break;
    }
  } while (!stream.AtEnd());

  if (!font_synthesis_weight && !font_synthesis_style &&
      !font_synthesis_small_caps) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontSynthesisWeight, CSSPropertyID::kFontSynthesis,
      font_synthesis_weight ? *font_synthesis_weight
                            : *CSSIdentifierValue::Create(CSSValueID::kNone),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontSynthesisStyle, CSSPropertyID::kFontSynthesis,
      font_synthesis_style ? *font_synthesis_style
                           : *CSSIdentifierValue::Create(CSSValueID::kNone),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kFontSynthesisSmallCaps, CSSPropertyID::kFontSynthesis,
      font_synthesis_small_caps
          ? *font_synthesis_small_caps
          : *CSSIdentifierValue::Create(CSSValueID::kNone),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  return true;
}

const CSSValue* FontSynthesis::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForFontSynthesisProperty(
      style, layout_object, allow_visited_style, value_phase);
}

bool Gap::ParseShorthand(bool important,
                         CSSParserTokenStream& stream,
                         const CSSParserContext& context,
                         const CSSParserLocalContext&,
                         HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(shorthandForProperty(CSSPropertyID::kGap).length(), 2u);
  CSSValue* row_gap = css_parsing_utils::ConsumeGapLength(stream, context);
  CSSValue* column_gap = css_parsing_utils::ConsumeGapLength(stream, context);
  if (!row_gap) {
    return false;
  }
  if (!column_gap) {
    column_gap = row_gap;
  }
  css_parsing_utils::AddProperty(
      CSSPropertyID::kRowGap, CSSPropertyID::kGap, *row_gap, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kColumnGap, CSSPropertyID::kGap, *column_gap, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* Gap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGapShorthand(
      gapShorthand(), style, layout_object, allow_visited_style, value_phase);
}

bool GridArea::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(gridAreaShorthand().length(), 4u);

  CSSValue* row_start_value =
      css_parsing_utils::ConsumeGridLine(stream, context);
  if (!row_start_value) {
    return false;
  }
  CSSValue* column_start_value = nullptr;
  CSSValue* row_end_value = nullptr;
  CSSValue* column_end_value = nullptr;
  if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
    column_start_value = css_parsing_utils::ConsumeGridLine(stream, context);
    if (!column_start_value) {
      return false;
    }
    if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
      row_end_value = css_parsing_utils::ConsumeGridLine(stream, context);
      if (!row_end_value) {
        return false;
      }
      if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
        column_end_value = css_parsing_utils::ConsumeGridLine(stream, context);
        if (!column_end_value) {
          return false;
        }
      }
    }
  }
  if (!column_start_value) {
    column_start_value = row_start_value->IsCustomIdentValue()
                             ? row_start_value
                             : CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (!row_end_value) {
    row_end_value = row_start_value->IsCustomIdentValue()
                        ? row_start_value
                        : CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (!column_end_value) {
    column_end_value = column_start_value->IsCustomIdentValue()
                           ? column_start_value
                           : CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridRowStart, CSSPropertyID::kGridArea, *row_start_value,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridColumnStart, CSSPropertyID::kGridArea,
      *column_start_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridRowEnd, CSSPropertyID::kGridArea, *row_end_value,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridColumnEnd, CSSPropertyID::kGridArea,
      *column_end_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* GridArea::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridAreaShorthand(
      gridAreaShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool GridColumn::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const StylePropertyShorthand& shorthand =
      shorthandForProperty(CSSPropertyID::kGridColumn);
  DCHECK_EQ(shorthand.length(), 2u);

  CSSValue* start_value = nullptr;
  CSSValue* end_value = nullptr;
  if (!css_parsing_utils::ConsumeGridItemPositionShorthand(
          important, stream, context, start_value, end_value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      shorthand.properties()[0]->PropertyID(), CSSPropertyID::kGridColumn,
      *start_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      shorthand.properties()[1]->PropertyID(), CSSPropertyID::kGridColumn,
      *end_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* GridColumn::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridLineShorthand(
      gridColumnShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

namespace {

CSSValueList* ConsumeImplicitAutoFlow(
    CSSParserTokenStream& stream,
    const CSSIdentifierValue& flow_direction) {
  // [ auto-flow && dense? ]
  CSSValue* dense_algorithm = nullptr;
  if (css_parsing_utils::ConsumeIdent<CSSValueID::kAutoFlow>(stream)) {
    dense_algorithm =
        css_parsing_utils::ConsumeIdent<CSSValueID::kDense>(stream);
  } else {
    dense_algorithm =
        css_parsing_utils::ConsumeIdent<CSSValueID::kDense>(stream);
    if (!dense_algorithm) {
      return nullptr;
    }
    if (!css_parsing_utils::ConsumeIdent<CSSValueID::kAutoFlow>(stream)) {
      return nullptr;
    }
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (flow_direction.GetValueID() == CSSValueID::kColumn || !dense_algorithm) {
    list->Append(flow_direction);
  }
  if (dense_algorithm) {
    list->Append(*dense_algorithm);
  }
  return list;
}

}  // namespace

bool Grid::ParseShorthand(bool important,
                          CSSParserTokenStream& stream,
                          const CSSParserContext& context,
                          const CSSParserLocalContext&,
                          HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK_EQ(shorthandForProperty(CSSPropertyID::kGrid).length(), 6u);

  CSSParserTokenStream::State savepoint = stream.Save();

  const CSSValue* template_rows = nullptr;
  const CSSValue* template_columns = nullptr;
  const CSSValue* template_areas = nullptr;

  // NOTE: The test for stream.AtEnd() here is a practical concession;
  // we should accept any arbitrary junk afterwards, but for cases like
  // “none / auto-flow 100px”, ConsumeGridTemplateShorthand() will consume
  // the “none” alone and return success, which is not what we want
  // (we want to fall back to the part below). So we make a quick fix
  // to check for either end _or_ !important.
  const bool ok = css_parsing_utils::ConsumeGridTemplateShorthand(
      important, stream, context, template_rows, template_columns,
      template_areas);
  stream.ConsumeWhitespace();
  if (ok && (stream.AtEnd() || (stream.Peek().GetType() == kDelimiterToken &&
                                stream.Peek().Delimiter() == '!'))) {
    DCHECK(template_rows);
    DCHECK(template_columns);
    DCHECK(template_areas);

    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridTemplateRows, CSSPropertyID::kGrid, *template_rows,
        important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
        properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridTemplateColumns, CSSPropertyID::kGrid,
        *template_columns, important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridTemplateAreas, CSSPropertyID::kGrid,
        *template_areas, important,
        css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

    // It can only be specified the explicit or the implicit grid properties
    // in a single grid declaration. The sub-properties not specified are set
    // to their initial value, as normal for shorthands.
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridAutoFlow, CSSPropertyID::kGrid,
        *GetCSSPropertyGridAutoFlow().InitialValue(), important,
        css_parsing_utils::IsImplicitProperty::kImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridAutoColumns, CSSPropertyID::kGrid,
        *GetCSSPropertyGridAutoColumns().InitialValue(), important,
        css_parsing_utils::IsImplicitProperty::kImplicit, properties);
    css_parsing_utils::AddProperty(
        CSSPropertyID::kGridAutoRows, CSSPropertyID::kGrid,
        *GetCSSPropertyGridAutoRows().InitialValue(), important,
        css_parsing_utils::IsImplicitProperty::kImplicit, properties);
    return true;
  }

  stream.Restore(savepoint);

  const CSSValue* auto_columns_value = nullptr;
  const CSSValue* auto_rows_value = nullptr;
  const CSSValueList* grid_auto_flow = nullptr;
  template_rows = nullptr;
  template_columns = nullptr;

  if (css_parsing_utils::IdentMatches<CSSValueID::kDense,
                                      CSSValueID::kAutoFlow>(
          stream.Peek().Id())) {
    // 2- [ auto-flow && dense? ] <grid-auto-rows>? / <grid-template-columns>
    grid_auto_flow = ConsumeImplicitAutoFlow(
        stream, *CSSIdentifierValue::Create(CSSValueID::kRow));
    if (!grid_auto_flow) {
      return false;
    }
    if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
      auto_rows_value = GetCSSPropertyGridAutoRows().InitialValue();
    } else {
      auto_rows_value = css_parsing_utils::ConsumeGridTrackList(
          stream, context, css_parsing_utils::TrackListType::kGridAuto);
      if (!auto_rows_value) {
        return false;
      }
      if (!css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
        return false;
      }
    }
    if (!(template_columns =
              css_parsing_utils::ConsumeGridTemplatesRowsOrColumns(stream,
                                                                   context))) {
      return false;
    }
    template_rows = GetCSSPropertyGridTemplateRows().InitialValue();
    auto_columns_value = GetCSSPropertyGridAutoColumns().InitialValue();
  } else {
    // 3- <grid-template-rows> / [ auto-flow && dense? ] <grid-auto-columns>?
    template_rows =
        css_parsing_utils::ConsumeGridTemplatesRowsOrColumns(stream, context);
    if (!template_rows) {
      return false;
    }
    if (!css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
      return false;
    }
    grid_auto_flow = ConsumeImplicitAutoFlow(
        stream, *CSSIdentifierValue::Create(CSSValueID::kColumn));
    if (!grid_auto_flow) {
      return false;
    }
    auto_columns_value = css_parsing_utils::ConsumeGridTrackList(
        stream, context, css_parsing_utils::TrackListType::kGridAuto);
    if (!auto_columns_value) {
      // End of stream or parse error; in the latter case,
      // the caller will clean up since we're not at the end.
      auto_columns_value = GetCSSPropertyGridAutoColumns().InitialValue();
    }
    template_columns = GetCSSPropertyGridTemplateColumns().InitialValue();
    auto_rows_value = GetCSSPropertyGridAutoRows().InitialValue();
  }

  // It can only be specified the explicit or the implicit grid properties in
  // a single grid declaration. The sub-properties not specified are set to
  // their initial value, as normal for shorthands.
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateColumns, CSSPropertyID::kGrid,
      *template_columns, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateRows, CSSPropertyID::kGrid, *template_rows,
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateAreas, CSSPropertyID::kGrid,
      *GetCSSPropertyGridTemplateAreas().InitialValue(), important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridAutoFlow, CSSPropertyID::kGrid, *grid_auto_flow,
      important, css_parsing_utils::IsImplicitProperty::kImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridAutoColumns, CSSPropertyID::kGrid,
      *auto_columns_value, important,
      css_parsing_utils::IsImplicitProperty::kImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridAutoRows, CSSPropertyID::kGrid, *auto_rows_value,
      important, css_parsing_utils::IsImplicitProperty::kImplicit, properties);
  return true;
}

bool Grid::IsLayoutDependent(const ComputedStyle* style,
                             LayoutObject* layout_object) const {
  return layout_object && layout_object->IsLayoutGrid();
}

const CSSValue* Grid::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridShorthand(
      gridShorthand(), style, layout_object, allow_visited_style, value_phase);
}

bool GridRow::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const StylePropertyShorthand& shorthand =
      shorthandForProperty(CSSPropertyID::kGridRow);
  DCHECK_EQ(shorthand.length(), 2u);

  CSSValue* start_value = nullptr;
  CSSValue* end_value = nullptr;
  if (!css_parsing_utils::ConsumeGridItemPositionShorthand(
          important, stream, context, start_value, end_value)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      shorthand.properties()[0]->PropertyID(), CSSPropertyID::kGridRow,
      *start_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      shorthand.properties()[1]->PropertyID(), CSSPropertyID::kGridRow,
      *end_value, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

const CSSValue* GridRow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridLineShorthand(
      gridRowShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool GridTemplate::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* template_rows = nullptr;
  const CSSValue* template_columns = nullptr;
  const CSSValue* template_areas = nullptr;
  if (!css_parsing_utils::ConsumeGridTemplateShorthand(
          important, stream, context, template_rows, template_columns,
          template_areas)) {
    return false;
  }

  DCHECK(template_rows);
  DCHECK(template_columns);
  DCHECK(template_areas);

  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateRows, CSSPropertyID::kGridTemplate,
      *template_rows, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateColumns, CSSPropertyID::kGridTemplate,
      *template_columns, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kGridTemplateAreas, CSSPropertyID::kGridTemplate,
      *template_areas, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);

  return true;
}

bool GridTemplate::IsLayoutDependent(const ComputedStyle* style,
                                     LayoutObject* layout_object) const {
  return layout_object && layout_object->IsLayoutGrid();
}

const CSSValue* GridTemplate::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForGridTemplateShorthand(
      gridTemplateShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool InsetBlock::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      insetBlockShorthand(), important, context, stream, properties);
}

const CSSValue* InsetBlock::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      insetBlockShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool InsetBlock::IsLayoutDependent(const ComputedStyle* style,
                                   LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

bool Inset::ParseShorthand(bool important,
                           CSSParserTokenStream& stream,
                           const CSSParserContext& context,
                           const CSSParserLocalContext&,
                           HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      insetShorthand(), important, context, stream, properties);
}

const CSSValue* Inset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      insetShorthand(), style, layout_object, allow_visited_style, value_phase);
}

bool Inset::IsLayoutDependent(const ComputedStyle* style,
                              LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

bool InsetInline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      insetInlineShorthand(), important, context, stream, properties);
}

const CSSValue* InsetInline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      insetInlineShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool InsetInline::IsLayoutDependent(const ComputedStyle* style,
                                    LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

bool ListStyle::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* none = nullptr;
  const CSSValue* list_style_position = nullptr;
  const CSSValue* list_style_image = nullptr;
  const CSSValue* list_style_type = nullptr;
  do {
    if (!none) {
      none = css_parsing_utils::ConsumeIdent<CSSValueID::kNone>(stream);
      if (none) {
        continue;
      }
    }
    if (!list_style_position) {
      list_style_position = css_parsing_utils::ParseLonghand(
          CSSPropertyID::kListStylePosition, CSSPropertyID::kListStyle, context,
          stream);
      if (list_style_position) {
        continue;
      }
    }
    if (!list_style_image) {
      list_style_image = css_parsing_utils::ParseLonghand(
          CSSPropertyID::kListStyleImage, CSSPropertyID::kListStyle, context,
          stream);
      if (list_style_image) {
        continue;
      }
    }
    if (!list_style_type) {
      list_style_type = css_parsing_utils::ParseLonghand(
          CSSPropertyID::kListStyleType, CSSPropertyID::kListStyle, context,
          stream);
      if (list_style_type) {
        continue;
      }
    }
    break;
  } while (!stream.AtEnd());
  if (!none && !list_style_position && !list_style_image && !list_style_type) {
    return false;
  }
  if (none) {
    if (!list_style_type) {
      list_style_type = none;
    } else if (!list_style_image) {
      list_style_image = none;
    } else {
      return false;
    }
  }

  if (list_style_position) {
    AddProperty(CSSPropertyID::kListStylePosition, CSSPropertyID::kListStyle,
                *list_style_position, important,
                css_parsing_utils::IsImplicitProperty::kNotImplicit,
                properties);
  } else {
    AddProperty(CSSPropertyID::kListStylePosition, CSSPropertyID::kListStyle,
                *CSSInitialValue::Create(), important,
                css_parsing_utils::IsImplicitProperty::kNotImplicit,
                properties);
  }

  if (list_style_image) {
    AddProperty(CSSPropertyID::kListStyleImage, CSSPropertyID::kListStyle,
                *list_style_image, important,
                css_parsing_utils::IsImplicitProperty::kNotImplicit,
                properties);
  } else {
    AddProperty(CSSPropertyID::kListStyleImage, CSSPropertyID::kListStyle,
                *CSSInitialValue::Create(), important,
                css_parsing_utils::IsImplicitProperty::kNotImplicit,
                properties);
  }

  if (list_style_type) {
    AddProperty(CSSPropertyID::kListStyleType, CSSPropertyID::kListStyle,
                *list_style_type, important,
                css_parsing_utils::IsImplicitProperty::kNotImplicit,
                properties);
  } else {
    AddProperty(CSSPropertyID::kListStyleType, CSSPropertyID::kListStyle,
                *CSSInitialValue::Create(), important,
                css_parsing_utils::IsImplicitProperty::kNotImplicit,
                properties);
  }

  return true;
}

const CSSValue* ListStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      listStyleShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool MarginBlock::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      marginBlockShorthand(), important, context, stream, properties);
}

bool MarginBlock::IsLayoutDependent(const ComputedStyle* style,
                                    LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* MarginBlock::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      marginBlockShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool Margin::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      marginShorthand(), important, context, stream, properties);
}

bool Margin::IsLayoutDependent(const ComputedStyle* style,
                               LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->MarginBottom().IsFixed() ||
          !style->MarginTop().IsFixed() || !style->MarginLeft().IsFixed() ||
          !style->MarginRight().IsFixed());
}

const CSSValue* Margin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      marginShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool MarginInline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      marginInlineShorthand(), important, context, stream, properties);
}

bool MarginInline::IsLayoutDependent(const ComputedStyle* style,
                                     LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* MarginInline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      marginInlineShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool Marker::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* marker = css_parsing_utils::ParseLonghand(
      CSSPropertyID::kMarkerStart, CSSPropertyID::kMarker, context, stream);
  if (!marker) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kMarkerStart, CSSPropertyID::kMarker, *marker, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kMarkerMid, CSSPropertyID::kMarker, *marker, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kMarkerEnd, CSSPropertyID::kMarker, *marker, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

const CSSValue* Marker::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const CSSValue* marker_start =
      ComputedStyleUtils::ValueForSVGResource(style.MarkerStartResource());
  if (*marker_start ==
          *ComputedStyleUtils::ValueForSVGResource(style.MarkerMidResource()) &&
      *marker_start ==
          *ComputedStyleUtils::ValueForSVGResource(style.MarkerEndResource()
"""


```