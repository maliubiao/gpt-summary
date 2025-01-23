Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. The file `longhands_custom.cc` seems to define how specific CSS properties are parsed and converted to internal representations within the engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:**  The code defines functions named `ParseSingleValue` and `CSSValueFromComputedStyleInternal` for various CSS properties. These function names strongly suggest parsing and conversion between CSS syntax and the engine's internal style representation.

2. **List the handled properties:**  Scan through the code and extract the names of the CSS properties being handled. This involves looking at the class names like `BreakAfter`, `BreakBefore`, `CaretColor`, etc.

3. **Categorize the functionality:** Group the properties based on their general purpose in CSS. For instance, properties related to page breaks (`break-after`, `break-before`, `break-inside`), text appearance (`caret-color`, `color`), layout (`clip`, `clip-path`, `clear`), and multi-column layout (`column-count`, `column-gap`, etc.).

4. **Explain `ParseSingleValue`:** This function is responsible for taking a stream of CSS tokens and converting them into a `CSSValue` object. It handles the syntax and possible values for each property.

5. **Explain `CSSValueFromComputedStyleInternal`:** This function does the reverse. It takes the engine's internal `ComputedStyle` object and creates a `CSSValue` that represents the computed value of the property.

6. **Connect to web technologies:** Explain how these functions relate to HTML, CSS, and JavaScript:
    * **HTML:**  The CSS properties are applied to HTML elements.
    * **CSS:** The code parses CSS syntax.
    * **JavaScript:** JavaScript can interact with these properties via the CSSOM (CSS Object Model).

7. **Provide examples:**  Illustrate the functionality with simple CSS examples for some of the properties.

8. **Discuss error handling:**  Point out potential user errors, such as incorrect syntax or using invalid values, and how the parsing functions might handle them (returning `nullptr`).

9. **Trace user interaction:** Explain a hypothetical user journey that would lead to this code being executed, focusing on the browser parsing CSS styles applied to HTML elements.

10. **Address the "part 3 of 13" instruction:**  Infer that this file likely handles a subset of CSS properties, and the overall styling process in Blink involves multiple files.

11. **Structure the summary:** Organize the information logically with clear headings and bullet points for readability.

12. **Refine and elaborate:** Add details about specific parsing logic (e.g., handling `rect()` for `clip`, different ways to specify `clip-path`), the concept of `ComputedStyle`, and the role of `CSSValue`.

13. **Review and verify:**  Ensure the explanation is accurate and addresses all aspects of the prompt. For instance, double-check the examples and the explanations of the functions' purposes. Make sure the connection to user errors and debugging is clear.

By following these steps, a comprehensive and informative summary of the code's functionality can be generated. The iterative process of identifying, explaining, connecting, and refining ensures that all the requirements of the prompt are addressed effectively.
This section of the `longhands_custom.cc` file in the Chromium Blink engine focuses on defining the parsing and computed style retrieval logic for a specific set of **CSS longhand properties**. These properties directly correspond to individual CSS style attributes.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Parsing CSS Values:** For many properties, this section defines the `ParseSingleValue` method. This method takes a stream of CSS tokens and attempts to parse a valid value for that specific property. It handles the expected syntax, keywords, and data types associated with the property.
* **Retrieving Computed Style Values:**  It defines the `CSSValueFromComputedStyleInternal` method for each property. This method takes a `ComputedStyle` object (which represents the final, calculated style of an element) and extracts the relevant property's value as a `CSSValue` object. This is crucial for tasks like:
    * **Rendering:** Determining the actual visual presentation of elements.
    * **JavaScript Interaction:** Allowing JavaScript to query the computed styles of elements.
    * **DevTools Inspection:** Displaying the computed styles in the browser's developer tools.

**Relationship to JavaScript, HTML, and CSS:**

* **CSS:** This file is directly responsible for understanding and processing CSS syntax for specific properties. The `ParseSingleValue` functions are the entry point for converting CSS text into the engine's internal representation.
    * **Example:** When the browser encounters the CSS rule `color: red;`, the `Color::ParseSingleValue` function is responsible for recognizing `red` as a valid color value and creating a corresponding `CSSValue`.
* **HTML:** These CSS properties are ultimately applied to HTML elements. The parsing and computed style logic ensures that the CSS rules applied to HTML elements are correctly interpreted and rendered.
    * **Example:** The `break-after` property controls page/column breaks for an HTML element. This file contains the logic to understand values like `auto`, `always`, `page`, etc., when applied to an HTML element.
* **JavaScript:** JavaScript can access and manipulate the computed styles of elements through the CSSOM (CSS Object Model). The `CSSValueFromComputedStyleInternal` functions are vital for this, as they provide the `CSSValue` representation that JavaScript can work with.
    * **Example:**  JavaScript code using `getComputedStyle(element).caretColor` will ultimately rely on the `CaretColor::CSSValueFromComputedStyleInternal` function to retrieve the computed color of the text cursor.

**Examples and Logical Reasoning:**

Let's take the `CaretColor` property as an example:

* **Parsing (Hypothetical Input & Output):**
    * **Input (CSS Token Stream):**  "auto"
    * **Output (CSSValue*):**  A `CSSIdentifierValue` object representing `auto`.
    * **Input (CSS Token Stream):**  "#FF0000"
    * **Output (CSSValue*):** A `CSSColor` object representing the color red.
    * **Input (CSS Token Stream):**  "invalid-color"
    * **Output (CSSValue*):** `nullptr` (indicating a parsing error).
* **Computed Style Retrieval (Hypothetical Input & Output):**
    * **Input (ComputedStyle):** A `ComputedStyle` object where the computed `CaretColor` is set to a specific color (e.g., red).
    * **Output (CSSValue*):** A `CSSColor` object representing that red color.
    * **Input (ComputedStyle):** A `ComputedStyle` object where `CaretColor` is `auto`.
    * **Output (CSSValue*):** A `CSSIdentifierValue` object representing `auto`.

The logic often involves checking the type of tokens in the stream and creating the appropriate `CSSValue` subclass. For computed styles, it usually involves directly accessing the corresponding member variable in the `ComputedStyle` object and wrapping it in a `CSSValue`.

**Common Usage Errors and Debugging:**

* **Incorrect CSS Syntax:**  Users might type invalid values for these properties in their CSS. The `ParseSingleValue` functions will attempt to catch these errors and might return `nullptr`.
    * **Example:** Typing `break-after: alway;` instead of `break-after: always;` would likely result in a parsing error.
* **Misunderstanding Property Values:** Users might not fully understand the allowed values or the implications of certain values for a property.
    * **Example:**  A user might expect `clip: 10px;` to clip all sides of an element equally, but the `clip` property with the `rect()` function requires four values.
* **Overriding Styles:**  Users might unintentionally override a previously set value for a property with a new rule.

**User Operation Leading to This Code (Debugging Clues):**

1. **User writes HTML and CSS:** A user creates an HTML file and includes CSS rules that use the properties defined in this file (e.g., `color: blue;`, `break-after: page;`).
2. **Browser loads the page:** The browser's rendering engine starts parsing the HTML and CSS.
3. **CSS Parser encounters a property:** When the CSS parser encounters a property like `color`, it identifies it as a longhand property.
4. **Lookup in property tables:** The engine uses internal tables to map the CSS property name (`color`) to the corresponding `CSSProperty` object (likely the `Color` class defined here).
5. **`ParseSingleValue` is called:** The `ParseSingleValue` method of the `Color` class is called, along with the relevant portion of the CSS token stream (`blue`). This function attempts to interpret "blue" as a color.
6. **Style Resolution:** After parsing, the resolved values are used during style resolution to determine the final styles of each element, resulting in `ComputedStyle` objects.
7. **`CSSValueFromComputedStyleInternal` (if needed):** If JavaScript queries the computed style of an element's color or if the DevTools need to display the computed color, the `Color::CSSValueFromComputedStyleInternal` method is called on the element's `ComputedStyle` to retrieve the computed color value as a `CSSValue`.

**Summary of this Section (Part 3 of 13):**

This specific part of `longhands_custom.cc` defines the **parsing and computed style retrieval logic for a subset of CSS longhand properties related to layout, text appearance, and page/column breaks.** It provides the mechanism for the Blink rendering engine to understand CSS syntax for these properties and to provide their calculated values for rendering and JavaScript interaction. It handles the conversion between CSS text and the engine's internal representations of these style attributes.

### 提示词
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
{
  return CSSIdentifierValue::Create(style.BreakAfter());
}

const CSSValue* BreakBefore::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BreakBefore());
}

const CSSValue* BreakInside::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BreakInside());
}

const CSSValue* BufferedRendering::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.BufferedRendering());
}

const CSSValue* CaptionSide::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.CaptionSide());
}

const CSSValue* CaretAnimation::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.CaretAnimation());
}

const CSSValue* CaretColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color CaretColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleAutoColor& auto_color = style.CaretColor();
  // TODO(rego): We may want to adjust the caret color if it's the same as
  // the background to ensure good visibility and contrast.
  const StyleColor result = auto_color.IsAutoColor()
                                ? StyleColor::CurrentColor()
                                : auto_color.ToStyleColor();
  if (style.ShouldForceColor(result)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return result.Resolve(style.GetCurrentColor(), style.UsedColorScheme(),
                        is_current_color);
}

const CSSValue* CaretColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (allow_visited_style) {
    return cssvalue::CSSColor::Create(style.VisitedDependentColor(*this));
  }

  const StyleAutoColor& auto_color = style.CaretColor();
  // TODO(rego): We may want to adjust the caret color if it's the same as
  // the background to ensure good visibility and contrast.
  const StyleColor result = auto_color.IsAutoColor()
                                ? StyleColor::CurrentColor()
                                : auto_color.ToStyleColor();
  if (value_phase == CSSValuePhase::kResolvedValue &&
      style.ShouldForceColor(result)) {
    return cssvalue::CSSColor::Create(style.GetInternalForcedCurrentColor());
  }

  return ComputedStyleUtils::ValueForStyleAutoColor(style, style.CaretColor(),
                                                    value_phase);
}

const CSSValue* Clear::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Clear());
}

namespace {

CSSValue* ConsumeClipComponent(CSSParserTokenStream& stream,
                               const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kAll,
      css_parsing_utils::UnitlessQuirk::kAllow);
}

}  // namespace

const CSSValue* Clip::ParseSingleValue(CSSParserTokenStream& stream,
                                       const CSSParserContext& context,
                                       const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  if (stream.Peek().FunctionId() != CSSValueID::kRect) {
    return nullptr;
  }

  CSSParserTokenStream::RestoringBlockGuard guard(stream);
  stream.ConsumeWhitespace();
  // rect(t, r, b, l) || rect(t r b l)
  CSSValue* top = ConsumeClipComponent(stream, context);
  if (!top) {
    return nullptr;
  }
  bool needs_comma = css_parsing_utils::ConsumeCommaIncludingWhitespace(stream);
  CSSValue* right = ConsumeClipComponent(stream, context);
  if (!right || (needs_comma &&
                 !css_parsing_utils::ConsumeCommaIncludingWhitespace(stream))) {
    return nullptr;
  }
  CSSValue* bottom = ConsumeClipComponent(stream, context);
  if (!bottom ||
      (needs_comma &&
       !css_parsing_utils::ConsumeCommaIncludingWhitespace(stream))) {
    return nullptr;
  }
  CSSValue* left = ConsumeClipComponent(stream, context);
  if (!left || !stream.AtEnd()) {
    // NOTE: This AtEnd() is fine, because we test within the
    // RestoringBlockGuard. But we need the stream to rewind in that case.
    return nullptr;
  }
  guard.Release();
  return MakeGarbageCollected<CSSQuadValue>(top, right, bottom, left,
                                            CSSQuadValue::kSerializeAsRect);
}

const CSSValue* Clip::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.HasAutoClip()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  CSSValue* top = ComputedStyleUtils::ZoomAdjustedPixelValueOrAuto(
      style.Clip().Top(), style);
  CSSValue* right = ComputedStyleUtils::ZoomAdjustedPixelValueOrAuto(
      style.Clip().Right(), style);
  CSSValue* bottom = ComputedStyleUtils::ZoomAdjustedPixelValueOrAuto(
      style.Clip().Bottom(), style);
  CSSValue* left = ComputedStyleUtils::ZoomAdjustedPixelValueOrAuto(
      style.Clip().Left(), style);
  return MakeGarbageCollected<CSSQuadValue>(top, right, bottom, left,
                                            CSSQuadValue::kSerializeAsRect);
}

const CSSValue* ClipPath::ParseSingleValue(CSSParserTokenStream& stream,
                                           const CSSParserContext& context,
                                           const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  if (cssvalue::CSSURIValue* url =
          css_parsing_utils::ConsumeUrl(stream, context)) {
    return url;
  }

  CSSValue* geometry_box = css_parsing_utils::ConsumeGeometryBox(stream);
  CSSValue* basic_shape = css_parsing_utils::ConsumeBasicShape(stream, context);
  if (basic_shape && !geometry_box) {
    geometry_box = css_parsing_utils::ConsumeGeometryBox(stream);
  }
  if (basic_shape || geometry_box) {
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    if (basic_shape) {
      list->Append(*basic_shape);
    }
    if (geometry_box) {
      if (list->length() == 0 ||
          To<CSSIdentifierValue>(geometry_box)->GetValueID() !=
              CSSValueID::kBorderBox) {
        list->Append(*geometry_box);
      }
    }
    return list;
  }

  return nullptr;
}

const CSSValue* ClipPath::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (ClipPathOperation* operation = style.ClipPath()) {
    if (auto* box = DynamicTo<GeometryBoxClipPathOperation>(operation)) {
      CSSValueList* list = CSSValueList::CreateSpaceSeparated();
      GeometryBox geometry_box = box->GetGeometryBox();
      list->Append(*CSSIdentifierValue::Create(geometry_box));
      return list;
    }
    if (auto* shape = DynamicTo<ShapeClipPathOperation>(operation)) {
      CSSValueList* list = CSSValueList::CreateSpaceSeparated();
      auto* basic_shape = ValueForBasicShape(style, shape->GetBasicShape());
      list->Append(*basic_shape);
      GeometryBox geometry_box = shape->GetGeometryBox();
      if (geometry_box != GeometryBox::kBorderBox) {
        list->Append(*CSSIdentifierValue::Create(geometry_box));
      }
      return list;
    }
    if (operation->GetType() == ClipPathOperation::kReference) {
      AtomicString url = To<ReferenceClipPathOperation>(operation)->Url();
      return MakeGarbageCollected<cssvalue::CSSURIValue>(CSSUrlData(url));
    }
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* ClipRule::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ClipRule());
}

const CSSValue* Color::ParseSingleValue(CSSParserTokenStream& stream,
                                        const CSSParserContext& context,
                                        const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

const blink::Color Color::ColorIncludingFallback(bool visited_link,
                                                 const ComputedStyle& style,
                                                 bool* is_current_color) const {
  DCHECK(!visited_link);
  if (style.ShouldForceColor(style.Color())) {
    return GetCSSPropertyInternalForcedColor().ColorIncludingFallback(
        false, style, is_current_color);
  }
  return style.GetCurrentColor(is_current_color);
}

const CSSValue* Color::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (value_phase == CSSValuePhase::kResolvedValue &&
      style.ShouldForceColor(style.Color())) {
    return GetCSSPropertyInternalForcedColor().CSSValueFromComputedStyle(
        style, nullptr, allow_visited_style, value_phase);
  }
  return cssvalue::CSSColor::Create(allow_visited_style
                                        ? style.VisitedDependentColor(*this)
                                        : style.GetCurrentColor());
}

void Color::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetColor(builder.InitialColorForColorScheme());
  builder.SetColorIsInherited(false);
  builder.SetColorIsCurrentColor(false);
}

void Color::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (builder.ShouldPreserveParentColor()) {
    builder.SetColor(StyleColor(
        state.ParentStyle()->VisitedDependentColor(GetCSSPropertyColor())));
  } else {
    builder.SetColor(state.ParentStyle()->Color());
  }
  builder.SetColorIsInherited(true);
  builder.SetColorIsCurrentColor(state.ParentStyle()->ColorIsCurrentColor());
}

void Color::ApplyValue(StyleResolverState& state,
                       const CSSValue& value,
                       ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (value.IsInitialColorValue()) {
    DCHECK_EQ(state.GetElement(), state.GetDocument().documentElement());
    builder.SetColor(builder.InitialColorForColorScheme());
  } else {
    StyleColor color = StyleBuilderConverter::ConvertStyleColor(state, value);
    if (color.IsUnresolvedColorFunction()) {
      // Unresolved color functions are a special case for this property.
      // currentColor used in the color property value refers to the parent's
      // computed currentColor which means we can fully resolve currentColor at
      // ApplyValue time to get the correct resolved and used values for the
      // color property in all cases.
      // For typed OM, currentColor and color functions containing
      // currentColor should have been preserved for values in
      // computedStyleMap().
      // See crbug.com/1099874
      color = StyleColor(color.Resolve(state.ParentStyle()->Color().GetColor(),
                                       mojom::blink::ColorScheme::kLight));
    } else if (color.IsCurrentColor()) {
      // As per the spec, 'color: currentColor' is treated as 'color: inherit'
      ApplyInherit(state);
      builder.SetColorIsCurrentColor(true);
      if (state.UsesHighlightPseudoInheritance() &&
          state.OriginatingElementStyle()) {
        builder.SetColor(state.OriginatingElementStyle()->Color());
      }
      return;
    }
    builder.SetColor(color);
  }
  builder.SetColorIsInherited(false);
  builder.SetColorIsCurrentColor(false);
}

const CSSValue* ColorInterpolation::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ColorInterpolation());
}

const CSSValue* ColorInterpolationFilters::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ColorInterpolationFilters());
}

const CSSValue* ColorRendering::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ColorRendering());
}

const CSSValue* ColorScheme::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValue* only = nullptr;
  CSSValueList* values = CSSValueList::CreateSpaceSeparated();
  do {
    CSSValueID id = stream.Peek().Id();
    // 'normal' is handled above, and needs to be excluded from
    // ConsumeCustomIdent below.
    if (id == CSSValueID::kNormal) {
      return nullptr;
    }
    CSSValue* value =
        css_parsing_utils::ConsumeIdent<CSSValueID::kDark, CSSValueID::kLight,
                                        CSSValueID::kOnly>(stream);
    if (id == CSSValueID::kOnly) {
      if (only) {
        return nullptr;
      }
      if (values->length()) {
        values->Append(*value);
        return values;
      }
      only = value;
      continue;
    }
    if (!value) {
      value = css_parsing_utils::ConsumeCustomIdent(stream, context);
    }
    if (!value) {
      break;
    }
    values->Append(*value);
  } while (!stream.AtEnd());
  if (!values->length()) {
    return nullptr;
  }
  if (only) {
    values->Append(*only);
  }
  return values;
}

const CSSValue* ColorScheme::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.ColorScheme().empty()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  for (auto ident : style.ColorScheme()) {
    list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(ident));
  }
  return list;
}

const CSSValue* ColorScheme::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNormal);
}

namespace {

void ApplyColorSchemeValue(StyleResolverState& state,
                           const CSSValueList* scheme_list) {
  ColorSchemeFlags flags =
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal);
  Vector<AtomicString> color_schemes;

  Document& document = state.GetDocument();
  if (scheme_list) {
    flags = StyleBuilderConverter::ExtractColorSchemes(document, *scheme_list,
                                                       &color_schemes);
  } else {
    flags = document.GetStyleEngine().GetPageColorSchemes();
  }

  state.StyleBuilder().SetColorScheme(std::move(color_schemes));
  state.StyleBuilder().SetUsedColorScheme(
      flags, document.GetStyleEngine().GetPreferredColorScheme(),
      document.GetStyleEngine().GetForceDarkModeEnabled());

  if (flags & static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark)) {
    // Record kColorSchemeDarkSupportedOnRoot if dark is present (though dark
    // may not be used). This metric is also recorded in
    // StyleEngine::UpdateColorSchemeMetrics if a meta tag supports dark.
    if (document.documentElement() == state.GetElement()) {
      UseCounter::Count(document, WebFeature::kColorSchemeDarkSupportedOnRoot);
    }
  }
}

}  // namespace

void ColorScheme::ApplyInitial(StyleResolverState& state) const {
  ApplyColorSchemeValue(state, nullptr /* scheme_list */);
}

void ColorScheme::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetColorScheme(state.ParentStyle()->ColorScheme());
  builder.SetDarkColorScheme(state.ParentStyle()->DarkColorScheme());
  builder.SetColorSchemeForced(state.ParentStyle()->ColorSchemeForced());
}

void ColorScheme::ApplyValue(StyleResolverState& state,
                             const CSSValue& value,
                             ValueMode) const {
  const CSSValueList* scheme_list = DynamicTo<CSSValueList>(value);
  DCHECK(scheme_list || (value.IsIdentifierValue() &&
                         DynamicTo<CSSIdentifierValue>(value)->GetValueID() ==
                             CSSValueID::kNormal));
  ApplyColorSchemeValue(state, scheme_list);
}

const CSSValue* ColumnCount::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColumnCount(stream, context);
}

const CSSValue* ColumnCount::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.HasAutoColumnCount()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return CSSNumericLiteralValue::Create(style.ColumnCount(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* ColumnFill::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetColumnFill());
}

const CSSValue* ColumnGap::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGapLength(stream, context);
}

const CSSValue* ColumnGap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGapLength(style.ColumnGap(), style);
}

const CSSValue* ColumnRuleColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGapDecorationPropertyList(
      stream, context, CSSGapDecorationPropertyType::kColor);
}

const blink::Color ColumnRuleColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  const StyleColor& column_rule_color =
      style.ColumnRuleColor().GetLegacyValue();
  if (style.ShouldForceColor(column_rule_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return column_rule_color.Resolve(style.GetCurrentColor(),
                                   style.UsedColorScheme(), is_current_color);
}

const CSSValue* ColumnRuleColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!RuntimeEnabledFeatures::CSSGapDecorationEnabled()) {
    if (allow_visited_style) {
      return cssvalue::CSSColor::Create(style.VisitedDependentColor(*this));
    }
  }

  // TODO(crbug.com/357648037): Add UseCounter to  measure the use of
  // column-rule-color in :visited style rules.
  return ComputedStyleUtils::ValueForGapDecorationColorDataList(
      style.ColumnRuleColor(), style, value_phase);
}

const CSSValue* ColumnRuleStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ColumnRuleStyle());
}

const CSSValue* ColumnRuleWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGapDecorationPropertyList(
      stream, context, CSSGapDecorationPropertyType::kWidth);
}

const CSSValue* ColumnRuleWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGapDecorationWidthDataList(
      style.ColumnRuleWidth(), style, value_phase);
}

const CSSValue* ColumnSpan::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIdent<CSSValueID::kAll, CSSValueID::kNone>(
      stream);
}

const CSSValue* ColumnSpan::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(static_cast<unsigned>(style.GetColumnSpan())
                                        ? CSSValueID::kAll
                                        : CSSValueID::kNone);
}

const CSSValue* ColumnWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColumnWidth(stream, context);
}

const CSSValue* ColumnWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.HasAutoColumnWidth()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return ZoomAdjustedPixelValue(style.ColumnWidth(), style);
}

// none | strict | content | [ size || layout || style || paint ]
const CSSValue* Contain::ParseSingleValue(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (id == CSSValueID::kStrict || id == CSSValueID::kContent) {
    list->Append(*css_parsing_utils::ConsumeIdent(stream));
    return list;
  }

  CSSIdentifierValue* size = nullptr;
  CSSIdentifierValue* layout = nullptr;
  CSSIdentifierValue* style = nullptr;
  CSSIdentifierValue* paint = nullptr;
  while (true) {
    id = stream.Peek().Id();
    if ((id == CSSValueID::kSize ||

         id == CSSValueID::kInlineSize) &&
        !size) {
      size = css_parsing_utils::ConsumeIdent(stream);
    } else if (id == CSSValueID::kLayout && !layout) {
      layout = css_parsing_utils::ConsumeIdent(stream);
    } else if (id == CSSValueID::kStyle && !style) {
      style = css_parsing_utils::ConsumeIdent(stream);
    } else if (id == CSSValueID::kPaint && !paint) {
      paint = css_parsing_utils::ConsumeIdent(stream);
    } else {
      break;
    }
  }
  if (size) {
    list->Append(*size);
  }
  if (layout) {
    list->Append(*layout);
  }
  if (style) {
    context.Count(WebFeature::kCSSValueContainStyle);
    list->Append(*style);
  }
  if (paint) {
    list->Append(*paint);
  }
  if (!list->length()) {
    return nullptr;
  }
  return list;
}

const CSSValue* Contain::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.Contain()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  if (style.Contain() == kContainsStrict) {
    return CSSIdentifierValue::Create(CSSValueID::kStrict);
  }
  if (style.Contain() == kContainsContent) {
    return CSSIdentifierValue::Create(CSSValueID::kContent);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  DCHECK_NE(style.Contain() & kContainsSize, kContainsBlockSize);
  if ((style.Contain() & kContainsSize) == kContainsSize) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kSize));
  } else {
    if (style.Contain() & kContainsInlineSize) {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kInlineSize));
    }
  }
  if (style.Contain() & kContainsLayout) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kLayout));
  }
  if (style.Contain() & kContainsStyle) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kStyle));
  }
  if (style.Contain() & kContainsPaint) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kPaint));
  }
  DCHECK(list->length());
  return list;
}

const CSSValue* ContainIntrinsicWidth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIntrinsicSizeLonghand(stream, context);
}

const CSSValue* ContainIntrinsicWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForIntrinsicLength(
      style, style.ContainIntrinsicWidth());
}

const CSSValue* ContainIntrinsicHeight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIntrinsicSizeLonghand(stream, context);
}

const CSSValue* ContainIntrinsicHeight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForIntrinsicLength(
      style, style.ContainIntrinsicHeight());
}

const CSSValue* ContainIntrinsicInlineSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIntrinsicSizeLonghand(stream, context);
}

const CSSValue* ContainIntrinsicBlockSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIntrinsicSizeLonghand(stream, context);
}

const CSSValue* ContainerName::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeContainerName(stream, context);
}

const CSSValue* ContainerName::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.ContainerName()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();

  for (const Member<const ScopedCSSName>& name :
       style.ContainerName()->GetNames()) {
    list->Append(*ComputedStyleUtils::ValueForCustomIdentOrNone(name.Get()));
  }
  return list;
}

const CSSValue* ContainerType::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeContainerType(stream);
}

const CSSValue* ContainerType::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  DCHECK_NE(style.ContainerType() & kContainerTypeSize,
            kContainerTypeBlockSize);

  if (style.ContainerType() == kContainerTypeNormal) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }
  CSSValueList* values = CSSValueList::CreateSpaceSeparated();
  if ((style.ContainerType() & kContainerTypeBlockSize) ==
      kContainerTypeBlockSize) {
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kSize));
  } else if (style.ContainerType() & kContainerTypeInlineSize) {
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kInlineSize));
  }
  if (style.ContainerType() & kContainerTypeScrollState) {
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kScrollState));
  }
  return values;
}

namespace {

CSSValue* ConsumeAttr(CSSParserTokenStream& stream,
                      const CSSParserContext& context) {
  DCHECK(!RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled());

  AtomicString attr_name;
  {
    CSSParserTokenStream::BlockGuard guard(stream);
    stream.ConsumeWhitespace();
    if (stream.Peek().GetType() != kIdentToken) {
      return nullptr;
    }

    attr_name = stream.ConsumeIncludingWhitespace().Value().ToAtomicString();
    if (!stream.AtEnd()) {
      // NOTE: This AtEnd() is fine, because we are inside a function block
      // (i.e., inside a BlockGuard).
      return nullptr;
    }
  }

  stream.ConsumeWhitespace();
  if (context.IsHTMLDocument()) {
    attr_name = attr_name.LowerASCII();
  }

  CSSFunctionValue* attr_value =
      MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kAttr);
  attr_value->Append(*MakeGarbageCollected<CSSCustomIdentValue>(attr_name));
  return attr_value;
}

CSSValue* ConsumeCounterContent(CSSParserTokenStream& stream,
                                const CSSParserContext& context,
                                bool counters) {
  CSSCustomIdentValue* identifier;
  CSSCustomIdentValue* list_style = nullptr;
  CSSStringValue* separator = nullptr;

  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();

    identifier = css_parsing_utils::ConsumeCustomIdent(stream, context);
    if (!identifier) {
      return nullptr;
    }

    if (!counters) {
      separator = MakeGarbageCollected<CSSStringValue>(String());
    } else {
      if (!css_parsing_utils::ConsumeCommaIncludingWhitespace(stream) ||
          stream.Peek().GetType() != kStringToken) {
        return nullptr;
      }
      separator = MakeGarbageCollected<CSSStringValue>(
          stream.ConsumeIncludingWhitespace().Value().ToString());
    }

    if (css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
      // Note: CSS3 spec doesn't allow 'none' but CSS2.1 allows it. We currently
      // allow it for backward compatibility.
      // See https://github.com/w3c/csswg-drafts/issues/5795 for details.
      if (stream.Peek().Id() == CSSValueID::kNone) {
        list_style =
            MakeGarbageCollected<CSSCustomIdentValue>(AtomicString("none"));
        stream.ConsumeIncludingWhitespace();
      } else {
        list_style =
            css_parsing_utils::ConsumeCounterStyleName(stream, context);
      }
    } else {
      list_style =
          MakeGarbageCollected<CSSCustomIdentValue>(keywords::kDecimal);
    }

    if (!list_style || !stream.AtEnd()) {
      // NOTE: This AtEnd() is fine, because we are inside a function block
      // (i.e., inside a RestoringBlockGuard).
      return nullptr;
    }
    guard.Release();
  }
  stream.ConsumeWhitespace();
  return MakeGarbageCollected<cssvalue::CSSCounterValue>(identifier, list_style,
                                                         separator);
}

const CSSValue* ParseContentValue(CSSParserTokenStream& stream,
                                  const CSSParserContext& context) {
  if (css_parsing_utils::IdentMatches<CSSValueID::kNone, CSSValueID::kNormal>(
          stream.Peek().Id())) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValueList* values = CSSValueList::CreateSpaceSeparated();
  CSSValueList* outer_list = CSSValueList::CreateSlashSeparated();
  bool alt_text_present = false;
  do {
    CSSParserSavePoint savepoint(stream);
    CSSValue* parsed_value = css_parsing_utils::ConsumeImage(stream, context);
    if (!parsed_value) {
      parsed_value = css_parsing_utils::ConsumeIdent<
          CSSValueID::
```