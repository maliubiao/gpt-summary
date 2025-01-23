Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. This code is specifically from `style_property_serializer.cc`. The request has three parts, and this is part 3, so I need to focus on summarizing the overall function of the file based on the previous parts.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:**  Based on the filename and the code content, the primary function is to serialize CSS style properties into their string representation. This involves handling both longhand and shorthand properties.

2. **Recall key functionalities from previous parts:**  Think about the different methods and logic observed in the code. This includes:
    * Iterating through style properties.
    * Handling default or initial values (omitting them in some cases).
    * Special handling for certain shorthand properties (e.g., `mask`, `transition`, `grid`).
    * Logic to determine when to include or omit values based on dependencies and defaults.
    * Functions for serializing different types of shorthand properties (`GetShorthandValue`, `GetShorthandValueFor...`).
    * Specific serialization logic for properties like `border-radius`, `border-image`, `page-break`, `contain-intrinsic-size`, `text-box`, `text-spacing`, `text-wrap`, `white-space`, `scroll-start`, and `position-try`.

3. **Synthesize a concise summary:** Combine the key functionalities into a clear and informative summary. Emphasize the core purpose and mention the handling of longhand and shorthand properties, along with the special cases.
Based on the provided code snippets from parts 1, 2, and 3 of `style_property_serializer.cc`, the primary function of this file in the Chromium Blink engine is to **serialize computed CSS style properties into their canonical string representation**.

Here's a summary of its key responsibilities:

* **Converting Internal Style Representation to CSS Text:** This file takes the internal representation of CSS properties (stored in `property_set_`) and converts them back into a CSS text string that can be understood by browsers and developers. This is crucial for tasks like:
    * Getting the computed style of an element via JavaScript (`window.getComputedStyle`).
    * Serializing styles for rendering optimizations or debugging tools.
    * Representing styles in the DevTools.

* **Handling Shorthand and Longhand Properties:** It has specific logic for handling both individual CSS properties (longhand) and their shorthand equivalents. It determines when it's appropriate to use the shorthand representation based on the values of the constituent longhand properties.

* **Omitting Default and Initial Values:**  The serializer often omits values that are set to their default or initial values when generating the shorthand representation, making the output cleaner and more concise.

* **Special Logic for Specific Properties:** The code includes special handling and logic for various CSS properties, particularly complex shorthands like `background`, `mask`, `transition`, `grid`, `border`, `border-radius`, `text-box`, `text-spacing`, `text-wrap`, and `white-space`. This logic ensures that the serialized output adheres to the correct CSS syntax and handles edge cases and dependencies between different longhand properties within a shorthand.

* **Managing Dependencies between Longhand Properties:** For some shorthands, the presence or value of one longhand property influences whether other related longhand properties need to be explicitly included in the serialized output (e.g., in `mask` and `grid`).

**Relationship to Javascript, HTML, and CSS:**

* **Javascript:** When JavaScript code uses methods like `window.getComputedStyle(element).getPropertyValue('...')`, this serializer is involved in converting the internal style information into the string value returned to the JavaScript code. For example:
    ```javascript
    const element = document.getElementById('myElement');
    const backgroundColor = window.getComputedStyle(element).backgroundColor;
    console.log(backgroundColor); // This will likely involve the serializer.
    ```
    The serializer ensures that the `backgroundColor` is returned as a valid CSS color string (e.g., "rgb(255, 0, 0)").

* **HTML:** The HTML structure defines the elements to which CSS styles are applied. The computed styles of these HTML elements are what this serializer works with. The styles defined in `<style>` tags or linked CSS files are eventually parsed and computed, and this serializer helps represent that computed state.

* **CSS:** This file is fundamentally about CSS. It's responsible for taking the *result* of CSS parsing, cascading, and inheritance (the computed style) and turning it back into a valid CSS string. It understands the nuances of CSS syntax, including shorthand notations and default values.

**Examples of Logic Inference (Based on Snippets):**

* **Assumption:**  The `mask` shorthand property has multiple longhand properties like `mask-image`, `mask-origin`, `mask-clip`, etc.
* **Input:** `property_set_` contains the following computed values:
    * `mask-image: none;`
    * `mask-origin: border-box;`
    * `mask-clip: border-box;`
* **Output:** The `GetShorthandValueForCSSProperty` function for the `mask` shorthand would likely output `"none"` because the `mask-image` is `none`, and the default values for `mask-origin` and `mask-clip` are omitted.

* **Assumption:** The `transition` shorthand omits default values.
* **Input:** `property_set_` contains:
    * `transition-property: all;` (default)
    * `transition-duration: 0s;` (default)
    * `transition-timing-function: ease;` (default)
    * `transition-delay: 0s;` (default)
* **Output:** The `GetShorthandValueForCSSProperty` function for `transition` would output `"all"`.

**Common User or Programming Errors and Debugging Clues:**

* **Incorrect Shorthand Serialization:**  If a shorthand property isn't being serialized correctly (e.g., missing values, incorrect order), developers might look at the logic within functions like `GetShorthandValueFor...` for that specific shorthand to understand how the serialization is being performed.
* **Unexpected Default Value Behavior:** If a developer expects a default value to be serialized but it's being omitted, they might need to investigate the conditions under which the `omit_value` flag is set within the serializer.
* **Debugging Tools:** When inspecting the computed styles in browser DevTools, the string representations shown are often generated using logic similar to what's in this file. If the displayed style is unexpected, it can point to an issue in the serialization logic.

**User Operation to Reach Here (Debugging Clue):**

1. **Open a web page in a Chromium-based browser.**
2. **Open the browser's Developer Tools (usually by pressing F12).**
3. **Select the "Elements" tab.**
4. **Inspect a specific HTML element.**
5. **In the "Styles" pane, look at the "Computed" tab.** This tab shows the final computed styles for the selected element after applying all CSS rules.
6. **The browser's rendering engine (Blink) internally calculates these computed styles.** During this process, the values of CSS properties are determined.
7. **When the DevTools need to display these computed styles as text, or when JavaScript calls `getComputedStyle()`, the `StylePropertySerializer` class is used to convert the internal representation of these styles into their CSS string equivalents.**  The code in this file is directly responsible for that conversion.

In essence, `style_property_serializer.cc` is a crucial component for representing the final, computed state of CSS styles in a human-readable and standard CSS string format within the Chromium rendering engine.

### 提示词
```
这是目录为blink/renderer/core/css/style_property_serializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
kAll) {
            omit_value = true;
          }
        }
      }

      if (shorthand.id() == CSSPropertyID::kMask) {
        if (property->IDEquals(CSSPropertyID::kMaskImage)) {
          if (auto* image_value = DynamicTo<CSSIdentifierValue>(value)) {
            if (image_value->GetValueID() == CSSValueID::kNone) {
              omit_value = true;
            }
          }
        } else if (property->IDEquals(CSSPropertyID::kMaskOrigin)) {
          if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
            mask_origin_value = ident->GetValueID();
          }
          // Omit this value as it is serialized alongside mask-clip.
          omit_value = true;
        } else if (property->IDEquals(CSSPropertyID::kMaskClip)) {
          CSSValueID mask_clip_id = CSSValueID::kBorderBox;
          if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
            mask_clip_id = ident->GetValueID();
          }
          SerializeMaskOriginAndClip(layer_result, mask_origin_value,
                                     mask_clip_id);
          omit_value = true;
        } else if (property->IDEquals(CSSPropertyID::kMaskComposite)) {
          if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
            if (ident->GetValueID() == CSSValueID::kAdd) {
              omit_value = true;
            }
          }
        } else if (property->IDEquals(CSSPropertyID::kMaskMode)) {
          if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
            if (ident->GetValueID() == CSSValueID::kMatchSource) {
              omit_value = true;
            }
          }
        } else if (property->IDEquals(CSSPropertyID::kMaskRepeat)) {
          if (auto* repeat = DynamicTo<CSSRepeatStyleValue>(value)) {
            if (repeat->IsRepeat()) {
              omit_value = true;
            }
          }
        } else if (property->IDEquals(CSSPropertyID::kMaskSize)) {
          if (auto* size_value = DynamicTo<CSSIdentifierValue>(value)) {
            if (size_value->GetValueID() == CSSValueID::kAuto) {
              omit_value = true;
            }
          }
        } else if (property->IDEquals(CSSPropertyID::kWebkitMaskPositionX)) {
          omit_value = true;
          mask_position_x = value;
        } else if (property->IDEquals(CSSPropertyID::kWebkitMaskPositionY)) {
          omit_value = true;

          if (!IsZeroPercent(mask_position_x) || !IsZeroPercent(value)) {
            is_position_x_serialized = true;
            is_position_y_serialized = true;

            if (!layer_result.empty()) {
              layer_result.Append(' ');
            }
            layer_result.Append(mask_position_x->CssText());
            layer_result.Append(' ');
            layer_result.Append(value->CssText());
          }
        }
      }

      if (!omit_value) {
        if (property->IDEquals(CSSPropertyID::kBackgroundSize) ||
            property->IDEquals(CSSPropertyID::kMaskSize)) {
          if (is_position_y_serialized || is_position_x_serialized) {
            layer_result.Append(" / ");
          } else {
            layer_result.Append(" 0% 0% / ");
          }
        } else if (!layer_result.empty()) {
          // Do this second to avoid ending up with an extra space in the output
          // if we hit the continue above.
          layer_result.Append(' ');
        }

        layer_result.Append(value->CssText());

        if (property->IDEquals(CSSPropertyID::kBackgroundPositionX)) {
          is_position_x_serialized = true;
        }
        if (property->IDEquals(CSSPropertyID::kBackgroundPositionY)) {
          is_position_y_serialized = true;
          // background-position is a special case. If only the first offset is
          // specified, the second one defaults to "center", not the same value.
        }
      }
    }
    if (shorthand.id() == CSSPropertyID::kMask && layer_result.empty()) {
      layer_result.Append(GetCSSValueNameAs<StringView>(CSSValueID::kNone));
    }
    if (shorthand.id() == CSSPropertyID::kTransition && layer_result.empty()) {
      // When serializing the transition shorthand, we omit all values which are
      // set to their defaults. If everything is set to the default, then emit
      // "all" instead of an empty string.
      layer_result.Append("all");
    }
    if (!layer_result.empty()) {
      if (!result.empty()) {
        result.Append(", ");
      }
      result.Append(layer_result);
    }
  }

  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValue(
    const StylePropertyShorthand& shorthand,
    String separator) const {
  StringBuilder result;
  for (const CSSProperty* const longhand : shorthand.properties()) {
    const CSSValue* value = property_set_.GetPropertyCSSValue(*longhand);
    String value_text = value->CssText();
    if (value->IsInitialValue()) {
      continue;
    }
    if (!result.empty()) {
      result.Append(separator);
    }
    result.Append(value_text);
  }
  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValueForColumnRule(
    const StylePropertyShorthand& shorthand) const {
  DCHECK_EQ(shorthand.length(), 3u);

  const CSSValue* column_rule_width =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[0]);
  const CSSValue* column_rule_style =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[1]);
  const CSSValue* column_rule_color =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[2]);

  StringBuilder result;
  if (const auto* ident_value =
          DynamicTo<CSSIdentifierValue>(column_rule_width);
      !(ident_value && ident_value->GetValueID() == CSSValueID::kMedium) &&
      !column_rule_width->IsInitialValue()) {
    String column_rule_width_text = column_rule_width->CssText();
    result.Append(column_rule_width_text);
  }

  if (const auto* ident_value =
          DynamicTo<CSSIdentifierValue>(column_rule_style);
      !(ident_value && ident_value->GetValueID() == CSSValueID::kNone) &&
      !column_rule_style->IsInitialValue()) {
    String column_rule_style_text = column_rule_style->CssText();
    if (!result.empty()) {
      result.Append(" ");
    }

    result.Append(column_rule_style_text);
  }
  if (const auto* ident_value =
          DynamicTo<CSSIdentifierValue>(column_rule_color);
      !(ident_value &&
        ident_value->GetValueID() == CSSValueID::kCurrentcolor) &&
      !column_rule_color->IsInitialValue()) {
    String column_rule_color_text = column_rule_color->CssText();
    if (!result.empty()) {
      result.Append(" ");
    }

    result.Append(column_rule_color_text);
  }

  if (result.empty()) {
    return "medium";
  }

  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValueForColumns(
    const StylePropertyShorthand& shorthand) const {
  DCHECK_EQ(shorthand.length(), 2u);

  StringBuilder result;
  for (const CSSProperty* const longhand : shorthand.properties()) {
    const CSSValue* value = property_set_.GetPropertyCSSValue(*longhand);
    String value_text = value->CssText();
    if (const auto* ident_value = DynamicTo<CSSIdentifierValue>(value);
        ident_value && ident_value->GetValueID() == CSSValueID::kAuto) {
      continue;
    }
    if (!result.empty()) {
      result.Append(" ");
    }
    result.Append(value_text);
  }

  if (result.empty()) {
    return "auto";
  }

  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValueForDoubleBarCombinator(
    const StylePropertyShorthand& shorthand) const {
  StringBuilder result;
  for (const CSSProperty* const property : shorthand.properties()) {
    const Longhand* longhand = To<Longhand>(property);
    DCHECK(!longhand->InitialValue()->IsInitialValue())
        << "Without InitialValue() implemented, 'initial' will show up in the "
           "serialization below.";
    const CSSValue* value = property_set_.GetPropertyCSSValue(*longhand);
    if (*value == *longhand->InitialValue()) {
      continue;
    }
    String value_text = value->CssText();
    if (!result.empty()) {
      result.Append(" ");
    }
    result.Append(value_text);
  }

  if (result.empty()) {
    return To<Longhand>(shorthand.properties()[0])->InitialValue()->CssText();
  }

  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValueForGrid(
    const StylePropertyShorthand& shorthand) const {
  DCHECK_EQ(shorthand.length(), 6u);

  const auto* template_row_values =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[0]);
  const auto* template_column_values =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[1]);
  const auto* template_area_value =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[2]);
  const auto* auto_flow_values =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[3]);
  const auto* auto_row_values =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[4]);
  const auto* auto_column_values =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[5]);

  // `auto-flow`, `grid-auto-rows`, and `grid-auto-columns` are parsed as either
  // an identifier with the default value, or a CSSValueList containing a single
  // entry with the default value. Unlike `grid-template-rows` and
  // `grid-template-columns`, we *can* determine if the author specified them by
  // the presence of an associated CSSValueList.
  auto HasInitialValueListValue = [](const CSSValueList* value_list,
                                     auto* definition) -> bool {
    return value_list && value_list->length() == 1 &&
           value_list->First() == *(definition().InitialValue());
  };
  auto HasInitialIdentifierValue = [](const CSSValue* value,
                                      CSSValueID initial_value) -> bool {
    return IsA<CSSIdentifierValue>(value) &&
           To<CSSIdentifierValue>(value)->GetValueID() == initial_value;
  };

  const auto* auto_row_value_list = DynamicTo<CSSValueList>(auto_row_values);
  const bool is_auto_rows_initial_value =
      HasInitialValueListValue(auto_row_value_list,
                               GetCSSPropertyGridAutoRows) ||
      HasInitialIdentifierValue(auto_row_values, CSSValueID::kAuto);
  const bool specified_non_initial_auto_rows =
      auto_row_value_list && !is_auto_rows_initial_value;

  const auto* auto_column_value_list =
      DynamicTo<CSSValueList>(auto_column_values);
  const bool is_auto_columns_initial_value =
      HasInitialValueListValue(auto_column_value_list,
                               GetCSSPropertyGridAutoColumns) ||
      HasInitialIdentifierValue(auto_column_values, CSSValueID::kAuto);
  const bool specified_non_initial_auto_columns =
      auto_column_value_list && !is_auto_columns_initial_value;

  const auto* auto_flow_value_list = DynamicTo<CSSValueList>(auto_flow_values);
  const bool is_auto_flow_initial_value =
      HasInitialValueListValue(auto_flow_value_list,
                               GetCSSPropertyGridAutoFlow) ||
      HasInitialIdentifierValue(auto_flow_values, CSSValueID::kRow);

  // `grid-auto-*` along with named lines is not valid per the grammar.
  if ((auto_flow_value_list || auto_row_value_list || auto_column_value_list) &&
      *template_area_value !=
          *GetCSSPropertyGridTemplateAreas().InitialValue()) {
    return String();
  }

  // `grid-template-rows` and `grid-template-columns` are shorthards within this
  // shorthand. Based on how parsing works, we can't differentiate between an
  // author specifying `none` and uninitialized.
  const bool non_initial_template_rows =
      (*template_row_values !=
       *GetCSSPropertyGridTemplateRows().InitialValue());
  const bool non_initial_template_columns =
      *template_column_values !=
      *GetCSSPropertyGridTemplateColumns().InitialValue();

  // `grid-template-*` and `grid-auto-*` are mutually exclusive per direction.
  if ((non_initial_template_rows && specified_non_initial_auto_rows) ||
      (non_initial_template_columns && specified_non_initial_auto_columns) ||
      (specified_non_initial_auto_rows && specified_non_initial_auto_columns)) {
    return String();
  }

  // 1- <'grid-template'>
  // If the author didn't specify `auto-flow`, we should go down the
  // `grid-template` path. This should also round-trip if the author specified
  // the initial value for `auto-flow`, unless `auto-columns` or `auto-rows`
  // were also set, causing it to match the shorthand syntax below.
  if (!auto_flow_value_list ||
      (is_auto_flow_initial_value && !(specified_non_initial_auto_columns ||
                                       specified_non_initial_auto_rows))) {
    return GetShorthandValueForGridTemplate(shorthand);
  } else if (non_initial_template_rows && non_initial_template_columns) {
    // Specifying both rows and columns is not valid per the grammar.
    return String();
  }

  // At this point, the syntax matches:
  // <'grid-template-rows'> / [ auto-flow && dense? ] <'grid-auto-columns'>? |
  // [ auto-flow && dense? ] <'grid-auto-rows'>? / <'grid-template-columns'>
  // ...and thus will include `auto-flow` no matter what.
  StringBuilder auto_flow_text;
  auto_flow_text.Append("auto-flow");
  if (auto_flow_value_list &&
      auto_flow_value_list->HasValue(
          *CSSIdentifierValue::Create(CSSValueID::kDense))) {
    auto_flow_text.Append(" dense");
  }

  // 2- <'grid-template-rows'> / [ auto-flow && dense? ] <'grid-auto-columns'>?
  // We can't distinguish between `grid-template-rows` being unspecified or
  // being specified as `none` (see the comment near the definition of
  // `non_initial_template_rows`), as both are initial values. So we must
  // distinguish between the remaining two possible paths via `auto-flow`.
  StringBuilder result;
  if (auto_flow_value_list &&
      auto_flow_value_list->HasValue(
          *CSSIdentifierValue::Create(CSSValueID::kColumn))) {
    result.Append(template_row_values->CssText());
    result.Append(" / ");
    result.Append(auto_flow_text);

    if (specified_non_initial_auto_columns) {
      result.Append(" ");
      result.Append(auto_column_values->CssText());
    }
  } else {
    // 3- [ auto-flow && dense? ] <'grid-auto-rows'>? /
    // <'grid-template-columns'>
    result.Append(auto_flow_text);

    if (specified_non_initial_auto_rows) {
      result.Append(" ");
      result.Append(auto_row_values->CssText());
    }

    result.Append(" / ");
    result.Append(template_column_values->CssText());
  }
  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValueForGridArea(
    const StylePropertyShorthand& shorthand) const {
  const String separator = " / ";

  DCHECK_EQ(shorthand.length(), 4u);
  const CSSValue* grid_row_start =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[0]);
  const CSSValue* grid_column_start =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[1]);
  const CSSValue* grid_row_end =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[2]);
  const CSSValue* grid_column_end =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[3]);

  // `grid-row-end` depends on `grid-row-start`, and `grid-column-end` depends
  // on `grid-column-start`, but what's not consistent is that
  // `grid-column-start` has a dependency on `grid-row-start`. For more details,
  // see https://www.w3.org/TR/css-grid-2/#placement-shorthands
  const bool include_column_start =
      CSSOMUtils::IncludeDependentGridLineEndValue(grid_row_start,
                                                   grid_column_start);
  const bool include_row_end = CSSOMUtils::IncludeDependentGridLineEndValue(
      grid_row_start, grid_row_end);
  const bool include_column_end = CSSOMUtils::IncludeDependentGridLineEndValue(
      grid_column_start, grid_column_end);

  StringBuilder result;

  // `grid-row-start` is always included.
  result.Append(grid_row_start->CssText());

  // If `IncludeDependentGridLineEndValue` returns true for a property,
  // all preceding values must be included.
  if (include_column_start || include_row_end || include_column_end) {
    result.Append(separator);
    result.Append(grid_column_start->CssText());
  }
  if (include_row_end || include_column_end) {
    result.Append(separator);
    result.Append(grid_row_end->CssText());
  }
  if (include_column_end) {
    result.Append(separator);
    result.Append(grid_column_end->CssText());
  }

  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValueForGridLine(
    const StylePropertyShorthand& shorthand) const {
  const String separator = " / ";

  DCHECK_EQ(shorthand.length(), 2u);
  const CSSValue* line_start =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[0]);
  const CSSValue* line_end =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[1]);

  StringBuilder result;

  // `grid-line-start` is always included.
  result.Append(line_start->CssText());
  if (CSSOMUtils::IncludeDependentGridLineEndValue(line_start, line_end)) {
    result.Append(separator);
    result.Append(line_end->CssText());
  }

  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValueForMasonryTrack() const {
  CHECK_EQ(masonryTrackShorthand().length(), 2u);
  CHECK_EQ(masonryTrackShorthand().properties()[0],
           &GetCSSPropertyMasonryTrackStart());
  CHECK_EQ(masonryTrackShorthand().properties()[1],
           &GetCSSPropertyMasonryTrackEnd());

  const auto* track_start =
      property_set_.GetPropertyCSSValue(GetCSSPropertyMasonryTrackStart());
  const auto* track_end =
      property_set_.GetPropertyCSSValue(GetCSSPropertyMasonryTrackStart());

  StringBuilder result;

  // `masonry-track-start` is always included.
  result.Append(track_start->CssText());
  if (CSSOMUtils::IncludeDependentGridLineEndValue(track_start, track_end)) {
    result.Append(" / ");
    result.Append(track_end->CssText());
  }

  return result.ReleaseString();
}

String StylePropertySerializer::GetShorthandValueForGridTemplate(
    const StylePropertyShorthand& shorthand) const {
  const CSSValue* template_row_values =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[0]);
  const CSSValue* template_column_values =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[1]);
  const CSSValue* template_area_values =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[2]);

  const CSSValueList* grid_template_list =
      CSSOMUtils::ComputedValueForGridTemplateShorthand(
          template_row_values, template_column_values, template_area_values);
  return grid_template_list->CssText();
}

// only returns a non-null value if all properties have the same, non-null value
String StylePropertySerializer::GetCommonValue(
    const StylePropertyShorthand& shorthand) const {
  String res;
  for (const CSSProperty* const longhand : shorthand.properties()) {
    const CSSValue* value = property_set_.GetPropertyCSSValue(*longhand);
    // FIXME: CSSInitialValue::CssText should generate the right value.
    String text = value->CssText();
    if (res.IsNull()) {
      res = text;
    } else if (res != text) {
      return String();
    }
  }
  return res;
}

String StylePropertySerializer::BorderPropertyValue(
    const StylePropertyShorthand& width,
    const StylePropertyShorthand& style,
    const StylePropertyShorthand& color) const {
  const CSSProperty* border_image_properties[] = {
      &GetCSSPropertyBorderImageSource(), &GetCSSPropertyBorderImageSlice(),
      &GetCSSPropertyBorderImageWidth(), &GetCSSPropertyBorderImageOutset(),
      &GetCSSPropertyBorderImageRepeat()};

  // If any of the border-image longhands differ from their initial
  // specified values, we should not serialize to a border shorthand
  // declaration.
  for (const auto* border_image_property : border_image_properties) {
    const CSSValue* value =
        property_set_.GetPropertyCSSValue(*border_image_property);
    const CSSValue* initial_specified_value =
        To<Longhand>(*border_image_property).InitialValue();
    if (value && !value->IsInitialValue() &&
        *value != *initial_specified_value) {
      return String();
    }
  }

  const StylePropertyShorthand shorthand_properties[3] = {width, style, color};
  StringBuilder result;
  for (const auto& shorthand_property : shorthand_properties) {
    const String value = GetCommonValue(shorthand_property);
    if (value.IsNull()) {
      return String();
    }
    if (value == "initial") {
      continue;
    }
    if (!result.empty()) {
      result.Append(' ');
    }
    result.Append(value);
  }
  return result.empty() ? String() : result.ReleaseString();
}

String StylePropertySerializer::BorderImagePropertyValue() const {
  StringBuilder result;
  const CSSProperty* properties[] = {
      &GetCSSPropertyBorderImageSource(), &GetCSSPropertyBorderImageSlice(),
      &GetCSSPropertyBorderImageWidth(), &GetCSSPropertyBorderImageOutset(),
      &GetCSSPropertyBorderImageRepeat()};
  size_t index = 0;
  for (const CSSProperty* property : properties) {
    const CSSValue& value = *property_set_.GetPropertyCSSValue(*property);
    if (!result.empty()) {
      result.Append(" ");
    }
    if (index == 2 || index == 3) {
      result.Append("/ ");
    }
    result.Append(value.CssText());
    index++;
  }
  return result.ReleaseString();
}

String StylePropertySerializer::BorderRadiusValue() const {
  auto serialize = [](const CSSValue& top_left, const CSSValue& top_right,
                      const CSSValue& bottom_right,
                      const CSSValue& bottom_left) -> String {
    bool show_bottom_left = !(top_right == bottom_left);
    bool show_bottom_right = !(top_left == bottom_right) || show_bottom_left;
    bool show_top_right = !(top_left == top_right) || show_bottom_right;

    StringBuilder result;
    result.Append(top_left.CssText());
    if (show_top_right) {
      result.Append(' ');
      result.Append(top_right.CssText());
    }
    if (show_bottom_right) {
      result.Append(' ');
      result.Append(bottom_right.CssText());
    }
    if (show_bottom_left) {
      result.Append(' ');
      result.Append(bottom_left.CssText());
    }
    return result.ReleaseString();
  };

  const CSSValuePair& top_left = To<CSSValuePair>(
      *property_set_.GetPropertyCSSValue(GetCSSPropertyBorderTopLeftRadius()));
  const CSSValuePair& top_right = To<CSSValuePair>(
      *property_set_.GetPropertyCSSValue(GetCSSPropertyBorderTopRightRadius()));
  const CSSValuePair& bottom_right =
      To<CSSValuePair>(*property_set_.GetPropertyCSSValue(
          GetCSSPropertyBorderBottomRightRadius()));
  const CSSValuePair& bottom_left =
      To<CSSValuePair>(*property_set_.GetPropertyCSSValue(
          GetCSSPropertyBorderBottomLeftRadius()));

  StringBuilder builder;
  builder.Append(serialize(top_left.First(), top_right.First(),
                           bottom_right.First(), bottom_left.First()));

  if (!(top_left.First() == top_left.Second()) ||
      !(top_right.First() == top_right.Second()) ||
      !(bottom_right.First() == bottom_right.Second()) ||
      !(bottom_left.First() == bottom_left.Second())) {
    builder.Append(" / ");
    builder.Append(serialize(top_left.Second(), top_right.Second(),
                             bottom_right.Second(), bottom_left.Second()));
  }

  return builder.ReleaseString();
}

String StylePropertySerializer::PageBreakPropertyValue(
    const StylePropertyShorthand& shorthand) const {
  const CSSValue* value =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[0]);
  CSSValueID value_id = To<CSSIdentifierValue>(value)->GetValueID();
  // https://drafts.csswg.org/css-break/#page-break-properties
  if (value_id == CSSValueID::kPage) {
    return "always";
  }
  if (value_id == CSSValueID::kAuto || value_id == CSSValueID::kLeft ||
      value_id == CSSValueID::kRight || value_id == CSSValueID::kAvoid) {
    return value->CssText();
  }
  return String();
}

String StylePropertySerializer::ContainIntrinsicSizeValue() const {
  // If the two values are identical, we return just one.
  String res = GetCommonValue(containIntrinsicSizeShorthand());
  if (!res.IsNull()) {
    return res;
  }
  // Otherwise just serialize them in sequence.
  return GetShorthandValue(containIntrinsicSizeShorthand());
}

String StylePropertySerializer::TextBoxValue() const {
  const auto* trim_value = DynamicTo<CSSIdentifierValue>(
      property_set_.GetPropertyCSSValue(GetCSSPropertyTextBoxTrim()));
  CHECK(trim_value);
  const CSSValueID trim_id = trim_value->GetValueID();
  const CSSValue* edge_value =
      property_set_.GetPropertyCSSValue(GetCSSPropertyTextBoxEdge());
  CHECK(edge_value);

  // If `text-box-edge: auto`, produce `normal` or `<text-box-trim>`.
  if (const auto* edge_identifier = DynamicTo<CSSIdentifierValue>(edge_value)) {
    const CSSValueID edge_id = edge_identifier->GetValueID();
    if (edge_id == CSSValueID::kAuto) {
      if (trim_id == CSSValueID::kNone) {
        return GetCSSValueNameAs<String>(CSSValueID::kNormal);
      }
      return trim_value->CssText();
    }
  }

  // Omit `text-box-trim` if `trim-both`, not when it's initial.
  if (trim_id == CSSValueID::kTrimBoth) {
    return edge_value->CssText();
  }

  // Otherwise build a multi-value list.
  StringBuilder result;
  result.Append(trim_value->CssText());
  result.Append(kSpaceCharacter);
  result.Append(edge_value->CssText());
  return result.ToString();
}

String StylePropertySerializer::TextSpacingValue() const {
  const auto* autospace_value = DynamicTo<CSSIdentifierValue>(
      property_set_.GetPropertyCSSValue(GetCSSPropertyTextAutospace()));
  DCHECK(autospace_value);
  const auto* spacing_trim_value = DynamicTo<CSSIdentifierValue>(
      property_set_.GetPropertyCSSValue(GetCSSPropertyTextSpacingTrim()));
  DCHECK(spacing_trim_value);

  // Check if longhands are one of pre-defined keywords.
  const CSSValueID autospace_id = autospace_value->GetValueID();
  const CSSValueID spacing_trim_id = spacing_trim_value->GetValueID();
  if (autospace_id == CSSValueID::kNormal &&
      spacing_trim_id == CSSValueID::kNormal) {
    return GetCSSValueNameAs<String>(CSSValueID::kNormal);
  }
  if (autospace_id == CSSValueID::kNoAutospace &&
      spacing_trim_id == CSSValueID::kSpaceAll) {
    return GetCSSValueNameAs<String>(CSSValueID::kNone);
  }

  // Otherwise build a multi-value list.
  StringBuilder result;
  if (spacing_trim_id != CSSValueID::kNormal) {
    result.Append(GetCSSValueNameAs<StringView>(spacing_trim_id));
  }
  if (autospace_id != CSSValueID::kNormal) {
    if (!result.empty()) {
      result.Append(kSpaceCharacter);
    }
    result.Append(GetCSSValueNameAs<StringView>(autospace_id));
  }
  // When all longhands are initial values, it should be `normal`.
  DCHECK(!result.empty());
  return result.ToString();
}

String StylePropertySerializer::TextWrapValue() const {
  const CSSValue* mode_value =
      property_set_.GetPropertyCSSValue(GetCSSPropertyTextWrapMode());
  const CSSValue* style_value =
      property_set_.GetPropertyCSSValue(GetCSSPropertyTextWrapStyle());
  if (!mode_value || !style_value) {
    // If any longhands are missing, don't serialize as a shorthand.
    return g_empty_string;
  }

  // If `text-wrap-style` is initial, return `text-wrap-mode`.
  const TextWrapMode mode = ToTextWrapMode(mode_value);
  const TextWrapStyle style = ToTextWrapStyle(style_value);
  if (style == ComputedStyleInitialValues::InitialTextWrapStyle()) {
    return PlatformEnumToCSSValueString(mode).ToString();
  }

  // Otherwise, if `text-wrap-mode` is initial, return `text-wrap-style`.
  if (mode == ComputedStyleInitialValues::InitialTextWrapMode()) {
    return PlatformEnumToCSSValueString(style).ToString();
  }

  // If neither is initial, return a list.
  StringBuilder result;
  result.Append(PlatformEnumToCSSValueString(mode));
  result.Append(kSpaceCharacter);
  result.Append(PlatformEnumToCSSValueString(style));
  return result.ToString();
}

String StylePropertySerializer::WhiteSpaceValue() const {
  const CSSValue* collapse_value =
      property_set_.GetPropertyCSSValue(GetCSSPropertyWhiteSpaceCollapse());
  const CSSValue* wrap_value =
      property_set_.GetPropertyCSSValue(GetCSSPropertyTextWrapMode());
  if (!collapse_value || !wrap_value) {
    // If any longhands are missing, don't serialize as a shorthand.
    return g_empty_string;
  }

  // Check if longhands are one of pre-defined keywords of `white-space`.
  const WhiteSpaceCollapse collapse = ToWhiteSpaceCollapse(collapse_value);
  const TextWrapMode wrap = ToTextWrapMode(wrap_value);
  const EWhiteSpace whitespace = ToWhiteSpace(collapse, wrap);
  if (IsValidWhiteSpace(whitespace)) {
    return PlatformEnumToCSSValueString(whitespace).ToString();
  }

  // Otherwise build a multi-value list.
  StringBuilder result;
  if (collapse != ComputedStyleInitialValues::InitialWhiteSpaceCollapse()) {
    result.Append(PlatformEnumToCSSValueString(collapse));
  }
  if (wrap != ComputedStyleInitialValues::InitialTextWrapMode()) {
    if (!result.empty()) {
      result.Append(kSpaceCharacter);
    }
    result.Append(PlatformEnumToCSSValueString(wrap));
  }
  // When all longhands are initial values, it should be `normal`, covered by
  // `IsValidWhiteSpace()` above.
  DCHECK(!result.empty());
  return result.ToString();
}

String StylePropertySerializer::ScrollStartValue() const {
  CHECK_EQ(scrollStartShorthand().length(), 2u);
  CHECK_EQ(scrollStartShorthand().properties()[0],
           &GetCSSPropertyScrollStartBlock());
  CHECK_EQ(scrollStartShorthand().properties()[1],
           &GetCSSPropertyScrollStartInline());

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  const CSSValue* block_value =
      property_set_.GetPropertyCSSValue(GetCSSPropertyScrollStartBlock());
  const CSSValue* inline_value =
      property_set_.GetPropertyCSSValue(GetCSSPropertyScrollStartInline());

  DCHECK(block_value);
  DCHECK(inline_value);

  list->Append(*block_value);

  if (const auto* ident_value = DynamicTo<CSSIdentifierValue>(inline_value);
      !ident_value || ident_value->GetValueID() != CSSValueID::kStart) {
    list->Append(*inline_value);
  }

  return list->CssText();
}

String StylePropertySerializer::PositionTryValue(
    const StylePropertyShorthand& shorthand) const {
  CHECK_EQ(shorthand.length(), 2u);
  CHECK_EQ(shorthand.properties()[0], &GetCSSPropertyPositionTryOrder());

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  const CSSValue* order_value =
      property_set_.GetPropertyCSSValue(GetCSSPropertyPositionTryOrder());
  const CSSValue* fallbacks_value =
      property_set_.GetPropertyCSSValue(*shorthand.properties()[1]);

  CHECK(order_value);
  CHECK(fallbacks_value);

  if (To<CSSIdentifierValue>(*order_value).GetValueID() !=
      CSSValueID::kNormal) {
    list->Append(*order_value);
  }
  list->Append(*fallbacks_value);
  return list->CssText();
}

}  // namespace blink
```