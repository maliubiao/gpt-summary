Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `style_property_serializer.cc`. This file is part of the Chromium Blink rendering engine and deals with serializing CSS style properties into their string representations.

Here's a breakdown of the code and its functions:

1. **`TimelineValueItem` Function:** This helper function takes individual components of a timeline CSS property (name, axis, inset) and constructs a space-separated list representing a single item within the timeline shorthand. It handles omitting default values.

2. **`TimelineValue` Function:** This function serializes the `scroll-timeline` or `view-timeline` shorthand property. It retrieves the values of the longhand properties (`*-timeline-name`, `*-timeline-axis`, and potentially `*-timeline-inset`), checks if the number of items in each longhand matches, and then uses `TimelineValueItem` to create comma-separated items for the shorthand value.

3. **`ScrollTimelineValue` and `ViewTimelineValue` Functions:** These are specific wrappers for `TimelineValue`, tailored to the `scroll-timeline` and `view-timeline` shorthands respectively. They perform checks to ensure the correct longhand properties are being used.

4. **`GetTimelineRangePercent` Function:** This helper function extracts the timeline name and offset (as a percentage) from a CSS value, used for `animation-range-start` and `animation-range-end`. It handles cases where the offset is omitted or not a percentage.

5. **`AnimationRangeShorthandValueItem` Function:**  This function constructs a space-separated value for a single item within the `animation-range` shorthand, combining the start and end values. It optimizes by omitting the end value if it's the default 100% and the start name is the same.

6. **`AnimationRangeShorthandValue` Function:** This function serializes the `animation-range` shorthand property. It retrieves the `animation-range-start` and `animation-range-end` values, checks if they have the same number of items, and then uses `AnimationRangeShorthandValueItem` to create comma-separated items for the shorthand.

7. **`FontValue` Function:** This function serializes the `font` shorthand property. It retrieves the values of various `font-*` longhand properties. It includes logic to avoid serialization if certain sub-properties have non-initial values that conflict with the shorthand representation. It constructs the string representation by appending non-default values of the longhands in the correct order.

8. **`FontVariantValue` Function:** This function serializes the `font-variant` shorthand. It concatenates the non-default values of the `font-variant-*` longhand properties. It has a special check to avoid serialization if it needs to represent `font-variant-ligatures: none` along with other non-normal `font-variant-*` values.

9. **`FontSynthesisValue` Function:** This function serializes the `font-synthesis` shorthand. It checks the `font-synthesis-weight`, `font-synthesis-style`, and `font-synthesis-small-caps` properties and outputs "weight", "style", or "small-caps" if their values are "auto". If all are not "auto", it outputs "none".

10. **`OffsetValue` Function:** This function serializes the `offset` shorthand property. It checks the values of `offset-position`, `offset-path`, `offset-distance`, `offset-rotate`, and `offset-anchor`, and includes them in the serialized string only if they are not at their initial values, with some specific logic for the `offset-rotate` property.

11. **`TextDecorationValue` Function:** This function serializes the `text-decoration` shorthand. It iterates through the longhand properties and appends their non-initial values to the result string, with a specific exclusion for the initial 'auto' value of `text-decoration-thickness`.

12. **`Get2Values` Function:** This is a generic helper function to serialize shorthands with two values, like `margin-inline`. It only includes the second value if it's different from the first.

13. **`Get4Values` Function:** This is a generic helper function to serialize shorthands with four values, like `margin`. It includes values only if they are different from the preceding value based on the standard CSS shorthand expansion rules (top, right, bottom, left).

14. **`SerializeMaskOriginAndClip` Function:** This helper function serializes the `mask-origin` and `mask-clip` properties together, following specific rules for omitting default values and combining the two properties when their values are the same.

15. **`GetLayeredShorthandValue` Function:** This function handles the serialization of layered shorthands like `background` and `mask`. It iterates through the layers and the properties within each layer, carefully handling singleton properties and properties that reset to their initial values in the shorthand. It has specific checks for properties like `animation-timeline`, `animation-range-start`, `animation-range-end`, and `transition-*` to ensure correct serialization and handle cases where the shorthand cannot represent the current state.
这是 `blink/renderer/core/css/style_property_serializer.cc` 文件的第二部分，主要负责将 CSS 属性值序列化（转换为字符串）以便在 CSS 样式表中表示。它专注于处理一些特定的 CSS 简写属性，并根据其包含的长写属性的值来生成简写形式的字符串。

以下是对这部分代码功能的归纳：

**主要功能:**

* **序列化 `scroll-timeline` 和 `view-timeline` 简写属性:**  `TimelineValue`, `ScrollTimelineValue`, 和 `ViewTimelineValue` 函数负责将 `scroll-timeline-name`, `scroll-timeline-axis` (以及 `view-timeline-inset` 对于 `view-timeline`) 这几个长写属性的值组合成 `scroll-timeline` 或 `view-timeline` 的简写形式。它会处理默认值的省略，并确保序列化后的字符串能够正确反序列化。
* **序列化 `animation-range` 简写属性:** `AnimationRangeShorthandValue` 函数将 `animation-range-start` 和 `animation-range-end` 两个长写属性的值合并成 `animation-range` 简写形式。它优化了输出，例如当 `animation-range-end` 为 100% 且 `animation-range-start` 的名字相同时，可以省略 `animation-range-end`。
* **序列化 `font` 简写属性:** `FontValue` 函数负责将大量的 `font-*` 长写属性（如 `font-style`, `font-weight`, `font-size`, `font-family` 等）的值组合成 `font` 简写形式。它包含复杂的逻辑来判断哪些长写属性可以被包含在简写形式中，并处理一些特殊情况，例如当某些 `font-variant-*` 子属性具有非初始值时，可能无法生成有效的 `font` 简写。
* **序列化 `font-variant` 简写属性:** `FontVariantValue` 函数将多个 `font-variant-*` 长写属性的值合并成 `font-variant` 简写形式。它有一个特殊的处理逻辑，当需要同时表示 `font-variant-ligatures: none` 和其他非 `normal` 的 `font-variant-*` 属性时，会返回空字符串，因为这种组合无法用 `font-variant` 简写来表示。
* **序列化 `font-synthesis` 简写属性:** `FontSynthesisValue` 函数将 `font-synthesis-weight`, `font-synthesis-style`, 和 `font-synthesis-small-caps` 的值组合成 `font-synthesis` 简写形式。如果所有子属性的值都是 `auto`，则输出相应的关键字；否则，如果所有子属性都不是 `auto`，则输出 `none`。
* **序列化 `offset` 简写属性:** `OffsetValue` 函数将 `offset-position`, `offset-path`, `offset-distance`, `offset-rotate`, 和 `offset-anchor` 的值组合成 `offset` 简写形式。它会根据属性值的特性来判断是否需要包含该部分，例如，当 `offset-distance` 为 0 时可以省略。
* **序列化 `text-decoration` 简写属性:** `TextDecorationValue` 函数将 `text-decoration-line`, `text-decoration-color`, 和 `text-decoration-style` 的值组合成 `text-decoration` 简写形式。它会忽略初始值，并且对于 `text-decoration-thickness` 的 `auto` 值也会忽略。
* **通用两值和四值简写属性序列化:** `Get2Values` 和 `Get4Values` 是通用的辅助函数，用于序列化具有两个或四个值的简写属性，例如 `margin-inline` 或 `padding`。它们根据 CSS 简写规则省略重复的值。
* **序列化 `mask-origin` 和 `mask-clip` 属性:** `SerializeMaskOriginAndClip` 函数负责处理 `mask-origin` 和 `mask-clip` 的序列化，根据它们的值来生成最简洁的表示形式，并遵循 CSS Masking 规范中的规则。
* **序列化分层简写属性:** `GetLayeredShorthandValue` 函数处理像 `background` 和 `mask` 这样的分层简写属性。它会遍历每一层，并将该层中各个长写属性的值组合起来。对于某些属性（如 `animation-*` 和 `transition-*`），如果其值不是初始值，则可能无法用简写形式表示，此时会返回空字符串。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **CSS:** 这个文件的核心功能就是处理 CSS 属性的序列化。它读取 CSS 属性的内部表示（`CSSValue` 对象）并将其转换为 CSS 语法中的字符串。
    * **例子:**  假设 `scroll-timeline-name` 的值为 `my-timeline`，`scroll-timeline-axis` 的值为 `block`。`TimelineValue` 函数会生成 CSS 字符串 `"view-timeline: my-timeline block;"`。
* **HTML:**  虽然这个文件不直接操作 HTML，但它生成的 CSS 字符串会被用于渲染 HTML 元素。浏览器解析 HTML 后，会应用 CSS 样式，而这些 CSS 样式最终会通过类似这样的序列化过程转换为字符串形式。
* **JavaScript:** JavaScript 可以通过 DOM API (例如 `element.style.cssText`) 读取或设置元素的样式。当 JavaScript 读取样式时，浏览器可能会使用这样的序列化机制将内部的样式表示转换为字符串返回给 JavaScript。
    * **假设输入:**  一个元素的 `style` 属性中设置了 `scroll-timeline-name: my-timeline; scroll-timeline-axis: block;`。
    * **JavaScript 操作:** `element.style.scrollTimeline`
    * **输出:** `"my-timeline block"` (经过 `ScrollTimelineValue` 函数处理)

**逻辑推理的假设输入与输出:**

* **假设输入:**  `font-style: italic; font-weight: bold; font-size: 16px; font-family: sans-serif;`
* **输出:** `"italic bold 16px sans-serif"` (经过 `FontValue` 函数处理)

**用户或编程常见的使用错误:**

* **尝试直接修改序列化后的字符串:**  用户或开发者不应该直接修改由这些函数生成的 CSS 字符串，而应该通过 CSSOM API 或 CSS 语法来修改样式，因为内部的 `CSSValue` 对象和样式结构需要正确更新。直接修改字符串可能导致状态不一致。
* **假设序列化总是无损的:**  虽然序列化的目标是生成可以反序列化的字符串，但在某些复杂情况下，特别是涉及到一些历史遗留的简写属性时，可能存在信息丢失或无法完美还原的情况。开发者应该避免依赖于序列化和反序列化的完全对等性。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在浏览器中加载一个包含 CSS 样式的网页。**
2. **浏览器解析 HTML 和 CSS。**
3. **渲染引擎根据 CSS 规则计算出每个元素的最终样式，并将样式信息存储在内部数据结构中。**
4. **在某些情况下，例如：**
    * **通过开发者工具检查元素的样式:** 开发者工具需要将内部的样式表示转换为 CSS 字符串显示出来。
    * **使用 `getComputedStyle` 方法获取元素的计算样式:** JavaScript 调用 `getComputedStyle` 时，浏览器需要将计算后的样式值序列化为字符串。
    * **序列化 CSS 样式以进行存储或传输:** 例如，保存用户编辑的样式或通过网络发送样式信息。
5. **当需要将内部的 CSS 属性值转换为字符串时，就会调用 `StylePropertySerializer` 中的相应函数，例如 `FontValue`、`TimelineValue` 等。**

因此，作为调试线索，如果开发者在以上场景中发现显示的 CSS 样式与预期的不符，或者通过 JavaScript 获取到的样式字符串不正确，那么可以考虑在这个 `style_property_serializer.cc` 文件中查找相关的序列化逻辑，以确定是否是序列化过程出现了问题。例如，检查特定的简写属性的序列化函数是否正确处理了各种长写属性的组合和默认值。

### 提示词
```
这是目录为blink/renderer/core/css/style_property_serializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
inset_list) {
  DCHECK_LT(index, name_list.length());
  DCHECK_LT(index, axis_list.length());
  DCHECK(!inset_list || index < inset_list->length());

  const CSSValue& name = name_list.Item(index);
  const CSSValue& axis = axis_list.Item(index);
  const CSSValue* inset = inset_list ? &inset_list->Item(index) : nullptr;

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();

  // Note that the name part can never be omitted, since e.g. serializing
  // "view-timeline:none inline" as "view-timeline:inline" doesn't roundtrip.
  // (It would set view-timeline-name to inline).
  list->Append(name);

  if (!IsIdentifier(axis, CSSValueID::kBlock)) {
    list->Append(axis);
  }
  if (inset && !IsIdentifierPair(*inset, CSSValueID::kAuto)) {
    list->Append(*inset);
  }

  return list;
}

}  // namespace

String StylePropertySerializer::TimelineValue(
    const StylePropertyShorthand& shorthand) const {
  CHECK_GE(shorthand.length(), 2u);
  CHECK_LE(shorthand.length(), 3u);

  const CSSValueList& name_list = To<CSSValueList>(
      *property_set_.GetPropertyCSSValue(*shorthand.properties()[0]));
  const CSSValueList& axis_list = To<CSSValueList>(
      *property_set_.GetPropertyCSSValue(*shorthand.properties()[1]));
  const CSSValueList* inset_list =
      shorthand.length() == 3u
          ? To<CSSValueList>(
                property_set_.GetPropertyCSSValue(*shorthand.properties()[2]))
          : nullptr;

  // The scroll/view-timeline shorthand can not expand to longhands of two
  // different lengths, so we can also not contract two different-longhands
  // into a single shorthand.
  if (name_list.length() != axis_list.length()) {
    return "";
  }
  if (inset_list && name_list.length() != inset_list->length()) {
    return "";
  }

  CSSValueList* list = CSSValueList::CreateCommaSeparated();

  for (wtf_size_t i = 0; i < name_list.length(); ++i) {
    list->Append(*TimelineValueItem(i, name_list, axis_list, inset_list));
  }

  return list->CssText();
}

String StylePropertySerializer::ScrollTimelineValue() const {
  CHECK_EQ(scrollTimelineShorthand().length(), 2u);
  CHECK_EQ(scrollTimelineShorthand().properties()[0],
           &GetCSSPropertyScrollTimelineName());
  CHECK_EQ(scrollTimelineShorthand().properties()[1],
           &GetCSSPropertyScrollTimelineAxis());
  return TimelineValue(scrollTimelineShorthand());
}

String StylePropertySerializer::ViewTimelineValue() const {
  CHECK_EQ(viewTimelineShorthand().length(), 3u);
  CHECK_EQ(viewTimelineShorthand().properties()[0],
           &GetCSSPropertyViewTimelineName());
  CHECK_EQ(viewTimelineShorthand().properties()[1],
           &GetCSSPropertyViewTimelineAxis());
  CHECK_EQ(viewTimelineShorthand().properties()[2],
           &GetCSSPropertyViewTimelineInset());
  return TimelineValue(viewTimelineShorthand());
}

namespace {

// Return the name and offset (in percent). This is useful for
// contracting '<somename> 0%' and '<somename> 100%' into just <somename>.
//
// If the offset is present, but not a <percentage>, -1 is returned as the
// offset. Otherwise (also in the 'normal' case), the `default_offset_percent`
// is returned.
std::pair<CSSValueID, double> GetTimelineRangePercent(
    const CSSValue& value,
    double default_offset_percent) {
  const auto* list = DynamicTo<CSSValueList>(value);
  if (!list) {
    return {CSSValueID::kNormal, default_offset_percent};
  }
  DCHECK_GE(list->length(), 1u);
  DCHECK_LE(list->length(), 2u);
  CSSValueID name = CSSValueID::kNormal;
  double offset_percent = default_offset_percent;

  if (list->Item(0).IsIdentifierValue()) {
    name = To<CSSIdentifierValue>(list->Item(0)).GetValueID();
    if (list->length() == 2u) {
      const auto& offset = To<CSSPrimitiveValue>(list->Item(1));
      offset_percent = offset.IsPercentage() ? offset.GetValue<double>() : -1.0;
    }
  } else {
    const auto& offset = To<CSSPrimitiveValue>(list->Item(0));
    offset_percent = offset.IsPercentage() ? offset.GetValue<double>() : -1.0;
  }

  return {name, offset_percent};
}

CSSValue* AnimationRangeShorthandValueItem(wtf_size_t index,
                                           const CSSValueList& start_list,
                                           const CSSValueList& end_list) {
  DCHECK_LT(index, start_list.length());
  DCHECK_LT(index, end_list.length());

  const CSSValue& start = start_list.Item(index);
  const CSSValue& end = end_list.Item(index);

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();

  list->Append(start);

  // The form "name X name 100%" must contract to "name X".
  //
  // https://github.com/w3c/csswg-drafts/issues/8438
  const auto& start_pair = GetTimelineRangePercent(start, 0.0);
  const auto& end_pair = GetTimelineRangePercent(end, 100.0);
  std::pair<CSSValueID, double> omittable_end = {start_pair.first, 100.0};
  if (end_pair != omittable_end) {
    list->Append(end);
  }

  return list;
}

}  // namespace

String StylePropertySerializer::AnimationRangeShorthandValue() const {
  CHECK_EQ(animationRangeShorthand().length(), 2u);
  CHECK_EQ(animationRangeShorthand().properties()[0],
           &GetCSSPropertyAnimationRangeStart());
  CHECK_EQ(animationRangeShorthand().properties()[1],
           &GetCSSPropertyAnimationRangeEnd());

  const CSSValueList& start_list = To<CSSValueList>(
      *property_set_.GetPropertyCSSValue(GetCSSPropertyAnimationRangeStart()));
  const CSSValueList& end_list = To<CSSValueList>(
      *property_set_.GetPropertyCSSValue(GetCSSPropertyAnimationRangeEnd()));

  if (start_list.length() != end_list.length()) {
    return "";
  }

  CSSValueList* list = CSSValueList::CreateCommaSeparated();

  for (wtf_size_t i = 0; i < start_list.length(); ++i) {
    list->Append(*AnimationRangeShorthandValueItem(i, start_list, end_list));
  }

  return list->CssText();
}

String StylePropertySerializer::FontValue() const {
  int font_size_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontSize());
  int font_family_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontFamily());
  int font_variant_caps_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontVariantCaps());
  int font_variant_ligatures_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontVariantLigatures());
  int font_variant_numeric_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontVariantNumeric());
  int font_variant_east_asian_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontVariantEastAsian());
  int font_kerning_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontKerning());
  int font_optical_sizing_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontOpticalSizing());
  int font_variation_settings_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontVariationSettings());
  int font_feature_settings_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontFeatureSettings());
  DCHECK_NE(font_size_property_index, -1);
  DCHECK_NE(font_family_property_index, -1);
  DCHECK_NE(font_variant_caps_property_index, -1);
  DCHECK_NE(font_variant_ligatures_property_index, -1);
  DCHECK_NE(font_variant_numeric_property_index, -1);
  DCHECK_NE(font_variant_east_asian_property_index, -1);
  DCHECK_NE(font_kerning_property_index, -1);
  DCHECK_NE(font_optical_sizing_property_index, -1);
  DCHECK_NE(font_variation_settings_property_index, -1);
  DCHECK_NE(font_feature_settings_property_index, -1);

  PropertyValueForSerializer font_size_property =
      property_set_.PropertyAt(font_size_property_index);
  PropertyValueForSerializer font_family_property =
      property_set_.PropertyAt(font_family_property_index);
  PropertyValueForSerializer font_variant_caps_property =
      property_set_.PropertyAt(font_variant_caps_property_index);
  PropertyValueForSerializer font_variant_ligatures_property =
      property_set_.PropertyAt(font_variant_ligatures_property_index);
  PropertyValueForSerializer font_variant_numeric_property =
      property_set_.PropertyAt(font_variant_numeric_property_index);
  PropertyValueForSerializer font_variant_east_asian_property =
      property_set_.PropertyAt(font_variant_east_asian_property_index);
  PropertyValueForSerializer font_kerning_property =
      property_set_.PropertyAt(font_kerning_property_index);
  PropertyValueForSerializer font_optical_sizing_property =
      property_set_.PropertyAt(font_optical_sizing_property_index);
  PropertyValueForSerializer font_variation_settings_property =
      property_set_.PropertyAt(font_variation_settings_property_index);
  PropertyValueForSerializer font_feature_settings_property =
      property_set_.PropertyAt(font_feature_settings_property_index);

  // Check that non-initial font-variant subproperties are not conflicting with
  // this serialization.
  const CSSValue* ligatures_value = font_variant_ligatures_property.Value();
  const CSSValue* numeric_value = font_variant_numeric_property.Value();
  const CSSValue* east_asian_value = font_variant_east_asian_property.Value();
  const CSSValue* feature_settings_value =
      font_feature_settings_property.Value();
  const CSSValue* variation_settings_value =
      font_variation_settings_property.Value();

  auto IsPropertyNonInitial = [](const CSSValue& value,
                                 const CSSValueID initial_value_id) {
    auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
    return (identifier_value &&
            identifier_value->GetValueID() != initial_value_id);
  };

  if (IsPropertyNonInitial(*ligatures_value, CSSValueID::kNormal) ||
      ligatures_value->IsValueList()) {
    return g_empty_string;
  }

  if (IsPropertyNonInitial(*numeric_value, CSSValueID::kNormal) ||
      numeric_value->IsValueList()) {
    return g_empty_string;
  }

  if (IsPropertyNonInitial(*east_asian_value, CSSValueID::kNormal) ||
      east_asian_value->IsValueList()) {
    return g_empty_string;
  }

  if (IsPropertyNonInitial(*font_kerning_property.Value(), CSSValueID::kAuto) ||
      IsPropertyNonInitial(*font_optical_sizing_property.Value(),
                           CSSValueID::kAuto)) {
    return g_empty_string;
  }

  if (IsPropertyNonInitial(*variation_settings_value, CSSValueID::kNormal) ||
      variation_settings_value->IsValueList()) {
    return g_empty_string;
  }

  if (IsPropertyNonInitial(*feature_settings_value, CSSValueID::kNormal) ||
      feature_settings_value->IsValueList()) {
    return g_empty_string;
  }

  int font_variant_alternates_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontVariantAlternates());
  DCHECK_NE(font_variant_alternates_property_index, -1);
  PropertyValueForSerializer font_variant_alternates_property =
      property_set_.PropertyAt(font_variant_alternates_property_index);
  const CSSValue* alternates_value = font_variant_alternates_property.Value();
  if (IsPropertyNonInitial(*alternates_value, CSSValueID::kNormal) ||
      alternates_value->IsValueList()) {
    return g_empty_string;
  }

  int font_variant_position_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontVariantPosition());
  DCHECK_NE(font_variant_position_property_index, -1);
  PropertyValueForSerializer font_variant_position_property =
      property_set_.PropertyAt(font_variant_position_property_index);
  if (IsPropertyNonInitial(*font_variant_position_property.Value(),
                           CSSValueID::kNormal)) {
    return g_empty_string;
  }

  if (RuntimeEnabledFeatures::FontVariantEmojiEnabled()) {
    int font_variant_emoji_property_index =
        property_set_.FindPropertyIndex(GetCSSPropertyFontVariantEmoji());
    DCHECK_NE(font_variant_emoji_property_index, -1);
    PropertyValueForSerializer font_variant_emoji_property =
        property_set_.PropertyAt(font_variant_emoji_property_index);
    if (IsPropertyNonInitial(*font_variant_emoji_property.Value(),
                             CSSValueID::kNormal)) {
      return g_empty_string;
    }
  }

  if (RuntimeEnabledFeatures::CSSFontSizeAdjustEnabled()) {
    int font_size_adjust_property_index =
        property_set_.FindPropertyIndex(GetCSSPropertyFontSizeAdjust());
    DCHECK_NE(font_size_adjust_property_index, -1);
    PropertyValueForSerializer font_size_adjust_property =
        property_set_.PropertyAt(font_size_adjust_property_index);
    const CSSValue* size_adjust_value = font_size_adjust_property.Value();
    if (IsPropertyNonInitial(*size_adjust_value, CSSValueID::kNone) ||
        size_adjust_value->IsNumericLiteralValue()) {
      return g_empty_string;
    }
  }

  const StylePropertyShorthand& shorthand = fontShorthand();
  const StylePropertyShorthand::Properties& longhands = shorthand.properties();
  const CSSValue* first = property_set_.GetPropertyCSSValue(*longhands[0]);
  if (const auto* system_font =
          DynamicTo<cssvalue::CSSPendingSystemFontValue>(first)) {
    for (const CSSProperty* const longhand : longhands.subspan<1>()) {
      const CSSValue* value = property_set_.GetPropertyCSSValue(*longhand);
      if (!base::ValuesEquivalent(first, value)) {
        return g_empty_string;
      }
    }
    return GetCSSValueNameAs<String>(system_font->SystemFontId());
  } else {
    for (const CSSProperty* const longhand : longhands.subspan<1>()) {
      const CSSValue* value = property_set_.GetPropertyCSSValue(*longhand);
      if (value->IsPendingSystemFontValue()) {
        return g_empty_string;
      }
    }
  }

  StringBuilder result;
  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontStyle(), result);

  const CSSValue* val = font_variant_caps_property.Value();
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(val);
  if (identifier_value &&
      (identifier_value->GetValueID() != CSSValueID::kSmallCaps &&
       identifier_value->GetValueID() != CSSValueID::kNormal)) {
    return g_empty_string;
  }
  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontVariantCaps(), result);

  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontWeight(), result);
  bool font_stretch_valid =
      AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontStretch(), result);
  if (!font_stretch_valid) {
    return String();
  }
  if (!result.empty()) {
    result.Append(' ');
  }
  result.Append(font_size_property.Value()->CssText());
  AppendFontLonghandValueIfNotNormal(GetCSSPropertyLineHeight(), result);
  if (!result.empty()) {
    result.Append(' ');
  }
  result.Append(font_family_property.Value()->CssText());
  return result.ReleaseString();
}

String StylePropertySerializer::FontVariantValue() const {
  StringBuilder result;
  bool is_variant_ligatures_none = false;

  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontVariantLigatures(),
                                     result);
  if (result.ToString() == "none") {
    is_variant_ligatures_none = true;
  }
  const unsigned variant_ligatures_result_length = result.length();

  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontVariantCaps(), result);
  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontVariantAlternates(),
                                     result);
  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontVariantNumeric(),
                                     result);
  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontVariantEastAsian(),
                                     result);
  AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontVariantPosition(),
                                     result);
  if (RuntimeEnabledFeatures::FontVariantEmojiEnabled()) {
    AppendFontLonghandValueIfNotNormal(GetCSSPropertyFontVariantEmoji(),
                                       result);
  }

  // The font-variant shorthand should return an empty string where
  // it cannot represent "font-variant-ligatures: none" along
  // with any other non-normal longhands.
  // https://drafts.csswg.org/cssom-1/#serializing-css-values
  if (is_variant_ligatures_none &&
      result.length() != variant_ligatures_result_length) {
    return g_empty_string;
  }

  if (result.empty()) {
    return "normal";
  }

  return result.ReleaseString();
}

String StylePropertySerializer::FontSynthesisValue() const {
  StringBuilder result;

  int font_synthesis_weight_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontSynthesisWeight());
  int font_synthesis_style_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontSynthesisStyle());
  int font_synthesis_small_caps_property_index =
      property_set_.FindPropertyIndex(GetCSSPropertyFontSynthesisSmallCaps());
  DCHECK_NE(font_synthesis_weight_property_index, -1);
  DCHECK_NE(font_synthesis_style_property_index, -1);
  DCHECK_NE(font_synthesis_small_caps_property_index, -1);

  PropertyValueForSerializer font_synthesis_weight_property =
      property_set_.PropertyAt(font_synthesis_weight_property_index);
  PropertyValueForSerializer font_synthesis_style_property =
      property_set_.PropertyAt(font_synthesis_style_property_index);
  PropertyValueForSerializer font_synthesis_small_caps_property =
      property_set_.PropertyAt(font_synthesis_small_caps_property_index);

  const CSSValue* font_synthesis_weight_value =
      font_synthesis_weight_property.Value();
  const CSSValue* font_synthesis_style_value =
      font_synthesis_style_property.Value();
  const CSSValue* font_synthesis_small_caps_value =
      font_synthesis_small_caps_property.Value();

  auto* font_synthesis_weight_identifier_value =
      DynamicTo<CSSIdentifierValue>(font_synthesis_weight_value);
  if (font_synthesis_weight_identifier_value &&
      font_synthesis_weight_identifier_value->GetValueID() ==
          CSSValueID::kAuto) {
    result.Append("weight");
  }

  auto* font_synthesis_style_identifier_value =
      DynamicTo<CSSIdentifierValue>(font_synthesis_style_value);
  if (font_synthesis_style_identifier_value &&
      font_synthesis_style_identifier_value->GetValueID() ==
          CSSValueID::kAuto) {
    if (!result.empty()) {
      result.Append(' ');
    }
    result.Append("style");
  }

  auto* font_synthesis_small_caps_identifier_value =
      DynamicTo<CSSIdentifierValue>(font_synthesis_small_caps_value);
  if (font_synthesis_small_caps_identifier_value &&
      font_synthesis_small_caps_identifier_value->GetValueID() ==
          CSSValueID::kAuto) {
    if (!result.empty()) {
      result.Append(' ');
    }
    result.Append("small-caps");
  }

  if (result.empty()) {
    return "none";
  }

  return result.ReleaseString();
}

String StylePropertySerializer::OffsetValue() const {
  const CSSValue* position =
      property_set_.GetPropertyCSSValue(GetCSSPropertyOffsetPosition());
  const CSSValue* path =
      property_set_.GetPropertyCSSValue(GetCSSPropertyOffsetPath());
  const CSSValue* distance =
      property_set_.GetPropertyCSSValue(GetCSSPropertyOffsetDistance());
  const CSSValue* rotate =
      property_set_.GetPropertyCSSValue(GetCSSPropertyOffsetRotate());
  const CSSValue* anchor =
      property_set_.GetPropertyCSSValue(GetCSSPropertyOffsetAnchor());

  auto is_initial_identifier_value = [](const CSSValue* value,
                                        CSSValueID id) -> bool {
    return value->IsIdentifierValue() &&
           DynamicTo<CSSIdentifierValue>(value)->GetValueID() == id;
  };

  bool use_distance =
      distance && !(distance->IsNumericLiteralValue() &&
                    To<CSSNumericLiteralValue>(*distance).DoubleValue() == 0.0);
  const auto* rotate_list_value = DynamicTo<CSSValueList>(rotate);
  bool is_rotate_auto = rotate_list_value && rotate_list_value->length() == 1 &&
                        is_initial_identifier_value(&rotate_list_value->First(),
                                                    CSSValueID::kAuto);
  bool is_rotate_zero =
      rotate_list_value && rotate_list_value->length() == 1 &&
      rotate_list_value->First().IsNumericLiteralValue() &&
      (To<CSSNumericLiteralValue>(rotate_list_value->First()).DoubleValue() ==
       0.0);
  bool is_rotate_auto_zero =
      rotate_list_value && rotate_list_value->length() == 2 &&
      rotate_list_value->Item(1).IsNumericLiteralValue() &&
      (To<CSSNumericLiteralValue>(rotate_list_value->Item(1)).DoubleValue() ==
       0.0) &&
      is_initial_identifier_value(&rotate_list_value->Item(0),
                                  CSSValueID::kAuto);
  bool use_rotate =
      rotate && ((use_distance && is_rotate_zero) ||
                 (!is_initial_identifier_value(rotate, CSSValueID::kAuto) &&
                  !is_rotate_auto && !is_rotate_auto_zero));
  bool use_path =
      path && (use_rotate || use_distance ||
               !is_initial_identifier_value(path, CSSValueID::kNone));
  bool use_position =
      position && (!use_path ||
                   !is_initial_identifier_value(position, CSSValueID::kNormal));
  bool use_anchor =
      anchor && (!is_initial_identifier_value(anchor, CSSValueID::kAuto));

  StringBuilder result;
  if (use_position) {
    result.Append(position->CssText());
  }
  if (use_path) {
    if (!result.empty()) {
      result.Append(" ");
    }
    result.Append(path->CssText());
  }
  if (use_distance) {
    result.Append(" ");
    result.Append(distance->CssText());
  }
  if (use_rotate) {
    result.Append(" ");
    result.Append(rotate->CssText());
  }
  if (use_anchor) {
    result.Append(" / ");
    result.Append(anchor->CssText());
  }
  return result.ReleaseString();
}

String StylePropertySerializer::TextDecorationValue() const {
  StringBuilder result;
  const auto& shorthand = shorthandForProperty(CSSPropertyID::kTextDecoration);
  for (const CSSProperty* const longhand : shorthand.properties()) {
    const CSSValue* value = property_set_.GetPropertyCSSValue(*longhand);
    String value_text = value->CssText();
    if (value->IsInitialValue()) {
      continue;
    }
    if (longhand->PropertyID() == CSSPropertyID::kTextDecorationThickness) {
      if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
        // Do not include initial value 'auto' for thickness.
        // TODO(https://crbug.com/1093826): general shorthand serialization
        // issues remain, in particular for text-decoration.
        CSSValueID value_id = identifier_value->GetValueID();
        if (value_id == CSSValueID::kAuto) {
          continue;
        }
      }
    }
    if (!result.empty()) {
      result.Append(" ");
    }
    result.Append(value_text);
  }

  if (result.empty()) {
    return "none";
  }
  return result.ReleaseString();
}

String StylePropertySerializer::Get2Values(
    const StylePropertyShorthand& shorthand) const {
  // Assume the properties are in the usual order start, end.
  int start_value_index =
      property_set_.FindPropertyIndex(*shorthand.properties()[0]);
  int end_value_index =
      property_set_.FindPropertyIndex(*shorthand.properties()[1]);

  if (start_value_index == -1 || end_value_index == -1) {
    return String();
  }

  PropertyValueForSerializer start =
      property_set_.PropertyAt(start_value_index);
  PropertyValueForSerializer end = property_set_.PropertyAt(end_value_index);

  bool show_end = !base::ValuesEquivalent(start.Value(), end.Value());

  StringBuilder result;
  result.Append(start.Value()->CssText());
  if (show_end) {
    result.Append(' ');
    result.Append(end.Value()->CssText());
  }
  return result.ReleaseString();
}

String StylePropertySerializer::Get4Values(
    const StylePropertyShorthand& shorthand) const {
  // Assume the properties are in the usual order top, right, bottom, left.
  int top_value_index =
      property_set_.FindPropertyIndex(*shorthand.properties()[0]);
  int right_value_index =
      property_set_.FindPropertyIndex(*shorthand.properties()[1]);
  int bottom_value_index =
      property_set_.FindPropertyIndex(*shorthand.properties()[2]);
  int left_value_index =
      property_set_.FindPropertyIndex(*shorthand.properties()[3]);

  if (top_value_index == -1 || right_value_index == -1 ||
      bottom_value_index == -1 || left_value_index == -1) {
    return String();
  }

  PropertyValueForSerializer top = property_set_.PropertyAt(top_value_index);
  PropertyValueForSerializer right =
      property_set_.PropertyAt(right_value_index);
  PropertyValueForSerializer bottom =
      property_set_.PropertyAt(bottom_value_index);
  PropertyValueForSerializer left = property_set_.PropertyAt(left_value_index);

  bool show_left = !base::ValuesEquivalent(right.Value(), left.Value());
  bool show_bottom =
      !base::ValuesEquivalent(top.Value(), bottom.Value()) || show_left;
  bool show_right =
      !base::ValuesEquivalent(top.Value(), right.Value()) || show_bottom;

  StringBuilder result;
  result.Append(top.Value()->CssText());
  if (show_right) {
    result.Append(' ');
    result.Append(right.Value()->CssText());
  }
  if (show_bottom) {
    result.Append(' ');
    result.Append(bottom.Value()->CssText());
  }
  if (show_left) {
    result.Append(' ');
    result.Append(left.Value()->CssText());
  }
  return result.ReleaseString();
}

namespace {

// Serialize clip and origin (https://drafts.fxtf.org/css-masking/#the-mask):
// * If one <geometry-box> value and the no-clip keyword are present then
//   <geometry-box> sets mask-origin and no-clip sets mask-clip to that value.
// * If one <geometry-box> value and no no-clip keyword are present then
//   <geometry-box> sets both mask-origin and mask-clip to that value.
// * If two <geometry-box> values are present, then the first sets mask-origin
//   and the second mask-clip.
// Additionally, omits components when possible (see:
// https://drafts.csswg.org/cssom/#serialize-a-css-value).
void SerializeMaskOriginAndClip(StringBuilder& result,
                                const CSSValueID& origin_id,
                                const CSSValueID& clip_id) {
  // If both values are border-box, omit everything as it is the default.
  if (origin_id == CSSValueID::kBorderBox &&
      clip_id == CSSValueID::kBorderBox) {
    return;
  }

  if (!result.empty()) {
    result.Append(' ');
  }
  if (origin_id == clip_id) {
    // If the values are the same, only emit one value. Note that mask-origin
    // does not support no-clip, so there is no need to consider no-clip
    // special cases.
    result.Append(GetCSSValueNameAs<StringView>(origin_id));
  } else if (origin_id == CSSValueID::kBorderBox &&
             clip_id == CSSValueID::kNoClip) {
    // Mask-origin does not support no-clip, so mask-origin can be omitted if it
    // is the default.
    result.Append(GetCSSValueNameAs<StringView>(clip_id));
  } else {
    result.Append(GetCSSValueNameAs<StringView>(origin_id));
    result.Append(' ');
    result.Append(GetCSSValueNameAs<StringView>(clip_id));
  }
}

}  // namespace

String StylePropertySerializer::GetLayeredShorthandValue(
    const StylePropertyShorthand& shorthand) const {
  const unsigned size = shorthand.length();

  // Begin by collecting the properties into a vector.
  HeapVector<Member<const CSSValue>> values(size);
  // If the below loop succeeds, there should always be at minimum 1 layer.
  wtf_size_t num_layers = 1U;

  // TODO(timloh): Shouldn't we fail if the lists are differently sized, with
  // the exception of background-color?
  for (unsigned i = 0; i < size; i++) {
    values[i] = property_set_.GetPropertyCSSValue(*shorthand.properties()[i]);
    if (values[i]->IsBaseValueList()) {
      const CSSValueList* value_list = To<CSSValueList>(values[i].Get());
      num_layers = std::max(num_layers, value_list->length());
    }
  }

  StringBuilder result;

  // Now stitch the properties together.
  for (wtf_size_t layer = 0; layer < num_layers; layer++) {
    StringBuilder layer_result;
    bool is_position_x_serialized = false;
    bool is_position_y_serialized = false;
    const CSSValue* mask_position_x = nullptr;
    CSSValueID mask_origin_value = CSSValueID::kBorderBox;

    for (unsigned property_index = 0; property_index < size; property_index++) {
      const CSSValue* value = nullptr;
      const CSSProperty* property = shorthand.properties()[property_index];

      // Get a CSSValue for this property and layer.
      if (values[property_index]->IsBaseValueList()) {
        const auto* property_values =
            To<CSSValueList>(values[property_index].Get());
        // There might not be an item for this layer for this property.
        if (layer < property_values->length()) {
          value = &property_values->Item(layer);
        }
      } else if ((layer == 0 &&
                  !property->IDEquals(CSSPropertyID::kBackgroundColor)) ||
                 (layer == num_layers - 1 &&
                  property->IDEquals(CSSPropertyID::kBackgroundColor))) {
        // Singletons except background color belong in the 0th layer.
        // Background color belongs in the last layer.
        value = values[property_index];
      }
      // No point proceeding if there's not a value to look at.
      if (!value) {
        continue;
      }

      bool omit_value = value->IsInitialValue();

      // The shorthand can not represent the following properties if they have
      // non-initial values. This is because they are always reset to their
      // initial value by the shorthand.
      //
      // Note that initial values for animation-* properties only contain
      // one list item, hence the check for 'layer > 0'.
      if (property->IDEquals(CSSPropertyID::kAnimationTimeline)) {
        auto* ident = DynamicTo<CSSIdentifierValue>(value);
        if (!ident ||
            (ident->GetValueID() !=
             CSSAnimationData::InitialTimeline().GetKeyword()) ||
            layer > 0) {
          DCHECK(RuntimeEnabledFeatures::ScrollTimelineEnabled());
          return g_empty_string;
        }
        omit_value = true;
      }
      if (property->IDEquals(CSSPropertyID::kAnimationRangeStart)) {
        auto* ident = DynamicTo<CSSIdentifierValue>(value);
        if (!ident || (ident->GetValueID() != CSSValueID::kNormal) ||
            layer > 0) {
          DCHECK(RuntimeEnabledFeatures::ScrollTimelineEnabled());
          return g_empty_string;
        }
        omit_value = true;
      }
      if (property->IDEquals(CSSPropertyID::kAnimationRangeEnd)) {
        auto* ident = DynamicTo<CSSIdentifierValue>(value);
        if (!ident || (ident->GetValueID() != CSSValueID::kNormal) ||
            layer > 0) {
          DCHECK(RuntimeEnabledFeatures::ScrollTimelineEnabled());
          return g_empty_string;
        }
        omit_value = true;
      }

      if (property->IDEquals(CSSPropertyID::kTransitionBehavior)) {
        CHECK_EQ(shorthand.id(), CSSPropertyID::kTransition);
        auto* ident = DynamicTo<CSSIdentifierValue>(value);
        CHECK(ident) << " transition-behavior should only have a "
                        "CSSIdentifierValue for a value. CssText: "
                     << value->CssText();
        if (ident->GetValueID() == CSSValueID::kNormal) {
          // transition-behavior overrides InitialValue to return "normal"
          // instead of "initial", but we don't want to include "normal" in the
          // shorthand serialization, so this special case is needed.
          // TODO(http://crbug.com/501673): We should have a better solution
          // before fixing all CSS properties to fix the above bug.
          omit_value = true;
        }
      }
      // The transition shorthand should only serialize values which aren't
      // set to their default value:
      // https://github.com/web-platform-tests/wpt/issues/43574
      if (property->IDEquals(CSSPropertyID::kTransitionDelay) ||
          property->IDEquals(CSSPropertyID::kTransitionDuration)) {
        auto* numeric_value = DynamicTo<CSSNumericLiteralValue>(value);
        if (numeric_value &&
            numeric_value->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue) {
          omit_value = true;
        }
      } else if (property->IDEquals(
                     CSSPropertyID::kTransitionTimingFunction)) {
        if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
          if (ident->GetValueID() == CSSValueID::kEase) {
            omit_value = true;
          }
        }
      } else if (property->IDEquals(CSSPropertyID::kTransitionProperty)) {
        if (auto* custom_ident = DynamicTo<CSSCustomIdentValue>(value)) {
          if (custom_ident->IsKnownPropertyID() &&
              custom_ident->ValueAsPropertyID() == CSSPropertyID::kAll) {
            omit_value = true;
          }
        } else if (auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
          if (ident->GetValueID() == CSSValueID::
```