Response:
The user wants to understand the functionality of the `style_property_serializer.cc` file in the Chromium Blink engine.

Here's a plan to generate the response:

1. **Identify the primary function:** Based on the file name and its contents, determine the core purpose of this file. It seems to be related to converting CSS property values into their string representations.
2. **Analyze included headers:** Examine the included headers to get hints about the functionalities the class interacts with (animations, CSS values, properties, etc.).
3. **Deconstruct key classes and methods:** Focus on the main classes and methods within the provided code snippet, such as `StylePropertySerializer`, `CSSPropertyValueSetForSerializer`, and methods like `AsText`, `SerializeShorthand`.
4. **Explain the relationship with JavaScript, HTML, and CSS:**  Illustrate how the serialization process is essential for reflecting the computed styles in the DOM, which JavaScript can access and manipulate. Explain how this relates to the rendering of HTML elements based on CSS rules.
5. **Provide examples for logical reasoning:**  Demonstrate the serialization process with a simple CSS property and its output. Consider both longhand and shorthand properties.
6. **Identify potential user/programming errors:**  Think about scenarios where the serialization might produce unexpected results due to incorrect CSS syntax or conflicting declarations.
7. **Describe the user journey to this code:** Outline the steps a user might take in a browser that would eventually lead to the execution of this code. This will involve parsing CSS, applying styles, and potentially inspecting computed styles.
8. **Summarize the functionalities:**  Condense the main responsibilities of the file into a concise summary for Part 1.
这是 `blink/renderer/core/css/style_property_serializer.cc` 文件的第一部分，主要功能是**将 CSS 属性值序列化为字符串形式**。更具体地说，它负责将 Blink 内部表示的 CSS 属性和它们的值转换成 CSS 文本格式，以便在多种场景中使用，例如：

**功能归纳:**

1. **CSS 属性值的字符串表示:**  核心功能是将内部的 `CSSValue` 对象转换为其对应的 CSS 文本表示形式（例如，将内部的长度值 `10px` 转换为字符串 `"10px"`）。
2. **处理长属性和短属性:**  能够处理 CSS 的长属性（例如 `margin-top`）和短属性（例如 `margin`）。对于短属性，它会根据其包含的长属性值来生成短属性的字符串表示。
3. **处理 `!important` 标志:**  能够正确处理 CSS 声明中的 `!important` 标志。
4. **处理自定义属性 (CSS Variables):**  可以序列化自定义 CSS 属性及其值。
5. **处理 `all` 属性:** 了解 `all` 属性的影响，并能正确处理它，可以选择展开 `all` 属性所影响的长属性。
6. **优化短属性序列化:** 尝试将多个相关的长属性值组合成更简洁的短属性表示，前提是这些长属性的值可以一致地表示为该短属性。
7. **避免重复序列化:**  在处理短属性时，会记录已经序列化的长属性，避免重复输出。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:** 当 JavaScript 代码需要读取元素的计算样式时（例如使用 `window.getComputedStyle(element).getPropertyValue('margin')`），Blink 引擎会调用类似这里的代码来将内部的样式信息转换为字符串，然后返回给 JavaScript。
    * **假设输入:** 一个 HTML 元素应用了 CSS 规则 `margin-top: 10px; margin-left: 20px;`。
    * **输出 (给 JavaScript):** 当 JavaScript 请求 `margin` 属性时，`style_property_serializer.cc` 可能会生成字符串 `"10px 20px 0 0"` (如果其他 margin 值是初始值)。

* **HTML:** HTML 元素通过 `style` 属性或外部 CSS 文件应用样式。浏览器解析这些样式后，会使用 `style_property_serializer.cc` 将解析后的样式信息转换为字符串，以便在某些场景下展示或存储。
    * **假设输入:** HTML 代码 `<div style="color: red;"></div>`。
    * **输出 (内部表示):** Blink 内部会将 `color` 属性和 `red` 值存储起来，当需要将这个内联样式转换回字符串时，会使用这里的代码生成 `"color: red;"`。

* **CSS:**  `style_property_serializer.cc` 的核心功能就是将 CSS 属性和值转换为 CSS 文本格式。它负责将 Blink 内部对 CSS 的理解（例如，各种不同的 `CSSValue` 子类）映射回标准的 CSS 语法。
    * **假设输入:** Blink 内部表示的 `background-color` 属性的值是一个 `CSSColorValue` 对象，代表红色。
    * **输出:** `style_property_serializer.cc` 会将其转换为字符串 `"red"` 或 `"rgb(255, 0, 0)"`，取决于具体的序列化逻辑。

**逻辑推理的假设输入与输出:**

假设我们有一个 `CSSPropertyValueSet` 对象，其中包含以下属性：

* `color`: `CSSIdentifierValue`，值为 `blue`
* `font-size`: `CSSPrimitiveValue`，值为 `16px`
* `margin-top`: `CSSPrimitiveValue`，值为 `10px`
* `margin-left`: `CSSPrimitiveValue`，值为 `20px`

调用 `AsText()` 方法后，`style_property_serializer.cc` 可能会生成如下字符串：

```
color: blue; font-size: 16px; margin-top: 10px; margin-left: 20px;
```

或者，如果它检测到可以优化为短属性，可能会生成：

```
color: blue; font-size: 16px; margin: 10px 20px 0 0;
```

**涉及用户或编程常见的使用错误举例说明:**

* **CSS 语法错误:** 如果用户在 CSS 中写了错误的语法（例如 `coloor: red;`），解析器可能无法正确解析，这部分代码就不会被调用，或者会处理为自定义属性。
* **覆盖 `!important` 规则时出现意外:** 用户可能会错误地使用 `!important` 导致样式覆盖的优先级不符合预期。虽然 `style_property_serializer.cc` 能正确处理 `!important`，但它无法解决用户在 CSS 规则定义上的逻辑错误。例如，如果两个规则都声明了 `!important`，后应用的规则会生效，这可能会让用户困惑。
* **JavaScript 操作 DOM 样式时的错误:**  开发者可能通过 JavaScript 设置了不合法的 CSS 属性值。虽然浏览器通常会忽略这些错误，但 `style_property_serializer.cc` 只负责将内部表示转换为字符串，它不会校验值的合法性。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载一个网页。**
2. **浏览器解析 HTML 代码，构建 DOM 树。**
3. **浏览器解析 CSS 代码（来自 `<style>` 标签、外部 CSS 文件或元素的 `style` 属性）。**
4. **样式计算 (Style Calculation):** Blink 引擎根据 CSS 规则和 DOM 结构计算每个元素的最终样式。这涉及到匹配 CSS 选择器，应用层叠规则，并解析 CSS 属性值。计算结果会被存储在类似 `ComputedStyle` 的对象中。
5. **获取计算样式 (Get Computed Style):**
   * **用户通过开发者工具 (DevTools) 检查元素的 "Computed" 标签页。**  DevTools 会请求 Blink 提供元素的计算样式，Blink 引擎会使用 `style_property_serializer.cc` 将内部的 `ComputedStyle` 信息转换为字符串，以便在 DevTools 中显示。
   * **JavaScript 代码调用 `window.getComputedStyle(element)`。** 这会触发 Blink 引擎内部的流程，最终调用 `style_property_serializer.cc` 来获取属性的字符串值。
6. **序列化 (Serialization):**  `style_property_serializer.cc` 中的 `AsText()` 或其他相关方法会被调用，遍历 `CSSPropertyValueSet` 中的属性，并将每个属性的值序列化为 CSS 字符串格式。

总而言之，`style_property_serializer.cc` 是 Blink 引擎中一个关键的组成部分，它负责将内部的 CSS 属性值表示转换为人类可读的字符串形式，这对于开发者工具、JavaScript 访问样式以及其他需要 CSS 文本表示的场景至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/style_property_serializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * (C) 1999-2003 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2011 Research In Motion Limited. All rights reserved.
 * Copyright (C) 2013 Intel Corporation. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/css/style_property_serializer.h"

#include <bitset>

#include "base/logging.h"
#include "base/memory/values_equivalent.h"
#include "third_party/blink/renderer/core/animation/css/css_animation_data.h"
#include "third_party/blink/renderer/core/css/css_grid_template_areas_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_markup.h"
#include "third_party/blink/renderer/core/css/css_pending_substitution_value.h"
#include "third_party/blink/renderer/core/css/css_pending_system_font_value.h"
#include "third_party/blink/renderer/core/css/css_repeat_style_value.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/css_value_pool.h"
#include "third_party/blink/renderer/core/css/cssom_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/css_property_instances.h"
#include "third_party/blink/renderer/core/css/properties/longhand.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/css_to_style_map.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

template <typename T>
T ConvertIdentifierTo(const CSSValue* value, T initial_value) {
  if (const auto* ident = DynamicTo<CSSIdentifierValue>(value)) {
    return ident->ConvertTo<T>();
  }
  DCHECK(value->IsInitialValue());
  return initial_value;
}

inline WhiteSpaceCollapse ToWhiteSpaceCollapse(const CSSValue* value) {
  return ConvertIdentifierTo<WhiteSpaceCollapse>(
      value, ComputedStyleInitialValues::InitialWhiteSpaceCollapse());
}

inline TextWrapMode ToTextWrapMode(const CSSValue* value) {
  return ConvertIdentifierTo<TextWrapMode>(
      value, ComputedStyleInitialValues::InitialTextWrapMode());
}

inline TextWrapStyle ToTextWrapStyle(const CSSValue* value) {
  return ConvertIdentifierTo<TextWrapStyle>(
      value, ComputedStyleInitialValues::InitialTextWrapStyle());
}

bool IsZeroPercent(const CSSValue* value) {
  if (const auto* num = DynamicTo<CSSNumericLiteralValue>(value)) {
    return num->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue &&
           num->IsPercentage();
  }

  return false;
}

template <typename T>
StringView PlatformEnumToCSSValueString(T e) {
  return GetCSSValueNameAs<StringView>(PlatformEnumToCSSValueID(e));
}

}  // namespace

StylePropertySerializer::CSSPropertyValueSetForSerializer::
    CSSPropertyValueSetForSerializer(const CSSPropertyValueSet& properties)
    : property_set_(&properties),
      all_index_(property_set_->FindPropertyIndex(CSSPropertyID::kAll)),
      need_to_expand_all_(false) {
  if (!HasAllProperty()) {
    return;
  }

  CSSPropertyValueSet::PropertyReference all_property =
      property_set_->PropertyAt(all_index_);
  for (unsigned i = 0; i < property_set_->PropertyCount(); ++i) {
    CSSPropertyValueSet::PropertyReference property =
        property_set_->PropertyAt(i);
    if (property.IsAffectedByAll()) {
      if (all_property.IsImportant() && !property.IsImportant()) {
        continue;
      }
      if (static_cast<unsigned>(all_index_) >= i) {
        continue;
      }
      if (property.Value() == all_property.Value() &&
          property.IsImportant() == all_property.IsImportant()) {
        continue;
      }
      need_to_expand_all_ = true;
    }
    if (!IsCSSPropertyIDWithName(property.Id())) {
      continue;
    }
    longhand_property_used_.set(GetCSSPropertyIDIndex(property.Id()));
  }
}

void StylePropertySerializer::CSSPropertyValueSetForSerializer::Trace(
    blink::Visitor* visitor) const {
  visitor->Trace(property_set_);
}

unsigned
StylePropertySerializer::CSSPropertyValueSetForSerializer::PropertyCount()
    const {
  unsigned count = property_set_->PropertyCount();
  if (HasExpandedAllProperty()) {
    // When expanding all:* we need to serialize all properties set by the "all"
    // property, but also still walk the actual property set to include any
    // custom property declarations.
    count += kIntLastCSSProperty - kIntFirstCSSProperty + 1;
  }
  return count;
}

StylePropertySerializer::PropertyValueForSerializer
StylePropertySerializer::CSSPropertyValueSetForSerializer::PropertyAt(
    unsigned index) const {
  if (IsIndexInPropertySet(index)) {
    return StylePropertySerializer::PropertyValueForSerializer(
        property_set_->PropertyAt(index));
  }

  // When expanding "all" into longhands, PropertyAt() is called with indices
  // outside the size of the property_set_ to serialize all longshands.
  DCHECK(HasExpandedAllProperty());
  CSSPropertyID property_id = IndexToPropertyID(index);
  DCHECK(IsCSSPropertyIDWithName(property_id));
  if (longhand_property_used_.test(GetCSSPropertyIDIndex(property_id))) {
    // A property declaration for property_id overrides the "all" declaration.
    // Access that declaration from the property set.
    int real_index = property_set_->FindPropertyIndex(property_id);
    DCHECK_NE(real_index, -1);
    return StylePropertySerializer::PropertyValueForSerializer(
        property_set_->PropertyAt(real_index));
  }

  CSSPropertyValueSet::PropertyReference property =
      property_set_->PropertyAt(all_index_);
  return StylePropertySerializer::PropertyValueForSerializer(
      CSSProperty::Get(property_id).GetCSSPropertyName(), &property.Value(),
      property.IsImportant());
}

bool StylePropertySerializer::CSSPropertyValueSetForSerializer::
    ShouldProcessPropertyAt(unsigned index) const {
  // CSSPropertyValueSet has all valid longhands. We should process.
  if (!HasAllProperty()) {
    return true;
  }

  // If all is not expanded, we need to process "all" and properties which
  // are not overwritten by "all".
  if (!need_to_expand_all_) {
    CSSPropertyValueSet::PropertyReference property =
        property_set_->PropertyAt(index);
    if (property.Id() == CSSPropertyID::kAll || !property.IsAffectedByAll()) {
      return true;
    }
    if (!IsCSSPropertyIDWithName(property.Id())) {
      return false;
    }
    return longhand_property_used_.test(GetCSSPropertyIDIndex(property.Id()));
  }

  // Custom property declarations are never overridden by "all" and are only
  // traversed for the indices into the property set.
  if (IsIndexInPropertySet(index)) {
    return property_set_->PropertyAt(index).Id() == CSSPropertyID::kVariable;
  }

  CSSPropertyID property_id = IndexToPropertyID(index);
  DCHECK(IsCSSPropertyIDWithName(property_id));
  const CSSProperty& property_class =
      CSSProperty::Get(ResolveCSSPropertyID(property_id));

  // Since "all" is expanded, we don't need to process "all".
  // We should not process expanded shorthands (e.g. font, background,
  // and so on) either.
  if (property_class.IsShorthand() ||
      property_class.IDEquals(CSSPropertyID::kAll)) {
    return false;
  }

  // The all property is a shorthand that resets all CSS properties except
  // direction and unicode-bidi. It only accepts the CSS-wide keywords.
  // c.f. https://drafts.csswg.org/css-cascade/#all-shorthand
  if (!property_class.IsAffectedByAll()) {
    return longhand_property_used_.test(GetCSSPropertyIDIndex(property_id));
  }

  return true;
}

int StylePropertySerializer::CSSPropertyValueSetForSerializer::
    FindPropertyIndex(const CSSProperty& property) const {
  CSSPropertyID property_id = property.PropertyID();
  if (!HasExpandedAllProperty()) {
    return property_set_->FindPropertyIndex(property_id);
  }
  return GetCSSPropertyIDIndex(property_id) + property_set_->PropertyCount();
}

const CSSValue*
StylePropertySerializer::CSSPropertyValueSetForSerializer::GetPropertyCSSValue(
    const CSSProperty& property) const {
  int index = FindPropertyIndex(property);
  if (index == -1) {
    return nullptr;
  }
  StylePropertySerializer::PropertyValueForSerializer value = PropertyAt(index);
  return value.Value();
}

bool StylePropertySerializer::CSSPropertyValueSetForSerializer::
    IsDescriptorContext() const {
  return property_set_->CssParserMode() == kCSSFontFaceRuleMode;
}

StylePropertySerializer::StylePropertySerializer(
    const CSSPropertyValueSet& properties)
    : property_set_(properties) {}

String StylePropertySerializer::GetCustomPropertyText(
    const PropertyValueForSerializer& property,
    bool is_not_first_decl) const {
  DCHECK_EQ(property.Name().Id(), CSSPropertyID::kVariable);
  StringBuilder result;
  if (is_not_first_decl) {
    result.Append(' ');
  }
  const CSSValue* value = property.Value();
  SerializeIdentifier(property.Name().ToAtomicString(), result,
                      is_not_first_decl);
  result.Append(": ");
  result.Append(value->CssText());
  if (property.IsImportant()) {
    result.Append(" !important");
  }
  result.Append(';');
  return result.ReleaseString();
}

String StylePropertySerializer::GetPropertyText(const CSSPropertyName& name,
                                                const String& value,
                                                bool is_important,
                                                bool is_not_first_decl) const {
  StringBuilder result;
  if (is_not_first_decl) {
    result.Append(' ');
  }
  result.Append(name.ToAtomicString());
  result.Append(": ");
  result.Append(value);
  if (is_important) {
    result.Append(" !important");
  }
  result.Append(';');
  return result.ReleaseString();
}

String StylePropertySerializer::AsText() const {
  StringBuilder result;

  std::bitset<kNumCSSPropertyIDs> longhand_serialized;
  std::bitset<kNumCSSPropertyIDs> shorthand_appeared;

  unsigned size = property_set_.PropertyCount();
  unsigned num_decls = 0;
  for (unsigned n = 0; n < size; ++n) {
    if (!property_set_.ShouldProcessPropertyAt(n)) {
      continue;
    }

    StylePropertySerializer::PropertyValueForSerializer property =
        property_set_.PropertyAt(n);

    const CSSPropertyName& name = property.Name();
    CSSPropertyID property_id = name.Id();

#if DCHECK_IS_ON()
    if (property_id != CSSPropertyID::kVariable) {
      const CSSProperty& property_class = CSSProperty::Get(property_id);
      // Only web exposed properties should be part of the style.
      DCHECK(property_class.IsWebExposed());
      // All shorthand properties should have been expanded at parse time.
      DCHECK(property_set_.IsDescriptorContext() ||
             (property_class.IsProperty() && !property_class.IsShorthand()));
      DCHECK(!property_set_.IsDescriptorContext() ||
             property_class.IsDescriptor());
    }
#endif  // DCHECK_IS_ON()

    switch (property_id) {
      case CSSPropertyID::kVariable:
        result.Append(GetCustomPropertyText(property, num_decls++));
        continue;
      case CSSPropertyID::kAll:
        result.Append(GetPropertyText(name, property.Value()->CssText(),
                                      property.IsImportant(), num_decls++));
        continue;
      default:
        break;
    }
    if (longhand_serialized.test(GetCSSPropertyIDIndex(property_id))) {
      continue;
    }

    Vector<StylePropertyShorthand, 4> shorthands;
    getMatchingShorthandsForLonghand(property_id, &shorthands);
    bool serialized_as_shorthand = false;
    for (const StylePropertyShorthand& shorthand : shorthands) {
      // Some aliases are implemented as a shorthand, in which case
      // we prefer to not use the shorthand.
      if (shorthand.length() == 1) {
        continue;
      }

      CSSPropertyID shorthand_property = shorthand.id();
      int shorthand_property_index = GetCSSPropertyIDIndex(shorthand_property);
      // We already tried serializing as this shorthand
      if (shorthand_appeared.test(shorthand_property_index)) {
        continue;
      }

      shorthand_appeared.set(shorthand_property_index);
      bool serialized_other_longhand = false;
      for (const CSSProperty* const longhand : shorthand.properties()) {
        if (longhand_serialized.test(
                GetCSSPropertyIDIndex(longhand->PropertyID()))) {
          serialized_other_longhand = true;
          break;
        }
      }
      if (serialized_other_longhand) {
        continue;
      }

      String shorthand_result = SerializeShorthand(shorthand_property);
      if (shorthand_result.empty()) {
        continue;
      }

      result.Append(GetPropertyText(
          CSSProperty::Get(shorthand_property).GetCSSPropertyName(),
          shorthand_result, property.IsImportant(), num_decls++));
      serialized_as_shorthand = true;
      for (const CSSProperty* const longhand : shorthand.properties()) {
        longhand_serialized.set(GetCSSPropertyIDIndex(longhand->PropertyID()));
      }
      break;
    }

    if (serialized_as_shorthand) {
      continue;
    }

    result.Append(GetPropertyText(name, property.Value()->CssText(),
                                  property.IsImportant(), num_decls++));
  }

  DCHECK(!num_decls ^ !result.empty());
  return result.ReleaseString();
}

// As per css-cascade, shorthands do not expand longhands to the value
// "initial", except when the shorthand is set to "initial", instead
// setting "missing" sub-properties to their initial values. This means
// that a shorthand can never represent a list of subproperties where
// some are "initial" and some are not, and so serialization should
// always fail in these cases (as per cssom). However we currently use
// "initial" instead of the initial values for certain shorthands, so
// these are special-cased here.
// TODO(timloh): Don't use "initial" in shorthands and remove this
// special-casing
static bool AllowInitialInShorthand(CSSPropertyID property_id) {
  switch (property_id) {
    case CSSPropertyID::kBackground:
    case CSSPropertyID::kBorder:
    case CSSPropertyID::kBorderTop:
    case CSSPropertyID::kBorderRight:
    case CSSPropertyID::kBorderBottom:
    case CSSPropertyID::kBorderLeft:
    case CSSPropertyID::kBorderBlockStart:
    case CSSPropertyID::kBorderBlockEnd:
    case CSSPropertyID::kBorderInlineStart:
    case CSSPropertyID::kBorderInlineEnd:
    case CSSPropertyID::kBorderBlock:
    case CSSPropertyID::kBorderInline:
    case CSSPropertyID::kOutline:
    case CSSPropertyID::kColumnRule:
    case CSSPropertyID::kColumns:
    case CSSPropertyID::kGridColumn:
    case CSSPropertyID::kGridRow:
    case CSSPropertyID::kGridArea:
    case CSSPropertyID::kGap:
    case CSSPropertyID::kListStyle:
    case CSSPropertyID::kTextDecoration:
    case CSSPropertyID::kTextEmphasis:
    case CSSPropertyID::kTextWrap:
    case CSSPropertyID::kMask:
    case CSSPropertyID::kWebkitTextStroke:
    case CSSPropertyID::kWhiteSpace:
      return true;
    default:
      return false;
  }
}

String StylePropertySerializer::CommonShorthandChecks(
    const StylePropertyShorthand& shorthand) const {
  unsigned longhand_count = shorthand.length();
  if (!longhand_count || longhand_count > kMaxShorthandExpansion) {
    NOTREACHED();
  }

  std::array<const CSSValue*, kMaxShorthandExpansion> longhands;

  bool has_important = false;
  bool has_non_important = false;

  for (unsigned i = 0; i < longhand_count; i++) {
    int index = property_set_.FindPropertyIndex(*shorthand.properties()[i]);
    if (index == -1) {
      return g_empty_string;
    }
    PropertyValueForSerializer value = property_set_.PropertyAt(index);

    has_important |= value.IsImportant();
    has_non_important |= !value.IsImportant();
    longhands[i] = value.Value();
  }

  if (has_important && has_non_important) {
    return g_empty_string;
  }

  if (longhands[0]->IsCSSWideKeyword() ||
      longhands[0]->IsPendingSubstitutionValue()) {
    bool success = true;
    for (unsigned i = 1; i < longhand_count; i++) {
      if (!base::ValuesEquivalent(longhands[i], longhands[0])) {
        // This should just return emptyString but some shorthands currently
        // allow 'initial' for their longhands.
        success = false;
        break;
      }
    }
    if (success) {
      if (const auto* substitution_value =
              DynamicTo<cssvalue::CSSPendingSubstitutionValue>(longhands[0])) {
        if (substitution_value->ShorthandPropertyId() != shorthand.id()) {
          return g_empty_string;
        }
        return substitution_value->ShorthandValue()->CssText();
      }
      return longhands[0]->CssText();
    }
  }

  bool allow_initial = AllowInitialInShorthand(shorthand.id());
  for (unsigned i = 0; i < longhand_count; i++) {
    const CSSValue& value = *longhands[i];
    if (!allow_initial && value.IsInitialValue()) {
      return g_empty_string;
    }
    if ((value.IsCSSWideKeyword() && !value.IsInitialValue()) ||
        value.IsPendingSubstitutionValue()) {
      return g_empty_string;
    }
    if (value.IsUnparsedDeclaration()) {
      return g_empty_string;
    }
  }

  return String();
}

String StylePropertySerializer::SerializeShorthand(
    CSSPropertyID property_id) const {
  const StylePropertyShorthand& shorthand = shorthandForProperty(property_id);
  DCHECK(shorthand.length());

  String result = CommonShorthandChecks(shorthand);
  if (!result.IsNull()) {
    return result;
  }

  switch (property_id) {
    case CSSPropertyID::kAnimation:
      return GetLayeredShorthandValue(animationShorthand());
    case CSSPropertyID::kAlternativeAnimationWithTimeline:
      return GetLayeredShorthandValue(
          alternativeAnimationWithTimelineShorthand());
    case CSSPropertyID::kAnimationRange:
      return AnimationRangeShorthandValue();
    case CSSPropertyID::kBorderSpacing:
      return Get2Values(borderSpacingShorthand());
    case CSSPropertyID::kBackgroundPosition:
      return GetLayeredShorthandValue(backgroundPositionShorthand());
    case CSSPropertyID::kBackground:
      return GetLayeredShorthandValue(backgroundShorthand());
    case CSSPropertyID::kBorder:
      return BorderPropertyValue(borderWidthShorthand(), borderStyleShorthand(),
                                 borderColorShorthand());
    case CSSPropertyID::kBorderImage:
      return BorderImagePropertyValue();
    case CSSPropertyID::kBorderTop:
      return GetShorthandValue(borderTopShorthand());
    case CSSPropertyID::kBorderRight:
      return GetShorthandValue(borderRightShorthand());
    case CSSPropertyID::kBorderBottom:
      return GetShorthandValue(borderBottomShorthand());
    case CSSPropertyID::kBorderLeft:
      return GetShorthandValue(borderLeftShorthand());
    case CSSPropertyID::kBorderBlock:
      return BorderPropertyValue(borderBlockWidthShorthand(),
                                 borderBlockStyleShorthand(),
                                 borderBlockColorShorthand());
    case CSSPropertyID::kBorderBlockColor:
      return Get2Values(borderBlockColorShorthand());
    case CSSPropertyID::kBorderBlockStyle:
      return Get2Values(borderBlockStyleShorthand());
    case CSSPropertyID::kBorderBlockWidth:
      return Get2Values(borderBlockWidthShorthand());
    case CSSPropertyID::kBorderBlockStart:
      return GetShorthandValue(borderBlockStartShorthand());
    case CSSPropertyID::kBorderBlockEnd:
      return GetShorthandValue(borderBlockEndShorthand());
    case CSSPropertyID::kBorderInline:
      return BorderPropertyValue(borderInlineWidthShorthand(),
                                 borderInlineStyleShorthand(),
                                 borderInlineColorShorthand());
    case CSSPropertyID::kBorderInlineColor:
      return Get2Values(borderInlineColorShorthand());
    case CSSPropertyID::kBorderInlineStyle:
      return Get2Values(borderInlineStyleShorthand());
    case CSSPropertyID::kBorderInlineWidth:
      return Get2Values(borderInlineWidthShorthand());
    case CSSPropertyID::kBorderInlineStart:
      return GetShorthandValue(borderInlineStartShorthand());
    case CSSPropertyID::kBorderInlineEnd:
      return GetShorthandValue(borderInlineEndShorthand());
    case CSSPropertyID::kContainer:
      return ContainerValue();
    case CSSPropertyID::kOutline:
      return GetShorthandValue(outlineShorthand());
    case CSSPropertyID::kBorderColor:
      return Get4Values(borderColorShorthand());
    case CSSPropertyID::kBorderWidth:
      return Get4Values(borderWidthShorthand());
    case CSSPropertyID::kBorderStyle:
      return Get4Values(borderStyleShorthand());
    case CSSPropertyID::kColumnRule:
      return GetShorthandValueForColumnRule(columnRuleShorthand());
    case CSSPropertyID::kColumns:
      return GetShorthandValueForColumns(columnsShorthand());
    case CSSPropertyID::kContainIntrinsicSize:
      return ContainIntrinsicSizeValue();
    case CSSPropertyID::kFlex:
      return GetShorthandValue(flexShorthand());
    case CSSPropertyID::kFlexFlow:
      return GetShorthandValueForDoubleBarCombinator(flexFlowShorthand());
    case CSSPropertyID::kGrid:
      return GetShorthandValueForGrid(gridShorthand());
    case CSSPropertyID::kGridTemplate:
      return GetShorthandValueForGridTemplate(gridTemplateShorthand());
    case CSSPropertyID::kGridColumn:
      return GetShorthandValueForGridLine(gridColumnShorthand());
    case CSSPropertyID::kGridRow:
      return GetShorthandValueForGridLine(gridRowShorthand());
    case CSSPropertyID::kGridArea:
      return GetShorthandValueForGridArea(gridAreaShorthand());
    case CSSPropertyID::kGap:
      return Get2Values(gapShorthand());
    case CSSPropertyID::kInset:
      return Get4Values(insetShorthand());
    case CSSPropertyID::kInsetBlock:
      return Get2Values(insetBlockShorthand());
    case CSSPropertyID::kInsetInline:
      return Get2Values(insetInlineShorthand());
    case CSSPropertyID::kPlaceContent:
      return Get2Values(placeContentShorthand());
    case CSSPropertyID::kPlaceItems:
      return Get2Values(placeItemsShorthand());
    case CSSPropertyID::kPlaceSelf:
      return Get2Values(placeSelfShorthand());
    case CSSPropertyID::kFont:
      return FontValue();
    case CSSPropertyID::kFontSynthesis:
      return FontSynthesisValue();
    case CSSPropertyID::kFontVariant:
      return FontVariantValue();
    case CSSPropertyID::kMargin:
      return Get4Values(marginShorthand());
    case CSSPropertyID::kMarginBlock:
      return Get2Values(marginBlockShorthand());
    case CSSPropertyID::kMarginInline:
      return Get2Values(marginInlineShorthand());
    case CSSPropertyID::kMasonryTrack:
      return GetShorthandValueForMasonryTrack();
    case CSSPropertyID::kOffset:
      return OffsetValue();
    case CSSPropertyID::kOverflow:
      return Get2Values(overflowShorthand());
    case CSSPropertyID::kOverscrollBehavior:
      return Get2Values(overscrollBehaviorShorthand());
    case CSSPropertyID::kPadding:
      return Get4Values(paddingShorthand());
    case CSSPropertyID::kPaddingBlock:
      return Get2Values(paddingBlockShorthand());
    case CSSPropertyID::kPaddingInline:
      return Get2Values(paddingInlineShorthand());
    case CSSPropertyID::kTextDecoration:
      return TextDecorationValue();
    case CSSPropertyID::kTransition:
      return GetLayeredShorthandValue(transitionShorthand());
    case CSSPropertyID::kListStyle:
      return GetShorthandValue(listStyleShorthand());
    case CSSPropertyID::kMaskPosition:
      return GetLayeredShorthandValue(maskPositionShorthand());
    case CSSPropertyID::kMask:
      return GetLayeredShorthandValue(maskShorthand());
    case CSSPropertyID::kTextBox:
      return TextBoxValue();
    case CSSPropertyID::kTextEmphasis:
      return GetShorthandValue(textEmphasisShorthand());
    case CSSPropertyID::kTextSpacing:
      return TextSpacingValue();
    case CSSPropertyID::kWebkitTextStroke:
      return GetShorthandValue(webkitTextStrokeShorthand());
    case CSSPropertyID::kTextWrap:
      return TextWrapValue();
    case CSSPropertyID::kMarker: {
      if (const CSSValue* start =
              property_set_.GetPropertyCSSValue(GetCSSPropertyMarkerStart())) {
        const CSSValue* mid =
            property_set_.GetPropertyCSSValue(GetCSSPropertyMarkerMid());
        const CSSValue* end =
            property_set_.GetPropertyCSSValue(GetCSSPropertyMarkerEnd());
        if (mid && end && *start == *mid && *start == *end) {
          return start->CssText();
        }
      }
      return String();
    }
    case CSSPropertyID::kBorderRadius:
      return BorderRadiusValue();
    case CSSPropertyID::kScrollPadding:
      return Get4Values(scrollPaddingShorthand());
    case CSSPropertyID::kScrollPaddingBlock:
      return Get2Values(scrollPaddingBlockShorthand());
    case CSSPropertyID::kScrollPaddingInline:
      return Get2Values(scrollPaddingInlineShorthand());
    case CSSPropertyID::kScrollMargin:
      return Get4Values(scrollMarginShorthand());
    case CSSPropertyID::kScrollMarginBlock:
      return Get2Values(scrollMarginBlockShorthand());
    case CSSPropertyID::kScrollMarginInline:
      return Get2Values(scrollMarginInlineShorthand());
    case CSSPropertyID::kScrollTimeline:
      return ScrollTimelineValue();
    case CSSPropertyID::kPageBreakAfter:
      return PageBreakPropertyValue(pageBreakAfterShorthand());
    case CSSPropertyID::kPageBreakBefore:
      return PageBreakPropertyValue(pageBreakBeforeShorthand());
    case CSSPropertyID::kPageBreakInside:
      return PageBreakPropertyValue(pageBreakInsideShorthand());
    case CSSPropertyID::kViewTimeline:
      return ViewTimelineValue();
    case CSSPropertyID::kWhiteSpace:
      return WhiteSpaceValue();
    case CSSPropertyID::kWebkitColumnBreakAfter:
    case CSSPropertyID::kWebkitColumnBreakBefore:
    case CSSPropertyID::kWebkitColumnBreakInside:
    case CSSPropertyID::kWebkitMaskBoxImage:
      // Temporary exceptions to the NOTREACHED() below.
      // TODO(crbug.com/1316689): Write something real here.
      return String();
    case CSSPropertyID::kScrollStart:
      return ScrollStartValue();
    case CSSPropertyID::kPositionTry:
      return PositionTryValue(positionTryShorthand());
    default:
      NOTREACHED()
          << "Shorthand property "
          << CSSPropertyName(property_id).ToAtomicString()
          << " must be handled in StylePropertySerializer::SerializeShorthand.";
  }
}

// The font shorthand only allows keyword font-stretch values. Thus, we check if
// a percentage value can be parsed as a keyword, and if so, serialize it as
// that keyword.
const CSSValue* GetFontStretchKeyword(const CSSValue* font_stretch_value) {
  if (IsA<CSSIdentifierValue>(font_stretch_value)) {
    return font_stretch_value;
  }
  if (auto* primitive_value =
          DynamicTo<CSSPrimitiveValue>(font_stretch_value)) {
    double value = primitive_value->GetDoubleValue();
    if (value == 50) {
      return CSSIdentifierValue::Create(CSSValueID::kUltraCondensed);
    }
    if (value == 62.5) {
      return CSSIdentifierValue::Create(CSSValueID::kExtraCondensed);
    }
    if (value == 75) {
      return CSSIdentifierValue::Create(CSSValueID::kCondensed);
    }
    if (value == 87.5) {
      return CSSIdentifierValue::Create(CSSValueID::kSemiCondensed);
    }
    if (value == 100) {
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    }
    if (value == 112.5) {
      return CSSIdentifierValue::Create(CSSValueID::kSemiExpanded);
    }
    if (value == 125) {
      return CSSIdentifierValue::Create(CSSValueID::kExpanded);
    }
    if (value == 150) {
      return CSSIdentifierValue::Create(CSSValueID::kExtraExpanded);
    }
    if (value == 200) {
      return CSSIdentifierValue::Create(CSSValueID::kUltraExpanded);
    }
  }
  return nullptr;
}

// Returns false if the value cannot be represented in the font shorthand
bool StylePropertySerializer::AppendFontLonghandValueIfNotNormal(
    const CSSProperty& property,
    StringBuilder& result) const {
  int found_property_index = property_set_.FindPropertyIndex(property);
  DCHECK_NE(found_property_index, -1);

  const CSSValue* val = property_set_.PropertyAt(found_property_index).Value();
  if (property.IDEquals(CSSPropertyID::kFontStretch)) {
    const CSSValue* keyword = GetFontStretchKeyword(val);
    if (!keyword) {
      return false;
    }
    val = keyword;
  }
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(val);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kNormal) {
    return true;
  }

  String value;
  if (property.IDEquals(CSSPropertyID::kFontVariantLigatures) &&
      identifier_value && identifier_value->GetValueID() == CSSValueID::kNone) {
    // A shorter representation is preferred in general. Thus, 'none' returns
    // instead of the spelling-out form.
    // https://www.w3.org/Bugs/Public/show_bug.cgi?id=29594#c1
    value = "none";
  } else {
    value = val->CssText();
  }

  // The font longhand property values can be empty where the font shorthand
  // properties (e.g., font, font-variant, etc.) initialize them.
  if (value.empty()) {
    return true;
  }

  if (!result.empty()) {
    switch (property.PropertyID()) {
      case CSSPropertyID::kFontStyle:
        break;  // No prefix.
      case CSSPropertyID::kFontFamily:
      case CSSPropertyID::kFontStretch:
      case CSSPropertyID::kFontVariantCaps:
      case CSSPropertyID::kFontVariantLigatures:
      case CSSPropertyID::kFontVariantNumeric:
      case CSSPropertyID::kFontVariantEastAsian:
      case CSSPropertyID::kFontVariantAlternates:
      case CSSPropertyID::kFontVariantPosition:
      case CSSPropertyID::kFontVariantEmoji:
      case CSSPropertyID::kFontWeight:
        result.Append(' ');
        break;
      case CSSPropertyID::kLineHeight:
        result.Append(" / ");
        break;
      default:
        NOTREACHED();
    }
  }
  result.Append(value);
  return true;
}

String StylePropertySerializer::ContainerValue() const {
  CHECK_EQ(containerShorthand().length(), 2u);
  CHECK_EQ(containerShorthand().properties()[0],
           &GetCSSPropertyContainerName());
  CHECK_EQ(containerShorthand().properties()[1],
           &GetCSSPropertyContainerType());

  CSSValueList* list = CSSValueList::CreateSlashSeparated();

  const CSSValue* name =
      property_set_.GetPropertyCSSValue(GetCSSPropertyContainerName());
  const CSSValue* type =
      property_set_.GetPropertyCSSValue(GetCSSPropertyContainerType());

  DCHECK(name);
  DCHECK(type);

  list->Append(*name);

  if (const auto* ident_value = DynamicTo<CSSIdentifierValue>(type);
      !ident_value || ident_value->GetValueID() != CSSValueID::kNormal) {
    list->Append(*type);
  }

  return list->CssText();
}

namespace {

bool IsIdentifier(const CSSValue& value, CSSValueID ident) {
  const auto* ident_value = DynamicTo<CSSIdentifierValue>(value);
  return ident_value && ident_value->GetValueID() == ident;
}

bool IsIdentifierPair(const CSSValue& value, CSSValueID ident) {
  const auto* pair_value = DynamicTo<CSSValuePair>(value);
  return pair_value && IsIdentifier(pair_value->First(), ident) &&
         IsIdentifier(pair_value->Second(), ident);
}

CSSValue* TimelineValueItem(wtf_size_t index,
                            const CSSValueList& name_list,
                            const CSSValueList& axis_list,
                            const CSSValueList*
```