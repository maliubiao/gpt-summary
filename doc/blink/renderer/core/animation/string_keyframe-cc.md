Response:
Let's break down the thought process for analyzing the `string_keyframe.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies, logical reasoning, and potential user/programming errors.

2. **Initial Scan and Keywords:**  Immediately scan the file for important keywords and class names. Keywords like `Keyframe`, `CSSProperty`, `String`, `V8ObjectBuilder`, `Animation`, `SVG`, `PresentationAttribute`, `Parse`, `Set`, `Get`, `MutableCSSPropertyValueSet` stand out. The filename `string_keyframe.cc` itself suggests it deals with string representations of keyframes.

3. **Identify the Core Class:** The central class is `StringKeyframe`. Its constructor and methods will reveal its purpose. Notice the inheritance from `Keyframe`, indicating it's a specific type of keyframe.

4. **Deconstruct the Constructor and Member Variables:** The constructor takes a `StringKeyframe` as input for copying, hinting at its role in cloning or manipulating keyframe data. The member variables are crucial:
    * `input_properties_`:  This looks like a core data structure holding the properties defined in the keyframe. The `PropertyHandle` key suggests a way to identify different types of properties (CSS, SVG, etc.). The `PropertyResolver` value hints at how these string values are parsed and interpreted.
    * `css_property_map_`:  A `MutableCSSPropertyValueSet` likely stores the processed CSS property values, ready for application.
    * `presentation_attribute_map_`, `svg_attribute_map_`:  These likely handle specific attribute types.
    * `has_logical_property_`, `writing_direction_`: These suggest handling of logical CSS properties (like `marginStart` which depends on text direction).

5. **Analyze Key Methods and Their Functionality:**  Go through the public methods and understand their actions:
    * `SetCSSPropertyValue`:  This is clearly the primary way to set CSS properties in the keyframe, both standard and custom. Pay attention to the parsing logic (`ParseAndSetProperty`, `ParseAndSetCustomProperty`) and how `PropertyResolver` is used. The handling of logical properties is important.
    * `SetPresentationAttributeValue`, `SetSVGAttributeValue`: These methods handle setting specific attribute types.
    * `Properties()`:  This method retrieves all the properties defined in the keyframe. The logic of combining CSS properties, presentation attributes, and SVG attributes is key.
    * `AddKeyframePropertiesToV8Object`: This directly relates to the interaction with JavaScript. It's about converting the internal representation of the keyframe into a JavaScript object.
    * `EnsureCssPropertyMap()`: This method implements lazy initialization of the `css_property_map_`. Understanding the logic of merging and prioritizing properties (especially shorthand vs. longhand, logical vs. physical) is vital.
    * `CreatePropertySpecificKeyframe`: This method seems to generate a more specialized keyframe for a *single* property, used during animation processing.

6. **Examine Helper Classes/Structures:**
    * `PropertyResolver`:  This class is crucial for understanding how string values are converted into a usable format. Note its constructor overloads and the `AppendTo` method, which explains how properties are added to the `css_property_map_`. The `HasLowerPriority` static method reveals the logic for resolving property conflicts.
    * `CSSPropertySpecificKeyframe`, `SVGPropertySpecificKeyframe`: These represent specialized keyframes for CSS and SVG properties, respectively. They are used when the animation is being applied.

7. **Relate to Web Technologies:** Based on the identified methods and classes, connect the functionality to HTML, CSS, and JavaScript:
    * **CSS:** The core of the file revolves around parsing and managing CSS properties from strings. Keyframe animations are a CSS feature. The handling of shorthands and logical properties is directly related to CSS concepts.
    * **HTML:**  Presentation attributes are HTML attributes that can be styled using CSS. The file handles these.
    * **JavaScript:** The `AddKeyframePropertiesToV8Object` method clearly shows the interaction with JavaScript. JavaScript can manipulate and read keyframes. The `element` parameter in this method also points to the DOM.

8. **Logical Reasoning and Examples:**  Think about the flow of data and provide examples. If a CSS string is provided, how does it get parsed and stored? How are shorthand properties expanded? How are conflicts between different keyframes resolved (though this file doesn't directly handle cross-keyframe conflicts)?

9. **User/Programming Errors:** Consider common mistakes developers might make when using keyframe animations:
    * **Syntax errors in CSS strings:** This is the most obvious error.
    * **Overriding properties unintentionally:**  Understanding how properties are merged is important.
    * **Incorrect use of shorthand properties:** Developers might not realize how shorthands are expanded.
    * **Forgetting vendor prefixes (though less common now):**  The parser handles standard CSS, but older code might have vendor prefixes.

10. **Structure the Output:** Organize the findings into logical sections as requested: Functionality, Relationship to Web Technologies, Logical Reasoning, and Common Errors. Use clear and concise language. Provide code snippets where helpful.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Is this file directly involved in *applying* the animation?  *Correction:* While it prepares the keyframe data, the actual animation application likely happens in other parts of the engine. This file is about *defining* the keyframe.
* **Focusing too much on low-level details:**  *Correction:* The request asks for the *functionality*. Avoid getting bogged down in the implementation details of `MutableCSSPropertyValueSet` unless it's directly relevant to the overall purpose.
* **Not enough concrete examples:** *Correction:*  Add specific examples of CSS properties, shorthand properties, and how they might be represented.

By following this structured approach and continuously refining the understanding, a comprehensive analysis of the `string_keyframe.cc` file can be achieved.
这个文件 `blink/renderer/core/animation/string_keyframe.cc` 的主要功能是 **表示和处理基于字符串定义的动画关键帧 (keyframes)**。 它是 Chromium Blink 渲染引擎中 Web Animations API 的一部分，负责解析和存储通过字符串形式（例如 CSS 样式字符串或 JavaScript 对象）定义的关键帧属性值。

以下是它的具体功能分解：

**1. 存储和管理关键帧数据:**

*   **解析字符串属性值:**  接收 CSS 属性名和对应的字符串值，并使用 Blink 的 CSS 解析器将这些字符串值解析成内部的 `CSSValue` 对象。
*   **存储不同类型的属性:**  能够存储和管理不同类型的属性，包括：
    *   **CSS 属性:**  例如 `opacity`, `transform`, `color` 等。
    *   **CSS 自定义属性 (CSS Variables):**  以 `--` 开头的属性。
    *   **SVG 属性:**  例如 SVG 元素的 `fill`, `stroke` 属性。
    *   **表示属性 (Presentation Attributes):**  HTML 元素的属性，例如 `<rect fill="red">` 中的 `fill`。
*   **处理简写属性 (Shorthand Properties):**  能够处理 CSS 的简写属性，例如 `margin`，并将其分解为对应的长写属性（`margin-top`, `margin-right` 等）。
*   **支持逻辑属性:**  能够处理 CSS 逻辑属性，例如 `marginStart`，这些属性的值会根据书写方向（从左到右或从右到左）映射到物理属性。
*   **存储关键帧元数据:** 除了属性值，还存储关键帧的 `offset` (关键帧发生的时间点)、`timeline_offset`、`composite` (合成操作) 和 `easing` (缓动函数)。

**2. 与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:**
    *   当使用 JavaScript 的 Web Animations API (例如 `element.animate()`) 并以对象形式提供关键帧时，Blink 内部会将这些对象转换为 `StringKeyframe` 对象。
    *   `AddKeyframePropertiesToV8Object` 方法用于将 `StringKeyframe` 中的属性添加到 V8 对象（JavaScript 对象），使其可以在 JavaScript 中被访问和操作。
    *   **举例:**  在 JavaScript 中可以这样定义动画关键帧：
        ```javascript
        element.animate([
          { opacity: '0', transform: 'scale(0)' }, // 对应一个 StringKeyframe
          { opacity: '1', transform: 'scale(1)' }  // 对应另一个 StringKeyframe
        ], { duration: 1000 });
        ```
*   **HTML:**
    *   当 CSS 动画的 `@keyframes` 规则被解析时，每个关键帧中的样式声明会被转换成一个 `StringKeyframe` 对象。
    *   `SetPresentationAttributeValue` 方法用于处理直接在 HTML 元素上设置的、可以被动画的属性。
    *   **举例:**  以下 CSS 关键帧定义会生成 `StringKeyframe` 对象：
        ```css
        @keyframes fadeIn {
          from { opacity: 0; } /* 对应一个 StringKeyframe */
          to { opacity: 1; }   /* 对应另一个 StringKeyframe */
        }
        ```
*   **CSS:**
    *   `StringKeyframe` 的核心功能就是解析和存储 CSS 属性值。
    *   它与 CSS 解析器 (`CSSParser`)、CSS 属性标识符 (`CSSPropertyID`)、CSS 值对象 (`CSSValue`) 等密切相关。
    *   `SetCSSPropertyValue` 方法用于设置 CSS 属性的值。
    *   **举例:**  在 CSS 关键帧中定义的 `color: red;` 会被 `StringKeyframe` 解析并存储。

**3. 逻辑推理 (假设输入与输出):**

**假设输入:**

*   一个 `StringKeyframe` 对象，表示一个动画的关键帧。
*   要获取的属性的 `PropertyHandle`，例如代表 `opacity` CSS 属性。

**输出:**

*   `CreatePropertySpecificKeyframe` 方法会根据输入的 `PropertyHandle` 创建一个更具体的关键帧对象，例如 `CSSPropertySpecificKeyframe`，其中包含了该属性在该关键帧的特定值、缓动函数和合成操作。

**更详细的假设输入与输出示例:**

**输入:**

*   一个 `StringKeyframe` 对象，其内部 `input_properties_` 存储了以下信息:
    *   `PropertyHandle(CSSPropertyID::kOpacity)` 对应的值为 `PropertyResolver` 对象，该对象内部存储了 `CSSValue` 表示的字符串 `"0.5"`.
    *   `PropertyHandle(CSSPropertyID::kTransform)` 对应的值为 `PropertyResolver` 对象，该对象内部存储了 `CSSValue` 表示的字符串 `"scale(2)"`.
*   调用 `CreatePropertySpecificKeyframe` 方法，并传入 `PropertyHandle(CSSPropertyID::kOpacity)`。

**输出:**

*   `CreatePropertySpecificKeyframe` 方法会返回一个指向 `CSSPropertySpecificKeyframe` 对象的指针。
*   这个 `CSSPropertySpecificKeyframe` 对象会包含：
    *   `offset`:  继承自原始 `StringKeyframe` 的偏移量。
    *   `easing`: 继承自原始 `StringKeyframe` 的缓动函数。
    *   `value_`: 一个指向 `CSSValue` 对象的指针，该对象表示浮点数 `0.5` (从字符串 `"0.5"` 解析而来)。
    *   `composite_`: 继承自原始 `StringKeyframe` 的合成操作。

**4. 用户或编程常见的使用错误:**

*   **CSS 语法错误:**  在 JavaScript 或 CSS 中提供无效的 CSS 属性值字符串会导致解析错误，`SetCSSPropertyValue` 方法会返回 `MutableCSSPropertyValueSet::kParseError`。例如，将 `opacity` 的值设置为 `"abc"`。
    ```javascript
    element.animate([{ opacity: 'abc' }], { duration: 1000 }); // 这会导致解析错误
    ```
*   **使用了动画影响属性作为关键帧属性:**  `CSSAnimations::IsAnimationAffectingProperty` 会检查某些属性是否会触发新的动画或影响现有动画的组合。尝试将这些属性用作关键帧属性可能会被忽略或产生意外行为。例如，尝试动画 `animation-name` 属性。
*   **误解简写属性的处理:**  开发者可能认为设置简写属性会覆盖所有相关的长写属性，但实际上 `StringKeyframe` 会将其展开。如果在不同的关键帧中混合使用简写和长写属性，可能会导致意外的覆盖或合并行为。
*   **尝试动画不支持的属性:**  并非所有 CSS 属性都可以被动画。尝试动画不支持的属性通常会被忽略。
*   **在不适用的元素上设置 SVG 属性:**  尝试在一个非 SVG 元素上设置 SVG 属性不会生效。
*   **大小写错误:**  CSS 属性名通常不区分大小写，但在 JavaScript 中访问时需要注意。在 `StringKeyframe` 中处理时，内部会统一使用规范的名称。

**总结:**

`string_keyframe.cc` 是 Blink 渲染引擎中处理动画关键帧的核心组件，负责解析、存储和管理基于字符串定义的动画属性值。它连接了 JavaScript 的 Web Animations API、CSS 动画和 HTML 元素的样式，使得开发者可以使用字符串的形式来定义丰富的动画效果。理解其功能有助于深入了解 Web Animations API 的内部实现。

### 提示词
```
这是目录为blink/renderer/core/animation/string_keyframe.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/string_keyframe.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/core/animation/animation_input_helpers.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/css/css_keyframe_shorthand_value.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

bool IsLogicalProperty(CSSPropertyID property_id) {
  const CSSProperty& property = CSSProperty::Get(property_id);
  const CSSProperty& resolved_property = property.ResolveDirectionAwareProperty(
      {WritingMode::kHorizontalTb, TextDirection::kLtr});
  return resolved_property.PropertyID() != property_id;
}

MutableCSSPropertyValueSet* CreateCssPropertyValueSet() {
  return MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
}

}  // namespace

using PropertyResolver = StringKeyframe::PropertyResolver;

StringKeyframe::StringKeyframe(const StringKeyframe& copy_from)
    : Keyframe(copy_from.offset_,
               copy_from.timeline_offset_,
               copy_from.composite_,
               copy_from.easing_),
      tree_scope_(copy_from.tree_scope_),
      input_properties_(copy_from.input_properties_),
      presentation_attribute_map_(
          copy_from.presentation_attribute_map_->MutableCopy()),
      svg_attribute_map_(copy_from.svg_attribute_map_),
      has_logical_property_(copy_from.has_logical_property_),
      writing_direction_(copy_from.writing_direction_) {
  if (copy_from.css_property_map_)
    css_property_map_ = copy_from.css_property_map_->MutableCopy();
}

MutableCSSPropertyValueSet::SetResult StringKeyframe::SetCSSPropertyValue(
    const AtomicString& custom_property_name,
    const String& value,
    SecureContextMode secure_context_mode,
    StyleSheetContents* style_sheet_contents) {
  bool is_animation_tainted = true;

  auto* property_map = CreateCssPropertyValueSet();
  MutableCSSPropertyValueSet::SetResult result =
      property_map->ParseAndSetCustomProperty(
          custom_property_name, value, false, secure_context_mode,
          style_sheet_contents, is_animation_tainted);

  const CSSValue* parsed_value =
      property_map->GetPropertyCSSValue(custom_property_name);

  if (result != MutableCSSPropertyValueSet::kParseError && parsed_value) {
    // Per specification we only keep properties around which are parsable.
    input_properties_.Set(PropertyHandle(custom_property_name),
                          MakeGarbageCollected<PropertyResolver>(
                              CSSPropertyID::kVariable, *parsed_value));
  }

  return result;
}

MutableCSSPropertyValueSet::SetResult StringKeyframe::SetCSSPropertyValue(
    CSSPropertyID property_id,
    const String& value,
    SecureContextMode secure_context_mode,
    StyleSheetContents* style_sheet_contents) {
  DCHECK_NE(property_id, CSSPropertyID::kInvalid);
  DCHECK_NE(property_id, CSSPropertyID::kVariable);
  const CSSProperty& property = CSSProperty::Get(property_id);

  if (CSSAnimations::IsAnimationAffectingProperty(property)) {
    return MutableCSSPropertyValueSet::kUnchanged;
  }

  auto* property_value_set = CreateCssPropertyValueSet();
  MutableCSSPropertyValueSet::SetResult result =
      property_value_set->ParseAndSetProperty(
          property_id, value, false, secure_context_mode, style_sheet_contents);

  // TODO(crbug.com/1132078): Add flag to CSSProperty to track if it is for a
  // logical style.
  bool is_logical = false;
  if (property.IsShorthand()) {
    // Logical shorthands to not directly map to physical shorthands. Determine
    // if the shorthand is for a logical property by checking the first
    // longhand.
    if (property_value_set->PropertyCount()) {
      CSSPropertyValueSet::PropertyReference reference =
          property_value_set->PropertyAt(0);
      if (IsLogicalProperty(reference.Id()))
        is_logical = true;
    }
  } else {
    is_logical = IsLogicalProperty(property_id);
  }
  if (is_logical)
    has_logical_property_ = true;

  if (result != MutableCSSPropertyValueSet::kParseError) {
    // Per specification we only keep properties around which are parsable.
    auto* resolver = MakeGarbageCollected<PropertyResolver>(
        property, property_value_set, is_logical);
    if (resolver->IsValid()) {
      input_properties_.Set(PropertyHandle(property), resolver);
      InvalidateCssPropertyMap();
    }
  }

  return result;
}

void StringKeyframe::SetCSSPropertyValue(const CSSPropertyName& name,
                                         const CSSValue& value) {
  CSSPropertyID property_id = name.Id();
  DCHECK_NE(property_id, CSSPropertyID::kInvalid);
#if DCHECK_IS_ON()
  if (property_id != CSSPropertyID::kVariable) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    DCHECK(!CSSAnimations::IsAnimationAffectingProperty(property));
    DCHECK(!property.IsShorthand());
  }
#endif  // DCHECK_IS_ON()
  DCHECK(!IsLogicalProperty(property_id));
  input_properties_.Set(
      PropertyHandle(name),
      MakeGarbageCollected<PropertyResolver>(property_id, value));
  InvalidateCssPropertyMap();
}

void StringKeyframe::RemoveCustomCSSProperty(const PropertyHandle& property) {
  DCHECK(property.IsCSSCustomProperty());
  if (css_property_map_)
    css_property_map_->RemoveProperty(property.CustomPropertyName());
  input_properties_.erase(property);
}

void StringKeyframe::SetPresentationAttributeValue(
    const CSSProperty& property,
    const String& value,
    SecureContextMode secure_context_mode,
    StyleSheetContents* style_sheet_contents) {
  DCHECK_NE(property.PropertyID(), CSSPropertyID::kInvalid);
  if (!CSSAnimations::IsAnimationAffectingProperty(property)) {
    presentation_attribute_map_->ParseAndSetProperty(
        property.PropertyID(), value, false, secure_context_mode,
        style_sheet_contents);
  }
}

void StringKeyframe::SetSVGAttributeValue(const QualifiedName& attribute_name,
                                          const String& value) {
  svg_attribute_map_.Set(&attribute_name, value);
}

PropertyHandleSet StringKeyframe::Properties() const {
  // This is not used in time-critical code, so we probably don't need to
  // worry about caching this result.
  EnsureCssPropertyMap();
  PropertyHandleSet properties;

  for (unsigned i = 0; i < css_property_map_->PropertyCount(); ++i) {
    CSSPropertyValueSet::PropertyReference property_reference =
        css_property_map_->PropertyAt(i);
    const CSSPropertyName& name = property_reference.Name();
    DCHECK(!name.IsCustomProperty() ||
           !CSSProperty::Get(name.Id()).IsShorthand())
        << "Web Animations: Encountered unexpanded shorthand CSS property ("
        << static_cast<int>(name.Id()) << ").";
    properties.insert(PropertyHandle(name));
  }

  for (unsigned i = 0; i < presentation_attribute_map_->PropertyCount(); ++i) {
    properties.insert(PropertyHandle(
        CSSProperty::Get(presentation_attribute_map_->PropertyAt(i).Id()),
        true));
  }

  for (auto* const key : svg_attribute_map_.Keys())
    properties.insert(PropertyHandle(*key));

  return properties;
}

bool StringKeyframe::HasCssProperty() const {
  PropertyHandleSet properties = Properties();
  for (const PropertyHandle& property : properties) {
    if (property.IsCSSProperty())
      return true;
  }
  return false;
}

void StringKeyframe::AddKeyframePropertiesToV8Object(
    V8ObjectBuilder& object_builder,
    Element* element) const {
  Keyframe::AddKeyframePropertiesToV8Object(object_builder, element);
  for (const auto& entry : input_properties_) {
    const PropertyHandle& property_handle = entry.key;
    const CSSValue* property_value = entry.value->CssValue();
    String property_name =
        AnimationInputHelpers::PropertyHandleToKeyframeAttribute(
            property_handle);

    object_builder.AddString(property_name, property_value->CssText());
  }

  // Legacy code path for SVG and Presentation attributes.
  //
  // TODO(816956): Move these to input_properties_ and remove this. Note that
  // this code path is not well tested given that removing it didn't cause any
  // test failures.
  for (const PropertyHandle& property : Properties()) {
    if (property.IsCSSProperty())
      continue;

    String property_name =
        AnimationInputHelpers::PropertyHandleToKeyframeAttribute(property);
    String property_value;
    if (property.IsPresentationAttribute()) {
      const auto& attribute = property.PresentationAttribute();
      property_value = PresentationAttributeValue(attribute).CssText();
    } else {
      DCHECK(property.IsSVGAttribute());
      property_value = SvgPropertyValue(property.SvgAttribute());
    }
    object_builder.AddString(property_name, property_value);
  }
}

void StringKeyframe::Trace(Visitor* visitor) const {
  visitor->Trace(tree_scope_);
  visitor->Trace(input_properties_);
  visitor->Trace(css_property_map_);
  visitor->Trace(presentation_attribute_map_);
  Keyframe::Trace(visitor);
}

Keyframe* StringKeyframe::Clone() const {
  return MakeGarbageCollected<StringKeyframe>(*this);
}

bool StringKeyframe::SetLogicalPropertyResolutionContext(
    WritingDirectionMode writing_direction) {
  if (writing_direction != writing_direction_) {
    writing_direction_ = writing_direction;
    if (has_logical_property_) {
      // force a rebuild of the property map on the next property fetch.
      InvalidateCssPropertyMap();
      return true;
    }
  }
  return false;
}

void StringKeyframe::EnsureCssPropertyMap() const {
  if (css_property_map_)
    return;

  css_property_map_ =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);

  bool requires_sorting = false;
  HeapVector<Member<PropertyResolver>> resolvers;
  for (const auto& entry : input_properties_) {
    const PropertyHandle& property_handle = entry.key;
    if (!property_handle.IsCSSProperty())
      continue;

    if (property_handle.IsCSSCustomProperty()) {
      CSSPropertyName property_name(property_handle.CustomPropertyName());
      const CSSValue* value = entry.value->CssValue();
      css_property_map_->SetLonghandProperty(
          CSSPropertyValue(property_name, *value));
    } else {
      PropertyResolver* resolver = entry.value;
      if (resolver->IsLogical() || resolver->IsShorthand())
        requires_sorting = true;
      resolvers.push_back(resolver);
    }
  }

  if (requires_sorting) {
    std::stable_sort(resolvers.begin(), resolvers.end(),
                     PropertyResolver::HasLowerPriority);
  }

  for (const auto& resolver : resolvers) {
    resolver->AppendTo(css_property_map_, writing_direction_);
  }
}

Keyframe::PropertySpecificKeyframe*
StringKeyframe::CreatePropertySpecificKeyframe(
    const PropertyHandle& property,
    EffectModel::CompositeOperation effect_composite,
    double offset) const {
  EffectModel::CompositeOperation composite =
      composite_.value_or(effect_composite);
  if (property.IsCSSProperty()) {
    return MakeGarbageCollected<CSSPropertySpecificKeyframe>(
        offset, &Easing(), &CssPropertyValue(property), composite);
  }

  if (property.IsPresentationAttribute()) {
    return MakeGarbageCollected<CSSPropertySpecificKeyframe>(
        offset, &Easing(),
        &PresentationAttributeValue(property.PresentationAttribute()),
        composite);
  }

  DCHECK(property.IsSVGAttribute());
  return MakeGarbageCollected<SVGPropertySpecificKeyframe>(
      offset, &Easing(), SvgPropertyValue(property.SvgAttribute()), composite);
}

bool StringKeyframe::CSSPropertySpecificKeyframe::
    PopulateCompositorKeyframeValue(const PropertyHandle& property,
                                    Element& element,
                                    const ComputedStyle& base_style,
                                    const ComputedStyle* parent_style) const {
  compositor_keyframe_value_cache_ =
      StyleResolver::CreateCompositorKeyframeValueSnapshot(
          element, base_style, parent_style, property, value_.Get(), offset_);
  return true;
}

bool StringKeyframe::CSSPropertySpecificKeyframe::IsRevert() const {
  return value_ && value_->IsRevertValue();
}

bool StringKeyframe::CSSPropertySpecificKeyframe::IsRevertLayer() const {
  return value_ && value_->IsRevertLayerValue();
}

Keyframe::PropertySpecificKeyframe*
StringKeyframe::CSSPropertySpecificKeyframe::NeutralKeyframe(
    double offset,
    scoped_refptr<TimingFunction> easing) const {
  return MakeGarbageCollected<CSSPropertySpecificKeyframe>(
      offset, std::move(easing), nullptr, EffectModel::kCompositeAdd);
}

void StringKeyframe::CSSPropertySpecificKeyframe::Trace(
    Visitor* visitor) const {
  visitor->Trace(value_);
  visitor->Trace(compositor_keyframe_value_cache_);
  Keyframe::PropertySpecificKeyframe::Trace(visitor);
}

Keyframe::PropertySpecificKeyframe*
StringKeyframe::CSSPropertySpecificKeyframe::CloneWithOffset(
    double offset) const {
  auto* clone = MakeGarbageCollected<CSSPropertySpecificKeyframe>(
      offset, easing_, value_.Get(), composite_);
  clone->compositor_keyframe_value_cache_ = compositor_keyframe_value_cache_;
  return clone;
}

Keyframe::PropertySpecificKeyframe*
SVGPropertySpecificKeyframe::CloneWithOffset(double offset) const {
  return MakeGarbageCollected<SVGPropertySpecificKeyframe>(offset, easing_,
                                                           value_, composite_);
}

Keyframe::PropertySpecificKeyframe*
SVGPropertySpecificKeyframe::NeutralKeyframe(
    double offset,
    scoped_refptr<TimingFunction> easing) const {
  return MakeGarbageCollected<SVGPropertySpecificKeyframe>(
      offset, std::move(easing), String(), EffectModel::kCompositeAdd);
}

// ----- Property Resolver -----

PropertyResolver::PropertyResolver(CSSPropertyID property_id,
                                   const CSSValue& css_value)
    : property_id_(property_id), css_value_(css_value) {}

PropertyResolver::PropertyResolver(
    const CSSProperty& property,
    const MutableCSSPropertyValueSet* property_value_set,
    bool is_logical)
    : property_id_(property.PropertyID()), is_logical_(is_logical) {
  DCHECK_NE(property_id_, CSSPropertyID::kInvalid);
  DCHECK_NE(property_id_, CSSPropertyID::kVariable);
  if (!property.IsShorthand())
    css_value_ = property_value_set->GetPropertyCSSValue(property_id_);
  else
    css_property_value_set_ = property_value_set->ImmutableCopyIfNeeded();
}

bool PropertyResolver::IsValid() const {
  return css_value_ || css_property_value_set_;
}

const CSSValue* PropertyResolver::CssValue() {
  DCHECK(IsValid());

  if (css_value_)
    return css_value_.Get();

  // For shorthands create a special wrapper value, |CSSKeyframeShorthandValue|,
  // which can be used to correctly serialize it given longhands that are
  // present in this set.
  css_value_ = MakeGarbageCollected<CSSKeyframeShorthandValue>(
      property_id_, css_property_value_set_);
  return css_value_.Get();
}

void PropertyResolver::AppendTo(MutableCSSPropertyValueSet* property_value_set,
                                WritingDirectionMode writing_direction) {
  DCHECK(property_id_ != CSSPropertyID::kInvalid);
  DCHECK(property_id_ != CSSPropertyID::kVariable);

  if (css_property_value_set_) {
    // Shorthand property. Extract longhands from css_property_value_set_.
    if (is_logical_) {
      // Walk set of properties converting each property name to its
      // corresponding physical property.
      for (unsigned i = 0; i < css_property_value_set_->PropertyCount(); i++) {
        CSSPropertyValueSet::PropertyReference reference =
            css_property_value_set_->PropertyAt(i);
        SetProperty(property_value_set, reference.Id(), reference.Value(),
                    writing_direction);
      }
    } else {
      property_value_set->MergeAndOverrideOnConflict(css_property_value_set_);
    }
  } else {
    SetProperty(property_value_set, property_id_, *css_value_,
                writing_direction);
  }
}

void PropertyResolver::SetProperty(
    MutableCSSPropertyValueSet* property_value_set,
    CSSPropertyID property_id,
    const CSSValue& value,
    WritingDirectionMode writing_direction) {
  const CSSProperty& physical_property =
      CSSProperty::Get(property_id)
          .ResolveDirectionAwareProperty(writing_direction);
  property_value_set->SetProperty(physical_property.PropertyID(), value);
}

void PropertyResolver::Trace(Visitor* visitor) const {
  visitor->Trace(css_value_);
  visitor->Trace(css_property_value_set_);
}

// static
bool PropertyResolver::HasLowerPriority(PropertyResolver* first,
                                        PropertyResolver* second) {
  // Longhand properties take precedence over shorthand properties.
  if (first->IsShorthand() != second->IsShorthand())
    return first->IsShorthand();

  // Physical properties take precedence over logical properties.
  if (first->IsLogical() != second->IsLogical())
    return first->IsLogical();

  // Two shorthands with overlapping longhand properties are sorted based
  // on the number of longhand properties in their expansions.
  if (first->IsShorthand())
    return first->ExpansionCount() > second->ExpansionCount();

  return false;
}

}  // namespace blink
```