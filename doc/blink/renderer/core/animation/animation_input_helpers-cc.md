Response:
Let's break down the thought process for analyzing this C++ code and generating the answer.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `animation_input_helpers.cc` file in the Chromium Blink engine, specifically in relation to CSS, HTML, and JavaScript, common errors, and any implicit logic.

**2. Initial Code Scan and Keyword Identification:**

First, I would quickly scan the code, looking for familiar keywords and patterns:

* **`#include` directives:** These tell us about the dependencies and what areas of the Blink engine this file touches (animation, CSS parsing, DOM, SVG, etc.). Key includes are: `animation/property_handle.h`, `css/...`, `dom/document.h`, `svg/...`.
* **Namespaces:**  The `blink` namespace confirms this is Blink code.
* **Function names:**  `KeyframeAttributeToCSSProperty`, `KeyframeAttributeToPresentationAttribute`, `KeyframeAttributeToSVGAttribute`, `ParseTimingFunction`, `PropertyHandleToKeyframeAttribute`, etc. These strongly suggest the file is involved in converting between different representations of animation properties.
* **String constants:** `kSVGPrefix`, `"cssFloat"`, `"cssOffset"`, `"Easing may not be the empty string"`. These hint at specific transformations and error handling.
* **Data structures:** `HashMap`, `QualifiedName`, `StringBuilder`. These are used for efficient lookups and string manipulation.
* **Conditional logic:** `if` statements, `switch` statements. These indicate branching based on property types or conditions.
* **Error handling:** `ExceptionState`. This signifies the file deals with reporting errors to the JavaScript environment.

**3. Deconstructing Key Functions (Hypothesis Formation):**

Now I'd focus on the key functions, trying to infer their purpose based on their names and the code within them:

* **`IsSVGPrefixed` and `RemoveSVGPrefix`:**  These seem to handle properties prefixed with "svg-", suggesting a separation between standard CSS properties and SVG attributes when used in animations.
* **`CSSPropertyToKeyframeAttribute`:**  This takes a `CSSPropertyID` and returns a string. The special cases for "float" and "offset" suggest this is for converting CSS property names to their JavaScript/keyframe equivalents (camelCase).
* **`PresentationAttributeToKeyframeAttribute`:**  This prepends "svg-" to a CSS property name, confirming the separation mentioned earlier.
* **`KeyframeAttributeToCSSProperty`:** This does the reverse of `CSSPropertyToKeyframeAttribute`, handling the camelCase to kebab-case conversion and checking for invalid names (hyphens, uppercase). The check for `CSSVariableParser::IsValidVariableName` indicates support for CSS custom properties.
* **`KeyframeAttributeToPresentationAttribute`:** This converts a keyframe attribute (potentially SVG prefixed) to a `CSSPropertyID` if it's a valid animatable SVG presentation attribute. It checks `RuntimeEnabledFeatures::WebAnimationsSVGEnabled()`, indicating this feature might be optional.
* **`GetSupportedAttributes` and `KeyframeAttributeToSVGAttribute`:** These deal with mapping keyframe attribute names (with the "svg-" prefix) to actual SVG attribute names. The `GetSupportedAttributes` function hardcodes a list of animatable SVG attributes, which is a crucial detail. The function also verifies if the attribute exists on the given `SVGElement`.
* **`ParseTimingFunction`:**  This function clearly parses a string representing an easing function (like "ease-in-out") into a `TimingFunction` object. It handles potential errors like empty strings or invalid values. The mention of `SecureContextMode` suggests security considerations.
* **`PropertyHandleToKeyframeAttribute`:**  This acts as a central dispatcher, converting a general `PropertyHandle` (which can represent a CSS property, a presentation attribute, or an SVG attribute) into its corresponding keyframe attribute string.

**4. Identifying Relationships with JavaScript, HTML, and CSS:**

Based on the function analysis:

* **JavaScript:** The functions converting to/from "keyframe attributes" strongly link to JavaScript's manipulation of animation properties, often using camelCase names. The `ExceptionState` usage also points to interaction with JavaScript error handling.
* **HTML:** The code deals with `Document` and `Element` objects, showing its connection to the HTML structure. The SVG attribute handling is specifically related to SVG elements embedded in HTML.
* **CSS:**  The inclusion of CSS parsing (`CSSParser`), CSS property IDs (`CSSPropertyID`), and value handling (`CSSValueList`) firmly establishes the connection to CSS. The handling of CSS variables is also a key aspect.

**5. Constructing Examples and Scenarios:**

To illustrate the functionality, I would create simple examples for each key function or concept:

* **CSS Property Conversion:** Show how "background-color" becomes "backgroundColor".
* **SVG Attribute Conversion:**  Demonstrate the "svg-cx" to "cx" mapping and the validation against the supported attributes.
* **Timing Function Parsing:** Provide examples of valid and invalid easing strings.
* **Error Handling:** Illustrate how invalid easing strings or property names result in JavaScript errors.

**6. Identifying Potential Errors:**

Thinking about how developers might misuse these features, I would focus on:

* **Incorrect SVG attribute names:**  Using "cx" instead of "svg-cx" in JavaScript.
* **Typos in CSS property names:**  "backgorund-color".
* **Invalid easing values:** "linear-out-ease".
* **Using unsupported SVG attributes for animation.

**7. Structuring the Answer:**

Finally, I would organize the findings into a clear and structured answer, covering:

* **Overall Functionality:** A high-level summary of the file's purpose.
* **Detailed Function Breakdown:** Explaining each function's role with examples.
* **Relationship to JavaScript, HTML, CSS:**  Explicitly outlining these connections.
* **Logic and Assumptions:**  Detailing the conversions and validations performed.
* **Common Errors:**  Providing concrete examples of potential developer mistakes.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps the file just deals with CSS animations.
* **Correction:**  The presence of "svg-" prefixes and SVG-related code clearly indicates support for SVG animations as well.
* **Initial thought:**  Maybe all SVG attributes are supported.
* **Correction:** The `GetSupportedAttributes` function shows a specific, limited set of animatable SVG attributes. This is important to highlight.
* **Initial thought:**  The file directly manipulates the DOM.
* **Correction:** While it interacts with DOM elements, its primary role is *conversion* and *validation* of animation input, not direct DOM manipulation. This distinction is important for understanding its scope.

By following this systematic approach, combining code analysis with domain knowledge (web development concepts like CSS animations and SVG), and using illustrative examples, I can effectively explain the functionality of this complex C++ file in an understandable way.
这个C++源代码文件 `animation_input_helpers.cc` 位于 Chromium Blink 引擎中，主要负责处理动画输入相关的辅助功能。 它的核心职责是在不同的动画表示形式之间进行转换和验证，特别是涉及到 JavaScript 传递的动画属性名称和 CSS 属性名称之间的映射，以及 SVG 属性的处理。

以下是该文件的主要功能点：

**1. 关键帧属性名和 CSS 属性 ID 之间的转换:**

*   **`KeyframeAttributeToCSSProperty(const String& property, const Document& document)`:**  将 JavaScript 中使用的关键帧属性名称（例如 `backgroundColor`, `cssFloat`）转换为对应的 CSS 属性 ID (`CSSPropertyID`)。
    *   **关系：JavaScript, CSS** - 当 JavaScript 代码通过 Web Animations API 或 CSSOM 修改元素的动画属性时，会使用驼峰命名法 (camelCase) 的属性名。此函数负责将这些 JavaScript 风格的属性名转换回 Blink 引擎内部使用的 CSS 属性 ID，以便进行后续的样式计算和应用。
    *   **假设输入与输出:**
        *   输入: `"backgroundColor"`, `document` 对象
        *   输出: `CSSPropertyID::kBackgroundColor`
        *   输入: `"cssFloat"`, `document` 对象
        *   输出: `CSSPropertyID::kFloat`
        *   输入: `"margin-left"`, `document` 对象
        *   输出: `CSSPropertyID::kInvalid` (因为包含连字符)
    *   **常见使用错误:**
        *   在 JavaScript 中使用了带连字符的 CSS 属性名（例如 `"margin-left"`)，此函数会返回 `kInvalid`，导致动画无法正确应用。

*   **`CSSPropertyToKeyframeAttribute(const CSSProperty& property)`:**  与上述函数相反，将 CSS 属性 ID 转换为 JavaScript 中使用的关键帧属性名称。
    *   **关系：JavaScript, CSS** - 在 Blink 引擎内部处理动画时，有时需要将 CSS 属性 ID 转换回 JavaScript 风格的属性名，例如在向 JavaScript 返回动画相关信息时。
    *   **假设输入与输出:**
        *   输入: `CSSProperty(CSSPropertyID::kBackgroundColor)`
        *   输出: `"backgroundColor"`
        *   输入: `CSSProperty(CSSPropertyID::kFloat)`
        *   输出: `"cssFloat"`

**2. 关键帧属性名和 SVG 属性名之间的转换:**

*   **`KeyframeAttributeToSVGAttribute(const String& property, Element* element)`:** 将 JavaScript 中使用的 SVG 关键帧属性名称（通常带有 `"svg-"` 前缀，例如 `"svg-cx"`) 转换为对应的 SVG 属性的 `QualifiedName`。
    *   **关系：JavaScript, HTML (SVG)** -  当动画作用于 SVG 元素时，JavaScript 需要使用特定的命名约定来指定要动画的 SVG 属性。此函数负责解析这些带有前缀的属性名，并查找对应的 SVG 属性。
    *   **假设输入与输出:**
        *   输入: `"svg-cx"`, 一个 `SVGCircleElement` 对象
        *   输出: `&svg_names::kCxAttr` (指向表示 "cx" 属性的常量)
        *   输入: `"cx"`, 一个 `SVGCircleElement` 对象
        *   输出: `nullptr` (因为缺少 "svg-" 前缀)
        *   输入: `"svg-width"`, 一个 `HTMLDivElement` 对象
        *   输出: `nullptr` (因为不是 SVG 元素)
    *   **常见使用错误:**
        *   在 JavaScript 中操作 SVG 动画属性时，忘记添加 `"svg-"` 前缀，导致无法找到对应的 SVG 属性。

*   **`KeyframeAttributeToPresentationAttribute(const String& property, const Element* element)`:**  将 JavaScript 中使用的 SVG 关键帧属性名称（带有 `"svg-"` 前缀）转换为 CSS 属性 ID，用于表示 SVG 的 presentation attribute。
    *   **关系：JavaScript, HTML (SVG), CSS** -  某些 SVG 属性也可以通过 CSS 来控制 (presentation attributes)。这个函数用于将 JavaScript 的 SVG 动画属性名映射到对应的 CSS 属性 ID。
    *   **假设输入与输出:**
        *   输入: `"svg-fill"`, 一个 `SVGRectElement` 对象
        *   输出: `CSSPropertyID::kFill`

*   **`PresentationAttributeToKeyframeAttribute(const CSSProperty& presentation_attribute)`:** 将表示 SVG presentation attribute 的 CSS 属性 ID 转换为 JavaScript 中使用的关键帧属性名（带有 `"svg-"` 前缀）。
    *   **关系：JavaScript, HTML (SVG), CSS** -  与上一个函数方向相反。
    *   **假设输入与输出:**
        *   输入: `CSSProperty(CSSPropertyID::kFill)`
        *   输出: `"svg-fill"`

**3. 处理 CSS 变量 (自定义属性):**

*   `KeyframeAttributeToCSSProperty` 函数会检查属性名是否是有效的 CSS 变量名。
    *   **关系：JavaScript, CSS** - 支持 JavaScript 动画 CSS 自定义属性。

**4. 解析 Timing Function (缓动函数):**

*   **`ParseTimingFunction(const String& string, Document* document, ExceptionState& exception_state)`:** 解析表示缓动函数的字符串（例如 `"ease-in-out"`, `"cubic-bezier(0.4, 0, 1, 1)"`），并返回一个 `TimingFunction` 对象。
    *   **关系：JavaScript, CSS** -  当 JavaScript 设置动画的 `easing` 属性时，会传递一个字符串。此函数负责将这个字符串解析成 Blink 引擎可以理解的缓动函数对象。
    *   **假设输入与输出:**
        *   输入: `"ease-in-out"`, `document` 对象, `exception_state`
        *   输出: 一个表示 ease-in-out 缓动函数的 `TimingFunction` 对象
        *   输入: `""`, `document` 对象, `exception_state`
        *   输出: `nullptr`, `exception_state` 会记录一个 TypeError
        *   输入: `"invalid-easing"`, `document` 对象, `exception_state`
        *   输出: `nullptr`, `exception_state` 会记录一个 TypeError
    *   **常见使用错误:**
        *   传递空的或无效的缓动函数字符串，会导致解析失败并抛出错误。

**5. 辅助函数:**

*   `IsSVGPrefixed(const String& property)`: 检查属性名是否以 `"svg-"` 开头。
*   `RemoveSVGPrefix(const String& property)`:  移除属性名中的 `"svg-"` 前缀。
*   `SvgAttributeName(const String& property)`:  将 SVG 属性名字符串转换为 `QualifiedName` 对象。
*   `PropertyHandleToKeyframeAttribute(PropertyHandle property)`:  根据 `PropertyHandle` 的类型（CSS 属性，SVG 属性等）返回对应的 JavaScript 关键帧属性名。

**6. 支持的 SVG 属性列表:**

*   `GetSupportedAttributes()`:  返回一个包含所有支持动画的 SVG 属性 `QualifiedName` 的哈希表。这限定了哪些 SVG 属性可以通过 JavaScript 进行动画控制。
    *   **关系：JavaScript, HTML (SVG)** -  限制了可以通过 Web Animations API 或 CSSOM 进行动画控制的 SVG 属性范围。尝试动画不支持的 SVG 属性将不会生效。

**总结:**

`animation_input_helpers.cc` 文件在 Blink 引擎的动画系统中扮演着重要的桥梁角色，它负责：

*   在 JavaScript 友好的关键帧属性名和 Blink 内部使用的 CSS 属性 ID 之间进行转换。
*   处理 SVG 动画属性，包括带有 `"svg-"` 前缀的属性名和实际的 SVG 属性。
*   解析 JavaScript 传递的缓动函数字符串。
*   验证动画输入的合法性，例如检查属性名是否有效。

这个文件对于连接 Web 开发者编写的 JavaScript/CSS 代码和 Blink 引擎内部的动画实现至关重要。它确保了动画属性能够被正确识别和处理，从而实现预期的动画效果。

### 提示词
```
这是目录为blink/renderer/core/animation/animation_input_helpers.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/animation_input_helpers.h"

#include "third_party/blink/renderer/core/animation/property_handle.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/resolver/css_to_style_map.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/svg/animation/svg_smil_element.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

const char kSVGPrefix[] = "svg-";
const unsigned kSVGPrefixLength = sizeof(kSVGPrefix) - 1;

static bool IsSVGPrefixed(const String& property) {
  return property.StartsWith(kSVGPrefix);
}

static String RemoveSVGPrefix(const String& property) {
  DCHECK(IsSVGPrefixed(property));
  return property.Substring(kSVGPrefixLength);
}

static String CSSPropertyToKeyframeAttribute(const CSSProperty& property) {
  DCHECK_NE(property.PropertyID(), CSSPropertyID::kInvalid);
  DCHECK_NE(property.PropertyID(), CSSPropertyID::kVariable);

  switch (property.PropertyID()) {
    case CSSPropertyID::kFloat:
      return "cssFloat";
    case CSSPropertyID::kOffset:
      return "cssOffset";
    default:
      return property.GetJSPropertyName();
  }
}

static String PresentationAttributeToKeyframeAttribute(
    const CSSProperty& presentation_attribute) {
  StringBuilder builder;
  builder.Append(base::byte_span_from_cstring(kSVGPrefix));
  builder.Append(presentation_attribute.GetPropertyName());
  return builder.ToString();
}

CSSPropertyID AnimationInputHelpers::KeyframeAttributeToCSSProperty(
    const String& property,
    const Document& document) {
  if (CSSVariableParser::IsValidVariableName(property))
    return CSSPropertyID::kVariable;

  // Disallow prefixed properties.
  if (property[0] == '-')
    return CSSPropertyID::kInvalid;
  if (IsASCIIUpper(property[0]))
    return CSSPropertyID::kInvalid;
  if (property == "cssFloat")
    return CSSPropertyID::kFloat;
  if (property == "cssOffset")
    return CSSPropertyID::kOffset;

  StringBuilder builder;
  for (wtf_size_t i = 0; i < property.length(); ++i) {
    // Disallow hyphenated properties.
    if (property[i] == '-')
      return CSSPropertyID::kInvalid;
    if (IsASCIIUpper(property[i]))
      builder.Append('-');
    builder.Append(property[i]);
  }
  return CssPropertyID(document.GetExecutionContext(), builder.ToString());
}

CSSPropertyID AnimationInputHelpers::KeyframeAttributeToPresentationAttribute(
    const String& property,
    const Element* element) {
  if (!RuntimeEnabledFeatures::WebAnimationsSVGEnabled() || !element ||
      !element->IsSVGElement() || !IsSVGPrefixed(property))
    return CSSPropertyID::kInvalid;

  String unprefixed_property = RemoveSVGPrefix(property);
  if (SVGElement::IsAnimatableCSSProperty(
          QualifiedName(AtomicString(unprefixed_property)))) {
    return CssPropertyID(element->GetExecutionContext(), unprefixed_property);
  }
  return CSSPropertyID::kInvalid;
}

using AttributeNameMap = HashMap<QualifiedName, const QualifiedName*>;

const AttributeNameMap& GetSupportedAttributes() {
  DEFINE_STATIC_LOCAL(AttributeNameMap, supported_attributes, ());
  if (supported_attributes.empty()) {
    // Fill the set for the first use.
    // Animatable attributes from http://www.w3.org/TR/SVG/attindex.html
    const auto attributes = std::to_array<const QualifiedName*>({
        &html_names::kClassAttr,
        &svg_names::kAmplitudeAttr,
        &svg_names::kAzimuthAttr,
        &svg_names::kBaseFrequencyAttr,
        &svg_names::kBiasAttr,
        &svg_names::kClipPathUnitsAttr,
        &svg_names::kCxAttr,
        &svg_names::kCyAttr,
        &svg_names::kDAttr,
        &svg_names::kDiffuseConstantAttr,
        &svg_names::kDivisorAttr,
        &svg_names::kDxAttr,
        &svg_names::kDyAttr,
        &svg_names::kEdgeModeAttr,
        &svg_names::kElevationAttr,
        &svg_names::kExponentAttr,
        &svg_names::kFilterUnitsAttr,
        &svg_names::kFxAttr,
        &svg_names::kFyAttr,
        &svg_names::kGradientTransformAttr,
        &svg_names::kGradientUnitsAttr,
        &svg_names::kHeightAttr,
        &svg_names::kHrefAttr,
        &svg_names::kIn2Attr,
        &svg_names::kInAttr,
        &svg_names::kInterceptAttr,
        &svg_names::kK1Attr,
        &svg_names::kK2Attr,
        &svg_names::kK3Attr,
        &svg_names::kK4Attr,
        &svg_names::kKernelMatrixAttr,
        &svg_names::kKernelUnitLengthAttr,
        &svg_names::kLengthAdjustAttr,
        &svg_names::kLimitingConeAngleAttr,
        &svg_names::kMarkerHeightAttr,
        &svg_names::kMarkerUnitsAttr,
        &svg_names::kMarkerWidthAttr,
        &svg_names::kMaskContentUnitsAttr,
        &svg_names::kMaskUnitsAttr,
        &svg_names::kMethodAttr,
        &svg_names::kModeAttr,
        &svg_names::kNumOctavesAttr,
        &svg_names::kOffsetAttr,
        &svg_names::kOperatorAttr,
        &svg_names::kOrderAttr,
        &svg_names::kOrientAttr,
        &svg_names::kPathLengthAttr,
        &svg_names::kPatternContentUnitsAttr,
        &svg_names::kPatternTransformAttr,
        &svg_names::kPatternUnitsAttr,
        &svg_names::kPointsAtXAttr,
        &svg_names::kPointsAtYAttr,
        &svg_names::kPointsAtZAttr,
        &svg_names::kPointsAttr,
        &svg_names::kPreserveAlphaAttr,
        &svg_names::kPreserveAspectRatioAttr,
        &svg_names::kPrimitiveUnitsAttr,
        &svg_names::kRAttr,
        &svg_names::kRadiusAttr,
        &svg_names::kRefXAttr,
        &svg_names::kRefYAttr,
        &svg_names::kResultAttr,
        &svg_names::kRotateAttr,
        &svg_names::kRxAttr,
        &svg_names::kRyAttr,
        &svg_names::kScaleAttr,
        &svg_names::kSeedAttr,
        &svg_names::kSlopeAttr,
        &svg_names::kSpacingAttr,
        &svg_names::kSpecularConstantAttr,
        &svg_names::kSpecularExponentAttr,
        &svg_names::kSpreadMethodAttr,
        &svg_names::kStartOffsetAttr,
        &svg_names::kStdDeviationAttr,
        &svg_names::kStitchTilesAttr,
        &svg_names::kSurfaceScaleAttr,
        &svg_names::kTableValuesAttr,
        &svg_names::kTargetAttr,
        &svg_names::kTargetXAttr,
        &svg_names::kTargetYAttr,
        &svg_names::kTextLengthAttr,
        &svg_names::kTransformAttr,
        &svg_names::kTypeAttr,
        &svg_names::kValuesAttr,
        &svg_names::kViewBoxAttr,
        &svg_names::kWidthAttr,
        &svg_names::kX1Attr,
        &svg_names::kX2Attr,
        &svg_names::kXAttr,
        &svg_names::kXChannelSelectorAttr,
        &svg_names::kY1Attr,
        &svg_names::kY2Attr,
        &svg_names::kYAttr,
        &svg_names::kYChannelSelectorAttr,
        &svg_names::kZAttr,
    });
    for (const QualifiedName* attribute : attributes) {
      DCHECK(!SVGElement::IsAnimatableCSSProperty(*attribute));
      supported_attributes.Set(*attribute, attribute);
    }
  }
  return supported_attributes;
}

QualifiedName SvgAttributeName(const String& property) {
  DCHECK(!IsSVGPrefixed(property));
  return QualifiedName(AtomicString(property));
}

const QualifiedName* AnimationInputHelpers::KeyframeAttributeToSVGAttribute(
    const String& property,
    Element* element) {
  auto* svg_element = DynamicTo<SVGElement>(element);
  if (!RuntimeEnabledFeatures::WebAnimationsSVGEnabled() || !svg_element ||
      !IsSVGPrefixed(property))
    return nullptr;

  if (IsA<SVGSMILElement>(svg_element))
    return nullptr;

  String unprefixed_property = RemoveSVGPrefix(property);
  QualifiedName attribute_name = SvgAttributeName(unprefixed_property);
  const AttributeNameMap& supported_attributes = GetSupportedAttributes();
  auto iter = supported_attributes.find(attribute_name);
  if (iter == supported_attributes.end() ||
      !svg_element->PropertyFromAttribute(*iter->value))
    return nullptr;

  return iter->value;
}

scoped_refptr<TimingFunction> AnimationInputHelpers::ParseTimingFunction(
    const String& string,
    Document* document,
    ExceptionState& exception_state) {
  if (string.empty()) {
    exception_state.ThrowTypeError("Easing may not be the empty string");
    return nullptr;
  }

  // Fallback to an insecure parsing mode if we weren't provided with a
  // document.
  SecureContextMode secure_context_mode =
      document && document->GetExecutionContext()
          ? document->GetExecutionContext()->GetSecureContextMode()
          : SecureContextMode::kInsecureContext;
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kTransitionTimingFunction, string,
      StrictCSSParserContext(secure_context_mode));
  const auto* value_list = DynamicTo<CSSValueList>(value);
  if (!value_list) {
    DCHECK(!value || value->IsCSSWideKeyword());
    exception_state.ThrowTypeError("'" + string +
                                   "' is not a valid value for easing");
    return nullptr;
  }
  if (value_list->length() > 1) {
    exception_state.ThrowTypeError("Easing may not be set to a list of values");
    return nullptr;
  }
  return CSSToStyleMap::MapAnimationTimingFunction(value_list->Item(0));
}

String AnimationInputHelpers::PropertyHandleToKeyframeAttribute(
    PropertyHandle property) {
  if (property.IsCSSProperty()) {
    return property.IsCSSCustomProperty()
               ? property.CustomPropertyName()
               : CSSPropertyToKeyframeAttribute(property.GetCSSProperty());
  }

  if (property.IsPresentationAttribute()) {
    return PresentationAttributeToKeyframeAttribute(
        property.PresentationAttribute());
  }

  DCHECK(property.IsSVGAttribute());
  return property.SvgAttribute().LocalName();
}

}  // namespace blink
```