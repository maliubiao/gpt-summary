Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code, its relationship to web technologies (HTML, CSS, JavaScript), examples of its usage, logical reasoning with input/output, and common usage errors.

2. **Identify the Core Functionality:**  The file name `css_interpolation_type.cc` and the surrounding code immediately point to CSS Animations and Transitions. Specifically, it seems to be about how different CSS property values are *interpolated* (transitioned smoothly) between different states.

3. **Break Down the Code Structure:** I'll look for key classes and their responsibilities:
    * `CSSInterpolationType`:  This is the central class, responsible for handling the interpolation logic for a specific CSS property. It likely has methods for converting between different value representations and applying the interpolated value.
    * `ConversionChecker`: Several derived classes (`ResolvedValueChecker`, `ResolvedVariableChecker`, etc.) suggest different checks performed during the interpolation process to ensure validity. This is crucial for understanding how the system handles various CSS value types (variables, `revert`, `initial`, etc.).
    * `InterpolationEnvironment`:  This provides context for the interpolation, likely including the current style state and other relevant information.
    * Helper functions and templates like `MaybeConvertSingle`, `MaybeConvertValue`, `Apply`, etc., will reveal the steps involved in the interpolation process.

4. **Map to Web Technologies:**
    * **CSS:** The entire file is about CSS property interpolation. I'll focus on how it relates to CSS Transitions and Animations. Keywords like `transition`, `animation`, `@keyframes`, and specific CSS property names will be relevant.
    * **JavaScript:**  JavaScript can trigger CSS Transitions and Animations by manipulating CSS properties or adding/removing classes. Therefore, this code is indirectly involved when JavaScript interacts with animated properties.
    * **HTML:** HTML elements are the targets of CSS styles and therefore the subjects of animations and transitions. The code operates *on* the styles applied to HTML elements.

5. **Identify Key Concepts and Scenarios:**
    * **Interpolation:** The core concept – smoothly transitioning between values.
    * **CSS Properties:** The code handles different types of CSS properties (standard, custom).
    * **CSS Values:** It deals with various CSS value types: keywords (`initial`, `inherit`, `revert`), variables (`var()`), and potentially complex types like colors, lengths, etc.
    * **Value Resolution:** The `Resolve` methods indicate a need to resolve CSS values based on the current context (e.g., resolving variables to their actual values).
    * **Custom Properties:**  The code has specific handling for CSS custom properties (variables), which are a significant CSS feature.
    * **`revert` Keyword:** The special handling for `revert` and `revert-layer` is noteworthy.
    * **`initial` and `inherit` Keywords:**  The code explicitly deals with these keywords.

6. **Construct Examples and Scenarios:**
    * **JavaScript Interaction:** Show how JavaScript can initiate an animation or transition that would involve this code.
    * **HTML Structure:**  Provide a simple HTML example to which the CSS is applied.
    * **CSS Transitions/Animations:** Demonstrate how CSS transitions or animations on various property types would utilize the interpolation logic.
    * **Custom Property Example:**  Illustrate how this code handles the interpolation of custom properties.
    * **`revert` Example:** Show how the `revert` keyword interacts with interpolation.

7. **Infer Logical Reasoning (Input/Output):** While the code is complex, I can make reasonable assumptions about input and output:
    * **Input:** A CSS property, a starting value, an ending value, and a timing function.
    * **Output:**  Intermediate values of the property as the animation/transition progresses. The `ConversionChecker` classes imply that the input might also include information about whether the values are valid in the given context.

8. **Consider Common Usage Errors:**
    * **Invalid CSS Syntax:**  The interpolation might fail if the CSS values are invalid.
    * **Incompatible Value Types:** Trying to interpolate between incompatible value types (e.g., a color and a length without a defined way to do so).
    * **Incorrect `revert` Usage:**  Misunderstanding how `revert` works in different contexts.
    * **Circular Dependencies with Custom Properties:**  While not directly in this code, it's a common issue related to custom properties.

9. **Structure the Answer:** Organize the information into clear sections based on the request:
    * Functionality Summary
    * Relationship to Web Technologies (with examples)
    * Logical Reasoning (Input/Output)
    * Common Usage Errors (with examples)

10. **Refine and Elaborate:**  Review the generated answer for clarity, accuracy, and completeness. Add more details and context where needed. For instance, explaining *why* certain checks are performed or *how* the interpolation actually works at a high level. Make sure the examples are practical and easy to understand.

By following these steps, I can analyze the C++ code and provide a comprehensive and informative answer that addresses all aspects of the original request. The key is to connect the low-level code to the high-level concepts of web development.
这个C++源代码文件 `css_interpolation_type.cc` 是 Chromium Blink 渲染引擎中负责 **CSS 属性值插值 (interpolation)** 的核心组件之一。它的主要功能是定义了如何将 CSS 属性值在动画或过渡过程中进行平滑过渡。

以下是该文件的详细功能列表：

**1. 定义 CSS 属性的插值类型：**

* 该文件定义了 `CSSInterpolationType` 类，它是 `InterpolationType` 的子类，专门用于处理 CSS 属性的插值。
* 每个 `CSSInterpolationType` 实例都与一个特定的 CSS 属性 (`PropertyHandle`) 关联。
* 它负责确定如何将该属性的起始值和结束值转换为可插值的形式，并在动画或过渡的每一帧生成中间值。

**2. 提供值转换和验证机制：**

* 文件中定义了多个 `ConversionChecker` 的子类，例如 `ResolvedValueChecker`, `ResolvedVariableChecker`, `InheritedCustomPropertyChecker`, `RevertChecker` 等。
* 这些 `Checker` 类用于在插值过程中验证 CSS 值的有效性，并确保在进行插值之前，值已被正确解析和处理。
* 例如，`ResolvedValueChecker` 检查一个 CSS 值是否通过 `CSSInterpolationEnvironment::Resolve` 得到了正确的解析。`ResolvedVariableChecker` 检查 CSS 变量引用是否已成功解析为实际值。
* 这些检查器确保了动画和过渡过程中使用的值是有效的，避免出现意外的渲染错误。

**3. 处理不同类型的 CSS 值：**

* 该文件能够处理各种类型的 CSS 值，包括：
    * **标准值:** 例如长度、颜色、数字等。
    * **CSS 变量 (Custom Properties):**  提供 `MaybeConvertCustomPropertyDeclaration` 方法来处理自定义属性的插值。
    * **CSS 关键字:** 例如 `initial`, `inherit`, `unset`, `revert`, `revert-layer`。针对这些关键字提供了特殊的处理逻辑。
    * **未解析的值:** 例如包含 `var()` 函数的 `CSSUnparsedDeclarationValue`，需要先进行解析。
    * **数学函数:** 例如 `calc()`，需要先进行解析。

**4. 处理 CSS 继承、初始值和 `unset`：**

* `MaybeConvertInitial` 和 `MaybeConvertInherit` 方法分别处理 `initial` 和 `inherit` 关键字，确保动画能够正确地过渡到这些特殊值。
* 对于 `unset` 关键字，会根据属性是否可继承来选择使用初始值或继承值。

**5. 处理 `revert` 和 `revert-layer` 关键字：**

* `RevertChecker` 类专门用于处理 `revert` 和 `revert-layer` 关键字，确保在动画或过渡过程中，这些关键字能够正确地恢复到浏览器默认样式或更早层叠层定义的样式。

**6. 应用插值后的值：**

* `Apply` 方法负责将插值计算得到的中间值应用到元素的样式上。
* 对于自定义属性，使用 `ApplyCustomPropertyValue` 方法。
* 对于标准属性，使用 `ApplyStandardPropertyValue` 方法。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  该文件直接参与 CSS 动画和过渡的实现。当 CSS 规则中定义了 `transition` 或 `animation` 属性时，Blink 引擎会使用 `CSSInterpolationType` 来平滑地改变元素的样式。例如，当一个元素的颜色从红色过渡到蓝色时，这个文件中的代码会计算出过渡过程中每一帧的颜色值。
* **JavaScript:** JavaScript 可以通过修改元素的样式或添加/删除带有过渡/动画效果的 CSS 类来触发 CSS 动画和过渡。因此，当 JavaScript 触发这些效果时，最终会调用到 `css_interpolation_type.cc` 中的代码来执行实际的插值计算。
* **HTML:** HTML 元素是 CSS 样式应用的目标。动画和过渡效果作用于 HTML 元素上。该文件处理的是如何平滑地改变这些元素的 CSS 属性值。

**举例说明：**

**CSS 示例：**

```css
.box {
  width: 100px;
  transition: width 1s ease-in-out;
}

.box:hover {
  width: 200px;
}
```

当鼠标悬停在 `.box` 元素上时，`width` 属性会从 `100px` 过渡到 `200px`。`css_interpolation_type.cc` 中的代码会负责计算这 1 秒内 `width` 属性的中间值，例如 `110px`, `130px`, `150px` 等，从而实现平滑的过渡效果。

**JavaScript 示例：**

```javascript
const box = document.querySelector('.box');
box.style.transform = 'translateX(0px)';
box.style.transition = 'transform 1s ease-in-out';
setTimeout(() => {
  box.style.transform = 'translateX(100px)';
}, 100);
```

这段 JavaScript 代码先将元素的 `transform` 属性设置为 `translateX(0px)` 并添加过渡效果，然后在 100 毫秒后将其修改为 `translateX(100px)`。`css_interpolation_type.cc` 会负责计算这 1 秒内 `transform` 属性的中间值，实现元素的平移动画。

**逻辑推理（假设输入与输出）：**

**假设输入：**

* **属性:** `opacity`
* **起始值:** `0`
* **结束值:** `1`
* **过渡时长:** `0.5s`
* **当前时间点:** 过渡开始后的 `0.25s`

**输出：**

* 中间值：`0.5` (假设使用线性插值)

**解释：**  对于 `opacity` 属性，`CSSInterpolationType` 会将起始值和结束值都视为数字进行插值。如果使用线性插值，在过渡进行到一半时，`opacity` 的值应该是起始值和结束值的中间值。

**假设输入（涉及 CSS 变量）：**

* **属性:** `--my-color` (自定义属性)
* **起始值:** `red`
* **结束值:** `blue`
* **过渡时长:** `1s`
* **当前时间点:** 过渡开始后的 `0.3s`

**输出：**

* 中间值：可能是一个表示从红色到蓝色渐变的颜色值，具体的表示方式取决于 Blink 内部的颜色插值实现。

**解释：** 对于自定义属性，`CSSInterpolationType` 需要根据其注册的语法来决定如何进行插值。如果未注册或注册为 `<color>` 类型，则会进行颜色插值。

**用户或编程常见的使用错误：**

1. **尝试在不可插值的属性之间进行过渡：** 例如，尝试在 `display: block` 和 `display: none` 之间进行过渡。`display` 属性是不可插值的，因此不会产生平滑的过渡效果。浏览器通常会直接切换到结束值。

   **示例：**

   ```css
   .element {
     display: block;
     transition: display 0.5s; /* 错误的使用方式 */
   }

   .element:hover {
     display: none;
   }
   ```

2. **对使用了 `auto` 关键字的属性进行不当的过渡：**  例如，尝试在 `width: auto` 和 `width: 200px` 之间进行过渡。`auto` 的含义取决于上下文，直接进行数值插值可能不是预期的效果。

   **示例：**

   ```css
   .element {
     width: auto;
     transition: width 0.5s; /* 可能不是预期效果 */
   }

   .element:hover {
     width: 200px;
   }
   ```

3. **忘记设置 `transition-property` 或 `animation-name`：**  如果没有明确指定哪些属性需要过渡或动画，浏览器将不会应用任何平滑的过渡效果。

   **示例：**

   ```css
   .element {
     width: 100px;
     transition-duration: 0.5s; /* 缺少 transition-property */
   }

   .element:hover {
     width: 200px;
   }
   ```

4. **对自定义属性的类型理解错误：**  如果自定义属性未注册或注册了错误的语法，可能会导致插值结果不符合预期。例如，如果一个自定义属性用于存储颜色值，但被错误地注册为 `<length>` 类型，则可能无法进行颜色插值。

5. **`revert` 关键字的使用场景理解错误：**  不清楚 `revert` 会将属性恢复到用户代理样式表、作者样式表还是继承值，可能导致动画效果不符合预期。

总之，`css_interpolation_type.cc` 是 Blink 引擎中实现 CSS 动画和过渡的关键部分，负责将抽象的 CSS 属性值变化转化为浏览器能够平滑渲染的中间状态。理解其功能有助于开发者更好地掌握 CSS 动画和过渡的原理，并避免常见的错误。

Prompt: 
```
这是目录为blink/renderer/core/animation/css_interpolation_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/css_interpolation_type.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/memory/values_equivalent.h"
#include "third_party/blink/renderer/core/animation/css_interpolation_environment.h"
#include "third_party/blink/renderer/core/animation/string_keyframe.h"
#include "third_party/blink/renderer/core/css/anchor_evaluator.h"
#include "third_party/blink/renderer/core/css/computed_style_css_value_mapping.h"
#include "third_party/blink/renderer/core/css/css_inherited_value.h"
#include "third_party/blink/renderer/core/css/css_initial_value.h"
#include "third_party/blink/renderer/core/css/css_revert_layer_value.h"
#include "third_party/blink/renderer/core/css/css_revert_value.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/css_unset_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/property_registration.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder.h"
#include "third_party/blink/renderer/core/css/resolver/style_cascade.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"

namespace blink {

// Generic checker for any value that needs resolution through
// CSSInterpolationEnvironment::Resolve (StyleCascade::Resolve).
//
// More specialized checkers (e.g. RevertChecker) may exist even though
// they could also be handled by this class (perhaps less efficiently).
//
// TODO(andruud): Unify this with some other checkers.
class ResolvedValueChecker : public CSSInterpolationType::ConversionChecker {
 public:
  ResolvedValueChecker(const PropertyHandle& property,
                       const CSSValue* unresolved_value,
                       const CSSValue* resolved_value)
      : property_(property),
        unresolved_value_(unresolved_value),
        resolved_value_(resolved_value) {}

  void Trace(Visitor* visitor) const final {
    CSSInterpolationType::ConversionChecker::Trace(visitor);
    visitor->Trace(unresolved_value_);
    visitor->Trace(resolved_value_);
  }

 private:
  bool IsValid(const InterpolationEnvironment& environment,
               const InterpolationValue&) const final {
    const auto& css_environment = To<CSSInterpolationEnvironment>(environment);
    const CSSValue* resolved_value =
        css_environment.Resolve(property_, unresolved_value_);
    return base::ValuesEquivalent(resolved_value_.Get(), resolved_value);
  }

  PropertyHandle property_;
  Member<const CSSValue> unresolved_value_;
  Member<const CSSValue> resolved_value_;
};

class ResolvedVariableChecker : public CSSInterpolationType::ConversionChecker {
 public:
  ResolvedVariableChecker(CSSPropertyID property,
                          const CSSValue* variable_reference,
                          const CSSValue* resolved_value)
      : property_(property),
        variable_reference_(variable_reference),
        resolved_value_(resolved_value) {}

  void Trace(Visitor* visitor) const final {
    CSSInterpolationType::ConversionChecker::Trace(visitor);
    visitor->Trace(variable_reference_);
    visitor->Trace(resolved_value_);
  }

 private:
  bool IsValid(const InterpolationEnvironment& environment,
               const InterpolationValue&) const final {
    const auto& css_environment = To<CSSInterpolationEnvironment>(environment);
    // TODO(alancutter): Just check the variables referenced instead of doing a
    // full CSSValue resolve.
    const CSSValue* resolved_value = css_environment.Resolve(
        PropertyHandle(CSSProperty::Get(property_)), variable_reference_);
    return base::ValuesEquivalent(resolved_value_.Get(), resolved_value);
  }

  CSSPropertyID property_;
  Member<const CSSValue> variable_reference_;
  Member<const CSSValue> resolved_value_;
};

class InheritedCustomPropertyChecker
    : public CSSInterpolationType::CSSConversionChecker {
 public:
  InheritedCustomPropertyChecker(const AtomicString& name,
                                 bool is_inherited_property,
                                 const CSSValue* inherited_value,
                                 const CSSValue* initial_value)
      : name_(name),
        is_inherited_property_(is_inherited_property),
        inherited_value_(inherited_value),
        initial_value_(initial_value) {}

  void Trace(Visitor* visitor) const final {
    CSSInterpolationType::ConversionChecker::Trace(visitor);
    visitor->Trace(inherited_value_);
    visitor->Trace(initial_value_);
  }

 private:
  bool IsValid(const StyleResolverState& state,
               const InterpolationValue&) const final {
    const CSSValue* inherited_value =
        state.ParentStyle()->GetVariableValue(name_, is_inherited_property_);
    if (!inherited_value) {
      inherited_value = initial_value_.Get();
    }
    return base::ValuesEquivalent(inherited_value_.Get(), inherited_value);
  }

  AtomicString name_;
  const bool is_inherited_property_;
  Member<const CSSValue> inherited_value_;
  Member<const CSSValue> initial_value_;
};

class ResolvedRegisteredCustomPropertyChecker
    : public InterpolationType::ConversionChecker {
 public:
  ResolvedRegisteredCustomPropertyChecker(const PropertyHandle& property,
                                          const CSSValue& value,
                                          CSSVariableData* resolved_tokens)
      : property_(property), value_(value), resolved_tokens_(resolved_tokens) {}

  void Trace(Visitor* visitor) const final {
    CSSInterpolationType::ConversionChecker::Trace(visitor);
    visitor->Trace(value_);
    visitor->Trace(resolved_tokens_);
  }

 private:
  bool IsValid(const InterpolationEnvironment& environment,
               const InterpolationValue&) const final {
    const auto& css_environment = To<CSSInterpolationEnvironment>(environment);
    const CSSValue* resolved = css_environment.Resolve(property_, value_);
    CSSVariableData* resolved_tokens = nullptr;
    if (const auto* decl = DynamicTo<CSSUnparsedDeclarationValue>(resolved)) {
      resolved_tokens = decl->VariableDataValue();
    }

    return base::ValuesEquivalent(resolved_tokens, resolved_tokens_.Get());
  }

  PropertyHandle property_;
  Member<const CSSValue> value_;
  Member<CSSVariableData> resolved_tokens_;
};

template <typename RevertValueType>
class RevertChecker : public CSSInterpolationType::ConversionChecker {
 public:
  static_assert(
      std::is_same<RevertValueType, cssvalue::CSSRevertValue>::value ||
          std::is_same<RevertValueType, cssvalue::CSSRevertLayerValue>::value,
      "RevertCheck only accepts CSSRevertValue and CSSRevertLayerValue");

  RevertChecker(const PropertyHandle& property_handle,
                const CSSValue* resolved_value)
      : property_handle_(property_handle), resolved_value_(resolved_value) {}

  void Trace(Visitor* visitor) const final {
    CSSInterpolationType::ConversionChecker::Trace(visitor);
    visitor->Trace(resolved_value_);
  }

 private:
  bool IsValid(const InterpolationEnvironment& environment,
               const InterpolationValue&) const final {
    const auto& css_environment = To<CSSInterpolationEnvironment>(environment);
    const CSSValue* current_resolved_value =
        css_environment.Resolve(property_handle_, RevertValueType::Create());
    return base::ValuesEquivalent(resolved_value_.Get(),
                                  current_resolved_value);
  }

  PropertyHandle property_handle_;
  Member<const CSSValue> resolved_value_;
};

CSSInterpolationType::CSSInterpolationType(
    PropertyHandle property,
    const PropertyRegistration* registration)
    : InterpolationType(property), registration_(registration) {
  DCHECK(!GetProperty().IsCSSCustomProperty() || registration);
  DCHECK(!CssProperty().IsShorthand());
}

InterpolationValue CSSInterpolationType::MaybeConvertSingle(
    const PropertySpecificKeyframe& keyframe,
    const InterpolationEnvironment& environment,
    const InterpolationValue& underlying,
    ConversionCheckers& conversion_checkers) const {
  InterpolationValue result = MaybeConvertSingleInternal(
      keyframe, environment, underlying, conversion_checkers);
  if (result && keyframe.Composite() !=
                    EffectModel::CompositeOperation::kCompositeReplace) {
    return PreInterpolationCompositeIfNeeded(std::move(result), underlying,
                                             keyframe.Composite(),
                                             conversion_checkers);
  }
  return result;
}

InterpolationValue CSSInterpolationType::MaybeConvertSingleInternal(
    const PropertySpecificKeyframe& keyframe,
    const InterpolationEnvironment& environment,
    const InterpolationValue& underlying,
    ConversionCheckers& conversion_checkers) const {
  const CSSValue* value = To<CSSPropertySpecificKeyframe>(keyframe).Value();
  const auto& css_environment = To<CSSInterpolationEnvironment>(environment);
  const StyleResolverState& state = css_environment.GetState();

  if (!value)
    return MaybeConvertNeutral(underlying, conversion_checkers);

  if (GetProperty().IsCSSCustomProperty()) {
    return MaybeConvertCustomPropertyDeclaration(*value, environment,
                                                 conversion_checkers);
  }

  if (value->IsUnparsedDeclaration() || value->IsPendingSubstitutionValue()) {
    const CSSValue* resolved_value =
        css_environment.Resolve(GetProperty(), value);

    DCHECK(resolved_value);
    conversion_checkers.push_back(MakeGarbageCollected<ResolvedVariableChecker>(
        CssProperty().PropertyID(), value, resolved_value));
    value = resolved_value;
  }
  if (value->IsMathFunctionValue()) {
    // Math functions can contain anchor() and anchor-size() functions,
    // and those functions can make the value invalid at computed-value time
    // if they reference an invalid anchor and also don't have a fallback.
    const CSSValue* resolved_value =
        css_environment.Resolve(GetProperty(), value);
    DCHECK(resolved_value);
    conversion_checkers.push_back(MakeGarbageCollected<ResolvedValueChecker>(
        GetProperty(), /* unresolved_value */ value, resolved_value));
    value = resolved_value;
  }

  if (value->IsRevertValue()) {
    value = css_environment.Resolve(GetProperty(), value);
    DCHECK(value);
    conversion_checkers.push_back(
        MakeGarbageCollected<RevertChecker<cssvalue::CSSRevertValue>>(
            GetProperty(), value));
  }

  if (value->IsRevertLayerValue()) {
    value = css_environment.Resolve(GetProperty(), value);
    DCHECK(value);
    conversion_checkers.push_back(
        MakeGarbageCollected<RevertChecker<cssvalue::CSSRevertLayerValue>>(
            GetProperty(), value));
  }

  bool is_inherited = CssProperty().IsInherited();
  if (value->IsInitialValue() || (value->IsUnsetValue() && !is_inherited)) {
    return MaybeConvertInitial(state, conversion_checkers);
  }

  if (value->IsInheritedValue() || (value->IsUnsetValue() && is_inherited)) {
    return MaybeConvertInherit(state, conversion_checkers);
  }

  return MaybeConvertValue(*value, &state, conversion_checkers);
}

InterpolationValue CSSInterpolationType::MaybeConvertCustomPropertyDeclaration(
    const CSSValue& declaration,
    const InterpolationEnvironment& environment,
    ConversionCheckers& conversion_checkers) const {
  const auto& css_environment = To<CSSInterpolationEnvironment>(environment);
  const StyleResolverState& state = css_environment.GetState();

  AtomicString name = GetProperty().CustomPropertyName();

  const CSSValue* value = &declaration;
  value = css_environment.Resolve(GetProperty(), value);
  DCHECK(value) << "CSSVarCycleInterpolationType should have handled nullptr";

  if (declaration.IsRevertValue()) {
    conversion_checkers.push_back(
        MakeGarbageCollected<RevertChecker<cssvalue::CSSRevertValue>>(
            GetProperty(), value));
  }
  if (declaration.IsRevertLayerValue()) {
    conversion_checkers.push_back(
        MakeGarbageCollected<RevertChecker<cssvalue::CSSRevertLayerValue>>(
            GetProperty(), value));
  }
  if (const auto* resolved_declaration =
          DynamicTo<CSSUnparsedDeclarationValue>(value)) {
    // If Resolve returned a different CSSUnparsedDeclarationValue, var()
    // references were substituted.
    if (resolved_declaration != &declaration) {
      conversion_checkers.push_back(
          MakeGarbageCollected<ResolvedRegisteredCustomPropertyChecker>(
              GetProperty(), declaration,
              resolved_declaration->VariableDataValue()));
    }
  }

  // Unfortunately we transport CSS-wide keywords inside the
  // CSSUnparsedDeclarationValue. Expand those keywords into real CSSValues
  // if present.
  bool is_inherited = Registration().Inherits();
  const StyleInitialData* initial_data = state.StyleBuilder().InitialData();
  DCHECK(initial_data);
  const CSSValue* initial_value = initial_data->GetVariableValue(name);

  // Handle CSS-wide keywords (except 'revert', which should have been
  // handled already).
  DCHECK(!value->IsRevertValue());
  if (value->IsInitialValue() || (value->IsUnsetValue() && !is_inherited)) {
    value = initial_value;
  } else if (value->IsInheritedValue() ||
             (value->IsUnsetValue() && is_inherited)) {
    value = state.ParentStyle()->GetVariableValue(name, is_inherited);
    if (!value) {
      value = initial_value;
    }
    conversion_checkers.push_back(
        MakeGarbageCollected<InheritedCustomPropertyChecker>(
            name, is_inherited, value, initial_value));
  }

  if (const auto* resolved_declaration =
          DynamicTo<CSSUnparsedDeclarationValue>(value)) {
    DCHECK(
        !resolved_declaration->VariableDataValue()->NeedsVariableResolution());
    value = resolved_declaration->VariableDataValue()->ParseForSyntax(
        registration_->Syntax(),
        state.GetDocument().GetExecutionContext()->GetSecureContextMode());
    if (!value)
      return nullptr;
  }

  DCHECK(value);
  return MaybeConvertValue(*value, &state, conversion_checkers);
}

InterpolationValue CSSInterpolationType::MaybeConvertUnderlyingValue(
    const InterpolationEnvironment& environment) const {
  const auto& css_environment = To<CSSInterpolationEnvironment>(environment);
  const ComputedStyle& style = css_environment.BaseStyle();
  if (!GetProperty().IsCSSCustomProperty()) {
    return MaybeConvertStandardPropertyUnderlyingValue(style);
  }

  const PropertyHandle property = GetProperty();
  const AtomicString& name = property.CustomPropertyName();
  const CSSValue* underlying_value =
      style.GetVariableValue(name, Registration().Inherits());
  if (!underlying_value)
    return nullptr;
  // TODO(alancutter): Remove the need for passing in conversion checkers.
  ConversionCheckers dummy_conversion_checkers;
  return MaybeConvertValue(*underlying_value,
                           css_environment.GetOptionalState(),
                           dummy_conversion_checkers);
}

void CSSInterpolationType::Apply(
    const InterpolableValue& interpolable_value,
    const NonInterpolableValue* non_interpolable_value,
    InterpolationEnvironment& environment) const {
  StyleResolverState& state =
      To<CSSInterpolationEnvironment>(environment).GetState();

  if (GetProperty().IsCSSCustomProperty()) {
    ApplyCustomPropertyValue(interpolable_value, non_interpolable_value, state);
    return;
  }

  // The anchor() and anchor-size() functions evaluate differently depending
  // on which property they are used in. The regular CSSProperty::ApplyValue
  // code paths take care of this, but we are bypassing those code paths,
  // so we have to do it ourselves.
  AnchorScope anchor_scope(
      CssProperty().PropertyID(),
      state.CssToLengthConversionData().GetAnchorEvaluator());
  ApplyStandardPropertyValue(interpolable_value, non_interpolable_value, state);
}

void CSSInterpolationType::ApplyCustomPropertyValue(
    const InterpolableValue& interpolable_value,
    const NonInterpolableValue* non_interpolable_value,
    StyleResolverState& state) const {
  DCHECK(GetProperty().IsCSSCustomProperty());

  const CSSValue* css_value =
      CreateCSSValue(interpolable_value, non_interpolable_value, state);
  DCHECK(!css_value->IsUnparsedDeclaration());
  StyleBuilder::ApplyProperty(GetProperty().GetCSSPropertyName(), state,
                              *css_value, StyleBuilder::ValueMode::kAnimated);
}

}  // namespace blink

"""

```