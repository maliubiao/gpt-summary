Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for an explanation of the `custom_property.cc` file in the Blink rendering engine. This involves identifying its purpose, how it interacts with other web technologies (JavaScript, HTML, CSS), potential errors, and debugging information.

2. **Initial Code Scan (Keywords and Structure):** Quickly scan the code for important keywords and structural elements:
    * `#include`:  Identifies dependencies on other Blink components (e.g., `CSSUnparsedDeclarationValue`, `CSSParserContext`, `PropertyRegistration`).
    * `namespace blink`:  Indicates this code belongs to the Blink rendering engine.
    * `class CustomProperty`:  The core class being analyzed.
    * Constructor(s):  Understanding how `CustomProperty` objects are created is crucial. Note the different constructor signatures.
    * Methods like `ApplyInitial`, `ApplyInherit`, `ApplyValue`, `ParseSingleValue`, `ParseUntyped`, `Parse`. These suggest the lifecycle and processing of custom properties.
    * Data members like `name_`, `registration_`. These hold the state of a `CustomProperty` object.

3. **Identify the Core Functionality:** Based on the class name and method names, it's clear this file is responsible for handling **CSS Custom Properties (also known as CSS Variables)** within the Blink rendering engine. The methods indicate actions related to:
    * Initialization.
    * Inheritance.
    * Applying values from CSS.
    * Parsing CSS values.
    * Retrieving computed values.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **CSS:** This is the most direct relationship. Custom properties are a CSS feature. Think about how they are declared (`--my-color: blue;`), used (`color: var(--my-color);`), and their behavior (inheritance, initial values).
    * **JavaScript:**  JavaScript can interact with custom properties using the CSS Object Model (CSSOM). Methods like `getPropertyValue()` and `setProperty()` are key here.
    * **HTML:**  While not directly involved in the *processing* of custom properties, HTML elements are where styles (and thus custom property declarations and usages) are applied. Consider inline styles or `<style>` tags.

5. **Logical Reasoning and Examples:** For each area of functionality, think about the flow of data and what inputs lead to what outputs.

    * **Parsing:**  If the input is a valid CSS value string, the output should be a representation of that value within Blink's internal structures. If the input is invalid, the parsing should fail. *Hypothetical Example:* Input `--my-font-size: 16px;`, output: an internal representation of `16px`. Input `--my-font-size: ;`, output: indication of an invalid value.
    * **Applying Values:** Consider the different ways a custom property's value can be set (initial, inherited, specified). How does the code handle each case?  Think about registered vs. unregistered properties.
    * **Inheritance:**  Trace how a custom property's value propagates from parent to child elements.

6. **Identify Potential Errors:** Consider common mistakes developers make when working with custom properties:
    * **Syntax errors:** Incorrectly formatted values.
    * **Using unregistered properties (early versions of the spec):** Understanding how Blink handles this.
    * **Circular dependencies (though this file doesn't directly handle that, it's a related concept).**
    * **Type mismatches (for registered properties):** Trying to assign a string to a property registered as a `<number>`.

7. **Debugging Clues (User Actions):** How does a user end up triggering this code?  Think about the user's workflow:
    * Writing CSS with custom properties.
    * The browser parsing that CSS.
    * Applying the styles to HTML elements.
    * JavaScript interacting with styles.
    * Inspecting elements in the developer tools.

8. **Structure the Explanation:** Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Break down the key functionalities with code snippets and explanations.
    * Provide concrete examples for JavaScript, HTML, and CSS interactions.
    * Detail logical reasoning with hypothetical inputs and outputs.
    * List common user errors.
    * Outline the user actions that lead to this code being executed.

9. **Refine and Elaborate:** Review the explanation for clarity and completeness. Add more detail where needed. For example, explain the difference between registered and unregistered custom properties. Clarify the role of `PropertyRegistration`.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file just parses custom property declarations.
* **Correction:** Looking at methods like `ApplyInitial` and `ApplyInherit`, it's clear it's involved in the entire lifecycle, including how values are applied during style resolution.
* **Initial thought:** The connection to JavaScript is just through setting and getting styles.
* **Correction:**  It's more accurate to say JavaScript interacts through the CSSOM, which provides a structured way to access and modify styles.

By following these steps, combining code analysis with knowledge of web technologies and common development practices, a comprehensive and helpful explanation can be generated. The process involves iterative refinement and focusing on the "why" and "how" behind the code's functionality.
这个文件 `custom_property.cc` 是 Chromium Blink 渲染引擎中负责处理 **CSS 自定义属性 (CSS Custom Properties)** 或称为 **CSS 变量 (CSS Variables)** 的核心代码。 它的主要功能如下：

**核心功能：**

1. **表示和管理自定义属性：**
   - `CustomProperty` 类是自定义属性在 Blink 内部的表示。它存储了自定义属性的名称 (`name_`) 和相关的注册信息 (`registration_`)。
   - 提供了获取属性名称的方法 (`GetPropertyNameAtomicString`, `GetCSSPropertyName`).
   - 提供了判断两个 `CSSProperty` 是否是同一个自定义属性的方法 (`HasEqualCSSPropertyName`).

2. **处理自定义属性的初始值：**
   - `ApplyInitial` 方法负责在元素没有显式设置自定义属性值时，应用其初始值。
   - 对于已注册的自定义属性，它会查找注册时定义的初始值。
   - 对于未注册的自定义属性，其初始值被认为是 `nullptr`。
   - 特别处理了在 flat tree 之外的元素，因为它们的样式可能不是最新的。

3. **处理自定义属性的继承：**
   - `ApplyInherit` 方法负责处理自定义属性的继承行为。
   - 如果父元素定义了该自定义属性，则子元素会继承父元素的值。
   - 如果父元素没有定义，则回退到初始值。

4. **应用自定义属性的值：**
   - `ApplyValue` 方法是核心，负责将 CSS 中声明的自定义属性值应用到元素的样式中。
   - 它会处理已注册和未注册的自定义属性。
   - **未注册的自定义属性：** 只能接受 `CSSUnparsedDeclarationValue` 类型的值，也就是原始的未解析的 CSS 文本。
   - **已注册的自定义属性：** 可以接受 `CSSUnparsedDeclarationValue` 或其他已解析的 CSS 值（例如，通过动画或 JavaScript 设置）。
   - 对于已注册的属性，如果接收到 `CSSUnparsedDeclarationValue`，它会尝试根据注册时定义的语法进行解析。
   - 处理无效值的情况，并根据属性是否支持 `guaranteed-invalid` 关键字进行回退。
   - 考虑动画的影响 (`ValueMode::kAnimated`)。
   - 将自定义属性的值和变量数据存储到 `ComputedStyleBuilder` 中，以便后续使用。

5. **解析自定义属性的值：**
   - `ParseSingleValue` 方法被标记为 `NOTREACHED()`, 表明自定义属性的值通常不会作为单个值被解析（它们是“长手”属性）。
   - `ParseUntyped` 方法用于解析未注册的自定义属性的原始文本值。
   - `Parse` 方法根据属性是否已注册，选择调用 `ParseUntyped` 或使用注册时定义的语法进行解析。

6. **获取计算后的自定义属性值：**
   - `CSSValueFromComputedStyleInternal` 方法用于从元素的计算样式 (`ComputedStyle`) 中获取自定义属性的值。
   - 对于已注册的属性，直接返回存储的 `CSSValue`。
   - 对于未注册的属性，返回一个 `CSSUnparsedDeclarationValue` 对象，包含原始的文本值。

7. **其他辅助功能：**
   - `HasInitialValue` 判断自定义属性是否有定义的初始值（仅对已注册的属性有效）。
   - `SupportsGuaranteedInvalid` 判断自定义属性是否支持 `guaranteed-invalid` 关键字。
   - `HasUniversalSyntax` 判断已注册的自定义属性是否具有通用的 `<custom-ident>` 语法。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**  `custom_property.cc` 的核心功能就是实现 CSS 自定义属性。
    * **举例:** 当 CSS 中声明了 `--main-color: blue;` 时，Blink 的 CSS 解析器会创建 `CustomProperty` 对象来表示 `--main-color`，并将值 "blue" 存储起来。
    * **举例:** 当 CSS 规则中使用 `color: var(--main-color);` 时，渲染引擎会查找 `--main-color` 的值并应用到 `color` 属性。

* **JavaScript:** JavaScript 可以通过 CSSOM (CSS Object Model) 与自定义属性进行交互。
    * **举例:** JavaScript 可以使用 `element.style.setProperty('--font-size', '16px')` 来设置自定义属性的值。  这最终会触发 Blink 内部更新 `CustomProperty` 的值的过程。
    * **举例:** JavaScript 可以使用 `getComputedStyle(element).getPropertyValue('--font-size')` 来获取元素的自定义属性的计算值。 这会调用 `CSSValueFromComputedStyleInternal` 等方法来获取存储的值。

* **HTML:** HTML 作为文档结构，承载了 CSS 样式。自定义属性的声明和使用都发生在 HTML 文档的 `<style>` 标签或元素的 `style` 属性中。
    * **举例:**  在 HTML 中定义 `<div style="--my-padding: 10px;"></div>`，Blink 在解析内联样式时会创建 `CustomProperty` 对象来表示 `--my-padding`。

**逻辑推理与假设输入输出：**

**假设输入：** 考虑以下 CSS 规则：

```css
:root {
  --primary-bg: #f0f0f0; /* 未注册的自定义属性 */
  --font-size: 16px;    /* 假设这是一个已注册的自定义属性，类型为 <length> */
}

body {
  background-color: var(--primary-bg);
  font-size: var(--font-size);
}
```

**逻辑推理和输出：**

1. **解析 `--primary-bg`:**
   - **输入:** CSS 文本 `--primary-bg: #f0f0f0;`
   - **处理:** `CustomProperty::ParseUntyped` 会被调用，因为 `--primary-bg` 未注册。
   - **输出:** 创建一个 `CSSUnparsedDeclarationValue` 对象，其中包含了 `#f0f0f0` 的原始文本。

2. **解析 `--font-size`:**
   - **输入:** CSS 文本 `--font-size: 16px;`
   - **处理:** `CustomProperty::Parse` 会被调用，因为它已注册。注册信息中会包含其类型为 `<length>`。
   - **输出:** 创建一个表示 `16px` 的 `CSSValue` 对象（例如，`CSSPrimitiveValue`）。

3. **应用 `background-color`:**
   - **输入:** `background-color: var(--primary-bg);`
   - **处理:** `CustomProperty::ApplyValue` 会被调用。由于 `--primary-bg` 未注册，会直接使用存储的 `CSSUnparsedDeclarationValue`。
   - **输出:** `body` 元素的计算样式中，`background-color` 的值将是 `#f0f0f0` (或其内部表示)。

4. **应用 `font-size`:**
   - **输入:** `font-size: var(--font-size);`
   - **处理:** `CustomProperty::ApplyValue` 会被调用。由于 `--font-size` 已注册，会使用已解析的 `CSSValue`。
   - **输出:** `body` 元素的计算样式中，`font-size` 的值将是 `16px` (或其内部表示)。

**用户或编程常见的使用错误及举例说明：**

1. **语法错误：**  自定义属性的值不符合 CSS 语法。
   * **错误示例:** `--my-color: red blue;`  (多个颜色值，未用逗号分隔)
   * **后果:** `CustomProperty::ParseUntyped` 或 `CustomProperty::Parse` 解析失败，可能导致属性被忽略或使用初始值。

2. **使用未注册的自定义属性，并期望它具有特定类型：**  在自定义属性 API 早期版本中，所有自定义属性都是未注册的。
   * **错误示例:**  CSS 中定义 `--my-number: 10;`，然后在 JavaScript 中尝试进行数值计算 `parseInt(getComputedStyle(element).getPropertyValue('--my-number')) + 5`。由于未注册，获取到的是字符串 "10"，直接 `parseInt` 是可以的，但如果值是 "10px"，就会出错。
   * **后果:**  可能导致类型错误或意外的行为。

3. **为已注册的自定义属性设置了不符合其注册类型的值：**
   * **错误示例:**  假设 `--my-length` 注册为 `<length>` 类型，但在 CSS 中设置 `--my-length: red;`。
   * **后果:** `CustomProperty::Parse` 会根据注册的语法尝试解析，如果解析失败，可能会回退到初始值或导致其他错误。Blink 可能会记录警告信息。

4. **循环依赖：** 自定义属性的值依赖于自身（直接或间接）。
   * **错误示例:** `:root { --a: var(--b); --b: var(--a); }`
   * **后果:** 这会导致无限循环。Blink 有机制来检测和打破这种循环，通常会将循环依赖的属性值设置为初始值。

**用户操作到达此处的调试线索：**

当开发者遇到与 CSS 自定义属性相关的渲染问题时，可能会进行以下调试操作，从而间接地涉及到 `custom_property.cc` 的代码执行：

1. **在浏览器的开发者工具中检查元素的计算样式 (Computed tab)：** 当查看元素的计算样式时，浏览器会调用 Blink 的样式解析和计算逻辑，包括 `CSSValueFromComputedStyleInternal` 来获取自定义属性的值。

2. **在开发者工具的 "Elements" 面板中编辑元素的 `style` 属性或 CSS 规则：** 当修改自定义属性的值时，Blink 会重新解析和应用样式，调用 `CustomProperty::ApplyValue` 和相关的解析方法。

3. **使用 JavaScript 操作 CSS 自定义属性：**
   - 使用 `element.style.setProperty()` 或 `element.style.removeProperty()` 会触发 Blink 内部对自定义属性的更新。
   - 使用 `getComputedStyle()` 获取自定义属性值也会调用相关的 Blink 代码。

4. **检查浏览器的控制台 (Console)：** 如果自定义属性的解析或应用过程中出现错误（例如，类型不匹配），Blink 可能会在控制台中输出警告或错误信息。

5. **进行性能分析 (Performance tab)：** 如果页面使用了大量的自定义属性或复杂的计算，性能分析工具可能会显示样式计算阶段的耗时，这与 `custom_property.cc` 的执行有关。

**总结：**

`custom_property.cc` 是 Blink 中处理 CSS 自定义属性的核心组件，负责表示、解析、应用和计算自定义属性的值。它与 CSS 的语法和行为紧密相关，并通过 CSSOM 与 JavaScript 交互。理解这个文件的功能有助于深入理解浏览器如何处理 CSS 变量，并有助于调试相关的渲染问题。

### 提示词
```
这是目录为blink/renderer/core/css/properties/longhands/custom_property.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/properties/longhands/custom_property.h"

#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/property_registration.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {

namespace {

CSSProperty::Flags InheritedFlag(const PropertyRegistration* registration) {
  if (!registration || registration->Inherits()) {
    return CSSProperty::kInherited;
  }
  return 0;
}

}  // namespace

CustomProperty::CustomProperty(AtomicString name, const Document& document)
    : CustomProperty(
          PropertyRegistration::From(document.GetExecutionContext(), name)) {
  // Initializing `name_` on the body prevents `name` to be used after the
  // std::move call.
  name_ = std::move(name);
  DCHECK_EQ(IsShorthand(), CSSProperty::IsShorthand(GetCSSPropertyName()));
  DCHECK_EQ(IsRepeated(), CSSProperty::IsRepeated(GetCSSPropertyName()));
}

CustomProperty::CustomProperty(const AtomicString& name,
                               const PropertyRegistry* registry)
    : CustomProperty(name, registry ? registry->Registration(name) : nullptr) {}

CustomProperty::CustomProperty(const AtomicString& name,
                               const PropertyRegistration* registration)
    : Variable(InheritedFlag(registration)),
      name_(name),
      registration_(registration) {
  DCHECK_EQ(IsShorthand(), CSSProperty::IsShorthand(GetCSSPropertyName()));
  DCHECK_EQ(IsRepeated(), CSSProperty::IsRepeated(GetCSSPropertyName()));
}

CustomProperty::CustomProperty(const PropertyRegistration* registration)
    : Variable(InheritedFlag(registration)), registration_(registration) {}

const AtomicString& CustomProperty::GetPropertyNameAtomicString() const {
  return name_;
}

CSSPropertyName CustomProperty::GetCSSPropertyName() const {
  return CSSPropertyName(name_);
}

bool CustomProperty::HasEqualCSSPropertyName(const CSSProperty& other) const {
  if (PropertyID() != other.PropertyID()) {
    return false;
  }
  return name_ == other.GetPropertyNameAtomicString();
}

void CustomProperty::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  bool is_inherited_property = IsInherited();

  builder.SetHasVariableDeclaration();

  if (!registration_) {
    builder.SetVariableData(name_, nullptr, is_inherited_property);
    return;
  }

  // TODO(crbug.com/831568): The ComputedStyle of elements outside the flat
  // tree is not guaranteed to be up-to-date. This means that the
  // StyleInitialData may also be missing. We just disable initial values in
  // this case, since we shouldn't really be returning a style for those
  // elements anyway.
  if (state.StyleBuilder().IsEnsuredOutsideFlatTree()) {
    return;
  }

  const StyleInitialData* initial_data = state.StyleBuilder().InitialData();
  DCHECK(initial_data);
  CSSVariableData* initial_variable_data = initial_data->GetVariableData(name_);
  const CSSValue* initial_value = initial_data->GetVariableValue(name_);

  builder.SetVariableData(name_, initial_variable_data, is_inherited_property);
  builder.SetVariableValue(name_, initial_value, is_inherited_property);
}

void CustomProperty::ApplyInherit(StyleResolverState& state) const {
  if (!state.ParentStyle()) {
    ApplyInitial(state);
    return;
  }
  ComputedStyleBuilder& builder = state.StyleBuilder();
  bool is_inherited_property = IsInherited();

  CSSVariableData* parent_data =
      state.ParentStyle()->GetVariableData(name_, is_inherited_property);

  builder.SetVariableData(name_, parent_data, is_inherited_property);

  if (registration_) {
    const CSSValue* parent_value = state.ParentStyle()->GetVariableValue(name_);
    builder.SetVariableValue(name_, parent_value, is_inherited_property);
  }
}

void CustomProperty::ApplyValue(StyleResolverState& state,
                                const CSSValue& value,
                                ValueMode value_mode) const {
  // Highlight Pseudos do not allow custom property definitions.
  // Properties are copied from the originating element when the
  // style is created.
  if (state.UsesHighlightPseudoInheritance()) {
    return;
  }

  ComputedStyleBuilder& builder = state.StyleBuilder();
  DCHECK(!value.IsCSSWideKeyword());

  builder.SetHasVariableDeclaration();

  if (value.IsInvalidVariableValue()) {
    if (!SupportsGuaranteedInvalid()) {
      state.SetHasUnsupportedGuaranteedInvalid();
      ApplyUnset(state);
      return;
    }
    builder.SetVariableData(name_, nullptr, IsInherited());
    if (registration_) {
      builder.SetVariableValue(name_, nullptr, IsInherited());
    }
    return;
  }

  bool is_inherited_property = IsInherited();

  const auto* declaration = DynamicTo<CSSUnparsedDeclarationValue>(value);

  // Unregistered custom properties can only accept
  // CSSUnparsedDeclarationValue objects.
  if (!registration_) {
    // We can reach here without a CSSUnparsedDeclarationValue
    // if we're removing a property registration while animating.
    // TODO(andruud): Cancel animations if the registration changed.
    if (declaration) {
      CSSVariableData& data = *declaration->VariableDataValue();
      DCHECK(!data.NeedsVariableResolution());
      builder.SetVariableData(name_, &data, is_inherited_property);
    }
    return;
  }

  // Registered custom properties can accept either
  // - A CSSUnparsedDeclarationValue, in which case we produce the
  //   `registered_value` value from that, or:
  // - Some other value (typically an interpolated value), which we'll use
  //   as the `registered_value` directly.

  const CSSParserContext* context =
      declaration ? declaration->ParserContext() : nullptr;

  if (!context) {
    // There is no "originating" CSSParserContext associated with the
    // declaration if it represents a "synthetic" token sequence such as those
    // constructed to represent interpolated (registered) custom properties. [1]
    //
    // However, such values should also not contain any relative url()
    // functions, so we don't need any particular parser context in that case.
    //
    // [1]
    // https://drafts.css-houdini.org/css-properties-values-api-1/#equivalent-token-sequence
    context = StrictCSSParserContext(
        state.GetDocument().GetExecutionContext()->GetSecureContextMode());
  }

  const CSSValue* registered_value = declaration ? nullptr : &value;

  if (!registered_value) {
    DCHECK(declaration);
    CSSVariableData& data = *declaration->VariableDataValue();
    registered_value =
        Parse(data.OriginalText(), *context, CSSParserLocalContext());
  }

  if (!registered_value) {
    state.SetHasUnsupportedGuaranteedInvalid();
    if (is_inherited_property) {
      ApplyInherit(state);
    } else {
      ApplyInitial(state);
    }
    return;
  }

  bool is_animation_tainted = value_mode == ValueMode::kAnimated;

  // Note that the computed value ("SetVariableValue") is stored separately
  // from the substitution value ("SetVariableData") on ComputedStyle.
  // The substitution value is used for substituting var() references to
  // the custom property, and the computed value is generally used in other
  // cases (e.g. serialization).
  //
  // Note also that `registered_value` may be attr-tainted at this point.
  // This is what we want when producing the substitution value,
  // since any tainting must survive the substitution. However, the computed
  // value should serialize without taint-tokens, hence we store an
  // UntaintedCopy of `registered_value`.
  //
  // See also css_attr_tainting.h.
  registered_value = &StyleBuilderConverter::ConvertRegisteredPropertyValue(
      state, *registered_value, context);
  CSSVariableData* data =
      StyleBuilderConverter::ConvertRegisteredPropertyVariableData(
          *registered_value, is_animation_tainted);
  builder.SetVariableData(name_, data, is_inherited_property);
  builder.SetVariableValue(name_, registered_value->UntaintedCopy(),
                           is_inherited_property);
}

const CSSValue* CustomProperty::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  NOTREACHED();
}

const CSSValue* CustomProperty::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (registration_) {
    const CSSValue* value = style.GetVariableValue(name_, IsInherited());
    if (value) {
      return value;
    }
    // If we don't have CSSValue for this registered property, it means that
    // that the property was not registered at the time |style| was calculated,
    // hence we proceed with unregistered behavior.
  }

  CSSVariableData* data = style.GetVariableData(name_, IsInherited());

  if (!data) {
    return nullptr;
  }

  return MakeGarbageCollected<CSSUnparsedDeclarationValue>(
      data, /* parser_context */ nullptr);
}

const CSSValue* CustomProperty::ParseUntyped(
    StringView text,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return CSSVariableParser::ParseDeclarationValue(
      text, local_context.IsAnimationTainted(), context);
}

const CSSValue* CustomProperty::Parse(
    StringView text,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  if (!registration_) {
    return ParseUntyped(text, context, local_context);
  }
  return registration_->Syntax().Parse(text, context,
                                       local_context.IsAnimationTainted());
}

bool CustomProperty::HasInitialValue() const {
  if (!registration_) {
    return false;
  }
  return registration_->Initial();
}

bool CustomProperty::SupportsGuaranteedInvalid() const {
  return !registration_ || registration_->Syntax().IsUniversal();
}

bool CustomProperty::HasUniversalSyntax() const {
  return registration_ && registration_->Syntax().IsUniversal();
}

}  // namespace blink
```