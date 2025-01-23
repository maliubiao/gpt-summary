Response:
Let's break down the thought process for analyzing this C++ file and generating the comprehensive explanation.

1. **Understand the Goal:** The request asks for a detailed explanation of `property_registration.cc`, focusing on its functions, relationships with web technologies, logical flow, potential errors, and debugging context.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, looking for key terms and concepts:
    * `#include`:  Indicates dependencies on other Blink components. Notice CSS-related headers like `css_syntax_definition.h`, `css_value.h`, `style_rule.h`, and `property_registry.h`. Also see binding-related headers like `v8_property_definition.h`.
    * `namespace blink`:  Confirms this is part of the Blink rendering engine.
    * `class PropertyRegistration`:  This is the central class, so understand its members and methods.
    * Method names like `From`, `ConvertSyntax`, `ConvertInherits`, `ConvertInitial`, `MaybeCreateForDeclaredProperty`, `registerProperty`, `RemoveDeclaredProperties`. These suggest the file's purpose is to manage the registration of CSS properties.

3. **Deconstruct the Class `PropertyRegistration`:**
    * **Members:** Identify the core data the class holds: `syntax_`, `inherits_`, `initial_`, `property_rule_`, `interpolation_types_`, `referenced_`. These hint at the information stored about a registered property.
    * **Constructor:** Understand how a `PropertyRegistration` object is created and what information is required.
    * **Methods:**  Analyze each method's purpose:
        * `From`:  Looks up an existing registration.
        * `GetViewportUnitFlags`:  Checks for viewport units in the initial value.
        * `Trace`: For garbage collection.
        * `ConvertSyntax`, `ConvertInherits`, `ConvertInitial`:  Deal with converting values from CSS into the appropriate types for registration. This is a strong connection to CSS.
        * `MaybeCreateForDeclaredProperty`:  Handles registration from `@property` rules in CSS.
        * `registerProperty`: Handles registration from JavaScript using `CSS.registerProperty()`.
        * `RemoveDeclaredProperties`:  Removes registered properties.

4. **Identify Core Functionalities:** Based on the analysis of the class and its methods, summarize the key functions of the file:
    * Registering custom CSS properties.
    * Storing information about registered properties (syntax, inheritance, initial value).
    * Handling registration from both CSS (`@property`) and JavaScript (`CSS.registerProperty()`).
    * Validating the syntax and initial values of registered properties.
    * Managing the lifecycle of registered properties (including removal).

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `registerProperty` method directly corresponds to the `CSS.registerProperty()` JavaScript API. Explain how this API allows developers to define custom CSS properties.
    * **CSS:** The file heavily interacts with CSS concepts like syntax, inheritance, initial values, and the `@property` rule. Explain how these CSS features relate to the functionality of the file.
    * **HTML:**  While not directly manipulating HTML elements, the registered properties affect how elements are styled, bridging the gap between CSS and HTML.

6. **Logical Flow and Assumptions (Hypothetical Inputs and Outputs):**
    * **Registration from JavaScript:**  Trace the execution flow when `CSS.registerProperty()` is called, highlighting the input parameters (name, syntax, inherits, initialValue) and how they are processed and stored.
    * **Registration from CSS (`@property`):** Describe the process when the CSS parser encounters an `@property` rule and how the file extracts and validates the information.
    * **Retrieval:** Explain how `PropertyRegistration::From` is used to retrieve information about a registered property.

7. **Common Errors:** Think about scenarios where developers might misuse the APIs related to custom properties:
    * Invalid syntax.
    * Invalid initial value.
    * Trying to register a property that already exists.
    * Providing an initial value that is not computationally independent.
    * Forgetting to provide an initial value when the syntax is not '*'.

8. **Debugging Context (User Operations):** Consider how a user's actions in a browser might lead to the execution of code in this file:
    * Loading a webpage with `<style>` tags or external CSS files containing `@property` rules.
    * JavaScript code using `CSS.registerProperty()`.
    * Inspecting styles in the browser's developer tools (which would trigger lookups of registered properties).
    * Animations involving custom properties.
    * Dynamic style changes through JavaScript.

9. **Structure and Refine:** Organize the information logically with clear headings and bullet points. Ensure the explanations are easy to understand and provide concrete examples where necessary. Review and refine the language for clarity and accuracy. For example, initially, I might just say "validates syntax."  Refining this would be "Validates the provided syntax string against the CSS syntax grammar, ensuring it's a valid pattern for the property's values."

10. **Self-Correction/Refinement during the process:**
    * Initially, I might focus too much on the C++ specifics. I need to remember the target audience and emphasize the connections to web technologies.
    * I might miss the significance of `ComputationallyIndependent`. Realizing this is a key validation step, I need to include a detailed explanation.
    * I might initially provide very simple examples. I need to expand them to be more illustrative of real-world scenarios.

By following these steps, breaking down the code, and focusing on the core functionalities and their relation to web development concepts, we can create a comprehensive and informative explanation like the example provided in the prompt.
好的，让我们详细分析一下 `blink/renderer/core/css/property_registration.cc` 这个文件。

**文件功能概述**

`property_registration.cc` 文件的主要功能是负责在 Blink 渲染引擎中注册和管理 CSS 自定义属性（也称为 CSS 变量或 CSS Houdini 属性）。它提供了机制来：

1. **定义自定义属性的元数据：**  例如，属性名称、语法（允许的值的类型和格式）、是否继承、初始值等。
2. **在 CSS 样式规则中声明自定义属性：**  当解析到 `@property` 规则时，此文件负责解析并创建 `PropertyRegistration` 对象。
3. **通过 JavaScript 注册自定义属性：**  允许开发者使用 `CSS.registerProperty()` API 在运行时注册自定义属性。
4. **查询已注册的自定义属性信息：**  提供方法来查找特定名称的已注册属性的信息。
5. **管理自定义属性的生命周期：**  例如，在文档卸载时移除已注册的属性。
6. **进行必要的验证：** 确保自定义属性的语法和初始值符合规范。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件是 Blink 引擎中连接 JavaScript、HTML 和 CSS 的关键桥梁，尤其是在 CSS 自定义属性方面。

1. **与 CSS 的关系:**
   * **`@property` 规则:**  这是 CSS 中声明自定义属性的语法。`property_registration.cc` 中的 `MaybeCreateForDeclaredProperty` 函数负责处理在 CSS 样式表中遇到的 `@property` 规则。它会解析规则中的 `syntax`, `inherits`, `initial-value` 等描述符，并创建一个 `PropertyRegistration` 对象来存储这些信息。

     **例子:**
     ```css
     @property --my-color {
       syntax: '<color>';
       inherits: false;
       initial-value: red;
     }

     div {
       background-color: var(--my-color);
     }
     ```
     当 Blink 解析到上面的 CSS 代码时，`MaybeCreateForDeclaredProperty` 会被调用，它会提取 `--my-color` 的语法是 `<color>`，不继承，初始值是 `red`。

   * **CSS 变量的使用 ( `var()` )：** 虽然此文件不直接处理 `var()` 函数的使用，但它管理的自定义属性信息会被用于解析和计算使用 `var()` 的样式。

2. **与 JavaScript 的关系:**
   * **`CSS.registerProperty()` API:**  JavaScript 提供了 `CSS.registerProperty()` 方法来动态注册自定义属性。`property_registration.cc` 中的 `registerProperty` 函数实现了这个 API 的后端逻辑。它接收 JavaScript 传递的属性名称、语法、继承性、初始值等信息，并创建 `PropertyRegistration` 对象。

     **例子:**
     ```javascript
     CSS.registerProperty({
       name: '--my-font-size',
       syntax: '<length>',
       inherits: true,
       initialValue: '16px'
     });

     document.querySelector('body').style.setProperty('--my-font-size', '20px');
     ```
     当执行这段 JavaScript 代码时，`registerProperty` 函数会被调用，将 `--my-font-size` 注册为一个类型为 `<length>`，继承，初始值为 `16px` 的自定义属性。

3. **与 HTML 的关系:**
   * 虽然此文件不直接操作 HTML 元素，但它管理的自定义属性最终会影响 HTML 元素的样式。通过 CSS 规则或 JavaScript 设置的自定义属性值会应用于匹配的 HTML 元素。

**逻辑推理 (假设输入与输出)**

假设输入一个包含 `@property` 规则的 CSS 字符串：

**假设输入:**
```css
@property --my-shadow {
  syntax: 'none | <shadow>';
  inherits: false;
  initial-value: none;
}
```

**逻辑推理过程:**

1. CSS 解析器会识别出 `@property` 规则。
2. 调用 `MaybeCreateForDeclaredProperty` 函数，并将规则的相关信息传递给它。
3. `ConvertSyntax` 函数会被调用，解析 `'none | <shadow>'` 字符串，创建一个 `CSSSyntaxDefinition` 对象，表示允许的值是 `none` 关键字或一个 `<shadow>` 类型的值。
4. `ConvertInherits` 函数会被调用，解析 `inherits: false`，返回 `false`。
5. `ConvertInitial` 函数会被调用，解析 `initial-value: none`，创建一个表示 `none` 关键字的 `CSSValue` 对象。
6. 创建一个新的 `PropertyRegistration` 对象，存储 `--my-shadow` 的名称、解析后的语法定义、继承性、初始值以及指向 `@property` 规则的指针。
7. 将这个 `PropertyRegistration` 对象添加到 `PropertyRegistry` 中。

**假设输出:**
一个 `PropertyRegistration` 对象被创建并注册，其内部状态大致如下：

```
PropertyRegistration {
  name_: "--my-shadow",
  syntax_: CSSSyntaxDefinition { /* 表示 'none | <shadow>' 的语法结构 */ },
  inherits_: false,
  initial_: CSSIdentifierValue(CSSValueID::kNone),
  property_rule_: 指向对应的 StyleRuleProperty 对象的指针
  // ... 其他成员
}
```

**用户或编程常见的使用错误及举例说明**

1. **语法错误的 `@property` 声明:**
   * **错误:**  `@property --my-size { syntax: <lenght>; }`  (拼写错误，应该是 `<length>`)
   * **后果:**  `ConvertSyntax` 函数解析失败，导致 `MaybeCreateForDeclaredProperty` 返回 `nullptr`，自定义属性注册失败。
   * **调试线索:**  开发者工具的 "Styles" 面板可能不会显示该自定义属性，或者显示一个解析错误。Blink 的控制台可能会输出相关的错误信息。

2. **JavaScript 注册时提供无效的语法或初始值:**
   * **错误:**
     ```javascript
     CSS.registerProperty({
       name: '--my-number',
       syntax: '<number>',
       initialValue: 'abc' // 'abc' 不是一个有效的数字
     });
     ```
   * **后果:** `registerProperty` 函数中的语法解析或初始值解析会失败，抛出 `DOMException`。
   * **调试线索:**  JavaScript 控制台会显示一个 `DOMException`，指出语法或初始值无效。

3. **尝试注册已存在的属性:**
   * **错误:**  多次调用 `CSS.registerProperty()` 注册同一个名称的属性。
   * **后果:** `registerProperty` 函数会检查 `PropertyRegistry`，发现该属性已存在，抛出 `DOMException`。
   * **调试线索:** JavaScript 控制台会显示一个 `DOMException`，指出该名称已被注册。

4. **初始值与语法不匹配:**
   * **错误:**
     ```css
     @property --my-boolean {
       syntax: 'true | false';
       initial-value: 123; // 数字与布尔值不匹配
     }
     ```
   * **后果:** `ConvertInitial` 函数会尝试使用 `syntax.Parse` 解析初始值，解析失败，导致 `MaybeCreateForDeclaredProperty` 返回 `nullptr`。
   * **调试线索:**  类似于语法错误的 `@property` 声明，开发者工具可能不会显示该自定义属性或显示解析错误。

5. **初始值不是计算独立的 (Computationally Independent):**
   * **错误:** 初始值中包含了对其他自定义属性的引用，导致在初始值解析时需要先解析其他变量，形成依赖循环或复杂的计算。
   * **后果:** `ComputationallyIndependent` 函数会返回 `false`，`registerProperty` 或 `MaybeCreateForDeclaredProperty` 会拒绝注册该属性。
   * **调试线索:** 控制台可能会输出错误信息，指出初始值不是计算独立的。

**用户操作是如何一步步的到达这里，作为调试线索**

以下是一些用户操作可能触发 `property_registration.cc` 中代码执行的场景，可以作为调试线索：

1. **加载包含 `<style>` 标签或外部 CSS 文件的 HTML 页面:**
   * **操作:** 用户在浏览器中打开一个网页。
   * **过程:** Blink 的 HTML 解析器会解析 HTML 结构，当遇到 `<style>` 标签或 `<link>` 标签引用的 CSS 文件时，CSS 解析器会开始工作。
   * **触发:** 如果 CSS 中包含 `@property` 规则，CSS 解析器会调用 `MaybeCreateForDeclaredProperty` 来处理这些规则。

2. **执行包含 `CSS.registerProperty()` 的 JavaScript 代码:**
   * **操作:** 用户访问的网页包含 JavaScript 代码，或者用户在开发者工具的控制台中输入并执行了这段代码.
   * **过程:**  JavaScript 引擎执行代码，当遇到 `CSS.registerProperty()` 调用时，会调用 Blink 提供的绑定接口。
   * **触发:** `property_registration.cc` 中的 `registerProperty` 函数会被执行。

3. **通过开发者工具检查元素的样式:**
   * **操作:** 用户打开浏览器的开发者工具，选择 "Elements" 面板，然后查看某个元素的 "Styles" 或 "Computed" 面板。
   * **过程:**  开发者工具会请求 Blink 引擎提供元素的样式信息，这可能涉及到查找和展示已注册的自定义属性。
   * **触发:** 虽然不直接触发注册，但在查找和展示自定义属性信息时，可能会用到 `PropertyRegistry` 中存储的 `PropertyRegistration` 对象。

4. **网页使用了 CSS 动画或过渡，涉及到自定义属性:**
   * **操作:** 网页加载完成，或者用户与网页交互触发了 CSS 动画或过渡。
   * **过程:**  Blink 的动画和过渡引擎会计算动画过程中的属性值，这可能涉及到自定义属性的插值计算。
   * **触发:** 虽然 `property_registration.cc` 不直接处理动画，但它提供的自定义属性信息是动画引擎进行计算的基础。

**总结**

`property_registration.cc` 是 Blink 渲染引擎中一个核心的 CSS 组件，专门负责自定义 CSS 属性的注册和管理。它连接了 CSS 样式声明、JavaScript 动态注册以及最终的样式应用，是理解 CSS Houdini 中自定义属性功能实现的关键。理解这个文件的功能和工作原理，对于调试与自定义属性相关的渲染问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/property_registration.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/property_registration.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_property_definition.h"
#include "third_party/blink/renderer/core/animation/css_interpolation_types_map.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_string_value.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_syntax_definition.h"
#include "third_party/blink/renderer/core/css/css_syntax_string_parser.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/css_variable_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"

namespace blink {

const PropertyRegistration* PropertyRegistration::From(
    const ExecutionContext* execution_context,
    const AtomicString& property_name) {
  const auto* window = DynamicTo<LocalDOMWindow>(execution_context);
  if (!window) {
    return nullptr;
  }
  const PropertyRegistry* registry = window->document()->GetPropertyRegistry();
  return registry ? registry->Registration(property_name) : nullptr;
}

PropertyRegistration::PropertyRegistration(const AtomicString& name,
                                           const CSSSyntaxDefinition& syntax,
                                           bool inherits,
                                           const CSSValue* initial,
                                           StyleRuleProperty* property_rule)
    : syntax_(syntax),
      inherits_(inherits),
      initial_(initial),
      property_rule_(property_rule),
      interpolation_types_(
          CSSInterpolationTypesMap::CreateInterpolationTypesForCSSSyntax(
              name,
              syntax,
              *this)),
      referenced_(false) {}

PropertyRegistration::~PropertyRegistration() = default;

unsigned PropertyRegistration::GetViewportUnitFlags() const {
  unsigned flags = 0;
  if (const auto* primitive_value =
          DynamicTo<CSSPrimitiveValue>(initial_.Get())) {
    CSSPrimitiveValue::LengthTypeFlags length_type_flags;
    primitive_value->AccumulateLengthUnitTypes(length_type_flags);
    if (CSSPrimitiveValue::HasStaticViewportUnits(length_type_flags)) {
      flags |= static_cast<unsigned>(ViewportUnitFlag::kStatic);
    }
    if (CSSPrimitiveValue::HasDynamicViewportUnits(length_type_flags)) {
      flags |= static_cast<unsigned>(ViewportUnitFlag::kDynamic);
    }
  }
  return flags;
}

void PropertyRegistration::Trace(Visitor* visitor) const {
  visitor->Trace(initial_);
  visitor->Trace(property_rule_);
}

static bool ComputationallyIndependent(const CSSValue& value) {
  DCHECK(!value.IsCSSWideKeyword());

  if (auto* variable_reference_value =
          DynamicTo<CSSUnparsedDeclarationValue>(value)) {
    return !variable_reference_value->VariableDataValue()
                ->NeedsVariableResolution();
  }

  if (auto* value_list = DynamicTo<CSSValueList>(value)) {
    for (const CSSValue* inner_value : *value_list) {
      if (!ComputationallyIndependent(*inner_value)) {
        return false;
      }
    }
    return true;
  }

  if (const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    return primitive_value->IsComputationallyIndependent();
  }

  // TODO(timloh): Images values can also contain lengths.

  return true;
}

std::optional<CSSSyntaxDefinition> PropertyRegistration::ConvertSyntax(
    const CSSValue* syntax_value) {
  // https://drafts.css-houdini.org/css-properties-values-api-1/#the-syntax-descriptor
  if (!syntax_value) {
    return {};
  }
  return CSSSyntaxStringParser(To<CSSStringValue>(*syntax_value).Value())
      .Parse();
}

std::optional<bool> PropertyRegistration::ConvertInherits(
    const CSSValue* inherits_value) {
  // https://drafts.css-houdini.org/css-properties-values-api-1/#inherits-descriptor
  if (!inherits_value) {
    return {};
  }

  CSSValueID inherits_id = To<CSSIdentifierValue>(*inherits_value).GetValueID();
  DCHECK(inherits_id == CSSValueID::kTrue || inherits_id == CSSValueID::kFalse);
  return inherits_id == CSSValueID::kTrue;
}

std::optional<const CSSValue*> PropertyRegistration::ConvertInitial(
    const CSSValue* initial_value,
    const CSSSyntaxDefinition& syntax,
    const CSSParserContext& parser_context) {
  // https://drafts.css-houdini.org/css-properties-values-api-1/#initial-value-descriptor
  if (!initial_value) {
    return syntax.IsUniversal() ? std::make_optional(nullptr) : std::nullopt;
  }
  CSSVariableData* initial_variable_data =
      To<CSSUnparsedDeclarationValue>(*initial_value).VariableDataValue();

  // Parse initial value, if we have it.
  const CSSValue* initial = nullptr;
  if (initial_variable_data) {
    const bool is_animation_tainted = false;
    initial = syntax.Parse(initial_variable_data->OriginalText(),
                           parser_context, is_animation_tainted);
    if (!initial) {
      return {};
    }
    if (!ComputationallyIndependent(*initial)) {
      return {};
    }
  }
  // For non-universal @property rules, the initial value is required for the
  // the rule to be valid.
  if (!initial && !syntax.IsUniversal()) {
    return {};
  }

  return initial;
}

PropertyRegistration* PropertyRegistration::MaybeCreateForDeclaredProperty(
    Document& document,
    const AtomicString& name,
    StyleRuleProperty& rule) {
  std::optional<CSSSyntaxDefinition> syntax = ConvertSyntax(rule.GetSyntax());
  if (!syntax.has_value()) {
    return nullptr;
  }
  std::optional<bool> inherits = ConvertInherits(rule.Inherits());
  if (!inherits.has_value()) {
    return nullptr;
  }
  const CSSParserContext* parser_context =
      document.ElementSheet().Contents()->ParserContext();

  std::optional<const CSSValue*> initial =
      ConvertInitial(rule.GetInitialValue(), *syntax, *parser_context);
  if (!initial.has_value()) {
    return nullptr;
  }

  return MakeGarbageCollected<PropertyRegistration>(name, *syntax, *inherits,
                                                    *initial, &rule);
}

void PropertyRegistration::registerProperty(
    ExecutionContext* execution_context,
    const PropertyDefinition* property_definition,
    ExceptionState& exception_state) {
  // Bindings code ensures these are set.
  DCHECK(property_definition->hasName());
  DCHECK(property_definition->hasInherits());
  DCHECK(property_definition->hasSyntax());

  String name = property_definition->name();
  if (!CSSVariableParser::IsValidVariableName(name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Custom property names must start with '--'.");
    return;
  }
  AtomicString atomic_name(name);
  Document* document = To<LocalDOMWindow>(execution_context)->document();
  PropertyRegistry& registry = document->EnsurePropertyRegistry();
  if (registry.IsInRegisteredPropertySet(atomic_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidModificationError,
        "The name provided has already been registered.");
    return;
  }

  std::optional<CSSSyntaxDefinition> syntax_definition =
      CSSSyntaxStringParser(property_definition->syntax()).Parse();
  if (!syntax_definition) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The syntax provided is not a valid custom property syntax.");
    return;
  }

  const CSSParserContext* parser_context =
      document->ElementSheet().Contents()->ParserContext();

  const CSSValue* initial = nullptr;
  if (property_definition->hasInitialValue()) {
    bool is_animation_tainted = false;
    initial = syntax_definition->Parse(property_definition->initialValue(),
                                       *parser_context, is_animation_tainted);
    if (!initial) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kSyntaxError,
          "The initial value provided does not parse for the given syntax.");
      return;
    }
    if (!ComputationallyIndependent(*initial)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kSyntaxError,
          "The initial value provided is not computationally independent.");
      return;
    }
  } else {
    if (!syntax_definition->IsUniversal()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kSyntaxError,
          "An initial value must be provided if the syntax is not '*'");
      return;
    }
  }
  registry.RegisterProperty(atomic_name,
                            *MakeGarbageCollected<PropertyRegistration>(
                                atomic_name, *syntax_definition,
                                property_definition->inherits(), initial));

  document->GetStyleEngine().PropertyRegistryChanged();
}

void PropertyRegistration::RemoveDeclaredProperties(Document& document) {
  if (!document.GetPropertyRegistry()) {
    return;
  }

  PropertyRegistry& registry = document.EnsurePropertyRegistry();

  size_t version_before = registry.Version();
  registry.RemoveDeclaredProperties();
  size_t version_after = registry.Version();

  if (version_before != version_after) {
    document.GetStyleEngine().PropertyRegistryChanged();
  }
}

}  // namespace blink
```