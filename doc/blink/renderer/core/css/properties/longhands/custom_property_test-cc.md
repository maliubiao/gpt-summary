Response:
Let's break down the thought process for analyzing the `custom_property_test.cc` file.

1. **Understand the Purpose:** The file name `custom_property_test.cc` strongly suggests this is a unit test file for the `CustomProperty` class. The location `blink/renderer/core/css/properties/longhands/` further indicates that `CustomProperty` is related to CSS properties, specifically "longhand" properties (individual properties like `margin-top` as opposed to shorthand like `margin`). The "custom" part likely refers to CSS Custom Properties (also known as CSS Variables).

2. **Identify Key Imports:**  The `#include` directives are crucial for understanding the dependencies and the scope of the tests. We see imports like:
    * `custom_property.h`:  Confirms this file tests the `CustomProperty` class.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates the use of Google Test for unit testing.
    * `CSSNumericLiteralValue.h`, `CSSPrimitiveValue.h`, `CSSUnparsedDeclarationValue.h`: These suggest testing how custom properties interact with different CSS value types.
    * `css_test_helpers.h`: Hints at helper functions specifically for CSS testing within Blink.
    * `parser/...`: Indicates testing the parsing of custom property values.
    * `resolver/...`: Suggests tests related to how custom properties are resolved in the style system.
    * `html/html_element.h`: Shows that tests involve manipulating HTML elements.
    * `testing/page_test_base.h`:  Implies the tests run within a simulated browser page environment.

3. **Examine the Test Fixture:** The `CustomPropertyTest` class inherits from `PageTestBase`. This is a common pattern in Blink for tests that need a minimal DOM environment. The helper functions `SetElementWithStyle`, `GetComputedStyle`, `GetComputedValue`, and `ParseValue` are defined within the fixture. These functions clearly provide the infrastructure for:
    * Setting CSS styles on an element.
    * Retrieving the computed style of an element.
    * Getting the computed value of a specific custom property.
    * Parsing a string as a custom property value.

4. **Analyze Individual Tests:**  Go through each `TEST_F` block and try to understand its purpose based on the test name and the assertions made:
    * **Inheritance Tests (`UnregisteredPropertyIsInherited`, `RegisteredNonInheritedPropertyIsNotInherited`, `RegisteredInheritedPropertyIsInherited`):**  These test the inheritance behavior of custom properties, both registered and unregistered.
    * **Static Instance Test (`StaticVariableInstance`):**  Checks if the `CustomProperty` instance is not static, while `GetCSSPropertyVariable()` is. This relates to the internal representation of properties.
    * **Property ID Test (`PropertyID`):** Verifies that the `CustomProperty` has the expected `CSSPropertyID::kVariable`.
    * **Property Name Test (`GetPropertyNameAtomicString`, `GetCSSPropertyName`):**  Ensures the correct property name is retrieved.
    * **Computed Value Tests (`ComputedCSSValueUnregistered`, `ComputedCSSValueInherited`, `ComputedCSSValueNonInherited`, `ComputedCSSValueInitial`, `ComputedCSSValueEmptyInitial`, `ComputedCSSValueLateRegistration`, `ComputedCSSValueNumberCalc`, `ComputedCSSValueIntegerCalc`):** These are critical for testing how the computed value of a custom property is determined under various conditions (unregistered, inherited, non-inherited, with initial values, after late registration, with `calc()` expressions).
    * **Parsing Tests (`ParseSingleValueUnregistered`, `ParseSingleValueAnimationTainted`, `ParseSingleValueTyped`):**  Focus on the parsing of custom property values, including handling of animation taint and type checking for registered properties.
    * **Support/Has Initial Value Tests (`SupportsGuaranteedInvalid`, `HasInitialValue`):**  Check properties related to whether a property has a guaranteed invalid state or an initial value.
    * **Anchor Query Tests (`ParseAnchorQueriesAsLength`, `ParseAnchorQueriesAsLengthPercentage`):**  Specifically test how anchor queries (related to CSS anchor positioning) are parsed within custom properties.
    * **Value Mode Test (`ValueMode`):**  Examines how the `ValueMode` (normal vs. animated) affects the `isAnimationTainted` flag of the custom property's value.

5. **Identify Relationships to Web Technologies:** Based on the understanding of the tests, connect them to JavaScript, HTML, and CSS:
    * **CSS:** The core of custom properties. The tests directly manipulate and assert the behavior of CSS custom properties (variables).
    * **HTML:** The tests create and manipulate HTML elements (`<div>`) to apply styles and check computed values.
    * **JavaScript (Indirect):**  While this is a C++ test file, the functionality it tests is directly exposed and used by JavaScript through the browser's styling engine. JavaScript can set, get, and manipulate CSS custom properties.

6. **Consider Logic and Examples:** For each test, think about the underlying logic being tested and come up with concrete examples of how a web developer might use this feature and potential issues.

7. **Think About Debugging:**  Imagine you are debugging a problem with custom properties. How would you use the information in this test file? It provides clues about how the system handles different scenarios, such as inheritance, initial values, and parsing. The test setup with `SetElementWithStyle` is similar to how you might set styles in a real web page.

8. **Structure the Explanation:** Organize the findings into logical sections, as shown in the initial good answer: Functionality, Relationship to Web Technologies, Logic and Examples, Common Errors, Debugging. This makes the information easier to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This file just tests parsing."  **Correction:** Realized that it tests much more than parsing, including computed values, inheritance, and interaction with registered properties.
* **Initial thought:** "The `PageTestBase` is just a simple setup." **Correction:** Recognized that `PageTestBase` provides a significant amount of browser environment simulation necessary for these tests.
* **While analyzing `ValueMode`:** Initially might not grasp the purpose of `ValueMode::kAnimated`. **Refinement:** Understand that this relates to how animations affect custom property values and the `isAnimationTainted` flag, which is important for the rendering engine.

By following these steps and continuously refining understanding through the analysis of the code and its context, a comprehensive explanation of the test file's functionality can be generated.
这个文件 `custom_property_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `CustomProperty` 类的单元测试文件。`CustomProperty` 类负责处理 CSS 自定义属性（也称为 CSS 变量）。

以下是该文件的主要功能：

**1. 测试 `CustomProperty` 类的各种行为和特性：**

* **继承性 (Inheritance):**
    * 测试未注册的自定义属性是否继承。
    * 测试已注册且明确声明为不继承的自定义属性是否不继承。
    * 测试已注册且明确声明为继承的自定义属性是否继承。
* **静态实例 (Static Instance):**
    * 验证 `CustomProperty` 的实例不是静态的，而全局的 CSS 变量属性（`GetCSSPropertyVariable()`）是静态的。这涉及到对象生命周期管理和性能优化。
* **属性 ID (Property ID):**
    * 确认 `CustomProperty` 的属性 ID 是 `CSSPropertyID::kVariable`。
* **属性名称 (Property Name):**
    * 测试获取自定义属性的原子字符串形式的名称。
    * 测试获取 `CSSPropertyName` 对象形式的名称。
* **计算值 (Computed Value):**
    * 测试未注册的自定义属性的计算值是一个 `CSSUnparsedDeclarationValue`，保留原始的字符串值。
    * 测试已注册的自定义属性在继承和非继承情况下，计算值是否正确。
    * 测试当样式中没有设置自定义属性时，已注册的自定义属性是否能正确返回初始值。
    * 测试当样式中没有设置自定义属性且没有初始值时，已注册的自定义属性是否返回空值。
    * 测试在计算样式后注册自定义属性，计算值是否仍然是未注册时的行为。
    * 测试包含 `calc()` 函数的自定义属性的计算值是否正确解析为数字。
* **解析 (Parsing):**
    * 测试解析未注册的自定义属性的值。
    * 测试解析自定义属性值时是否能正确标记动画污染 (animation tainted) 状态。
    * 测试解析已注册的自定义属性的值，能正确解析符合类型的值，并拒绝不符合类型的值。
* **支持保证无效 (Supports Guaranteed Invalid):**
    * 测试某些类型的自定义属性（例如，通用类型 `*`）是否可以支持保证无效的状态，这意味着无论设置什么值，都将被认为是无效的。
* **拥有初始值 (Has Initial Value):**
    * 测试已注册的自定义属性是否拥有定义的初始值。
* **解析锚点查询 (Parse Anchor Queries):**
    * 测试对于注册为 `<length>` 类型的自定义属性，是否不能解析锚点查询相关的语法。
    * 测试对于注册为 `<length-percentage>` 类型的自定义属性，是否能正确解析锚点查询相关的语法。
* **值模式 (Value Mode):**
    * 测试在应用自定义属性值时，根据 `ValueMode` 的不同（例如，`kNormal` 和 `kAnimated`），是否会影响值的状态（例如，是否被标记为动画污染）。

**2. 与 JavaScript, HTML, CSS 的功能关系以及举例说明：**

* **CSS:** 该文件直接测试 CSS 自定义属性的核心功能。自定义属性允许开发者在 CSS 中定义变量，并在整个样式表中重用。
    * **例子:**  在 CSS 中定义 `--main-color: blue;`，然后在其他 CSS 规则中使用 `color: var(--main-color);`。
* **JavaScript:** JavaScript 可以读取和修改 CSS 自定义属性的值。
    * **例子:** 使用 JavaScript 获取自定义属性的值：`getComputedStyle(element).getPropertyValue('--main-color')`.
    * **例子:** 使用 JavaScript 设置自定义属性的值：`element.style.setProperty('--main-color', 'red')`. 该测试文件中的逻辑会影响 JavaScript 获取到的计算值。
* **HTML:** HTML 元素是应用 CSS 样式的目标。该测试文件会创建 HTML 元素并设置内联样式来测试自定义属性的效果。
    * **例子:** `<div id="target" style="--my-size: 10px; width: var(--my-size);"></div>`。

**3. 逻辑推理与假设输入输出：**

**假设输入：**

* **场景1：** 未注册的自定义属性 `--my-var` 被设置为 `10px`。
    * **输入:** `SetElementWithStyle("--my-var: 10px;")`
    * **输出:** `GetComputedValue(CustomProperty(AtomicString("--my-var"), GetDocument()))` 将返回一个 `CSSUnparsedDeclarationValue`，其 `CssText()` 为 `"10px"`。
* **场景2：** 已注册的自定义属性 `--my-length` 注册为 `<length>` 类型，初始值为 `0px`，然后在样式中设置为 `20px`。
    * **输入:** `RegisterProperty(GetDocument(), "--my-length", "<length>", "0px", false); SetElementWithStyle("--my-length: 20px;")`
    * **输出:** `GetComputedValue(CustomProperty(AtomicString("--my-length"), GetDocument()))` 将返回一个 `CSSPrimitiveValue`，其长度值为 20。
* **场景3：** 已注册的自定义属性 `--my-color` 注册为 `<color>` 类型，然后在样式中设置为 `invalid-color`。
    * **输入:** `RegisterProperty(GetDocument(), "--my-color", "<color>", "red", false); ParseValue(CustomProperty(AtomicString("--my-color"), GetDocument()), "invalid-color", CSSParserLocalContext())`
    * **输出:** `ParseValue` 将返回 `nullptr`，表示解析失败。

**4. 用户或编程常见的使用错误举例说明：**

* **拼写错误：** 用户在 CSS 或 JavaScript 中使用自定义属性时，可能会拼写错误，导致样式不生效。例如，定义了 `--main-color` 但在其他地方使用了 `var(--mian-color)`。
* **类型不匹配：**  如果注册了自定义属性的类型，但赋予了不匹配的值，可能会导致解析错误或回退到初始值。例如，注册了 `--my-number` 为 `<number>`，但设置了字符串值 `"abc"`。
* **循环依赖：**  自定义属性之间存在循环引用可能导致无限循环或性能问题。例如，`--var-a: var(--var-b); --var-b: var(--var-a);`。虽然浏览器通常会处理这种情况，但仍然是一个潜在的错误。
* **忘记注册：**  在需要特定类型检查或初始值的情况下，忘记注册自定义属性会导致其行为像未注册的属性，只能存储任意字符串值。
* **在不支持的环境中使用：** 虽然现代浏览器都支持自定义属性，但在一些旧版本的浏览器中可能不兼容。

**5. 用户操作如何一步步到达这里作为调试线索：**

假设用户发现一个自定义属性没有按预期工作，例如，一个使用 `var()` 的属性没有显示正确的计算值。以下是可能的调试步骤，最终可能会涉及到查看 `custom_property_test.cc` 这样的测试文件：

1. **检查 CSS 语法：** 用户首先会检查 CSS 文件中是否正确定义和使用了自定义属性，例如拼写是否正确，`var()` 函数的使用是否正确。
2. **检查 JavaScript 代码：** 如果通过 JavaScript 设置或读取自定义属性，用户会检查 JavaScript 代码中是否存在错误。
3. **使用浏览器开发者工具：**
    * **Elements 面板:** 查看元素的 computed style，确认自定义属性的值是否如预期。如果值是未解析的字符串，可能说明注册或解析有问题。
    * **Styles 面板:** 查看元素应用的样式规则，确认自定义属性的定义和使用位置。
    * **Console 面板:** 查看是否有任何 CSS 解析错误或 JavaScript 错误与自定义属性相关。
4. **简化问题：** 用户可能会尝试创建一个最小化的 HTML, CSS 示例来复现问题，以隔离可能的干扰因素。
5. **查阅文档和社区：** 用户会查阅关于 CSS 自定义属性的文档，或者在开发者社区寻求帮助。
6. **深入浏览器引擎源码 (高级)：**  如果问题很复杂，并且怀疑是浏览器引擎本身的问题，开发者可能会查看 Blink 的源码。
    * **定位相关代码：** 通过搜索相关的类名（例如 `CustomProperty`）或者关键词（例如 "CSS variable", "custom property"）来找到 `custom_property_test.cc` 这样的测试文件。
    * **理解测试逻辑：**  查看测试文件可以帮助理解 `CustomProperty` 类的预期行为，以及各种场景下的处理方式。例如，查看关于计算值的测试可以了解在什么情况下会返回 `CSSUnparsedDeclarationValue`，什么情况下会返回具体的类型值。
    * **对比实际行为与预期行为：**  通过测试文件中的例子，开发者可以对比自己遇到的问题，判断是自己的使用方式错误还是浏览器引擎存在 bug。

总之，`custom_property_test.cc` 文件是 Chromium Blink 引擎中用于验证 CSS 自定义属性功能正确性的重要组成部分。它涵盖了自定义属性的各种核心行为，并为理解和调试相关问题提供了宝贵的参考。

### 提示词
```
这是目录为blink/renderer/core/css/properties/longhands/custom_property_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

using css_test_helpers::RegisterProperty;

namespace {

class CustomPropertyTest : public PageTestBase {
 public:
  void SetElementWithStyle(const String& value) {
    GetDocument().body()->setInnerHTML("<div id='target' style='" + value +
                                       "'></div>");
    UpdateAllLifecyclePhasesForTest();
  }

  const ComputedStyle& GetComputedStyle() {
    Element* node = GetDocument().getElementById(AtomicString("target"));
    return node->ComputedStyleRef();
  }

  const CSSValue* GetComputedValue(const CustomProperty& property) {
    return property.CSSValueFromComputedStyle(
        GetComputedStyle(), nullptr /* layout_object */,
        false /* allow_visited_style */, CSSValuePhase::kComputedValue);
  }

  const CSSValue* ParseValue(const CustomProperty& property,
                             const String& value,
                             const CSSParserLocalContext& local_context) {
    auto* context = MakeGarbageCollected<CSSParserContext>(GetDocument());
    return property.Parse(value, *context, local_context);
  }
};

}  // namespace

TEST_F(CustomPropertyTest, UnregisteredPropertyIsInherited) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  EXPECT_TRUE(property.IsInherited());
}

TEST_F(CustomPropertyTest, RegisteredNonInheritedPropertyIsNotInherited) {
  RegisterProperty(GetDocument(), "--x", "<length>", "42px", false);
  CustomProperty property(AtomicString("--x"), GetDocument());
  EXPECT_FALSE(property.IsInherited());
}

TEST_F(CustomPropertyTest, RegisteredInheritedPropertyIsInherited) {
  RegisterProperty(GetDocument(), "--x", "<length>", "42px", true);
  CustomProperty property(AtomicString("--x"), GetDocument());
  EXPECT_TRUE(property.IsInherited());
}

TEST_F(CustomPropertyTest, StaticVariableInstance) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  EXPECT_FALSE(Variable::IsStaticInstance(property));
  EXPECT_TRUE(Variable::IsStaticInstance(GetCSSPropertyVariable()));
}

TEST_F(CustomPropertyTest, PropertyID) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  EXPECT_EQ(CSSPropertyID::kVariable, property.PropertyID());
}

TEST_F(CustomPropertyTest, GetPropertyNameAtomicString) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  EXPECT_EQ(AtomicString("--x"), property.GetPropertyNameAtomicString());
}

TEST_F(CustomPropertyTest, ComputedCSSValueUnregistered) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  SetElementWithStyle("--x:foo");
  const CSSValue* value = GetComputedValue(property);
  EXPECT_TRUE(value->IsUnparsedDeclaration());
  EXPECT_EQ("foo", value->CssText());
}

TEST_F(CustomPropertyTest, ComputedCSSValueInherited) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", true);
  CustomProperty property(AtomicString("--x"), GetDocument());
  SetElementWithStyle("--x:100px");
  const CSSValue* value = GetComputedValue(property);
  ASSERT_TRUE(value->IsPrimitiveValue());
  const auto* primitive_value = To<CSSPrimitiveValue>(value);
  EXPECT_EQ(100, primitive_value->ComputeLength<double>(
                     CSSToLengthConversionData(/*element=*/nullptr)));
}

TEST_F(CustomPropertyTest, ComputedCSSValueNonInherited) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);
  CustomProperty property(AtomicString("--x"), GetDocument());
  SetElementWithStyle("--x:100px");
  const CSSValue* value = GetComputedValue(property);
  ASSERT_TRUE(value->IsPrimitiveValue());
  const auto* primitive_value = To<CSSPrimitiveValue>(value);
  EXPECT_EQ(100, primitive_value->ComputeLength<double>(
                     CSSToLengthConversionData(/*element=*/nullptr)));
}

TEST_F(CustomPropertyTest, ComputedCSSValueInitial) {
  RegisterProperty(GetDocument(), "--x", "<length>", "100px", false);
  CustomProperty property(AtomicString("--x"), GetDocument());
  SetElementWithStyle("");  // Do not apply --x.
  const CSSValue* value = GetComputedValue(property);
  ASSERT_TRUE(value->IsPrimitiveValue());
  const auto* primitive_value = To<CSSPrimitiveValue>(value);
  EXPECT_EQ(100, primitive_value->ComputeLength<double>(
                     CSSToLengthConversionData(/*element=*/nullptr)));
}

TEST_F(CustomPropertyTest, ComputedCSSValueEmptyInitial) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  SetElementWithStyle("");  // Do not apply --x.
  const CSSValue* value = GetComputedValue(property);
  EXPECT_FALSE(value);
}

TEST_F(CustomPropertyTest, ComputedCSSValueLateRegistration) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  SetElementWithStyle("--x:100px");
  RegisterProperty(GetDocument(), "--x", "<length>", "100px", false);
  // The property was not registered when the style was computed, hence the
  // computed value should be what we expect for an unregistered property.
  const CSSValue* value = GetComputedValue(property);
  EXPECT_TRUE(value->IsUnparsedDeclaration());
  EXPECT_EQ("100px", value->CssText());
}

TEST_F(CustomPropertyTest, ComputedCSSValueNumberCalc) {
  RegisterProperty(GetDocument(), "--x", "<number>", "0", false);
  CustomProperty property(AtomicString("--x"), GetDocument());
  SetElementWithStyle("--x:calc(24 / 10)");
  const CSSValue* value = GetComputedValue(property);
  ASSERT_TRUE(value->IsNumericLiteralValue());
  const auto* numeric_literal = To<CSSNumericLiteralValue>(value);
  EXPECT_DOUBLE_EQ(2.4, numeric_literal->GetDoubleValue());
}

TEST_F(CustomPropertyTest, ComputedCSSValueIntegerCalc) {
  RegisterProperty(GetDocument(), "--x", "<integer>", "0", false);
  CustomProperty property(AtomicString("--x"), GetDocument());
  SetElementWithStyle("--x:calc(24 / 10)");
  const CSSValue* value = GetComputedValue(property);
  ASSERT_TRUE(value->IsNumericLiteralValue());
  const auto* numeric_literal = To<CSSNumericLiteralValue>(value);
  EXPECT_DOUBLE_EQ(2.0, numeric_literal->GetDoubleValue());
}

TEST_F(CustomPropertyTest, ParseSingleValueUnregistered) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  const CSSValue* value =
      ParseValue(property, "100px", CSSParserLocalContext());
  ASSERT_TRUE(value->IsUnparsedDeclaration());
  EXPECT_EQ("100px", value->CssText());
}

TEST_F(CustomPropertyTest, ParseSingleValueAnimationTainted) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  const CSSValue* value1 = ParseValue(
      property, "100px", CSSParserLocalContext().WithAnimationTainted(true));
  const CSSValue* value2 = ParseValue(
      property, "100px", CSSParserLocalContext().WithAnimationTainted(false));

  EXPECT_TRUE(To<CSSUnparsedDeclarationValue>(value1)
                  ->VariableDataValue()
                  ->IsAnimationTainted());
  EXPECT_FALSE(To<CSSUnparsedDeclarationValue>(value2)
                   ->VariableDataValue()
                   ->IsAnimationTainted());
}

TEST_F(CustomPropertyTest, ParseSingleValueTyped) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);
  CustomProperty property(AtomicString("--x"), GetDocument());
  const CSSValue* value1 =
      ParseValue(property, "100px", CSSParserLocalContext());
  EXPECT_TRUE(value1->IsPrimitiveValue());
  EXPECT_EQ(100, To<CSSPrimitiveValue>(value1)->ComputeLength<double>(
                     CSSToLengthConversionData(/*element=*/nullptr)));

  const CSSValue* value2 =
      ParseValue(property, "maroon", CSSParserLocalContext());
  EXPECT_FALSE(value2);
}

TEST_F(CustomPropertyTest, GetCSSPropertyName) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  EXPECT_EQ(CSSPropertyName(AtomicString("--x")),
            property.GetCSSPropertyName());
}

TEST_F(CustomPropertyTest, SupportsGuaranteedInvalid) {
  RegisterProperty(GetDocument(), "--universal", "*", "foo", true);
  RegisterProperty(GetDocument(), "--no-initial", "*", std::nullopt, true);
  RegisterProperty(GetDocument(), "--length", "<length>", "0px", true);

  CustomProperty unregistered(AtomicString("--unregistered"), GetDocument());
  CustomProperty universal(AtomicString("--universal"), GetDocument());
  CustomProperty no_initial_value(AtomicString("--no-initial"), GetDocument());
  CustomProperty length(AtomicString("--length"), GetDocument());

  EXPECT_TRUE(unregistered.SupportsGuaranteedInvalid());
  EXPECT_TRUE(universal.SupportsGuaranteedInvalid());
  EXPECT_TRUE(no_initial_value.SupportsGuaranteedInvalid());
  EXPECT_FALSE(length.SupportsGuaranteedInvalid());
}

TEST_F(CustomPropertyTest, HasInitialValue) {
  RegisterProperty(GetDocument(), "--universal", "*", "foo", true);
  RegisterProperty(GetDocument(), "--no-initial", "*", std::nullopt, true);
  RegisterProperty(GetDocument(), "--length", "<length>", "0px", true);

  CustomProperty unregistered(AtomicString("--unregistered"), GetDocument());
  CustomProperty universal(AtomicString("--universal"), GetDocument());
  CustomProperty no_initial_value(AtomicString("--no-initial"), GetDocument());
  CustomProperty length(AtomicString("--length"), GetDocument());

  EXPECT_FALSE(unregistered.HasInitialValue());
  EXPECT_TRUE(universal.HasInitialValue());
  EXPECT_FALSE(no_initial_value.HasInitialValue());
  EXPECT_TRUE(length.HasInitialValue());
}

TEST_F(CustomPropertyTest, ParseAnchorQueriesAsLength) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);
  CustomProperty property(AtomicString("--x"), GetDocument());

  // We can't parse anchor queries as a <length>, because it can't be resolved
  // into a pixel value at style time.
  EXPECT_FALSE(
      ParseValue(property, "anchor(--foo top)", CSSParserLocalContext()));
  EXPECT_FALSE(ParseValue(property, "anchor-size(--foo width)",
                          CSSParserLocalContext()));
}

TEST_F(CustomPropertyTest, ParseAnchorQueriesAsLengthPercentage) {
  RegisterProperty(GetDocument(), "--x", "<length-percentage>", "0px", false);
  CustomProperty property(AtomicString("--x"), GetDocument());

  {
    const CSSValue* value =
        ParseValue(property, "anchor(--foo top)", CSSParserLocalContext());
    ASSERT_TRUE(value);
    EXPECT_EQ("anchor(--foo top)", value->CssText());
  }

  {
    const CSSValue* value = ParseValue(property, "anchor-size(--foo width)",
                                       CSSParserLocalContext());
    ASSERT_TRUE(value);
    EXPECT_EQ("anchor-size(--foo width)", value->CssText());
  }

  {
    // There are no restrictions on what anchor queries are allowed in a custom
    // property, so mixing anchor() and anchor-size() is also allowed, although
    // using it in any builtin property via var() makes it invalid at
    // computed-value time.
    const CSSValue* value = ParseValue(
        property, "calc(anchor(--foo top) + anchor-size(--foo width))",
        CSSParserLocalContext());
    ASSERT_TRUE(value);
    EXPECT_EQ("calc(anchor(--foo top) + anchor-size(--foo width))",
              value->CssText());
  }
}

TEST_F(CustomPropertyTest, ValueMode) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  CustomProperty property(AtomicString("--x"), GetDocument());

  CSSVariableData* data = css_test_helpers::CreateVariableData("100px");
  ASSERT_FALSE(data->IsAnimationTainted());
  auto* declaration = MakeGarbageCollected<CSSUnparsedDeclarationValue>(
      data, /* parser_context */ nullptr);

  // ValueMode::kNormal
  {
    StyleResolverState state(GetDocument(), *GetDocument().documentElement(),
                             /* StyleRecalcContext */ nullptr, StyleRequest());
    state.SetStyle(*GetDocument().GetStyleResolver().InitialStyleForElement());
    property.ApplyValue(state, *declaration, CSSProperty::ValueMode::kNormal);
    const ComputedStyle* style = state.TakeStyle();
    ASSERT_TRUE(style->GetVariableData(AtomicString("--x")));
    EXPECT_FALSE(
        style->GetVariableData(AtomicString("--x"))->IsAnimationTainted());
  }

  // ValueMode::kAnimated
  {
    StyleResolverState state(GetDocument(), *GetDocument().documentElement(),
                             /* StyleRecalcContext */ nullptr, StyleRequest());
    state.SetStyle(*GetDocument().GetStyleResolver().InitialStyleForElement());
    property.ApplyValue(state, *declaration, CSSProperty::ValueMode::kAnimated);
    const ComputedStyle* style = state.TakeStyle();
    ASSERT_TRUE(style->GetVariableData(AtomicString("--x")));
    EXPECT_TRUE(
        style->GetVariableData(AtomicString("--x"))->IsAnimationTainted());
  }
}

}  // namespace blink
```