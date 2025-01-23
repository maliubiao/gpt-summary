Response:
Let's break down the thought process to analyze the `css_test_helpers.cc` file.

1. **Understand the Purpose:** The file name itself is a strong clue: `css_test_helpers.cc`. This immediately suggests it's a collection of utility functions specifically designed for testing CSS-related functionality within the Blink rendering engine.

2. **Examine the Includes:**  The included headers provide a wealth of information about the file's capabilities. Let's go through some key ones:
    * `testing/gtest/include/gtest/gtest.h`: This confirms the testing purpose, as `gtest` is a popular C++ testing framework.
    * `third_party/blink/renderer/bindings/core/v8/...`:  These headers indicate interaction with the V8 JavaScript engine's CSSOM bindings. This suggests the helpers are used to test how JavaScript interacts with CSS.
    * `third_party/blink/renderer/core/css/...`:  This is the core of the file's purpose. It includes various CSS-related classes like `CSSRuleList`, `CSSStyleSheet`, `CSSParser`, `CSSSelectorParser`, `CSSPropertyRef`, `PropertyRegistration`, etc. This confirms the file provides tools to create and manipulate these CSS objects for testing.
    * `third_party/blink/renderer/core/dom/document.h`: This suggests the helpers need to create or interact with `Document` objects, which are fundamental to the DOM and rendering.
    * `third_party/blink/renderer/core/execution_context/security_context.h`: Indicates some context related to security, perhaps in the parsing or application of CSS.
    * `third_party/blink/renderer/core/testing/page_test_base.h`:  Further reinforces the testing nature and might provide a base class for more complex tests.

3. **Analyze the Namespace:** The code is within `namespace blink::css_test_helpers`. This clearly demarcates the scope of these utility functions.

4. **Go Through the Functions (Top-Down):** Now, let's examine each function and its purpose:
    * `TestStyleSheet`:  This class likely encapsulates the creation and management of a CSS stylesheet for testing. The destructor and constructor reveal the creation of a `Document` and a `CSSStyleSheet`. `CssRules()` and `GetRuleSet()` provide access to the rules within the stylesheet. `AddCSSRules()` allows adding CSS text to the stylesheet.
    * `CreateStyleSheet`:  A simple function to create an inline `CSSStyleSheet`.
    * `CreateRuleSet`:  Creates a `CSSStyleSheet` and then parses the provided `text` to populate its rules.
    * `CreatePropertyRegistration`, `CreateLengthRegistration`: These functions are for registering custom CSS properties. They take arguments for the property name, syntax, initial value, and inheritance. `CreateLengthRegistration` is a specialized version for length properties.
    * `RegisterProperty` (two overloads): These register CSS properties through the `PropertyRegistry`. One takes an `ExceptionState`, allowing for explicit error handling during testing.
    * `DeclareProperty`: This function simulates declaring a custom property using the `@property` at-rule. This is important for testing the new CSS Custom Properties and Values API.
    * `CreateVariableData`:  Likely creates an object representing a CSS variable (custom property).
    * `CreateCustomIdent`: Creates a CSS `custom-ident` value.
    * `ParseLonghand`: Parses a single value for a specific CSS longhand property. This is essential for testing how individual property values are interpreted.
    * `ParseDeclarationBlock`:  Parses a block of CSS declarations (like `color: red; font-size: 16px;`).
    * `ParseRule`: Parses a complete CSS rule (selector + declaration block).
    * `ParseValue`: Parses a CSS value according to a specified syntax. This is very flexible for testing different value types.
    * `ParseSelectorList` (two overloads): Parses a CSS selector list. The overloads handle different nesting contexts, which are important for advanced CSS features.

5. **Identify Key Functionality Categories:** Based on the function analysis, we can group the functionalities:
    * **Stylesheet Creation and Manipulation:** `TestStyleSheet`, `CreateStyleSheet`, `CreateRuleSet`, `AddCSSRules`.
    * **Custom Property Registration:** `CreatePropertyRegistration`, `CreateLengthRegistration`, `RegisterProperty`, `DeclareProperty`.
    * **Value and Declaration Parsing:** `ParseLonghand`, `ParseDeclarationBlock`, `ParseValue`.
    * **Rule and Selector Parsing:** `ParseRule`, `ParseSelectorList`.
    * **Other CSS Value Creation:** `CreateVariableData`, `CreateCustomIdent`.

6. **Connect to Web Technologies:** Now, think about how these functions relate to JavaScript, HTML, and CSS:
    * **JavaScript:**  The helpers are used to set up CSS states that JavaScript code will then interact with. For example, a test might use `AddCSSRules` to add a rule and then use JavaScript to query the computed style or modify the rule. The V8 binding includes are crucial here.
    * **HTML:**  The `Document` object is the root of the HTML structure. The CSS created by these helpers applies to elements within that document.
    * **CSS:**  This is the core focus. The helpers provide tools to create and parse almost any CSS construct for testing purposes.

7. **Develop Examples and Scenarios:** Think of concrete examples of how these helpers would be used in tests:
    * Testing a CSS property's parsing logic.
    * Testing how a custom property affects the layout.
    * Testing JavaScript's ability to get and set CSS property values.
    * Testing how different selectors match elements.

8. **Consider Error Scenarios:**  Think about common mistakes developers might make or edge cases in CSS that these helpers could be used to test:
    * Invalid CSS syntax.
    * Incorrect custom property syntax.
    * Selectors that don't match any elements.
    * Conflicting CSS rules.

9. **Debugging Perspective:** Imagine you're debugging a CSS issue in Chromium. How could you end up looking at this file?  Likely because you're writing or debugging a *test* related to CSS functionality. The steps to get there would involve navigating the Chromium source code, recognizing the file name's purpose, or being directed to it by a failing test or a colleague.

10. **Structure the Output:** Finally, organize the information clearly, using headings, bullet points, and examples. Start with a general overview of the file's purpose, then detail the functionalities, and connect them to the web technologies. Include examples, error scenarios, and the debugging perspective.
`blink/renderer/core/css/css_test_helpers.cc` 是 Chromium Blink 引擎中的一个源代码文件，它提供了一系列辅助函数和类，专门用于编写和运行 CSS 相关的单元测试。 它的主要目的是简化在 Blink 内部对 CSS 引擎各个方面的测试过程。

以下是该文件的主要功能：

**1. 创建和操作 CSS 样式表 (CSSStyleSheet):**

* **`TestStyleSheet` 类:**  封装了一个用于测试的 CSS 样式表。它包含一个 `Document` 对象和一个 `CSSStyleSheet` 对象，并提供了添加 CSS 规则、获取 CSS 规则列表、获取内部 `RuleSet` 的方法。这使得在隔离的环境中创建和操作样式表变得容易。
    * **功能:**  创建一个临时的、可控的 CSS 样式表，用于测试 CSS 规则的解析、应用和交互。
    * **与 CSS 关系:** 直接操作 CSS 样式表对象，这是 CSS 的核心概念。
    * **假设输入与输出:**
        * **输入:**  创建 `TestStyleSheet` 对象，调用 `AddCSSRules("body { color: red; }")`。
        * **输出:** `CssRules()` 方法将返回一个包含一个 `CSSStyleRule` 对象的 `CSSRuleList`，该规则将选择器设置为 `body`，并将 `color` 属性设置为 `red`。
* **`CreateStyleSheet(Document& document)`:**  创建一个内联的 `CSSStyleSheet` 对象。
    * **功能:**  快速创建一个用于测试的空的内联样式表。
    * **与 CSS 关系:**  创建标准的 CSS 样式表对象。
* **`CreateRuleSet(Document& document, String text)`:**  创建一个 `CSSStyleSheet` 并解析给定的 CSS 文本，返回其内部的 `RuleSet`。
    * **功能:**  创建一个包含特定 CSS 规则的样式表，方便直接访问其内部的规则集合。
    * **与 CSS 关系:**  操作 CSS 样式表和规则集合。
    * **假设输入与输出:**
        * **输入:** `CreateRuleSet(document, ".foo { width: 100px; }")`
        * **输出:** 返回一个 `RuleSet` 对象，其中包含一个选择器为 `.foo`，并且包含 `width: 100px;` 声明的规则。
* **`AddCSSRules(const String& css_text, bool is_empty_sheet)`:** 向 `TestStyleSheet` 对象中添加 CSS 规则。
    * **功能:**  动态地向测试样式表中添加 CSS 规则，用于逐步构建复杂的测试场景。
    * **与 CSS 关系:**  直接修改 CSS 样式表的内容。

**2. 注册和操作 CSS 属性 (CSS Properties):**

* **`CreatePropertyRegistration(...)` 和 `CreateLengthRegistration(...)`:**  创建 `PropertyRegistration` 对象，用于模拟 CSS 自定义属性的注册。
    * **功能:**  允许在测试环境中注册自定义 CSS 属性，以便测试与自定义属性相关的特性。
    * **与 CSS 关系:**  模拟 CSS 自定义属性的注册过程，涉及到 `@property` 规则。
    * **假设输入与输出:**
        * **输入:** `CreatePropertyRegistration("my-color", "<color>", nullptr, true)`
        * **输出:** 返回一个 `PropertyRegistration` 对象，表示名为 `my-color` 的自定义属性，其语法为 `<color>`，没有初始值，并且可以被继承。
* **`RegisterProperty(...)` (两个重载):** 将 `PropertyDefinition` 注册到全局属性注册表中。
    * **功能:**  在测试环境中注册 CSS 属性，包括标准属性和自定义属性。
    * **与 CSS 关系:**  模拟 CSS 属性的注册机制。
* **`DeclareProperty(...)`:**  模拟使用 `@property` 规则声明自定义属性。
    * **功能:**  测试 `@property` 规则的解析和处理逻辑。
    * **与 CSS 关系:**  直接涉及到 CSS 的 `@property` 规则。
    * **假设输入与输出:**
        * **输入:** `DeclareProperty(document, "my-size", "<length>", "10px", false)`
        * **输出:** 将一个名为 `my-size` 的自定义属性注册到 `document` 的属性注册表中，其语法为 `<length>`，初始值为 `10px`，且不可继承。

**3. 解析 CSS 值、声明块和规则:**

* **`ParseLonghand(Document& document, const CSSProperty& property, const String& value)`:**  解析一个 CSS 长属性的值。
    * **功能:**  单独测试特定 CSS 属性值的解析逻辑。
    * **与 CSS 关系:**  直接操作 CSS 属性值。
    * **假设输入与输出:**
        * **输入:** `ParseLonghand(document, CSSProperty::kColor, "red")`
        * **输出:** 返回一个 `CSSPrimitiveValue` 对象，表示颜色 `red`。
* **`ParseDeclarationBlock(const String& block_text, CSSParserMode mode)`:**  解析一个 CSS 声明块（例如：`color: red; font-size: 16px;`）。
    * **功能:**  测试 CSS 声明块的解析逻辑。
    * **与 CSS 关系:**  操作 CSS 声明块，这是 CSS 规则的重要组成部分。
    * **假设输入与输出:**
        * **输入:** `ParseDeclarationBlock("color: blue; font-weight: bold;", kHTMLStandardMode)`
        * **输出:** 返回一个 `CSSPropertyValueSet` 对象，包含 `color: blue` 和 `font-weight: bold` 两个声明。
* **`ParseRule(Document& document, String text)`:**  解析一个完整的 CSS 规则（包括选择器和声明块）。
    * **功能:**  测试 CSS 规则的完整解析逻辑。
    * **与 CSS 关系:**  操作 CSS 规则，这是样式表的基本单元。
    * **假设输入与输出:**
        * **输入:** `ParseRule(document, ".container { width: 50%; }")`
        * **输出:** 返回一个 `StyleRule` 对象，其选择器为 `.container`，并且包含 `width: 50%;` 的声明。
* **`ParseValue(Document& document, String syntax, String value)`:**  根据给定的语法解析 CSS 值。
    * **功能:**  更灵活地测试各种 CSS 值的解析，可以指定预期的语法。
    * **与 CSS 关系:**  操作 CSS 属性值，并可以根据自定义语法进行解析。
    * **假设输入与输出:**
        * **输入:** `ParseValue(document, "<length>", "20px")`
        * **输出:** 返回一个 `CSSPrimitiveValue` 对象，表示长度 `20px`。

**4. 解析 CSS 选择器:**

* **`ParseSelectorList(...)` (两个重载):** 解析 CSS 选择器列表。
    * **功能:**  测试 CSS 选择器的解析逻辑，包括不同类型的选择器和组合。
    * **与 CSS 关系:**  操作 CSS 选择器，用于确定样式规则的应用对象。
    * **假设输入与输出:**
        * **输入:** `ParseSelectorList(".item, #main")`
        * **输出:** 返回一个 `CSSSelectorList` 对象，包含两个选择器：类选择器 `.item` 和 ID 选择器 `#main`。

**5. 创建其他 CSS 相关对象:**

* **`CreateVariableData(String s)`:** 创建 `CSSVariableData` 对象，用于表示 CSS 变量。
    * **功能:**  创建 CSS 变量的内部表示，用于测试与 CSS 变量相关的特性。
    * **与 CSS 关系:**  直接操作 CSS 变量。
* **`CreateCustomIdent(const char* s)`:** 创建 `CSSCustomIdentValue` 对象，用于表示 CSS 的 `<custom-ident>` 类型的值。
    * **功能:**  创建 CSS 自定义标识符，用于测试诸如关键字等场景。
    * **与 CSS 关系:**  操作 CSS 的自定义标识符。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**  测试 JavaScript 如何获取和修改 CSS 样式。例如，可以使用 `TestStyleSheet` 添加 CSS 规则，然后使用 JavaScript 代码获取元素的 `computedStyle` 来验证规则是否生效。
    * **假设输入与输出:**
        * **C++ (使用 `css_test_helpers.cc`):**
          ```c++
          TestStyleSheet sheet;
          sheet.AddCSSRules("body { color: red; }");
          ```
        * **JavaScript (在测试环境中执行):**
          ```javascript
          const body = document.querySelector('body');
          const style = getComputedStyle(body);
          // 期望 style.color 的值为 "rgb(255, 0, 0)"
          ```
* **HTML:**  `css_test_helpers.cc` 中创建的 `Document` 对象是测试 CSS 规则应用的基础。测试可以创建包含特定 HTML 结构的 `Document`，然后使用 `css_test_helpers.cc` 添加 CSS 规则，验证规则是否正确地应用于 HTML 元素。
    * **假设输入与输出:**
        * **C++ (创建包含特定 HTML 的 Document，并使用 `css_test_helpers.cc`):**
          ```c++
          auto document = Document::CreateForTest();
          document->AppendChild(Element::Create(HTMLNames::divTag, document.Get()));
          TestStyleSheet sheet(document);
          sheet.AddCSSRules("div { width: 100px; }");
          // ... 进行布局计算和样式验证 ...
          ```
* **CSS:**  `css_test_helpers.cc` 的核心功能就是为了方便地创建、解析和操作各种 CSS 结构，例如样式表、规则、选择器和属性值。 上面的所有功能点都直接与 CSS 相关。

**逻辑推理的假设输入与输出 (更多例子):**

* **场景: 测试选择器的优先级**
    * **假设输入 (C++):**
      ```c++
      TestStyleSheet sheet;
      sheet.AddCSSRules("body { color: blue; }");
      sheet.AddCSSRules("#my-element { color: red; }");
      // 假设 HTML 中存在 id 为 "my-element" 的元素
      ```
    * **输出 (预期结果):**  当检查 id 为 "my-element" 的元素的计算样式时，`color` 属性的值应该为 `red`，因为 ID 选择器优先级更高。
* **场景: 测试 `@media` 查询**
    * **假设输入 (C++):**
      ```c++
      TestStyleSheet sheet;
      sheet.AddCSSRules("@media (max-width: 600px) { body { font-size: 14px; } }");
      // 模拟视口宽度小于 600px 的情况
      ```
    * **输出 (预期结果):** 在模拟的视口宽度下，`body` 元素的 `font-size` 应该为 `14px`。

**用户或编程常见的使用错误举例:**

* **错误地构建 CSS 字符串:**  在调用 `AddCSSRules` 或其他解析函数时，如果提供的 CSS 字符串存在语法错误，解析过程可能会失败，或者产生意外的结果。
    * **例子:** `sheet.AddCSSRules("body { color: red }");`  (缺少分号)
* **忘记注册自定义属性:**  在使用自定义属性之前，如果没有使用 `RegisterProperty` 或 `DeclareProperty` 进行注册，Blink 可能会将其视为无效属性。
    * **例子:**  在添加使用了未注册的自定义属性的 CSS 规则后，该属性可能不会生效。
* **在错误的 `Document` 上注册属性:**  如果在一个 `Document` 对象上注册了属性，但在另一个 `Document` 上使用了该属性，可能会导致问题，因为属性注册是与特定的 `Document` 关联的。

**用户操作如何一步步的到达这里，作为调试线索:**

假设开发者正在调试一个与 CSS 自定义属性相关的渲染问题：

1. **问题出现:** 用户在网页上看到了一个元素样式不符合预期，怀疑是某个自定义属性没有正确应用。
2. **检查元素:** 开发者使用浏览器开发者工具检查该元素，发现相关的自定义属性的值或者应用方式有问题。
3. **定位代码:** 开发者需要追踪 Blink 引擎中处理该自定义属性的代码。 由于涉及到 CSS 解析和属性注册，开发者可能会查阅与 CSS 相关的代码目录，例如 `blink/renderer/core/css/`。
4. **寻找测试:** 为了理解 Blink 如何处理自定义属性，开发者可能会查看相关的单元测试。 通常，测试代码会使用类似 `css_test_helpers.cc` 这样的辅助文件来简化测试编写。
5. **查看 `css_test_helpers.cc`:** 开发者可能会打开 `css_test_helpers.cc` 文件，查看其中用于注册和操作自定义属性的函数，例如 `CreatePropertyRegistration` 和 `DeclareProperty`，来理解 Blink 内部是如何测试这些特性的。
6. **分析测试用例:**  通过阅读使用了这些辅助函数的测试用例，开发者可以更深入地了解自定义属性的预期行为、解析流程以及可能出现的问题。
7. **调试 Blink 代码:**  如果测试用例没有覆盖到特定的错误场景，开发者可能会需要在 Blink 引擎的源代码中进行更深入的调试，例如查看 `CSSParser` 和 `PropertyRegistry` 的实现。

总而言之，`blink/renderer/core/css/css_test_helpers.cc` 是 Blink 引擎中用于 CSS 单元测试的关键辅助文件，它提供了一系列工具，使得测试 CSS 引擎的各个方面变得更加便捷和高效。 开发者可以通过查看和使用这个文件中的函数来理解 Blink 内部对 CSS 特性的实现和测试方法。

### 提示词
```
这是目录为blink/renderer/core/css/css_test_helpers.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/css_test_helpers.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_css_style_sheet_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_property_definition.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_syntax_definition.h"
#include "third_party/blink/renderer/core/css/css_syntax_string_parser.h"
#include "third_party/blink/renderer/core/css/css_variable_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhand.h"
#include "third_party/blink/renderer/core/css/property_registration.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/rule_set.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

namespace blink {
namespace css_test_helpers {

TestStyleSheet::~TestStyleSheet() = default;

TestStyleSheet::TestStyleSheet() {
  document_ = Document::CreateForTest(execution_context_.GetExecutionContext());
  style_sheet_ = CreateStyleSheet(*document_);
}

CSSRuleList* TestStyleSheet::CssRules() {
  DummyExceptionStateForTesting exception_state;
  CSSRuleList* result = style_sheet_->cssRules(exception_state);
  EXPECT_FALSE(exception_state.HadException());
  return result;
}

RuleSet& TestStyleSheet::GetRuleSet() {
  RuleSet& rule_set = style_sheet_->Contents()->EnsureRuleSet(
      MediaQueryEvaluator(document_->GetFrame()));
  rule_set.CompactRulesIfNeeded();
  return rule_set;
}

void TestStyleSheet::AddCSSRules(const String& css_text, bool is_empty_sheet) {
  unsigned sheet_length = style_sheet_->length();
  style_sheet_->Contents()->ParseString(css_text);
  if (!is_empty_sheet) {
    ASSERT_GT(style_sheet_->length(), sheet_length);
  } else {
    ASSERT_EQ(style_sheet_->length(), sheet_length);
  }
}

CSSStyleSheet* CreateStyleSheet(Document& document) {
  return CSSStyleSheet::CreateInline(
      document, NullURL(), TextPosition::MinimumPosition(), UTF8Encoding());
}

RuleSet* CreateRuleSet(Document& document, String text) {
  DummyExceptionStateForTesting exception_state;
  auto* init = CSSStyleSheetInit::Create();
  auto* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(document.GetFrame());
  auto* sheet = CSSStyleSheet::Create(document, init, exception_state);
  sheet->replaceSync(text, exception_state);
  return &sheet->Contents()->EnsureRuleSet(*media_query_evaluator);
}

PropertyRegistration* CreatePropertyRegistration(const String& name,
                                                 String syntax,
                                                 const CSSValue* initial_value,
                                                 bool is_inherited) {
  auto syntax_definition = CSSSyntaxStringParser(syntax).Parse();
  DCHECK(syntax_definition);
  DCHECK(syntax_definition->IsUniversal() || initial_value);
  return MakeGarbageCollected<PropertyRegistration>(
      AtomicString(name), *syntax_definition, is_inherited, initial_value);
}

PropertyRegistration* CreateLengthRegistration(const String& name, int px) {
  const CSSValue* initial =
      CSSNumericLiteralValue::Create(px, CSSPrimitiveValue::UnitType::kPixels);
  return CreatePropertyRegistration(name, "<length>", initial,
                                    false /* is_inherited */);
}

void RegisterProperty(Document& document,
                      const String& name,
                      const String& syntax,
                      const std::optional<String>& initial_value,
                      bool is_inherited) {
  DummyExceptionStateForTesting exception_state;
  RegisterProperty(document, name, syntax, initial_value, is_inherited,
                   exception_state);
  ASSERT_FALSE(exception_state.HadException());
}

void RegisterProperty(Document& document,
                      const String& name,
                      const String& syntax,
                      const std::optional<String>& initial_value,
                      bool is_inherited,
                      ExceptionState& exception_state) {
  DCHECK(!initial_value || !initial_value.value().IsNull());
  PropertyDefinition* property_definition = PropertyDefinition::Create();
  property_definition->setName(name);
  property_definition->setSyntax(syntax);
  property_definition->setInherits(is_inherited);
  if (initial_value) {
    property_definition->setInitialValue(initial_value.value());
  }
  PropertyRegistration::registerProperty(document.GetExecutionContext(),
                                         property_definition, exception_state);
}

void DeclareProperty(Document& document,
                     const String& name,
                     const String& syntax,
                     const std::optional<String>& initial_value,
                     bool is_inherited) {
  StringBuilder builder;
  builder.Append("@property ");
  builder.Append(name);
  builder.Append(" { ");

  // syntax:
  builder.Append("syntax:\"");
  builder.Append(syntax);
  builder.Append("\";");

  // initial-value:
  if (initial_value.has_value()) {
    builder.Append("initial-value:");
    builder.Append(initial_value.value());
    builder.Append(";");
  }

  // inherits:
  builder.Append("inherits:");
  builder.Append(is_inherited ? "true" : "false");
  builder.Append(";");

  builder.Append(" }");

  auto* rule =
      DynamicTo<StyleRuleProperty>(ParseRule(document, builder.ToString()));
  if (!rule) {
    return;
  }
  auto* registration = PropertyRegistration::MaybeCreateForDeclaredProperty(
      document, AtomicString(name), *rule);
  if (!registration) {
    return;
  }
  document.EnsurePropertyRegistry().DeclareProperty(AtomicString(name),
                                                    *registration);
  document.GetStyleEngine().PropertyRegistryChanged();
}

CSSVariableData* CreateVariableData(String s) {
  bool is_animation_tainted = false;
  bool needs_variable_resolution = false;
  return CSSVariableData::Create(s, is_animation_tainted,
                                 needs_variable_resolution);
}

const CSSValue* CreateCustomIdent(const char* s) {
  return MakeGarbageCollected<CSSCustomIdentValue>(AtomicString(s));
}

const CSSValue* ParseLonghand(Document& document,
                              const CSSProperty& property,
                              const String& value) {
  const auto* longhand = DynamicTo<Longhand>(property);
  if (!longhand) {
    return nullptr;
  }

  const auto* context = MakeGarbageCollected<CSSParserContext>(document);
  CSSParserLocalContext local_context;

  CSSParserTokenStream stream(value);
  return longhand->ParseSingleValue(stream, *context, local_context);
}

const CSSPropertyValueSet* ParseDeclarationBlock(const String& block_text,
                                                 CSSParserMode mode) {
  auto* set = MakeGarbageCollected<MutableCSSPropertyValueSet>(mode);
  set->ParseDeclarationList(block_text, SecureContextMode::kSecureContext,
                            nullptr);
  return set;
}

StyleRuleBase* ParseRule(Document& document, String text) {
  auto* sheet = CSSStyleSheet::CreateInline(
      document, NullURL(), TextPosition::MinimumPosition(), UTF8Encoding());
  const auto* context = MakeGarbageCollected<CSSParserContext>(document);
  return CSSParser::ParseRule(context, sheet->Contents(), CSSNestingType::kNone,
                              /*parent_rule_for_nesting=*/nullptr,
                              /*is_within_scope=*/false, text);
}

const CSSValue* ParseValue(Document& document, String syntax, String value) {
  auto syntax_definition = CSSSyntaxStringParser(syntax).Parse();
  if (!syntax_definition.has_value()) {
    return nullptr;
  }
  const auto* context = MakeGarbageCollected<CSSParserContext>(document);
  return syntax_definition->Parse(value, *context,
                                  /* is_animation_tainted */ false);
}

CSSSelectorList* ParseSelectorList(const String& string) {
  return ParseSelectorList(string, CSSNestingType::kNone,
                           /*parent_rule_for_nesting=*/nullptr,
                           /*is_within_scope=*/false);
}

CSSSelectorList* ParseSelectorList(const String& string,
                                   CSSNestingType nesting_type,
                                   const StyleRule* parent_rule_for_nesting,
                                   bool is_within_scope) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserTokenStream stream(string);
  HeapVector<CSSSelector> arena;
  base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
      stream, context, nesting_type, parent_rule_for_nesting, is_within_scope,
      /* semicolon_aborts_nested_selector */ false, sheet, arena);
  return CSSSelectorList::AdoptSelectorVector(vector);
}

}  // namespace css_test_helpers
}  // namespace blink
```