Response:
Let's break down the thought process for analyzing the `css_property_test.cc` file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ source code file (`css_property_test.cc`) and explain its purpose, its relationship to web technologies (HTML, CSS, JavaScript), provide examples, and offer debugging insights.

2. **Initial Scan for Keywords:**  A quick skim reveals keywords like "CSSProperty", "TEST_F", "Parse", "ComputedValue", "OriginTrial", "Anchor", etc. These immediately suggest the file is about testing CSS property functionality within the Blink rendering engine. The `TEST_F` macro points to the use of Google Test for unit testing.

3. **Identify Core Functionality:**
    * **Parsing CSS:**  The `Parse` and `ParseShorthand` functions indicate the ability to take CSS property names and values (as strings) and convert them into internal Blink representations (`CSSValue`, `CSSPropertyValueSet`). This is fundamental to how the browser understands and applies CSS.
    * **Computing Styles:** The `ComputedValue` function is crucial. It simulates the process of calculating the final computed value of a CSS property based on a given input value and style context. This involves style resolution and building.
    * **Testing Framework:** The `TEST_F` macros define individual test cases, each focusing on a specific aspect of CSS property behavior. This is standard unit testing practice.

4. **Analyze Individual Test Cases (Grouping by Functionality):**  Go through the test cases and group them conceptually:

    * **Basic Property Attributes:**  Tests like `VisitedPropertiesAreNotWebExposed`, `GetVisitedPropertyOnlyReturnsVisitedProperties`, `GetUnvisitedPropertyFromVisited`, `InternalFontSizeDeltaNotWebExposed` are checking basic boolean flags and relationships between regular and visited properties.

    * **Parsing and Value Handling:** `VisitedPropertiesCanParseValues`, `Surrogates`, `PairsWithIdenticalValues` test how CSS values are parsed and handled, including special cases like visited states and shorthand property surrogates.

    * **Origin Trials:** `OriginTrialTestProperty` and `OriginTrialTestPropertyWithContext` specifically address how CSS properties interact with the Origin Trials mechanism, which allows for experimental features.

    * **Alternative Properties:** `AlternativePropertyData`, `AlternativePropertyExposure`, `AlternativePropertySingle`, `AlternativePropertyCycle` focus on the concept of alternative CSS properties (like `-webkit-`) and ensure their consistency and correct relationships.

    * **Anchor Positioning:** The series of `AnchorMode*` tests (Top, Right, Bottom, Left, Width, Height) is dedicated to testing the functionality of CSS anchor positioning, a newer CSS feature. These tests likely verify how `anchor()` and `anchor-size()` functions compute values based on different anchor modes.

    * **Feature Flags:** `AnchorSizeInsetsMarginsDisabled` checks behavior when a specific feature flag (`CSSAnchorSizeInsetsMargins`) is disabled.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**

    * **CSS:** The entire file is about testing CSS properties. Give concrete examples of CSS properties being tested (e.g., `top`, `width`, `border-radius`, `-webkit-writing-mode`).
    * **HTML:** The tests operate within a simulated HTML document environment (`PageTestBase`, `GetDocument()`, `GetDocument().body()`). Explain that CSS is applied to HTML elements.
    * **JavaScript:**  Mention how JavaScript can interact with CSS properties (getting and setting styles). While this file doesn't *directly* test JS interaction, it tests the underlying CSS property logic that JS would rely on.

6. **Infer Logical Reasoning and Provide Examples:**

    * **Property Relationships (Visited/Unvisited):** If a property is visited, it should have a corresponding unvisited version, and vice-versa.
    * **Alternative Properties:**  The alternative property should have the same web-facing name as the main property but might have different exposure rules.
    * **Anchor Positioning:** The `AnchorMode*` tests demonstrate how the `anchor()` function evaluates to different values for properties like `top`, `left`, `width`, etc., depending on the specified anchor mode. Create a simple HTML/CSS example to illustrate the concept.

7. **Identify Potential User/Programming Errors:**

    * **Incorrect CSS Syntax:**  Show an example of invalid CSS that would fail parsing.
    * **Typos in Property Names:**  Illustrate how a simple typo can lead to styles not being applied.
    * **Misunderstanding Anchor Functions:** Explain common mistakes when using `anchor()` and `anchor-size()`, like incorrect mode specification.

8. **Debug Clues (User Actions):** Think about how a developer might end up needing to investigate this code. This involves tracing user interactions that lead to CSS being parsed and applied:

    * **Loading a webpage:** The browser parses the HTML and CSS.
    * **Applying stylesheets:**  CSS rules are matched to HTML elements.
    * **Dynamic CSS changes:** JavaScript can modify styles.
    * **Inspecting styles in DevTools:** Developers might notice unexpected computed values and want to understand why.

9. **Structure and Refine:** Organize the information logically with clear headings and examples. Use precise language and avoid jargon where possible (or explain it). Review for clarity and completeness. Ensure the examples are easy to understand and directly relate to the code's functionality.

10. **Self-Correction/Refinement during the process:**
    * Initially, I might focus too heavily on the C++ specifics. I need to constantly remind myself to connect it back to the web technologies and user experience.
    * I might initially misunderstand the purpose of some tests. Rereading the test names and the code within the test helps clarify the intent.
    *  The `SurrogateFor` tests might seem abstract initially. Realizing they are about how properties behave differently in different writing modes provides context.
    *  Ensuring the examples are *concrete* and not just abstract descriptions is important. Showing actual CSS syntax makes the explanation much clearer.
好的，让我们来分析一下 `blink/renderer/core/css/properties/css_property_test.cc` 这个文件。

**文件功能总览**

`css_property_test.cc` 是 Chromium Blink 渲染引擎中负责测试 CSS 属性相关功能的单元测试文件。它使用 Google Test 框架来验证 `blink::CSSProperty` 类及其相关类的行为是否符合预期。

更具体地说，这个文件测试了以下几个方面：

1. **`CSSProperty` 类的基本属性和方法:**  例如，属性是否是 visited 状态的、是否暴露给 Web 开发者、是否是内部使用的等等。
2. **CSS 属性的解析:** 验证能否正确解析各种 CSS 属性值，包括长属性和简写属性。
3. **CSS 属性的计算值:**  测试在特定条件下，CSS 属性的计算值是否正确。这涉及到样式解析、层叠和继承等过程。
4. **CSS 属性的别名 (Surrogates) 和替代属性 (Alternatives):** 测试在不同上下文 (例如，书写模式) 下，CSS 属性的别名机制是否正常工作，以及替代属性之间的关系。
5. **与 Origin Trials 的集成:** 验证 CSS 属性是否正确地受到 Origin Trials 特性的影响，从而控制其是否暴露给 Web 开发者。
6. **新的 CSS 特性测试:**  特别是测试了 CSS 锚点定位 (Anchor Positioning) 的相关功能，例如 `anchor()` 和 `anchor-size()` 函数的计算。
7. **Feature Flag 的影响:** 测试特定 Feature Flag 的启用或禁用对 CSS 属性行为的影响。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个测试文件直接关系到 CSS 的功能，因为它的核心是测试 `CSSProperty` 类的行为，而 `CSSProperty` 类代表了 CSS 属性在 Blink 引擎中的抽象。

* **CSS:**  文件中大量的测试用例都在验证各种 CSS 属性的解析和计算。例如：
    * `TEST_F(CSSPropertyTest, PairsWithIdenticalValues)` 测试了 `border-top-left-radius` 和 `perspective-origin` 属性在处理相同值时的差异 (前者会缩写，后者不会)。 这直接关系到 CSS 值的序列化和反序列化。
    * `TEST_F(CSSPropertyTest, AnchorModeTop)` 等一系列 `AnchorMode` 测试用例，验证了 CSS 锚点定位功能中 `anchor()` 函数在不同模式下的计算结果。这直接关联到开发者在 CSS 中使用 `anchor()` 函数实现元素相对于锚点元素的定位。

    **例子 (CSS):**
    ```css
    /* 使用 anchor() 函数进行定位 */
    #target {
      position: absolute;
      top: anchor(--my-anchor, top);
      left: anchor(--my-anchor, left);
    }

    #anchor {
      --my-anchor: this();
      position: absolute;
      top: 100px;
      left: 100px;
      width: 50px;
      height: 50px;
    }
    ```
    `css_property_test.cc` 中的 `AnchorModeTop` 测试用例会验证当 `--my-anchor` 的锚点模式为 `top` 时，`#target` 的 `top` 属性计算值是否正确。

* **HTML:**  虽然这个测试文件本身不直接操作 HTML 元素，但它模拟了样式计算的环境，这些样式最终会应用到 HTML 元素上。例如，`ComputedValue` 函数内部会创建 `HTMLElement` 实例，并模拟样式解析和应用的过程。

    **例子 (HTML):**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        #myElement {
          width: 100px;
        }
      </style>
    </head>
    <body>
      <div id="myElement"></div>
    </body>
    </html>
    ```
    虽然 `css_property_test.cc` 不会直接创建这个 HTML 结构，但它会测试像 `width: 100px;` 这样的 CSS 规则如何被解析和计算。

* **JavaScript:** JavaScript 可以通过 DOM API (如 `element.style`) 来获取和设置 CSS 属性。`css_property_test.cc` 确保了 CSS 属性在 Blink 引擎内部的行为是正确的，这直接影响到 JavaScript 操作 CSS 的结果。

    **例子 (JavaScript):**
    ```javascript
    const element = document.getElementById('myElement');
    console.log(element.style.width); // 获取元素的 width 样式
    element.style.backgroundColor = 'red'; // 设置元素的背景颜色
    ```
    如果 `css_property_test.cc` 中关于 `width` 属性的测试失败，可能意味着 JavaScript 通过 `element.style.width` 获取到的值是不正确的，或者设置 `backgroundColor` 的行为与预期不符。

**逻辑推理的假设输入与输出**

让我们以 `TEST_F(CSSPropertyTest, AnchorModeTop)` 这个测试用例为例进行逻辑推理：

**假设输入:**

* CSS 属性: `top`
* CSS 值: `"anchor(top, 0px)"`
* `AnchorEvaluator` 的模式: `AnchorScope::Mode::kTop`

**逻辑推理过程:**

这个测试用例创建了一个 `ModeCheckingAnchorEvaluator` 实例，并将其模式设置为 `kTop`。然后，它调用 `ComputedValue` 函数来计算 `top` 属性的值。`ComputedValue` 函数会模拟样式解析和计算的过程。由于 `AnchorEvaluator` 的模式是 `kTop`，当计算 `anchor(top, 0px)` 时，`AnchorEvaluator::Evaluate` 方法会返回 `std::optional<LayoutUnit>(1)` (转换为 "1px")。

**预期输出:**

`"1px"`

**另一个例子，`TEST_F(CSSPropertyTest, PairsWithIdenticalValues)`:**

**假设输入:**

* CSS 属性: `border-top-left-radius`
* CSS 值: `"1% 1%"`

**逻辑推理过程:**

测试用例调用 `css_test_helpers::ParseLonghand` 解析 `border-top-left-radius: 1% 1%`。由于 `border-top-left-radius` 属性在两个值相同时会进行缩写。

**预期输出:**

`"1%"`

**假设输入:**

* CSS 属性: `perspective-origin`
* CSS 值: `"1% 1%"`

**逻辑推理过程:**

测试用例调用 `css_test_helpers::ParseLonghand` 解析 `perspective-origin: 1% 1%`。`perspective-origin` 属性即使两个值相同也不会进行缩写。

**预期输出:**

`"1% 1%"`

**用户或编程常见的使用错误举例说明**

1. **CSS 语法错误:**
   * **错误输入 (CSS):**  `element.style.widht = '100px';` (拼写错误，`width` 拼成了 `widht`)
   * **结果:**  样式不会生效，或者会被浏览器忽略。`css_property_test.cc` 中的解析测试可以帮助发现这种拼写错误导致的解析失败。

2. **使用了不被支持的 CSS 属性或值:**
   * **错误输入 (CSS):** `element.style.nonExistentProperty = 'someValue';`
   * **结果:**  样式不会生效。`css_property_test.cc` 中会测试哪些属性是有效或无效的。

3. **误解了 CSS 属性的计算方式:**
   * **错误输入 (JavaScript):** 假设一个元素的 `width` 是 `auto`，然后期望通过 JavaScript 读取到的 `element.style.width` 是一个具体的像素值。
   * **结果:**  `element.style.width` 可能返回空字符串或者 "auto"，而不是计算后的像素值。开发者需要使用 `getComputedStyle` 来获取计算后的值。`css_property_test.cc` 中的 `ComputedValue` 测试确保了在各种情况下，计算值是正确的。

4. **错误地使用了需要特定 Feature Flag 才能启用的 CSS 属性:**
   * **错误输入 (CSS):** 使用了某个实验性的 CSS 属性，但用户的浏览器没有启用相应的 Feature Flag。
   * **结果:**  样式不会生效。`css_property_test.cc` 中关于 Origin Trials 的测试确保了这些属性在 Feature Flag 未启用时不会暴露。

**用户操作是如何一步步到达这里的 (调试线索)**

通常，开发者不会直接接触到 `css_property_test.cc` 这个文件，除非他们正在参与 Chromium 或 Blink 引擎的开发或调试。以下是一些可能导致开发者查看或调试这个文件的场景：

1. **Web 开发者报告了 CSS 行为的 Bug:**
   * 用户在浏览器中访问一个网页，发现某个 CSS 属性的行为不符合预期 (例如，锚点定位没有正确工作，或者某个属性的计算值不正确)。
   * Web 开发者会尝试简化问题，编写最小化的 HTML/CSS 代码来复现 Bug。
   * Chromium 开发者会根据这个复现步骤，尝试在 Blink 引擎中找到问题的根源。他们可能会怀疑是某个 CSS 属性的实现有问题，因此会查看相关的测试文件，例如 `css_property_test.cc`，看是否已有的测试覆盖了这种情况，或者需要添加新的测试来暴露 Bug。

2. **Blink 引擎的新功能开发或 Bug 修复:**
   * 当 Chromium 开发者实现一个新的 CSS 特性 (例如，新的锚点定位功能) 或修复一个与 CSS 相关的 Bug 时，他们需要编写单元测试来验证代码的正确性。
   * 他们会在 `css_property_test.cc` 或类似的文件中添加新的 `TEST_F` 用例，来覆盖新功能或 Bug 修复的各种场景。

3. **性能分析和优化:**
   * 如果在渲染过程中发现 CSS 属性的计算存在性能问题，开发者可能会分析相关的代码，并查看测试文件以了解其覆盖范围，确保优化不会引入新的 Bug。

4. **代码审查:**
   * 在代码提交到 Chromium 代码库之前，其他开发者会进行代码审查。他们可能会查看 `css_property_test.cc` 文件，以确保新添加或修改的代码有充分的测试覆盖。

**调试线索步骤:**

1. **用户报告或开发者发现 CSS 渲染问题。**
2. **开发者尝试使用浏览器开发者工具 (如 Chrome DevTools) 分析问题，查看元素的样式和计算值。**
3. **如果问题涉及到特定的 CSS 属性，开发者可能会搜索 Blink 源代码中与该属性相关的代码。**
4. **开发者会找到 `blink/renderer/core/css/properties/css_property.cc` (实现文件) 和 `blink/renderer/core/css/properties/css_property_test.cc` (测试文件)。**
5. **开发者会查看 `css_property_test.cc` 中是否有相关的测试用例覆盖了出现问题的场景。**
6. **如果已有测试未覆盖，开发者可能会添加新的测试用例来复现 Bug。**
7. **运行测试，如果新添加的测试失败，开发者会着手修复 `css_property.cc` 中的代码。**
8. **修复代码后，重新运行测试，确保所有测试都通过。**

总而言之，`css_property_test.cc` 是 Blink 引擎中一个至关重要的测试文件，它确保了 CSS 属性的各种功能按照规范正确运行，从而保证了 Web 页面的正常渲染和用户体验。对于 Web 开发者来说，理解这些测试背后的原理，可以帮助他们更好地理解 CSS 的工作方式，并避免一些常见的错误。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/css_property_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/properties/css_property.h"

#include <cstring>

#include "base/memory/values_equivalent.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/origin_trials/origin_trial_feature.mojom-shared.h"
#include "third_party/blink/renderer/core/css/anchor_evaluator.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/properties/css_bitset.h"
#include "third_party/blink/renderer/core/css/properties/css_property_instances.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

namespace {

// Evaluates any query to '1' when it's in the expected mode,
// otherwise std::nullopt.
class ModeCheckingAnchorEvaluator : public AnchorEvaluator {
  STACK_ALLOCATED();

 public:
  explicit ModeCheckingAnchorEvaluator(AnchorScope::Mode required_mode)
      : required_mode_(required_mode) {}

  std::optional<LayoutUnit> Evaluate(
      const AnchorQuery&,
      const ScopedCSSName* position_anchor,
      const std::optional<PositionAreaOffsets>&) override {
    return (required_mode_ == GetMode()) ? std::optional<LayoutUnit>(1)
                                         : std::optional<LayoutUnit>();
  }

  std::optional<PositionAreaOffsets> ComputePositionAreaOffsetsForLayout(
      const ScopedCSSName*,
      PositionArea) override {
    return std::nullopt;
  }
  std::optional<PhysicalOffset> ComputeAnchorCenterOffsets(
      const ComputedStyleBuilder& builder) override {
    return std::nullopt;
  }

 private:
  AnchorScope::Mode required_mode_;
};

}  // namespace

class CSSPropertyTest : public PageTestBase {
 public:
  const CSSValue* Parse(String name, String value) {
    const CSSPropertyValueSet* set =
        css_test_helpers::ParseDeclarationBlock(name + ":" + value);
    DCHECK(set);
    if (set->PropertyCount() != 1) {
      return nullptr;
    }
    return &set->PropertyAt(0).Value();
  }

  const CSSPropertyValueSet* ParseShorthand(String name, String value) {
    return css_test_helpers::ParseDeclarationBlock(name + ":" + value);
  }

  String ComputedValue(String property_str,
                       String value_str,
                       StyleRecalcContext style_recalc_context) {
    CSSPropertyRef ref(property_str, GetDocument());
    CHECK(ref.IsValid());
    const CSSProperty& property = ref.GetProperty();

    const CSSValue* value =
        css_test_helpers::ParseLonghand(GetDocument(), property, value_str);
    CHECK(value);
    // Any tree-scoped references within `result` need to be populated with
    // their TreeScope. This is normally done by StyleCascade before length
    // conversion, and we're simulating that here.
    value = &value->EnsureScopedValue(&GetDocument());

    StyleResolverState state(GetDocument(), *GetDocument().body(),
                             &style_recalc_context);
    state.SetStyle(GetDocument().GetStyleResolver().InitialStyle());

    StyleBuilder::ApplyProperty(property, state, *value);
    const ComputedStyle* style = state.TakeStyle();
    CHECK(style);

    const CSSValue* computed_value = property.CSSValueFromComputedStyle(
        *style,
        /* layout_object */ nullptr,
        /* allow_visited_style */ true, CSSValuePhase::kComputedValue);
    CHECK(computed_value);

    return computed_value->CssText();
  }

  const ExecutionContext* GetExecutionContext() const {
    return GetDocument().GetExecutionContext();
  }
};

TEST_F(CSSPropertyTest, VisitedPropertiesAreNotWebExposed) {
  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    EXPECT_TRUE(!property.IsVisited() ||
                !property.IsWebExposed(GetDocument().GetExecutionContext()));
  }
}

TEST_F(CSSPropertyTest, GetVisitedPropertyOnlyReturnsVisitedProperties) {
  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    const CSSProperty* visited = property.GetVisitedProperty();
    EXPECT_TRUE(!visited || visited->IsVisited());
  }
}

TEST_F(CSSPropertyTest, GetUnvisitedPropertyFromVisited) {
  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    EXPECT_EQ(property.IsVisited(),
              static_cast<bool>(property.GetUnvisitedProperty()));
  }
}

TEST_F(CSSPropertyTest, InternalFontSizeDeltaNotWebExposed) {
  ASSERT_FALSE(
      CSSProperty::Get(CSSPropertyID::kInternalFontSizeDelta).IsWebExposed());
}

TEST_F(CSSPropertyTest, VisitedPropertiesCanParseValues) {
  const ComputedStyle& initial_style =
      GetDocument().GetStyleResolver().InitialStyle();

  // Count the number of 'visited' properties seen.
  size_t num_visited = 0;

  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    const CSSProperty* visited = property.GetVisitedProperty();
    if (!visited) {
      continue;
    }

    // Get any value compatible with 'property'. The initial value will do.
    const CSSValue* initial_value = property.CSSValueFromComputedStyle(
        initial_style, nullptr /* layout_object */,
        false /* allow_visited_style */, CSSValuePhase::kComputedValue);
    ASSERT_TRUE(initial_value);

    // Parse the initial value using both the regular property, and the
    // accompanying 'visited' property.
    const CSSValue* parsed_regular_value = css_test_helpers::ParseLonghand(
        GetDocument(), property, initial_value->CssText());
    const CSSValue* parsed_visited_value = css_test_helpers::ParseLonghand(
        GetDocument(), *visited, initial_value->CssText());

    // The properties should have identical parsing behavior.
    EXPECT_TRUE(
        base::ValuesEquivalent(parsed_regular_value, parsed_visited_value));

    num_visited++;
  }

  // Verify that we have seen at least one visited property. If we didn't (and
  // there is no bug), it means this test can be removed.
  EXPECT_GT(num_visited, 0u);
}

TEST_F(CSSPropertyTest, Surrogates) {
  // NOTE: The downcast here is to go through the CSSProperty vtable,
  // so that we don't have to mark these functions as CORE_EXPORT only for
  // the test.
  const CSSProperty& inline_size = GetCSSPropertyInlineSize();
  const CSSProperty& writing_mode = GetCSSPropertyWebkitWritingMode();
  const WritingDirectionMode kHorizontalLtr = {WritingMode::kHorizontalTb,
                                               TextDirection::kLtr};
  EXPECT_EQ(&GetCSSPropertyWidth(), inline_size.SurrogateFor(kHorizontalLtr));
  EXPECT_EQ(&GetCSSPropertyHeight(),
            inline_size.SurrogateFor(
                {WritingMode::kVerticalRl, TextDirection::kLtr}));
  EXPECT_EQ(&GetCSSPropertyWritingMode(),
            writing_mode.SurrogateFor(kHorizontalLtr));
  EXPECT_FALSE(GetCSSPropertyWidth().SurrogateFor(kHorizontalLtr));
}

TEST_F(CSSPropertyTest, PairsWithIdenticalValues) {
  const CSSValue* border_radius = css_test_helpers::ParseLonghand(
      GetDocument(), GetCSSPropertyBorderTopLeftRadius(), "1% 1%");
  const CSSValue* perspective_origin = css_test_helpers::ParseLonghand(
      GetDocument(), GetCSSPropertyPerspectiveOrigin(), "1% 1%");

  // Border radius drops identical values
  EXPECT_EQ("1%", border_radius->CssText());
  // Perspective origin keeps identical values
  EXPECT_EQ("1% 1%", perspective_origin->CssText());
  // Therefore, the values are different
  EXPECT_NE(*border_radius, *perspective_origin);
}

TEST_F(CSSPropertyTest, StaticVariableInstanceFlags) {
  EXPECT_FALSE(GetCSSPropertyVariable().IsShorthand());
  EXPECT_FALSE(GetCSSPropertyVariable().IsRepeated());
}

TEST_F(CSSPropertyTest, OriginTrialTestProperty) {
  const CSSProperty& property = GetCSSPropertyOriginTrialTestProperty();

  {
    ScopedOriginTrialsSampleAPIForTest scoped_feature(false);

    EXPECT_FALSE(property.IsWebExposed());
    EXPECT_FALSE(property.IsUAExposed());
    EXPECT_EQ(CSSExposure::kNone, property.Exposure());
  }

  {
    ScopedOriginTrialsSampleAPIForTest scoped_feature(true);

    EXPECT_TRUE(property.IsWebExposed());
    EXPECT_TRUE(property.IsUAExposed());
    EXPECT_EQ(CSSExposure::kWeb, property.Exposure());
  }
}

TEST_F(CSSPropertyTest, OriginTrialTestPropertyWithContext) {
  const CSSProperty& property = GetCSSPropertyOriginTrialTestProperty();

  // Origin trial not enabled:
  EXPECT_FALSE(property.IsWebExposed(GetExecutionContext()));
  EXPECT_FALSE(property.IsUAExposed(GetExecutionContext()));
  EXPECT_EQ(CSSExposure::kNone, property.Exposure(GetExecutionContext()));

  // Enable it:
  LocalDOMWindow* window = GetFrame().DomWindow();
  OriginTrialContext* context = window->GetOriginTrialContext();
  context->AddFeature(mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI);

  // Context-aware exposure functions should now report the property as
  // exposed.
  EXPECT_TRUE(property.IsWebExposed(GetExecutionContext()));
  EXPECT_TRUE(property.IsUAExposed(GetExecutionContext()));
  EXPECT_EQ(CSSExposure::kWeb, property.Exposure(GetExecutionContext()));

  // Context-agnostic exposure functions should still report kNone:
  EXPECT_FALSE(property.IsWebExposed());
  EXPECT_FALSE(property.IsUAExposed());
  EXPECT_EQ(CSSExposure::kNone, property.Exposure());
}

TEST_F(CSSPropertyTest, AlternativePropertyData) {
  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    // TODO(pdr): Remove this IsPropertyAlias check, and properly handle aliases
    // in this test.
    if (CSSPropertyID alternative_id = property.GetAlternative();
        alternative_id != CSSPropertyID::kInvalid &&
        !IsPropertyAlias(alternative_id)) {
      SCOPED_TRACE(property.GetPropertyName());

      const CSSProperty& alternative = CSSProperty::Get(alternative_id);

      // The web-facing names of a alternative must be equal to that of the main
      // property.
      EXPECT_EQ(property.GetPropertyNameAtomicString(),
                alternative.GetPropertyNameAtomicString());
      EXPECT_EQ(property.GetPropertyNameString(),
                alternative.GetPropertyNameString());
      EXPECT_EQ(std::strcmp(property.GetPropertyName(),
                            alternative.GetPropertyName()),
                0);
      EXPECT_EQ(std::strcmp(property.GetJSPropertyName(),
                            alternative.GetJSPropertyName()),
                0);

      // Alternative properties should should also use the same CSSSampleId.
      EXPECT_EQ(GetCSSSampleId(property_id), GetCSSSampleId(alternative_id));
    }
  }
}

TEST_F(CSSPropertyTest, AlternativePropertyExposure) {
  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    // TODO(pdr): Remove this call to `ResolveCSSPropertyID` by properly
    // handling aliases in this test.
    if (CSSPropertyID alternative_id =
            ResolveCSSPropertyID(property.GetAlternative());
        alternative_id != CSSPropertyID::kInvalid) {
      SCOPED_TRACE(property.GetPropertyName());

      const CSSProperty& alternative = CSSProperty::Get(alternative_id);

      bool property_exposed = property.Exposure() != CSSExposure::kNone;
      bool alternative_exposed = alternative.Exposure() != CSSExposure::kNone;

      // If the alternative is exposed, the main property can not be exposed.
      EXPECT_TRUE(alternative_exposed ? !property_exposed : true);
    }
  }
}

TEST_F(CSSPropertyTest, AlternativePropertySingle) {
  CSSBitset seen_properties;

  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    if (property.GetAlternative() != CSSPropertyID::kInvalid) {
      SCOPED_TRACE(property.GetPropertyName());

      // A alternative is only pointed to from a single property.
      ASSERT_FALSE(seen_properties.Has(property_id));
      seen_properties.Set(property_id);
    }
  }
}

TEST_F(CSSPropertyTest, AlternativePropertyCycle) {
  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    SCOPED_TRACE(property.GetPropertyName());

    // Verify that alternative properties aren't cyclic.
    CSSBitset seen_properties;
    for (CSSPropertyID current_id = property_id;
         current_id != CSSPropertyID::kInvalid;
         // TODO(pdr): Remove this call to `ResolveCSSPropertyID` by properly
         // handling aliases in this test.
         current_id = ResolveCSSPropertyID(
             CSSProperty::Get(current_id).GetAlternative())) {
      ASSERT_FALSE(seen_properties.Has(current_id));
      seen_properties.Set(current_id);
    }
  }
}

TEST_F(CSSPropertyTest, AnchorModeTop) {
  ModeCheckingAnchorEvaluator anchor_evaluator(AnchorScope::Mode::kTop);
  StyleRecalcContext context = {.anchor_evaluator = &anchor_evaluator};

  EXPECT_EQ("1px", ComputedValue("top", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("right", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("bottom", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("left", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-height", "anchor-size(width, 0px)", context));
}

TEST_F(CSSPropertyTest, AnchorModeRight) {
  ModeCheckingAnchorEvaluator anchor_evaluator(AnchorScope::Mode::kRight);
  StyleRecalcContext context = {.anchor_evaluator = &anchor_evaluator};

  EXPECT_EQ("0px", ComputedValue("top", "anchor(top, 0px)", context));
  EXPECT_EQ("1px", ComputedValue("right", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("bottom", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("left", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-height", "anchor-size(width, 0px)", context));
}

TEST_F(CSSPropertyTest, AnchorModeBottom) {
  ModeCheckingAnchorEvaluator anchor_evaluator(AnchorScope::Mode::kBottom);
  StyleRecalcContext context = {.anchor_evaluator = &anchor_evaluator};

  EXPECT_EQ("0px", ComputedValue("top", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("right", "anchor(top, 0px)", context));
  EXPECT_EQ("1px", ComputedValue("bottom", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("left", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-height", "anchor-size(width, 0px)", context));
}

TEST_F(CSSPropertyTest, AnchorModeLeft) {
  ModeCheckingAnchorEvaluator anchor_evaluator(AnchorScope::Mode::kLeft);
  StyleRecalcContext context = {.anchor_evaluator = &anchor_evaluator};

  EXPECT_EQ("0px", ComputedValue("top", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("right", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("bottom", "anchor(top, 0px)", context));
  EXPECT_EQ("1px", ComputedValue("left", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-height", "anchor-size(width, 0px)", context));
}

TEST_F(CSSPropertyTest, AnchorModeWidth) {
  ModeCheckingAnchorEvaluator anchor_evaluator(AnchorScope::Mode::kWidth);
  StyleRecalcContext context = {.anchor_evaluator = &anchor_evaluator};

  EXPECT_EQ("0px", ComputedValue("top", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("right", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("bottom", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("left", "anchor(top, 0px)", context));
  EXPECT_EQ("1px", ComputedValue("width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("1px",
            ComputedValue("min-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("1px",
            ComputedValue("max-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-height", "anchor-size(width, 0px)", context));
}

TEST_F(CSSPropertyTest, AnchorModeHeight) {
  ModeCheckingAnchorEvaluator anchor_evaluator(AnchorScope::Mode::kHeight);
  StyleRecalcContext context = {.anchor_evaluator = &anchor_evaluator};

  EXPECT_EQ("0px", ComputedValue("top", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("right", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("bottom", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("left", "anchor(top, 0px)", context));
  EXPECT_EQ("0px", ComputedValue("width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("1px", ComputedValue("height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("min-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("1px",
            ComputedValue("min-height", "anchor-size(width, 0px)", context));
  EXPECT_EQ("0px",
            ComputedValue("max-width", "anchor-size(width, 0px)", context));
  EXPECT_EQ("1px",
            ComputedValue("max-height", "anchor-size(width, 0px)", context));
}

TEST_F(CSSPropertyTest, AnchorSizeInsetsMarginsDisabled) {
  ScopedCSSAnchorSizeInsetsMarginsForTest enabled(false);

  String anchor_size_value("anchor-size(width)");
  EXPECT_EQ(Parse("top", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("left", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("bottom", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("right", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("inset-block-start", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("inset-block-end", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("inset-inline-start", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("inset-inline-end", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("margin-top", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("margin-left", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("margin-bottom", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("margin-right", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("margin-block-start", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("margin-block-end", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("margin-inline-start", anchor_size_value), nullptr);
  EXPECT_EQ(Parse("margin-inline-end", anchor_size_value), nullptr);
}

}  // namespace blink

"""

```