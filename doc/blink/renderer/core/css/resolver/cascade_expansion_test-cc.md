Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core request is to analyze the functionality of `cascade_expansion_test.cc` within the Blink rendering engine. This means identifying what it tests and how those tests relate to CSS, HTML, and JavaScript. We also need to consider potential errors and how a user might reach this code during debugging.

2. **Initial Skim for Structure and Keywords:** The first step is to quickly scan the file for structural elements and important keywords. We see:
    * `#include` statements: This tells us about the dependencies, particularly `cascade_expansion.h`, `css_property_ref.h`, and various `css/` headers. This immediately points to the core functionality being related to CSS property resolution.
    * `namespace blink`:  Confirms this is Blink-specific code.
    * `CascadeExpansionTest`:  The main test fixture class.
    * `TEST_F`:  Indicates individual test cases.
    * Function names like `ExpansionAt`, `AllProperties`, `VisitedPropertiesInExpansion`. These seem to be helper functions for the tests.
    *  Specific CSS property names (e.g., `cursor`, `top`, `color`, `font-size`, `all`). This strongly suggests the tests are about how different CSS properties are handled during cascade expansion.
    * Keywords like `MatchResult`, `CascadeOrigin`, `CascadePriority`, `ValidPropertyFilter`. These are related to the CSS cascading and specificity mechanisms.

3. **Identify Core Functionality:** Based on the includes and the class name, the central theme is "cascade expansion."  The `#include "third_party/blink/renderer/core/css/resolver/cascade_expansion.h"` is the key indicator. This confirms the file is testing the `CascadeExpansion` class/functionality.

4. **Analyze Test Cases:**  Now, examine the individual `TEST_F` blocks. Each test case focuses on a specific aspect of cascade expansion:
    * `UARules`, `UserRules`, `AuthorRules`, `AllOriginRules`: These test the different origins of CSS rules and how they are expanded.
    * `Name`: Checks the handling of custom properties (`--x`, `--y`).
    * `LinkOmitted`, `InternalVisited`, `InternalVisitedOmitted`, `InternalVisitedWithTrailer`: These focus on how visited link styles are expanded (or omitted).
    * `All`, `InlineAll`: Test the `all` CSS property and its behavior.
    * `FilterFirstLetter`, `FilterFirstLine`, etc.: Verify how property filters (related to pseudo-elements/classes) affect expansion.
    * `Importance`, `AllImportance`, `AllNonImportance`: Test the handling of `!important` in cascade expansion.
    * `AllVisitedOnly`, `AllVisitedOrLink`, `AllLinkOnly`: Further testing of visited/link specific expansions in combination with `all`.
    * `Position`: Examines the position information associated with expanded properties.
    * `MatchedPropertiesLimit`, `MatchedDeclarationsLimit`:  These explore the limits on the number of matched properties and declarations.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **CSS:** The entire file is deeply intertwined with CSS. It tests the core mechanism of how CSS rules are processed and applied to elements. Examples abound in each test case (e.g., `cursor: help`, `color: red`, `font-size: 1px`).
    * **HTML:** While not directly manipulating HTML elements in the *test code*, the underlying functionality being tested is crucial for rendering HTML. The CSS rules are eventually applied to HTML elements to determine their visual presentation. The `GetDocument()` call indicates interaction with the DOM, which represents HTML structure.
    * **JavaScript:** The connection to JavaScript is less direct in this *specific test file*. However, JavaScript can dynamically manipulate CSS styles (e.g., using `element.style` or by adding/removing CSS classes). The correctness of cascade expansion is vital for these JavaScript-driven style changes to work as expected. For instance, if JavaScript sets a style, the cascade needs to properly integrate it.

6. **Logical Reasoning (Assumptions and Outputs):**  For each test case, we can infer the assumption (the input CSS rules) and the expected output (the expanded list of properties with their priorities). The examples provided in the detailed explanation illustrate this.

7. **User/Programming Errors:**  Consider common mistakes developers make with CSS that these tests might help catch:
    * Incorrect specificity leading to unexpected styles.
    * Misunderstanding the `all` property's behavior.
    * Incorrectly using or omitting `!important`.
    * Not accounting for visited link styles.
    * Exceeding limits on the number of CSS declarations.

8. **Debugging Scenario:**  Think about how a developer might end up looking at this file during debugging:
    * A user reports an unexpected visual style on a webpage.
    * The developer investigates the CSS rules affecting the element.
    * If the issue is related to the order of application of styles or the influence of different origins (user agent, author, user), they might delve into the cascade resolution process.
    * If a breakpoint is set within the cascade expansion logic, the execution might lead into this test file or related code.

9. **Refine and Organize:**  Finally, organize the information into clear sections, providing concise explanations and illustrative examples. Use the file's structure and test case names as a guide for structuring the analysis.

By following this structured approach, combining code analysis with knowledge of web technologies and potential error scenarios, we can arrive at a comprehensive understanding of the `cascade_expansion_test.cc` file.
好的，我们来分析一下 `blink/renderer/core/css/resolver/cascade_expansion_test.cc` 这个文件。

**文件功能概要:**

这个 C++ 文件是 Chromium Blink 引擎的一部分，专门用于测试 **CSS 级联展开 (Cascade Expansion)** 的功能。级联展开是 CSS 样式计算过程中一个关键步骤，它负责将匹配到的 CSS 声明展开成最终应用到元素上的属性列表。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

这个测试文件直接关联到 **CSS** 的核心机制，并间接地与 **HTML** 和 **JavaScript** 相关：

* **CSS (核心关系):**
    * **功能测试:** 文件中的测试用例模拟了各种 CSS 规则的匹配场景，例如来自用户代理样式表、用户样式表、作者样式表的规则。它验证了 `ExpandCascade` 函数能否正确地将这些匹配到的声明展开成一系列具体的 CSS 属性。
    * **属性覆盖和优先级:**  测试用例验证了不同来源、不同优先级的 CSS 属性在级联展开过程中的处理方式，例如 `!important` 的影响。
    * **简写属性展开:** 可能会测试简写属性（如 `border`，`margin`，`padding` 等）如何展开成具体的长属性（如 `border-top-width`，`margin-left` 等）。虽然在这个给定的代码片段中没有直接体现简写属性的展开，但这通常是级联展开的一部分。
    * **`all` 属性:**  文件中包含了对 `all` 属性的测试，验证了当 `all` 设置为某个值（如 `unset`）时，所有可继承或非继承属性都会被重置或设置为初始值。
    * **伪类 `:visited`:**  测试用例验证了与 `:visited` 伪类相关的内部属性（例如 `kInternalVisitedColor`）的展开行为。

* **HTML (间接关系):**
    * **目标:** 级联展开的最终目的是确定 HTML 元素应该应用哪些 CSS 属性。测试用例虽然没有直接创建 HTML 元素，但其模拟的场景基于 HTML 结构和 CSS 选择器的匹配结果。`GetDocument()` 函数表明测试运行在某种模拟的文档环境下。

* **JavaScript (间接关系):**
    * **动态样式修改:** JavaScript 可以动态地修改元素的样式。级联展开确保了 JavaScript 修改的样式能够正确地参与到样式的计算过程中。虽然此测试文件不直接测试 JavaScript 交互，但它验证了 CSS 引擎的正确性，这对于 JavaScript 操作 CSS 来说至关重要。

**逻辑推理 (假设输入与输出):**

让我们看一个测试用例 `TEST_F(CascadeExpansionTest, AuthorRules)`：

* **假设输入:**
    * CSS 规则 1: `cursor:help;top:1px` (来自作者样式表)
    * CSS 规则 2: `float:left` (来自作者样式表)
* **执行流程:**  `ExpansionAt(result, 0)` 会对第一个匹配到的规则进行级联展开。
* **预期输出:**  展开后应该包含两个 `ExpansionResult` 对象：
    * 一个代表 `cursor` 属性，优先级为 `CascadeOrigin::kAuthor`。
    * 一个代表 `top` 属性，优先级为 `CascadeOrigin::kAuthor`。

对于 `ExpansionAt(result, 1)`，输入是第二个匹配到的规则，预期输出是一个代表 `float` 属性的 `ExpansionResult` 对象，优先级为 `CascadeOrigin::kAuthor`。

**用户或编程常见的使用错误举例说明:**

* **错误理解 `all` 属性:**
    * **用户操作/代码:**  开发者可能会错误地认为 `all: initial;` 只会影响可继承的属性。
    * **测试用例对应:** `TEST_F(CascadeExpansionTest, All)` 验证了 `all: unset` 会影响所有属性，包括不可继承的属性。
    * **调试线索:** 如果开发者在调试时发现设置了 `all: initial;` 或 `all: unset;` 后，某些不可继承的属性也受到了影响，他们可能会查看级联展开的相关代码，以理解 `all` 属性的完整行为。

* **`:visited` 样式的意外应用:**
    * **用户操作/代码:**  开发者可能在没有考虑 `:visited` 状态的情况下设置了链接的样式，导致用户访问过的链接显示了意想不到的样式。
    * **测试用例对应:**  `TEST_F(CascadeExpansionTest, InternalVisited)` 和相关的测试用例验证了 `:visited` 状态下内部属性的展开，帮助理解为什么某些样式只在链接被访问后才生效。
    * **调试线索:**  如果开发者看到已访问链接的样式与预期不符，他们可能会检查与 `:visited` 相关的 CSS 规则，并可能深入到级联展开的逻辑中，查看 `:visited` 伪类是如何影响属性值的。

* **`!important` 的滥用:**
    * **用户操作/代码:**  开发者过度使用 `!important` 可能会导致样式覆盖关系变得难以理解和维护。
    * **测试用例对应:** `TEST_F(CascadeExpansionTest, Importance)` 和 `TEST_F(CascadeExpansionTest, AllImportance)` 验证了 `!important` 对属性优先级的提升作用。
    * **调试线索:** 当样式冲突难以解决，且涉及到 `!important` 时，开发者可能会研究级联展开的优先级规则，以确定哪些声明最终生效。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户报告页面样式问题:** 用户在浏览网页时发现某个元素的样式显示不正确 (例如，颜色不对，布局错乱)。
2. **开发者检查 CSS 规则:** 开发者使用浏览器开发者工具检查该元素的 CSS 规则，查看哪些规则匹配到了该元素。
3. **样式冲突或优先级问题:** 开发者发现有多个 CSS 规则试图设置同一个属性，或者怀疑是不同来源的样式（用户代理、作者、用户）之间发生了冲突。
4. **深入研究级联机制:** 开发者意识到问题可能出在 CSS 级联的机制上，需要理解哪个规则的优先级更高，最终生效。
5. **查看 Blink 渲染引擎代码 (可选):**  为了更深入地理解级联的实现细节，开发者可能会选择查看 Blink 渲染引擎的源代码。
6. **定位到级联展开相关代码:**  开发者可能会搜索与 CSS 级联、样式解析、属性计算相关的代码文件，最终找到 `cascade_expansion_test.cc` 或 `cascade_expansion.h/cc` 等文件。
7. **分析测试用例:**  通过阅读测试用例，开发者可以了解 Blink 引擎是如何测试级联展开的各种场景的，从而更好地理解浏览器的行为。
8. **设置断点进行调试:**  如果问题非常复杂，开发者可能会在 Blink 渲染引擎的代码中设置断点，例如在 `ExpandCascade` 函数中，以便逐步跟踪样式计算的过程，观察属性是如何被展开和覆盖的。

总而言之，`cascade_expansion_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够正确地实现 CSS 级联的核心逻辑，这对于网页的正确渲染至关重要。理解这个文件的功能可以帮助开发者更深入地了解 CSS 的工作原理，并能更好地调试与样式相关的问题。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/cascade_expansion_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/resolver/cascade_expansion.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_expansion-inl.h"

#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_unset_value.h"
#include "third_party/blink/renderer/core/css/resolver/match_result.h"
#include "third_party/blink/renderer/core/css/rule_set.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

using css_test_helpers::ParseDeclarationBlock;

namespace {

// This list does not necessarily need to be exhaustive.
const CSSPropertyID kVisitedPropertySamples[] = {
    CSSPropertyID::kInternalVisitedColor,
    CSSPropertyID::kInternalVisitedBackgroundColor,
    CSSPropertyID::kInternalVisitedBorderBlockEndColor,
    CSSPropertyID::kInternalVisitedBorderBlockStartColor,
    CSSPropertyID::kInternalVisitedBorderBottomColor,
    CSSPropertyID::kInternalVisitedBorderInlineEndColor,
    CSSPropertyID::kInternalVisitedBorderInlineStartColor,
    CSSPropertyID::kInternalVisitedBorderLeftColor,
    CSSPropertyID::kInternalVisitedBorderRightColor,
    CSSPropertyID::kInternalVisitedBorderTopColor,
    CSSPropertyID::kInternalVisitedCaretColor,
    CSSPropertyID::kInternalVisitedColumnRuleColor,
    CSSPropertyID::kInternalVisitedFill,
    CSSPropertyID::kInternalVisitedOutlineColor,
    CSSPropertyID::kInternalVisitedStroke,
    CSSPropertyID::kInternalVisitedTextDecorationColor,
    CSSPropertyID::kInternalVisitedTextEmphasisColor,
    CSSPropertyID::kInternalVisitedTextFillColor,
    CSSPropertyID::kInternalVisitedTextStrokeColor,
};

}  // namespace

class CascadeExpansionTest : public PageTestBase {
 public:
  struct ExpansionResult : public GarbageCollected<ExpansionResult> {
    CascadePriority priority;
    CSSPropertyRef ref;

    explicit ExpansionResult(const CSSProperty& property) : ref(property) {}

    void Trace(Visitor* visitor) const { visitor->Trace(ref); }
  };

  HeapVector<Member<ExpansionResult>> ExpansionAt(const MatchResult& result,
                                                  wtf_size_t i) {
    HeapVector<Member<ExpansionResult>> ret;
    ExpandCascade(
        result.GetMatchedProperties()[i], GetDocument(), i,
        [this, &ret](CascadePriority cascade_priority,
                     const AtomicString& name) {
          ExpansionResult* er = MakeGarbageCollected<ExpansionResult>(
              CustomProperty(name, GetDocument()));
          er->priority = cascade_priority;
          ret.push_back(er);
        },
        [&ret](CascadePriority cascade_priority, CSSPropertyID id) {
          ExpansionResult* er =
              MakeGarbageCollected<ExpansionResult>(CSSProperty::Get(id));
          er->priority = cascade_priority;
          ret.push_back(er);
        });
    return ret;
  }

  Vector<CSSPropertyID> AllProperties(CascadeFilter filter = CascadeFilter()) {
    Vector<CSSPropertyID> all;
    for (CSSPropertyID id : CSSPropertyIDList()) {
      const CSSProperty& property = CSSProperty::Get(id);
      if (!IsInAllExpansion(id)) {
        continue;
      }
      if (filter.Rejects(property)) {
        continue;
      }
      all.push_back(id);
    }
    return all;
  }

  Vector<CSSPropertyID> VisitedPropertiesInExpansion(
      const MatchedProperties& matched_properties,
      wtf_size_t i) {
    Vector<CSSPropertyID> visited;

    ExpandCascade(
        matched_properties, GetDocument(), i,
        [](CascadePriority cascade_priority [[maybe_unused]],
           const AtomicString& name [[maybe_unused]]) {
          // Do nothing.
        },
        [&visited](CascadePriority cascade_priority [[maybe_unused]],
                   CSSPropertyID id) {
          const CSSProperty& css_property = CSSProperty::Get(id);
          if (css_property.IsVisited()) {
            visited.push_back(css_property.PropertyID());
          }
        });

    return visited;
  }
};

TEST_F(CascadeExpansionTest, UARules) {
  MatchResult result;
  result.AddMatchedProperties(ParseDeclarationBlock("cursor:help;top:1px"),
                              {.origin = CascadeOrigin::kUserAgent});

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(2u, e.size());
  EXPECT_EQ(CSSPropertyID::kCursor, e[0]->ref.GetProperty().PropertyID());
  EXPECT_EQ(CascadeOrigin::kUserAgent, e[0]->priority.GetOrigin());
  EXPECT_EQ(CSSPropertyID::kTop, e[1]->ref.GetProperty().PropertyID());
  EXPECT_EQ(CascadeOrigin::kUserAgent, e[1]->priority.GetOrigin());
}

TEST_F(CascadeExpansionTest, UserRules) {
  MatchResult result;
  result.AddMatchedProperties(ParseDeclarationBlock("cursor:help"),
                              {.origin = CascadeOrigin::kUser});
  result.AddMatchedProperties(ParseDeclarationBlock("float:left"),
                              {.origin = CascadeOrigin::kUser});

  ASSERT_EQ(2u, result.GetMatchedProperties().size());

  {
    auto e = ExpansionAt(result, 0);
    ASSERT_EQ(1u, e.size());
    EXPECT_EQ(CSSPropertyID::kCursor, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kUser, e[0]->priority.GetOrigin());
  }

  {
    auto e = ExpansionAt(result, 1);
    ASSERT_EQ(1u, e.size());
    EXPECT_EQ(CSSPropertyID::kFloat, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kUser, e[0]->priority.GetOrigin());
  }
}

TEST_F(CascadeExpansionTest, AuthorRules) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("cursor:help;top:1px"),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(ParseDeclarationBlock("float:left"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(2u, result.GetMatchedProperties().size());

  {
    auto e = ExpansionAt(result, 0);
    ASSERT_EQ(2u, e.size());
    EXPECT_EQ(CSSPropertyID::kCursor, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kAuthor, e[0]->priority.GetOrigin());
    EXPECT_EQ(CSSPropertyID::kTop, e[1]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kAuthor, e[1]->priority.GetOrigin());
  }

  {
    auto e = ExpansionAt(result, 1);
    ASSERT_EQ(1u, e.size());
    EXPECT_EQ(CSSPropertyID::kFloat, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kAuthor, e[0]->priority.GetOrigin());
  }
}

TEST_F(CascadeExpansionTest, AllOriginRules) {
  MatchResult result;
  result.AddMatchedProperties(ParseDeclarationBlock("font-size:2px"),
                              {.origin = CascadeOrigin::kUserAgent});
  result.AddMatchedProperties(ParseDeclarationBlock("cursor:help;top:1px"),
                              {.origin = CascadeOrigin::kUser});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("left:1px"),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(ParseDeclarationBlock("float:left"),
                              {.origin = CascadeOrigin::kAuthor});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("bottom:2px"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(5u, result.GetMatchedProperties().size());

  {
    auto e = ExpansionAt(result, 0);
    ASSERT_EQ(1u, e.size());
    EXPECT_EQ(CSSPropertyID::kFontSize, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kUserAgent, e[0]->priority.GetOrigin());
  }

  {
    auto e = ExpansionAt(result, 1);
    ASSERT_EQ(2u, e.size());
    EXPECT_EQ(CSSPropertyID::kCursor, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kUser, e[0]->priority.GetOrigin());
    EXPECT_EQ(CSSPropertyID::kTop, e[1]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kUser, e[1]->priority.GetOrigin());
  }

  {
    auto e = ExpansionAt(result, 2);
    ASSERT_EQ(1u, e.size());
    EXPECT_EQ(CSSPropertyID::kLeft, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kAuthor, e[0]->priority.GetOrigin());
  }

  {
    auto e = ExpansionAt(result, 3);
    ASSERT_EQ(1u, e.size());
    EXPECT_EQ(CSSPropertyID::kFloat, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kAuthor, e[0]->priority.GetOrigin());
  }

  {
    auto e = ExpansionAt(result, 4);
    ASSERT_EQ(1u, e.size());
    EXPECT_EQ(CSSPropertyID::kBottom, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CascadeOrigin::kAuthor, e[0]->priority.GetOrigin());
  }
}

TEST_F(CascadeExpansionTest, Name) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("--x:1px;--y:2px"),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(ParseDeclarationBlock("float:left"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(2u, result.GetMatchedProperties().size());

  {
    auto e = ExpansionAt(result, 0);
    ASSERT_EQ(2u, e.size());
    EXPECT_EQ(CSSPropertyName(AtomicString("--x")),
              e[0]->ref.GetProperty().GetCSSPropertyName());
    EXPECT_EQ(CSSPropertyID::kVariable, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(CSSPropertyName(AtomicString("--y")),
              e[1]->ref.GetProperty().GetCSSPropertyName());
    EXPECT_EQ(CSSPropertyID::kVariable, e[1]->ref.GetProperty().PropertyID());
  }

  {
    auto e = ExpansionAt(result, 1);
    ASSERT_EQ(1u, e.size());
    EXPECT_EQ(CSSPropertyName(CSSPropertyID::kFloat),
              e[0]->ref.GetProperty().GetCSSPropertyName());
    EXPECT_EQ(CSSPropertyID::kFloat, e[0]->ref.GetProperty().PropertyID());
  }
}

TEST_F(CascadeExpansionTest, LinkOmitted) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("color:red"),
                              {
                                  .link_match_type = CSSSelector::kMatchVisited,
                                  .origin = CascadeOrigin::kAuthor,
                              });

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(1u, e.size());
  EXPECT_EQ(CSSPropertyID::kInternalVisitedColor,
            e[0]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, InternalVisited) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("color:red"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(2u, e.size());
  EXPECT_EQ(CSSPropertyID::kColor, e[0]->ref.GetProperty().PropertyID());
  EXPECT_EQ(CSSPropertyID::kInternalVisitedColor,
            e[1]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, InternalVisitedOmitted) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("color:red"),
                              {
                                  .link_match_type = CSSSelector::kMatchLink,
                                  .origin = CascadeOrigin::kAuthor,
                              });

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(1u, e.size());
  EXPECT_EQ(CSSPropertyID::kColor, e[0]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, InternalVisitedWithTrailer) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("color:red;left:1px"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(3u, e.size());
  EXPECT_EQ(CSSPropertyID::kColor, e[0]->ref.GetProperty().PropertyID());
  EXPECT_EQ(CSSPropertyID::kInternalVisitedColor,
            e[1]->ref.GetProperty().PropertyID());
  EXPECT_EQ(CSSPropertyID::kLeft, e[2]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, All) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("all:unset"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  const Vector<CSSPropertyID> all = AllProperties();
  auto e = ExpansionAt(result, 0);

  ASSERT_EQ(all.size(), e.size());

  int index = 0;
  for (CSSPropertyID expected : all) {
    EXPECT_EQ(expected, e[index++]->ref.GetProperty().PropertyID());
  }
}

TEST_F(CascadeExpansionTest, InlineAll) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock("left:1px;all:unset;right:1px"),
      {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  const Vector<CSSPropertyID> all = AllProperties();

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(all.size() + 2, e.size());

  EXPECT_EQ(CSSPropertyID::kLeft, e[0]->ref.GetProperty().PropertyID());

  int index = 1;
  for (CSSPropertyID expected : all) {
    EXPECT_EQ(expected, e[index++]->ref.GetProperty().PropertyID());
  }

  EXPECT_EQ(CSSPropertyID::kRight, e[index++]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, FilterFirstLetter) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock("object-fit:unset;font-size:1px"),
      {
          .valid_property_filter =
              static_cast<uint8_t>(ValidPropertyFilter::kFirstLetter),
          .origin = CascadeOrigin::kAuthor,
      });

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(1u, e.size());
  EXPECT_EQ(CSSPropertyID::kFontSize, e[0]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, FilterFirstLine) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock("display:none;font-size:1px"),
      {
          .valid_property_filter =
              static_cast<uint8_t>(ValidPropertyFilter::kFirstLine),
          .origin = CascadeOrigin::kAuthor,
      });

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(1u, e.size());
  EXPECT_EQ(CSSPropertyID::kFontSize, e[0]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, FilterCue) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock("object-fit:unset;font-size:1px"),
      {
          .valid_property_filter =
              static_cast<uint8_t>(ValidPropertyFilter::kCue),
          .origin = CascadeOrigin::kAuthor,
      });

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(1u, e.size());
  EXPECT_EQ(CSSPropertyID::kFontSize, e[0]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, FilterMarker) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock("object-fit:unset;font-size:1px"),
      {
          .valid_property_filter =
              static_cast<uint8_t>(ValidPropertyFilter::kMarker),
          .origin = CascadeOrigin::kAuthor,
      });

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(1u, e.size());
  EXPECT_EQ(CSSPropertyID::kFontSize, e[0]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, FilterHighlightLegacy) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock(
          "display:block;background-color:lime;forced-color-adjust:none"),
      {
          .valid_property_filter =
              static_cast<uint8_t>(ValidPropertyFilter::kHighlightLegacy),
          .origin = CascadeOrigin::kAuthor,
      });

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(3u, e.size());
  EXPECT_EQ(CSSPropertyID::kBackgroundColor,
            e[0]->ref.GetProperty().PropertyID());
  EXPECT_EQ(CSSPropertyID::kInternalVisitedBackgroundColor,
            e[1]->ref.GetProperty().PropertyID());
  EXPECT_EQ(CSSPropertyID::kForcedColorAdjust,
            e[2]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, FilterHighlight) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock(
          "display:block;background-color:lime;forced-color-adjust:none"),
      {
          .valid_property_filter =
              static_cast<uint8_t>(ValidPropertyFilter::kHighlight),
          .origin = CascadeOrigin::kAuthor,
      });

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(2u, e.size());
  EXPECT_EQ(CSSPropertyID::kBackgroundColor,
            e[0]->ref.GetProperty().PropertyID());
  EXPECT_EQ(CSSPropertyID::kInternalVisitedBackgroundColor,
            e[1]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, FilterPositionFallback) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock("display:inline;position:static;left:auto"),
      {
          .valid_property_filter =
              static_cast<uint8_t>(ValidPropertyFilter::kPositionTry),
          .origin = CascadeOrigin::kAuthor,
      });
  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(1u, e.size());
  EXPECT_EQ(CSSPropertyID::kLeft, e[0]->ref.GetProperty().PropertyID());
}

TEST_F(CascadeExpansionTest, Importance) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ParseDeclarationBlock("cursor:help;display:block !important"),
      {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(2u, e.size());

  EXPECT_EQ(CSSPropertyID::kCursor, e[0]->ref.GetProperty().PropertyID());
  EXPECT_FALSE(e[0]->priority.IsImportant());
  EXPECT_EQ(CSSPropertyID::kDisplay, e[1]->ref.GetProperty().PropertyID());
  EXPECT_TRUE(e[1]->priority.IsImportant());
}

TEST_F(CascadeExpansionTest, AllImportance) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("all:unset !important"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  const Vector<CSSPropertyID> all = AllProperties();
  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(all.size(), e.size());

  int index = 0;
  for (CSSPropertyID expected : AllProperties()) {
    EXPECT_EQ(expected, e[index]->ref.GetProperty().PropertyID());
    EXPECT_TRUE(e[index]->priority.IsImportant());
    ++index;
  }
}

TEST_F(CascadeExpansionTest, AllNonImportance) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("all:unset"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  const Vector<CSSPropertyID> all = AllProperties();
  auto e = ExpansionAt(result, 0);
  ASSERT_EQ(all.size(), e.size());

  int index = 0;
  for (CSSPropertyID expected : AllProperties()) {
    EXPECT_EQ(expected, e[index]->ref.GetProperty().PropertyID());
    EXPECT_FALSE(e[index]->priority.IsImportant());
    ++index;
  }
}

TEST_F(CascadeExpansionTest, AllVisitedOnly) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("all:unset"),
                              {
                                  .link_match_type = CSSSelector::kMatchVisited,
                                  .valid_property_filter = static_cast<uint8_t>(
                                      ValidPropertyFilter::kNoFilter),
                                  .origin = CascadeOrigin::kAuthor,
                              });

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  Vector<CSSPropertyID> visited =
      VisitedPropertiesInExpansion(result.GetMatchedProperties()[0], 0);

  for (CSSPropertyID id : kVisitedPropertySamples) {
    EXPECT_TRUE(visited.Contains(id))
        << CSSProperty::Get(id).GetPropertyNameString()
        << " should be in the expansion";
  }
}

TEST_F(CascadeExpansionTest, AllVisitedOrLink) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("all:unset"),
                              {
                                  .link_match_type = CSSSelector::kMatchAll,
                                  .valid_property_filter = static_cast<uint8_t>(
                                      ValidPropertyFilter::kNoFilter),
                                  .origin = CascadeOrigin::kAuthor,
                              });

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  Vector<CSSPropertyID> visited =
      VisitedPropertiesInExpansion(result.GetMatchedProperties()[0], 0);

  for (CSSPropertyID id : kVisitedPropertySamples) {
    EXPECT_TRUE(visited.Contains(id))
        << CSSProperty::Get(id).GetPropertyNameString()
        << " should be in the expansion";
  }
}

TEST_F(CascadeExpansionTest, AllLinkOnly) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("all:unset"),
                              {
                                  .link_match_type = CSSSelector::kMatchLink,
                                  .valid_property_filter = static_cast<uint8_t>(
                                      ValidPropertyFilter::kNoFilter),
                                  .origin = CascadeOrigin::kAuthor,
                              });

  ASSERT_EQ(1u, result.GetMatchedProperties().size());

  Vector<CSSPropertyID> visited =
      VisitedPropertiesInExpansion(result.GetMatchedProperties()[0], 0);
  EXPECT_EQ(visited.size(), 0u);
}

TEST_F(CascadeExpansionTest, Position) {
  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(ParseDeclarationBlock("left:1px;top:1px"),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(ParseDeclarationBlock("bottom:1px;right:1px"),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(2u, result.GetMatchedProperties().size());

  {
    auto e = ExpansionAt(result, 0);
    ASSERT_EQ(2u, e.size());

    EXPECT_EQ(CSSPropertyID::kLeft, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(0u, DecodeMatchedPropertiesIndex(e[0]->priority.GetPosition()));
    EXPECT_EQ(0u, DecodeDeclarationIndex(e[0]->priority.GetPosition()));
    EXPECT_EQ(CSSPropertyID::kTop, e[1]->ref.GetProperty().PropertyID());
    EXPECT_EQ(0u, DecodeMatchedPropertiesIndex(e[1]->priority.GetPosition()));
    EXPECT_EQ(1u, DecodeDeclarationIndex(e[1]->priority.GetPosition()));
  }

  {
    auto e = ExpansionAt(result, 1);
    ASSERT_EQ(2u, e.size());

    EXPECT_EQ(CSSPropertyID::kBottom, e[0]->ref.GetProperty().PropertyID());
    EXPECT_EQ(1u, DecodeMatchedPropertiesIndex(e[0]->priority.GetPosition()));
    EXPECT_EQ(0u, DecodeDeclarationIndex(e[0]->priority.GetPosition()));
    EXPECT_EQ(CSSPropertyID::kRight, e[1]->ref.GetProperty().PropertyID());
    EXPECT_EQ(1u, DecodeMatchedPropertiesIndex(e[1]->priority.GetPosition()));
    EXPECT_EQ(1u, DecodeDeclarationIndex(e[1]->priority.GetPosition()));
  }
}

TEST_F(CascadeExpansionTest, MatchedPropertiesLimit) {
  constexpr wtf_size_t max = std::numeric_limits<uint16_t>::max();

  static_assert(kMaxMatchedPropertiesIndex == max,
                "Unexpected max. If the limit increased, evaluate whether it "
                "still makes sense to run this test");

  auto* set = ParseDeclarationBlock("left:1px");

  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  for (wtf_size_t i = 0; i < max + 3; ++i) {
    result.AddMatchedProperties(set, {.origin = CascadeOrigin::kAuthor});
  }

  ASSERT_EQ(max + 3u, result.GetMatchedProperties().size());

  for (wtf_size_t i = 0; i < max + 1; ++i) {
    EXPECT_GT(ExpansionAt(result, i).size(), 0u);
  }

  // The indices beyond the max should not yield anything.
  EXPECT_EQ(0u, ExpansionAt(result, max + 1).size());
  EXPECT_EQ(0u, ExpansionAt(result, max + 2).size());
}

TEST_F(CascadeExpansionTest, MatchedDeclarationsLimit) {
  constexpr wtf_size_t max = std::numeric_limits<uint16_t>::max();

  static_assert(kMaxDeclarationIndex == max,
                "Unexpected max. If the limit increased, evaluate whether it "
                "still makes sense to run this test");

  HeapVector<CSSPropertyValue> declarations(max + 2);

  // Actually give the indexes a value, such that the calls to
  // ExpansionAt() does not crash.
  for (wtf_size_t i = 0; i < max + 2; ++i) {
    declarations[i] = CSSPropertyValue(CSSPropertyName(CSSPropertyID::kColor),
                                       *cssvalue::CSSUnsetValue::Create());
  }

  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(
      ImmutableCSSPropertyValueSet::Create(
          base::span(declarations).first(max + 1), kHTMLStandardMode),
      {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(
      ImmutableCSSPropertyValueSet::Create(
          base::span(declarations).first(max + 2), kHTMLStandardMode),
      {.origin = CascadeOrigin::kAuthor});

  EXPECT_GT(ExpansionAt(result, 0).size(), 0u);
  EXPECT_EQ(ExpansionAt(result, 1).size(), 0u);
}

}  // namespace blink

"""

```