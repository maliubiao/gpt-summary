Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of `rule_set_test.cc`, its relation to web technologies, examples of logical reasoning, common errors, debugging hints, and finally, a concise summary of its purpose.

2. **Initial Code Scan (High-Level):** I quickly skim the code to identify key elements:
    * **Includes:**  `rule_set.h`, testing frameworks (`gtest`), CSS-related classes (`css_default_style_sheets.h`, `css_keyframes_rule.h`, etc.), and some platform testing utilities. This strongly suggests the file is about testing the `RuleSet` class.
    * **Test Fixture (`RuleSetTest`):** The `TEST(RuleSetTest, ...)` macros clearly indicate this is a unit test file for the `RuleSet` class.
    * **Helper Functions:**  The `CreateDummyStyleRule()` function suggests the tests need to create CSS rules for testing.
    * **Specific Test Cases:** The names of the test cases (`findBestRuleSetAndAdd_...`, `LargeNumberOfAttributeRules`, `IsCoveredByBucketing`, etc.) give clues about the specific functionalities being tested.

3. **Deeper Dive into Functionality (Categorization):** I go through the test cases more systematically, grouping them by the feature they seem to be testing:

    * **Rule Matching and Bucketing:**  Tests like `findBestRuleSetAndAdd_Id`, `_ClassThenId`, `_AttrThenId`, `_NthChild`, `_ThreeClasses`, etc., focus on how the `RuleSet` organizes and retrieves rules based on different CSS selectors (IDs, classes, attributes, tags, pseudo-classes, pseudo-elements). The "best" in the name hints at selector specificity and how the `RuleSet` prioritizes rules.
    * **Pseudo-elements and Pseudo-classes:** Tests like `_CustomPseudoElements`, `_Host`, `_HostWithId`, `_Focus`, `_LinkVisited`, `_Cue`, `_PlaceholderPseudo`, `_PartPseudoElements`, `_ShadowPseudoAfterPart`  demonstrate testing the handling of various CSS pseudo-elements and pseudo-classes.
    * **Functional Pseudo-classes:** Tests involving `:is()` and `:where()` show how the `RuleSet` deals with these more complex selectors.
    * **Performance/Scalability:** `LargeNumberOfAttributeRules` and related tests suggest checking how the `RuleSet` performs with a large number of rules, potentially involving optimizations like Aho-Corasick.
    * **Selector Indexing and Limits:** `SelectorIndexLimit` and `RuleDataPositionLimit` indicate tests for internal data structure limitations and how selectors are indexed within the `RuleSet`.
    * **Style Scopes:**  Tests like `NoStyleScope`, `StyleScope`, and `NestedStyleScope` demonstrate the handling of CSS `@scope` rules.
    * **Parent and Scope Pseudo-classes:** `ParentPseudoBucketing_...` and `ScopePseudoBucketing_...` test the specific behavior of the `&` (parent) and `:scope` pseudo-classes within `@scope` rules.
    * **Visited Link Logic:** The tests involving `:link` and `:visited` show how the `RuleSet` handles the special case of visited links, where rules are often duplicated.
    * **`IsCoveredByBucketing` (DCHECK):** This test (enabled in debug builds) appears to verify an internal optimization related to how rules are "bucketed" for efficient matching.

4. **Connecting to Web Technologies:** I relate the identified functionalities to core web technologies:

    * **CSS:** The entire file is fundamentally about CSS. It tests how CSS rules are stored, organized, and retrieved.
    * **HTML:** The tests implicitly relate to HTML because CSS rules target HTML elements. The inclusion of `HTMLStyleElement` and shadow DOM related elements (`shadow_element_names.h`) makes this connection explicit.
    * **JavaScript:** While this specific file doesn't directly involve JavaScript *execution*, it's crucial for how the browser *applies* styles calculated based on these rules, which is often triggered by JavaScript actions or DOM manipulation.

5. **Logical Reasoning Examples:** I look for tests that involve some form of conditional logic or prioritization:

    * **Selector Specificity:** Tests like `_ClassThenId` and `_IdThenClass` are excellent examples. They demonstrate how the `RuleSet` prioritizes ID selectors over class selectors, even if the order in the CSS is different. I formulate the input CSS and the expected output (which rule is preferred).
    * **Attribute Matching Optimization:** The `LargeNumberOfAttributeRules` tests illustrate a logic where, for performance, the `RuleSet` might use a different data structure (Aho-Corasick) for a large number of attribute selectors. The input is the number of rules, and the output is the expectation of whether the optimization kicks in.

6. **Common User/Programming Errors:** I consider what mistakes developers might make that would be caught by these tests:

    * **Incorrect Selector Specificity:** A developer might assume a rule with a class defined later overrides an ID rule defined earlier. The tests for `_ClassThenId` highlight this.
    * **Misunderstanding Pseudo-element/Pseudo-class Behavior:**  The tests for `:host`, `::part`, etc., help ensure developers' understanding of how these selectors work within shadow DOM and other contexts.
    * **Performance Issues with Many Rules:** While not a direct *error*, the large attribute rule tests indirectly address potential performance problems if the `RuleSet` wasn't efficiently implemented.

7. **Debugging Hints:** I think about how a developer might end up looking at this file:

    * **CSS Styling Issues:** If a webpage's styling is not as expected, a developer might investigate the browser's style resolution process, potentially leading them to the `RuleSet` code.
    * **Performance Bottlenecks:** If CSS style calculation is slow, developers might profile the browser and find that a significant amount of time is spent in `RuleSet` operations.
    * **Investigating Specific CSS Features:**  A developer working on a new CSS feature or encountering a bug related to a specific selector might need to delve into the `RuleSet` implementation.

8. **Concise Summary:** Finally, I synthesize the information into a short summary that captures the essence of the file's purpose.

By following these steps, I can analyze the code and generate a comprehensive answer that addresses all aspects of the request. The key is to move from a high-level understanding to specific details, making connections to broader web technologies and considering the practical implications for developers.
好的，这是对 `blink/renderer/core/css/rule_set_test.cc` 文件功能的详细分析和归纳（第 1 部分）。

**文件功能概述 (第 1 部分)**

`blink/renderer/core/css/rule_set_test.cc` 是 Chromium Blink 渲染引擎中的一个 **单元测试文件**。它的主要目的是 **测试 `RuleSet` 类** 的各种功能。`RuleSet` 类在 Blink 引擎中负责存储和管理 CSS 规则，是样式计算和应用的核心组成部分。

**详细功能列举与说明**

这个测试文件通过编写一系列独立的测试用例来验证 `RuleSet` 类的行为是否符合预期。 具体来说，它测试了以下关键功能：

1. **规则的添加和查找 (findBestRuleSetAndAdd_*)：**
   - 测试 `RuleSet` 类 **添加 CSS 规则** 的能力，包括处理不同类型的选择器（ID、类、标签、属性、伪类、伪元素等）。
   - 测试 `RuleSet` 类 **根据不同类型的选择器高效查找匹配的规则** 的能力。例如，通过 ID 查找 (`IdRules`)、类名查找 (`ClassRules`)、标签名查找 (`TagRules`)、属性查找 (`AttrRules`)、伪元素查找 (`UAShadowPseudoElementRules`, `CuePseudoRules`, `PartPseudoRules`) 等。
   - **与 CSS 的关系：**  这是 `RuleSet` 最核心的功能，直接关系到浏览器如何根据 CSS 选择器找到应用于特定 HTML 元素的样式规则。
   - **举例说明：**
     - `TEST(RuleSetTest, findBestRuleSetAndAdd_Id)` 测试添加 `#id { }` 规则，并验证可以通过 `rule_set.IdRules("id")` 找到该规则。
     - `TEST(RuleSetTest, findBestRuleSetAndAdd_ClassThenId)` 测试 `.class#id { }` 规则，验证即使类选择器在前，仍然优先通过 ID 选择器进行查找。
   - **逻辑推理 (假设输入与输出)：**
     - **输入 CSS:** `#myElement { color: blue; }`
     - **预期输出:** `rule_set.IdRules("myElement")` 应该返回包含该规则的 `RuleData` 集合。

2. **复杂选择器的处理：**
   - 测试 `RuleSet` 类处理 **组合选择器** 的能力，例如包含多个类、属性、ID 的选择器。
   - 测试 `RuleSet` 类处理 **伪类和伪元素选择器** 的能力，包括标准伪类（如 `:focus`, `:link`, `:visited`）、WebKit 特有的伪类（如 `::-webkit-details-marker`）、以及 Shadow DOM 相关的伪类 (`:host`, `:host-context`) 和伪元素 (`::part`, `::placeholder`).
   - 测试 `RuleSet` 类处理 **功能性伪类** (`:is()`, `:where()`) 的能力。
   - **与 CSS 的关系：** 这些测试确保 `RuleSet` 能够正确解析和存储各种复杂的 CSS 选择器，以便在样式匹配时能够正确工作。
   - **举例说明：**
     - `TEST(RuleSetTest, findBestRuleSetAndAdd_ClassThenId)` 测试 `.class#id { }`，验证 ID 选择器的优先级。
     - `TEST(RuleSetTest, findBestRuleSetAndAdd_Host)` 测试 `:host { }`，验证对 Shadow DOM host 伪类的处理。
     - `TEST(RuleSetTest, findBestRuleSetAndAdd_IsSingleArg)` 测试 `:is(.a) { }`，验证功能性伪类的处理。
   - **逻辑推理 (假设输入与输出)：**
     - **输入 CSS:** `:host(.active) button { ... }`
     - **预期输出:** `rule_set.ShadowHostRules()` 应该包含该规则，并且该规则与类名 "active" 和标签名 "button" 相关联。

3. **Visited 链接的处理：**
   - 测试 `RuleSet` 类如何处理与 `:link` 和 `:visited` 伪类相关的规则。由于浏览器对已访问链接的样式处理有所限制，这些规则通常会被特殊处理。
   - **与 CSS 的关系：**  确保 `:link` 和 `:visited` 伪类的行为符合 CSS 规范和浏览器安全策略。
   - **举例说明:** `TEST(RuleSetTest, findBestRuleSetAndAdd_LinkVisited)` 测试包含 `:link` 和 `:visited` 的规则，验证这些规则被正确添加和分类。

4. **大规模属性选择器的处理：**
   - 测试当存在 **大量基于属性的选择器** 时，`RuleSet` 的性能和正确性。这通常涉及到内部优化，例如使用 Aho-Corasick 算法来加速匹配。
   - **与 CSS 的关系：**  确保在包含大量属性选择器的页面上，样式计算仍然能够高效进行。
   - **举例说明:** `TEST(RuleSetTest, LargeNumberOfAttributeRules)` 创建了超过 50 个不同的属性选择器，并测试了 `CanIgnoreEntireList` 方法，该方法用于优化属性查找。
   - **逻辑推理 (假设输入与输出)：**
     - **假设输入:** 100 个类似 `[attr="value1"]`, `[attr="value2"]` ... 的规则。
     - **预期输出:** `rule_set.AttrRules("attr")` 返回的规则列表应该能够利用内部优化来快速判断某个特定的属性值是否存在匹配的规则。

5. **选择器索引限制：**
   - 测试 `RuleSet` 类内部用于存储选择器信息的索引是否能够处理 **非常长的选择器链**。
   - **与 CSS 的关系：**  虽然实际场景中极少出现如此长的选择器，但这是一个边界测试，确保代码的健壮性。
   - **举例说明:** `TEST(RuleSetTest, SelectorIndexLimit)` 创建了一个包含 8191 个 `div` 选择器的规则，用于测试索引的上限。

6. **规则数据位置限制：**
   - 测试 `RuleSet` 类内部存储规则数据的能力是否存在限制，并确保能够存储 **大量的规则**。
   - **内部实现细节：** 这涉及到 `RuleData` 类中用于存储规则位置的位数。
   - **举例说明:** `TEST(RuleSetTest, RuleDataPositionLimit)` 尝试添加超过内部位置限制的规则数量。

7. **Style Scope (`@scope`) 的处理：**
   - 测试 `RuleSet` 类对 CSS `@scope` 规则的处理，包括嵌套的 `@scope`。
   - **与 CSS 的关系：**  确保 `RuleSet` 能够正确存储和关联与特定 scope 相关的规则。
   - **举例说明:**
     - `TEST(RuleSetTest, StyleScope)` 测试基本的 `@scope (.a) { #b {} }` 规则。
     - `TEST(RuleSetTest, NestedStyleScope)` 测试嵌套的 `@scope` 规则。
   - **逻辑推理 (假设输入与输出)：**
     - **输入 CSS:** `@scope (.container) { .item { ... } }`
     - **预期输出:**  `rule_set.ScopeIntervals()` 应该包含一个与该 `@scope` 规则对应的区间，并且该区间内的规则与选择器 `.item` 相关联。

8. **`:scope` 和 `&` (父选择器) 伪类的处理：**
   - 测试在 `@scope` 规则中使用 `:scope` 伪类，以及在其他规则中使用 `&` 伪类的行为。
   - **与 CSS 的关系：** 确保这些上下文相关的伪类能够正确地被 `RuleSet` 处理和索引。
   - **举例说明:**
     - `TEST(RuleSetTest, ScopePseudoBucketing_Single)` 测试 `@scope (.a) { :scope { ... } }`。
     - `TEST(RuleSetTest, ParentPseudoBucketing_Single)` 测试 `.a { & { ... } }`。

9. **错误处理：**
   - `TEST(RuleSetTest, RuleCountNotIncreasedByInvalidRuleData)` 测试当尝试添加具有 **无效选择器索引** 的规则时，`RuleSet` 是否能够正确处理，防止规则计数错误增加。
   - **编程常见的使用错误：** 在 Blink 内部开发中，如果传递了错误的选择器索引，可能会导致 `RuleSet` 状态不一致。这个测试可以防止这种情况。

**与 JavaScript, HTML 的关系**

虽然 `rule_set_test.cc` 主要关注 CSS 规则的管理，但它与 JavaScript 和 HTML 也有间接但重要的关系：

* **HTML:** CSS 规则最终会应用于 HTML 元素。`RuleSet` 负责存储这些规则，以便在浏览器渲染 HTML 时能够找到匹配的样式。测试用例中使用的选择器（如 `#id`, `.class`, `div`）都对应 HTML 元素。
* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和元素的类名、属性等，这些修改可能会触发样式的重新计算。`RuleSet` 的高效查找能力对于保证 JavaScript 交互的性能至关重要。此外，JavaScript 可以通过 CSSOM API 来访问和修改样式规则，这也会涉及到 `RuleSet` 的操作。

**用户操作是如何一步步的到达这里，作为调试线索。**

作为一个开发者，你通常不会直接“到达”这个测试文件，除非你正在进行 Blink 引擎的开发或调试。以下是一些可能导致你查看或修改 `rule_set_test.cc` 的场景：

1. **修复 CSS 样式相关的 Bug:**
   - 用户报告了某个网页的样式显示不正确。
   - 你通过调试发现问题可能出在 CSS 规则的匹配或应用上。
   - 为了验证你的修复，你可能会修改或添加 `rule_set_test.cc` 中的测试用例，以确保 `RuleSet` 类在特定情况下能够正确工作。

2. **开发新的 CSS 特性:**
   - 你正在实现一个新的 CSS 特性（例如，一个新的伪类或 `@` 规则）。
   - 你需要修改 Blink 引擎中处理 CSS 规则的相关代码，包括 `RuleSet` 类。
   - 为了确保新特性的正确性，你需要在 `rule_set_test.cc` 中添加相应的测试用例。

3. **性能优化:**
   - 你发现 Blink 引擎在处理大量 CSS 规则时性能不佳。
   - 你可能会研究 `RuleSet` 类的实现，寻找优化的机会。
   - 你可能会添加性能相关的测试用例到 `rule_set_test.cc`，以衡量优化效果。

4. **代码重构或维护:**
   - 你正在对 `RuleSet` 类进行代码重构或维护。
   - 你需要确保在修改代码后，现有的功能仍然能够正常工作。
   - `rule_set_test.cc` 中的测试用例可以作为回归测试的手段。

**用户或编程常见的使用错误**

尽管这是一个测试文件，但它可以间接地反映用户或编程中可能出现的与 CSS 相关的错误：

* **选择器优先级理解错误:** 用户可能错误地认为某个 CSS 规则应该覆盖另一个，但由于选择器优先级的原因，实际并非如此。`findBestRuleSetAndAdd_ClassThenId` 等测试用例可以帮助理解选择器优先级的工作方式。
* **伪类或伪元素使用错误:** 用户可能对某些伪类或伪元素的行为不熟悉，导致样式不符合预期。相关的测试用例可以帮助理解这些选择器的正确用法。
* **大量 CSS 规则导致的性能问题:** 虽然用户不会直接操作 `RuleSet`，但编写包含大量复杂选择器的 CSS 可能会导致性能问题。`LargeNumberOfAttributeRules` 等测试用例暗示了浏览器需要处理这种情况。
* **在 JavaScript 中操作 CSSOM 时的错误:**  虽然这个文件不直接测试 CSSOM，但理解 `RuleSet` 的工作原理对于正确使用 CSSOM API 是有帮助的。

**总结 (第 1 部分)**

`blink/renderer/core/css/rule_set_test.cc` 的主要功能是 **对 `RuleSet` 类进行全面的单元测试**。它覆盖了规则的添加、查找、复杂选择器的处理、特殊伪类的处理、性能测试以及错误处理等方面。 这些测试确保了 `RuleSet` 类作为 Blink 引擎中关键的 CSS 规则管理组件能够正确、高效地工作，从而保证网页样式的正确渲染和良好的性能。

Prompt: 
```
这是目录为blink/renderer/core/css/rule_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2014, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Opera Software ASA nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/rule_set.h"

#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

using ::testing::ElementsAreArray;

namespace blink {

namespace {

StyleRule* CreateDummyStyleRule() {
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules("#id { color: tomato; }");
  const RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> rules = rule_set.IdRules(AtomicString("id"));
  DCHECK_EQ(1u, rules.size());
  return rules.front().Rule();
}

}  // namespace

TEST(RuleSetTest, findBestRuleSetAndAdd_CustomPseudoElements) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("summary::-webkit-details-marker { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  AtomicString str("-webkit-details-marker");
  base::span<const RuleData> rules = rule_set.UAShadowPseudoElementRules(str);
  ASSERT_EQ(1u, rules.size());
  ASSERT_EQ(str, rules.front().Selector().Value());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_Id) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("#id { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  AtomicString str("id");
  base::span<const RuleData> rules = rule_set.IdRules(str);
  ASSERT_EQ(1u, rules.size());
  ASSERT_EQ(str, rules.front().Selector().Value());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_NthChild) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("div:nth-child(2) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  AtomicString str("div");
  base::span<const RuleData> rules = rule_set.TagRules(str);
  ASSERT_EQ(1u, rules.size());
  ASSERT_EQ(str, rules.front().Selector().TagQName().LocalName());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_ClassThenId) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(".class#id { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  AtomicString str("id");
  // id is prefered over class even if class preceeds it in the selector.
  base::span<const RuleData> rules = rule_set.IdRules(str);
  ASSERT_EQ(1u, rules.size());
  AtomicString class_str("class");
  ASSERT_EQ(class_str, rules.front().Selector().Value());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_IdThenClass) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("#id.class { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  AtomicString str("id");
  base::span<const RuleData> rules = rule_set.IdRules(str);
  ASSERT_EQ(1u, rules.size());
  ASSERT_EQ(str, rules.front().Selector().Value());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_AttrThenId) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("[attr]#id { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  AtomicString str("id");
  base::span<const RuleData> rules = rule_set.IdRules(str);
  ASSERT_EQ(1u, rules.size());
  AtomicString attr_str("attr");
  ASSERT_EQ(attr_str, rules.front().Selector().Attribute().LocalName());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_TagThenAttrThenId) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("div[attr]#id { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  AtomicString str("id");
  base::span<const RuleData> rules = rule_set.IdRules(str);
  ASSERT_EQ(1u, rules.size());
  AtomicString tag_str("div");
  ASSERT_EQ(tag_str, rules.front().Selector().TagQName().LocalName());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_TagThenAttr) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("div[attr] { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  ASSERT_EQ(1u, rule_set.AttrRules(AtomicString("attr")).size());
  ASSERT_TRUE(rule_set.TagRules(AtomicString("div")).empty());
}

// It's arbitrary which of these we choose, but it needs to match
// the behavior in IsCoveredByBucketing().
TEST(RuleSetTest, findBestRuleSetAndAdd_ThreeClasses) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(".a.b.c { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(0u, rule_set.ClassRules(AtomicString("a")).size());
  EXPECT_EQ(0u, rule_set.ClassRules(AtomicString("b")).size());
  EXPECT_EQ(1u, rule_set.ClassRules(AtomicString("c")).size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_AttrThenClass) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("[attr].class { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  ASSERT_TRUE(rule_set.AttrRules(AtomicString("attr")).empty());
  ASSERT_EQ(1u, rule_set.ClassRules(AtomicString("class")).size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_Host) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":host { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.ShadowHostRules();
  ASSERT_EQ(1u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_HostWithId) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":host(#x) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.ShadowHostRules();
  ASSERT_EQ(1u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_HostContext) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":host-context(*) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.ShadowHostRules();
  ASSERT_EQ(1u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_HostContextWithId) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":host-context(#x) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.ShadowHostRules();
  ASSERT_EQ(1u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_HostAndHostContextNotInRightmost) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":host-context(#x) .y, :host(.a) > #b  { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> shadow_rules = rule_set.ShadowHostRules();
  base::span<const RuleData> id_rules = rule_set.IdRules(AtomicString("b"));
  base::span<const RuleData> class_rules =
      rule_set.ClassRules(AtomicString("y"));
  ASSERT_EQ(0u, shadow_rules.size());
  ASSERT_EQ(1u, id_rules.size());
  ASSERT_EQ(1u, class_rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_HostAndClass) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(".foo:host { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.ShadowHostRules();
  ASSERT_EQ(0u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_HostContextAndClass) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(".foo:host-context(*) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.ShadowHostRules();
  ASSERT_EQ(0u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_Focus) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":focus { }");
  sheet.AddCSSRules("[attr]:focus { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  ASSERT_EQ(1u, rule_set.FocusPseudoClassRules().size());
  ASSERT_EQ(1u, rule_set.AttrRules(AtomicString("attr")).size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_LinkVisited) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":link { }");
  sheet.AddCSSRules("[attr]:link { }");
  sheet.AddCSSRules(":visited { }");
  sheet.AddCSSRules("[attr]:visited { }");
  sheet.AddCSSRules(":-webkit-any-link { }");
  sheet.AddCSSRules("[attr]:-webkit-any-link { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  // Visited-dependent rules (which include selectors that contain :link)
  // are added twice.
  ASSERT_EQ(5u, rule_set.LinkPseudoClassRules().size());
  ASSERT_EQ(5u, rule_set.AttrRules(AtomicString("attr")).size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_Cue) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("::cue(b) { }");
  sheet.AddCSSRules("video::cue(u) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.CuePseudoRules();
  ASSERT_EQ(2u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_PlaceholderPseudo) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("::placeholder { }");
  sheet.AddCSSRules("input::placeholder { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> rules = rule_set.UAShadowPseudoElementRules(
      AtomicString("-webkit-input-placeholder"));
  ASSERT_EQ(2u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_PartPseudoElements) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("::part(dummy):focus, #id::part(dummy) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.PartPseudoRules();
  ASSERT_EQ(2u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_ShadowPseudoAfterPart) {
  ScopedCSSCascadeCorrectScopeForTest scoped_feature(true);
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("::part(p)::file-selector-button { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.UAShadowPseudoElementRules(
      shadow_element_names::kPseudoFileUploadButton);
  ASSERT_EQ(1u, rules.size());
  const base::span<const RuleData> part_rules = rule_set.PartPseudoRules();
  ASSERT_EQ(0u, part_rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_IsSingleArg) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":is(.a) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> rules = rule_set.ClassRules(AtomicString("a"));
  ASSERT_FALSE(rules.empty());
  ASSERT_EQ(1u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_WhereSingleArg) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":where(.a) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> rules = rule_set.ClassRules(AtomicString("a"));
  ASSERT_FALSE(rules.empty());
  ASSERT_EQ(1u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_WhereSingleArgNested) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":where(:is(.a)) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> rules = rule_set.ClassRules(AtomicString("a"));
  ASSERT_FALSE(rules.empty());
  ASSERT_EQ(1u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_IsMultiArg) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":is(.a, .b) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.UniversalRules();
  ASSERT_EQ(1u, rules.size());
}

TEST(RuleSetTest, findBestRuleSetAndAdd_WhereMultiArg) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(":where(.a, .b) { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const base::span<const RuleData> rules = rule_set.UniversalRules();
  ASSERT_EQ(1u, rules.size());
}

static void AddManyAttributeRules(base::test::ScopedFeatureList& feature_list,
                                  css_test_helpers::TestStyleSheet& sheet) {
  // Create more than 50 rules, in order to trigger building the Aho-Corasick
  // tree.
  for (int i = 0; i < 100; ++i) {
    char buf[256];
    snprintf(buf, sizeof(buf), "[attr=\"value%d\"] {}", i);
    sheet.AddCSSRules(buf);
  }
}

TEST(RuleSetTest, LargeNumberOfAttributeRules) {
  test::TaskEnvironment task_environment;
  base::test::ScopedFeatureList feature_list;
  css_test_helpers::TestStyleSheet sheet;
  AddManyAttributeRules(feature_list, sheet);

  sheet.AddCSSRules("[otherattr=\"value\"] {}");

  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> list = rule_set.AttrRules(AtomicString("attr"));
  ASSERT_FALSE(list.empty());

  EXPECT_TRUE(rule_set.CanIgnoreEntireList(list, AtomicString("attr"),
                                           AtomicString("notfound")));
  EXPECT_FALSE(rule_set.CanIgnoreEntireList(list, AtomicString("attr"),
                                            AtomicString("value20")));
  EXPECT_FALSE(rule_set.CanIgnoreEntireList(list, AtomicString("attr"),
                                            AtomicString("VALUE20")));

  // A false positive that we expect (value20 is a substring, even though
  // the rule said = and not =*, so we need to check the entire set).
  EXPECT_FALSE(rule_set.CanIgnoreEntireList(list, AtomicString("attr"),
                                            AtomicString("--value20--")));

  // One rule is not enough to build a tree, so we will not mass-reject
  // anything on otherattr.
  base::span<const RuleData> list2 =
      rule_set.AttrRules(AtomicString("otherattr"));
  EXPECT_FALSE(rule_set.CanIgnoreEntireList(list2, AtomicString("otherattr"),
                                            AtomicString("notfound")));
}

TEST(RuleSetTest, LargeNumberOfAttributeRulesWithEmpty) {
  test::TaskEnvironment task_environment;
  base::test::ScopedFeatureList feature_list;
  css_test_helpers::TestStyleSheet sheet;
  AddManyAttributeRules(feature_list, sheet);

  sheet.AddCSSRules("[attr=\"\"] {}");

  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> list = rule_set.AttrRules(AtomicString("attr"));
  ASSERT_FALSE(list.empty());
  EXPECT_TRUE(rule_set.CanIgnoreEntireList(list, AtomicString("attr"),
                                           AtomicString("notfound")));
  EXPECT_FALSE(
      rule_set.CanIgnoreEntireList(list, AtomicString("attr"), g_empty_atom));
}

TEST(RuleSetTest, LargeNumberOfAttributeRulesWithCatchAll) {
  test::TaskEnvironment task_environment;
  base::test::ScopedFeatureList feature_list;
  css_test_helpers::TestStyleSheet sheet;
  AddManyAttributeRules(feature_list, sheet);

  // This should match everything, so we cannot reject anything.
  sheet.AddCSSRules("[attr] {}");

  RuleSet& rule_set = sheet.GetRuleSet();

  base::span<const RuleData> list = rule_set.AttrRules(AtomicString("attr"));
  ASSERT_FALSE(list.empty());
  EXPECT_FALSE(rule_set.CanIgnoreEntireList(list, AtomicString("attr"),
                                            AtomicString("notfound")));
  EXPECT_FALSE(
      rule_set.CanIgnoreEntireList(list, AtomicString("attr"), g_empty_atom));
}

TEST(RuleSetTest, LargeNumberOfAttributeRulesWithCatchAll2) {
  test::TaskEnvironment task_environment;
  base::test::ScopedFeatureList feature_list;
  css_test_helpers::TestStyleSheet sheet;
  AddManyAttributeRules(feature_list, sheet);

  // This should _also_ match everything, so we cannot reject anything.
  sheet.AddCSSRules("[attr^=\"\"] {}");

  RuleSet& rule_set = sheet.GetRuleSet();

  base::span<const RuleData> list = rule_set.AttrRules(AtomicString("attr"));
  ASSERT_FALSE(list.empty());
  EXPECT_FALSE(rule_set.CanIgnoreEntireList(list, AtomicString("attr"),
                                            AtomicString("notfound")));
  EXPECT_FALSE(
      rule_set.CanIgnoreEntireList(list, AtomicString("attr"), g_empty_atom));
}

#if DCHECK_IS_ON()  // Requires all_rules_, to find back the rules we add.

// Parse the given selector, buckets it and returns which of the constituent
// simple selectors were marked as covered by that bucketing. Note the the
// result value is stored in the order the selector is stored, which means
// that the order of the compound selectors are reversed (see comment in
// CSSSelectorParser::ConsumeComplexSelector()).
//
// A single selector may produce more than one RuleData, since visited-dependent
// rules are added to the RuleSet twice. The `rule_index` parameter can used
// to specify which of the added RuleData objects we want to produce bucket-
// coverage information from.
std::deque<bool> CoveredByBucketing(const String& selector_text,
                                    wtf_size_t rule_index = 0) {
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(selector_text + " { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const HeapVector<RuleData>& rules = rule_set.AllRulesForTest();
  EXPECT_LT(rule_index, rules.size());
  if (rule_index >= rules.size()) {
    return {};
  } else {
    const CSSSelector* selector = &rules[rule_index].Selector();

    std::deque<bool> covered;
    while (selector) {
      covered.push_back(selector->IsCoveredByBucketing());
      selector = selector->NextSimpleSelector();
    }
    return covered;
  }
}

wtf_size_t RuleCount(const String& selector_text) {
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(selector_text + " { }");
  return sheet.GetRuleSet().AllRulesForTest().size();
}

TEST(RuleSetTest, IsCoveredByBucketing) {
  test::TaskEnvironment task_environment;
  // Base cases.
  EXPECT_THAT(CoveredByBucketing(".c"), ElementsAreArray({true}));
  EXPECT_THAT(CoveredByBucketing("#id.c"), ElementsAreArray({true, false}));
  EXPECT_THAT(CoveredByBucketing(".c .c.c"),
              ElementsAreArray({true, true, false}));
  EXPECT_THAT(
      CoveredByBucketing(".a.b.c"),
      ElementsAreArray(
          {false, false, true}));  // See findBestRuleSetAndAdd_ThreeClasses.
  EXPECT_THAT(CoveredByBucketing(".c > [attr]"),
              ElementsAreArray({false, false}));
  EXPECT_THAT(CoveredByBucketing("*"), ElementsAreArray({true}));

  // Tag namespacing (including universal selector).
  EXPECT_THAT(CoveredByBucketing("div"), ElementsAreArray({true}));
  EXPECT_THAT(CoveredByBucketing("*|div"), ElementsAreArray({true}));
  EXPECT_THAT(
      CoveredByBucketing("@namespace ns \"http://example.org\";\nns|div"),
      ElementsAreArray({false}));
  EXPECT_THAT(CoveredByBucketing("@namespace \"http://example.org\";\ndiv"),
              ElementsAreArray({false}));
  EXPECT_THAT(CoveredByBucketing("@namespace \"http://example.org\";\n*"),
              ElementsAreArray({false}));

  // Attribute selectors.
  EXPECT_THAT(CoveredByBucketing("[attr]"), ElementsAreArray({false}));
  EXPECT_THAT(CoveredByBucketing("div[attr]"),
              ElementsAreArray({false, false}));

  // Link pseudo-class behavior due to visited multi-bucketing.
  EXPECT_THAT(CoveredByBucketing(":any-link"), ElementsAreArray({true}));
  EXPECT_THAT(CoveredByBucketing(":visited:link"),
              ElementsAreArray({false, false}));
  EXPECT_THAT(CoveredByBucketing(":visited:any-link"),
              ElementsAreArray({false, false}));
  EXPECT_THAT(CoveredByBucketing(":any-link:visited"),
              ElementsAreArray({false, false}));

  // The second rule added by visited-dependent selectors must not have the
  // covered-by-bucketing flag set.
  EXPECT_THAT(CoveredByBucketing(":visited", /* rule_index */ 1u),
              ElementsAreArray({false}));
  EXPECT_THAT(CoveredByBucketing(":link", /* rule_index */ 1u),
              ElementsAreArray({false}));

  // Some more pseudos.
  EXPECT_THAT(CoveredByBucketing(":focus"), ElementsAreArray({true}));
  EXPECT_THAT(CoveredByBucketing(":focus-visible"), ElementsAreArray({true}));
  EXPECT_THAT(CoveredByBucketing(":host"), ElementsAreArray({false}));
}

TEST(RuleSetTest, VisitedDependentRuleCount) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(2u, RuleCount(":link"));
  EXPECT_EQ(2u, RuleCount(":visited"));
  // Not visited-dependent:
  EXPECT_EQ(1u, RuleCount("#a"));
  EXPECT_EQ(1u, RuleCount(":any-link"));
}

#endif  // DCHECK_IS_ON()

TEST(RuleSetTest, SelectorIndexLimit) {
  test::TaskEnvironment task_environment;
  // It's not feasible to run this test for a large number of bits. If the
  // number of bits have increased to a large number, consider removing this
  // test and making do with RuleSetTest.RuleDataSelectorIndexLimit.
  static_assert(
      RuleData::kSelectorIndexBits == 13,
      "Please manually consider whether this test should be removed.");

  StringBuilder builder;

  // We use 13 bits to storing the selector start index in RuleData. This is a
  // test to check that we don't regress. We WONTFIX issues asking for more
  // since 2^13 simple selectors in a style rule is already excessive.
  for (unsigned i = 0; i < 8191; i++) {
    builder.Append("div,");
  }

  builder.Append("b,span {}");

  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(builder.ToString());
  const RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> rules = rule_set.TagRules(AtomicString("b"));
  ASSERT_EQ(1u, rules.size());
  EXPECT_EQ("b", rules.front().Selector().TagQName().LocalName());
  EXPECT_TRUE(rule_set.TagRules(AtomicString("span")).empty());
}

TEST(RuleSetTest, RuleDataPositionLimit) {
  test::TaskEnvironment task_environment;
  StyleRule* rule = CreateDummyStyleRule();
  AddRuleFlags flags = kRuleHasNoSpecialState;
  const unsigned selector_index = 0;
  const ContainerQuery* container_query = nullptr;
  const CascadeLayer* cascade_layer = nullptr;
  const StyleScope* style_scope = nullptr;

  auto* rule_set = MakeGarbageCollected<RuleSet>();
  for (int i = 0; i < (1 << RuleData::kPositionBits) + 1; ++i) {
    rule_set->AddRule(rule, selector_index, flags, container_query,
                      cascade_layer, style_scope);
  }
  EXPECT_EQ(1u << RuleData::kPositionBits, rule_set->RuleCount());
}

TEST(RuleSetTest, RuleCountNotIncreasedByInvalidRuleData) {
  test::TaskEnvironment task_environment;
  auto* rule_set = MakeGarbageCollected<RuleSet>();
  EXPECT_EQ(0u, rule_set->RuleCount());

  AddRuleFlags flags = kRuleHasNoSpecialState;
  StyleRule* rule = CreateDummyStyleRule();

  // Add with valid selector_index=0.
  rule_set->AddRule(rule, 0, flags, nullptr /* container_query */,
                    nullptr /* cascade_layer */, nullptr /* scope */);
  EXPECT_EQ(1u, rule_set->RuleCount());

  // Adding with invalid selector_index should not lead to a change in count.
  rule_set->AddRule(rule, 1 << RuleData::kSelectorIndexBits, flags,
                    nullptr /* container_query */, nullptr /* cascade_layer */,
                    nullptr /* scope */);
  EXPECT_EQ(1u, rule_set->RuleCount());
}

TEST(RuleSetTest, NoStyleScope) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("#b {}");
  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> rules = rule_set.IdRules(AtomicString("b"));
  ASSERT_EQ(1u, rules.size());
  EXPECT_EQ(0u, rule_set.ScopeIntervals().size());
}

TEST(RuleSetTest, StyleScope) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules("@scope (.a) { #b {} }");
  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> rules = rule_set.IdRules(AtomicString("b"));
  ASSERT_EQ(1u, rules.size());
  EXPECT_EQ(1u, rule_set.ScopeIntervals().size());
}

TEST(RuleSetTest, NestedStyleScope) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(R"CSS(
    @scope (.a) {
      #a {}
      @scope (.b) {
        #b {}
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  base::span<const RuleData> a_rules = rule_set.IdRules(AtomicString("a"));
  base::span<const RuleData> b_rules = rule_set.IdRules(AtomicString("b"));

  ASSERT_EQ(1u, a_rules.size());
  ASSERT_EQ(1u, b_rules.size());

  ASSERT_EQ(2u, rule_set.ScopeIntervals().size());

  EXPECT_EQ(a_rules.front().GetPosition(),
            rule_set.ScopeIntervals()[0].start_position);
  const StyleScope* a_rule_scope = rule_set.ScopeIntervals()[0].value;

  EXPECT_EQ(b_rules.front().GetPosition(),
            rule_set.ScopeIntervals()[1].start_position);
  const StyleScope* b_rule_scope = rule_set.ScopeIntervals()[1].value;

  EXPECT_NE(nullptr, a_rule_scope);
  EXPECT_EQ(nullptr, a_rule_scope->Parent());

  EXPECT_NE(nullptr, b_rule_scope);
  EXPECT_EQ(a_rule_scope, b_rule_scope->Parent());

  EXPECT_NE(nullptr, b_rule_scope->Parent());
  EXPECT_EQ(nullptr, b_rule_scope->Parent()->Parent());
}

TEST(RuleSetTest, SingleScope) {
  test::TaskEnvironment task_environment;
  {
    css_test_helpers::TestStyleSheet sheet;
    sheet.AddCSSRules(R"CSS(
      @scope {
        div { color: green; }
      }
    )CSS");
    EXPECT_TRUE(sheet.GetRuleSet().SingleScope());
  }

  {
    css_test_helpers::TestStyleSheet sheet;
    sheet.AddCSSRules(R"CSS(
      @scope {
        div { color: green; }
        div { color: red; }
        div { color: blue; }
      }
    )CSS");
    EXPECT_TRUE(sheet.GetRuleSet().SingleScope());
  }

  {
    css_test_helpers::TestStyleSheet sheet;
    sheet.AddCSSRules(R"CSS(
      @scope (.a) {
        div { color: green; }
      }
    )CSS");
    EXPECT_TRUE(sheet.GetRuleSet().SingleScope());
  }

  {
    css_test_helpers::TestStyleSheet sheet;
    sheet.AddCSSRules(R"CSS(
      @scope (.a) {
        div { color: green; }
      }
      div { color: red; }
    )CSS");
    EXPECT_FALSE(sheet.GetRuleSet().SingleScope());
  }

  {
    css_test_helpers::TestStyleSheet sheet;
    sheet.AddCSSRules(R"CSS(
      div { color: red; }
      @scope (.a) {
        div { color: green; }
      }
    )CSS");
    EXPECT_FALSE(sheet.GetRuleSet().SingleScope());
  }

  {
    css_test_helpers::TestStyleSheet sheet;
    sheet.AddCSSRules(R"CSS(
      @scope {
        div { color: green; }
      }
      div { color: red; }
    )CSS");
    EXPECT_FALSE(sheet.GetRuleSet().SingleScope());
  }

  {
    css_test_helpers::TestStyleSheet sheet;
    sheet.AddCSSRules(R"CSS(
      div { color: red; }
      @scope {
        div { color: green; }
      }
    )CSS");
    EXPECT_FALSE(sheet.GetRuleSet().SingleScope());
  }
}

TEST(RuleSetTest, ParentPseudoBucketing_Single) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(R"CSS(
    .a {
      & {
        color: green;
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(0u, rule_set.UniversalRules().size());
  EXPECT_EQ(2u, rule_set.ClassRules(AtomicString("a")).size());
}

TEST(RuleSetTest, ParentPseudoBucketing_Multiple) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(R"CSS(
    .a, .b {
      & {
        color: green;
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(1u, rule_set.UniversalRules().size());
  EXPECT_EQ(1u, rule_set.ClassRules(AtomicString("a")).size());
  EXPECT_EQ(1u, rule_set.ClassRules(AtomicString("b")).size());
}

TEST(RuleSetTest, ScopePseudoBucketing_Single) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(R"CSS(
    @scope (.a) {
      :scope {
        color: green;
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(0u, rule_set.UniversalRules().size());
  EXPECT_EQ(1u, rule_set.ClassRules(AtomicString("a")).size());
}

TEST(RuleSetTest, ScopePseudoBucketing_Multiple) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(R"CSS(
    @scope (.a, .b) {
      :scope {
        color: green;
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(1u, rule_set.UniversalRules().size());
  EXPECT_EQ(0u, rule_set.ClassRules(AtomicString("a")).size());
  EXPECT_EQ(0u, rule_set.ClassRules(AtomicString("b")).size());
}

TEST(RuleSetTest, ScopePseudoBucketing_WhereIs) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(R"CSS(
    @scope (.a) {
      :where(:scope) {
        color: green;
      }
      :is(:scope) {
        color: green;
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(0u, rule_set.UniversalRules().size());
  EXPECT_EQ(2u, rule_set.ClassRules(AtomicString("a")).size());
}

TEST(RuleSetTest, ScopePseudoBucketing_WhereIsMultiple) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(R"CSS(
    @scope (.a, .b) {
      :where(:scope) {
        color: green;
      }
      :is(:scope) {
        color: green;
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(2u, rule_set.UniversalRules().size());
  EXPECT_EQ(0u, rule_set.ClassRules(AtomicString("a")).size());
  EXPECT_EQ(0u, rule_set.ClassRules(AtomicString("b")).size());
}

TEST(RuleSetTest, ScopePseudoBucketing_Implicit) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(R"CSS(
    @scope {
      :scope {
        color: green;
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(1u, rule_set.UniversalRules().size());
}

TEST(RuleSetTest, ScopePseudoBucketing_NestedDeclarations) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(R"CSS(
    .a {
      @scope (&) {
        color: green; /* Matches like :where(:scope) */
      }
    }
  )CSS");
  RuleSet& rule_set = sheet.GetRuleSet();
  EXPECT_EQ(0u, rule_set.UniversalRules().size());
  EXPECT_EQ(2u, rule_set.ClassRules(AtomicString("a")).size());
}

class RuleSetCascadeLayerTest : public SimTest {
 public:
  using LayerName = StyleRuleBase::LayerName;

 protected:
  const RuleSet& GetRuleSet() {
    RuleSet& rule_set =
        To<HTMLStyleElement>(GetDocument().QuerySelector(AtomicString("style")))
            ->sheet()
            ->Contents()
            ->Ensur
"""


```