Response:
Let's break down the thought process to analyze the provided C++ test file.

**1. Initial Understanding: Core Purpose**

The filename `css_selector_test.cc` immediately suggests this file contains unit tests for CSS selectors within the Blink rendering engine. The `TEST()` macros confirm this. The `#include` directives give hints about the tested components:

* `testing/gtest/include/gtest/gtest.h`: Indicates Google Test framework is being used.
* `third_party/blink/renderer/core/css/...`: Points to the CSS-related parts of the Blink engine. Specifically, `css_test_helpers.h`, `parser/css_parser.h`, `rule_set.h`.
* `third_party/blink/renderer/core/html_names.h`:  Suggests interaction with HTML elements.
* `third_party/blink/renderer/platform/testing/task_environment.h`:  Indicates the tests need a simulated environment.

**2. Dissecting the Tests: Identifying Functionality**

The `TEST()` blocks are the key to understanding the functionality. I'll go through each one and infer its purpose:

* **`CSSSelector, Representations`:** This test defines a set of CSS rules and adds them to a `TestStyleSheet`. It then checks the number of rules added. The `#ifndef NDEBUG` block suggests it also has a debug output. The variety of selectors hints at testing the parsing and internal representation of different CSS selector types.

* **`CSSSelector, OverflowRareDataMatchNth`:** This test focuses on edge cases related to the `:nth-child()` pseudo-class. The use of `std::numeric_limits<int>::max()` and `min()` suggests testing for integer overflow scenarios. The `MatchNth()` method likely determines if an element matches an `:nth-child()` selector.

* **`CSSSelector, Specificity_Is`:** This test uses the `:is()` pseudo-class and compares the specificity of selectors using `:is()` with equivalent selectors without it. This points to verifying the correct specificity calculation for `:is()`.

* **`CSSSelector, Specificity_Where`:** Similar to `Specificity_Is`, but for the `:where()` pseudo-class. This indicates testing the specificity of `:where()`, which is known to have zero specificity impact on its arguments.

* **`CSSSelector, Specificity_Slotted`:** This test involves `::slotted()`, a pseudo-element related to Shadow DOM. It compares its specificity to other pseudo-elements.

* **`CSSSelector, Specificity_Host`:**  Tests the specificity of the `:host` pseudo-class used within Shadow DOM.

* **`CSSSelector, Specificity_HostContext`:** Tests the specificity of the `:host-context()` pseudo-class, also related to Shadow DOM.

* **`CSSSelector, Specificity_Not`:**  Tests the specificity of the `:not()` pseudo-class. It compares its specificity to equivalent `:is()` selectors.

* **`CSSSelector, Specificity_Has`:** Tests the specificity of the `:has()` pseudo-class, which checks for the presence of descendant elements.

* **`CSSSelector, HasLinkOrVisited`:** This test checks a specific method, `HasLinkOrVisited()`, which determines if a selector includes the `:link` or `:visited` pseudo-classes. This is important for privacy and performance considerations in browser rendering.

* **`CSSSelector, CueDefaultNamespace`:** This test deals with the `::cue()` pseudo-element used for styling video subtitles. It verifies that the default XML namespace doesn't affect the parsing of the cue selector's arguments.

* **`CSSSelector, CopyInvalidList`, `CopyValidList`, `FirstInInvalidList`:** These tests focus on the `CSSSelectorList` class, checking its behavior when copying and accessing elements in both valid and invalid (empty) lists.

* **`CSSSelector, ImplicitPseudoDescendant`, `ImplicitPseudoChild`, `NonImplicitPseudoChild`, `ImplicitScopeSpecificity`, `ExplicitScopeSpecificity`:** These tests explore the `:scope` pseudo-class (implicit and explicit) and how it interacts with descendant and child combinators, including its effect on specificity.

* **`CSSSelector, CheckSelectorTextExpandingPseudoParent`:** This test appears to be about how nested selectors and the `&` (parent selector) are represented and expanded.

* **`CSSSelector, CheckHasArgumentMatchInShadowTreeFlag`:** This test investigates a specific flag, `HasArgumentMatchInShadowTree()`, related to the `:has()` pseudo-class and its behavior within Shadow DOM. It checks if the `:has()` argument needs to match elements inside the shadow tree.

**3. Identifying Relationships with Web Technologies**

As I analyzed each test, I looked for connections to HTML, CSS, and JavaScript:

* **HTML:**  The tests use HTML tags (`div`, `summary`, `video`). Selectors target these elements. Shadow DOM features (`:host`, `:host-context`, `::slotted`) are directly related to HTML's component model.
* **CSS:** This is the core focus. The tests parse CSS selectors, evaluate their specificity, and check the behavior of various pseudo-classes and pseudo-elements.
* **JavaScript:** While this file is C++, the functionality it tests is directly used when JavaScript interacts with the DOM and CSSOM (CSS Object Model). For example, JavaScript can query elements based on CSS selectors.

**4. Providing Examples and Scenarios**

For each relationship, I tried to come up with concrete examples of how these features are used in web development. This involves writing snippets of HTML, CSS, and sometimes explaining how JavaScript might interact.

**5. Logical Reasoning and Hypothetical Inputs/Outputs**

For tests involving logic (like `OverflowRareDataMatchNth` or specificity calculations), I tried to:

* **Identify the core function:** What is the test trying to verify? (e.g., the `MatchNth` function or specificity calculation logic).
* **Determine the inputs:** What data is being fed to the function/method? (e.g., the `a` and `b` values in `:nth-child(an+b)`, the selector string).
* **Predict the expected output:** Based on my understanding of the CSS specification and the test's intent, what should the function return? (e.g., `true` or `false` for `MatchNth`, a specific specificity value).

**6. Identifying Common User/Programming Errors**

I thought about common mistakes developers make when working with CSS selectors, especially the more complex ones:

* **Specificity misunderstandings:**  Incorrectly predicting which CSS rule will apply.
* **Typos in selectors:** Simple mistakes that prevent styles from being applied.
* **Incorrect use of pseudo-classes/elements:**  Misunderstanding their behavior or limitations.
* **Shadow DOM interaction issues:**  Not understanding how selectors pierce or don't pierce shadow boundaries.

**7. Tracing User Operations (Debugging Clues)**

This part requires thinking about how user actions translate into browser behavior that might trigger the code being tested:

* **Page load:**  The browser parses HTML and CSS, which involves the code being tested.
* **User interaction:** Hovering, clicking links, focusing elements can trigger state changes that CSS selectors depend on (e.g., `:hover`, `:focus`, `:visited`).
* **JavaScript manipulation:**  JavaScript can dynamically add, remove, or modify elements and their classes, which affects selector matching.
* **Shadow DOM creation/modification:** Creating or changing Shadow DOM structures directly impacts the relevance of Shadow DOM selectors.

**Self-Correction/Refinement During the Process:**

* **Initially, I might just identify the test name and a general idea.** Then, I would look deeper at the code within the `TEST()` block to understand the specifics.
* **If I wasn't sure about a particular CSS feature (like `:where()` or `::slotted()`), I would quickly look up its definition and purpose.** This ensures my explanations are accurate.
* **I tried to connect the C++ test code back to the higher-level web concepts.**  Why are these tests important for a web browser? What user-facing issues could these tests help prevent?

By following this systematic process of reading the code, inferring purpose, connecting to web technologies, providing examples, reasoning logically, and considering potential errors and debugging scenarios, I was able to generate a comprehensive analysis of the provided C++ test file.
这个文件 `blink/renderer/core/css/css_selector_test.cc` 是 Chromium Blink 渲染引擎中的一个 C++ 单元测试文件。它的主要功能是 **测试 CSS 选择器的各种特性和行为是否符合预期**。

更具体地说，这个文件测试了 `blink::CSSSelector` 类及其相关功能，涵盖了 CSS 选择器的解析、匹配、特异性计算以及与其他 CSS 特性的交互。

**它与 javascript, html, css 的功能有关系，具体举例说明如下：**

* **CSS (核心关系):**  这个文件直接测试 CSS 选择器的实现。它验证了各种 CSS 选择器语法（例如，标签选择器、类选择器、ID 选择器、属性选择器、伪类、伪元素、组合器等）是否被正确解析和处理。
    * **例子:**
        * 测试用例 `TEST(CSSSelector, Representations)` 中定义了大量的 CSS 规则字符串，例如 `"div {}"`, `"#id {}"`, `".class {}"`, `"div:hover {}"`,  这些规则中的选择器会被解析并用于后续的测试。
        * 测试用例 `TEST(CSSSelector, Specificity_Is)` 验证了 `:is()` 伪类的特异性计算是否正确。例如，`Specificity(".a :is(.b, div.c)")` 和 `Specificity(".a div.c")` 应该返回相同的值，因为 `:is()` 不会影响特异性。

* **HTML:** CSS 选择器的目的是选择 HTML 元素。这个文件虽然不直接操作 HTML DOM 树，但它测试的选择器语法是用来匹配 HTML 元素的。
    * **例子:**
        * 选择器 `"div"` 会匹配所有的 `<div>` 元素。
        * 选择器 `".class"` 会匹配所有带有 `class="class"` 的元素。
        * 测试用例 `TEST(CSSSelector, ImplicitPseudoDescendant)` 创建了一个针对 `<div>` 元素的 CSS 选择器。

* **JavaScript:** JavaScript 可以通过 DOM API (例如 `querySelectorAll`) 使用 CSS 选择器来查询和操作 HTML 元素。这个文件中测试的 CSS 选择器功能是 JavaScript 操作 DOM 的基础。
    * **例子:**  虽然此文件是 C++ 测试，但其测试的逻辑直接影响 JavaScript 中 `document.querySelectorAll(".my-class")` 等方法的行为。如果 CSS 选择器解析或匹配有误，JavaScript 的选择器 API 也会受到影响。

**逻辑推理与假设输入/输出：**

许多测试用例都基于逻辑推理，验证特定 CSS 选择器在特定情况下的行为。

* **测试用例 `TEST(CSSSelector, OverflowRareDataMatchNth)`:**
    * **假设输入:**  `:nth-child(a, b)` 选择器的 `a` 和 `b` 值设置为接近或等于整数的最大值和最小值。
    * **逻辑推理:** 当计算 `an + b` 时，如果 `a` 和 `b` 的值导致整数溢出，匹配结果应该为 `false`。
    * **输出:**  `EXPECT_FALSE(selector.MatchNth(max_int))` 等断言验证了在溢出情况下 `MatchNth` 方法返回 `false`。

* **测试用例 `TEST(CSSSelector, Specificity_Is)`:**
    * **假设输入:** 包含 `:is()` 伪类的 CSS 选择器字符串，例如 `".a :is(.b, div.c)"`。
    * **逻辑推理:** `:is()` 伪类本身不增加特异性，其特异性由其参数列表中特异性最高的选择器决定。
    * **输出:** `EXPECT_EQ(Specificity(".a :is(.b, div.c)"), Specificity(".a div.c"))` 断言验证了包含 `:is()` 的选择器和其等价的、特异性最高的参数选择器具有相同的特异性。

**用户或编程常见的使用错误举例说明：**

虽然这个文件是测试代码，但它覆盖了 CSS 选择器可能出现的各种情况，也间接反映了用户或编程中可能出现的错误。

* **特异性理解错误:** 用户可能不清楚不同选择器的特异性权重，导致样式应用出现意外。测试用例 `TEST(CSSSelector, Specificity_...)` 系列验证了各种选择器的特异性计算，帮助开发者理解。
    * **例子:** 用户可能认为 `.a :is(.b, div.c)` 的特异性与 `.a .b` 相同，但实际上它与 `.a div.c` 相同。

* **伪类和伪元素的误用:**  用户可能混淆伪类和伪元素，或者不清楚某些伪类和伪元素的适用场景。测试用例中包含了对各种伪类（例如 `:hover`, `:visited`, `:nth-child`, `:not`, `:is`, `:where`, `:has`）和伪元素（例如 `::first-line`, `::cue`, `::slotted`) 的测试。
    * **例子:** 用户可能错误地将 `:visited` 用于非链接元素，或者不理解 `:not(:visited)` 的含义。

* **`:nth-child` 的复杂用法错误:**  `a` 和 `b` 参数的组合可能会导致理解上的困难，尤其是在涉及 `of <selector-list>` 语法时。测试用例 `TEST(CSSSelector, OverflowRareDataMatchNth)` 覆盖了极端情况，也提醒开发者注意参数的有效范围。

* **Shadow DOM 选择器错误:**  用户可能不理解 `:host`, `:host-context`, `::slotted` 等 Shadow DOM 相关选择器的作用域和穿透规则。测试用例 `TEST(CSSSelector, Specificity_Host)`、`TEST(CSSSelector, Specificity_HostContext)` 和 `TEST(CSSSelector, Specificity_Slotted)` 验证了这些选择器的特异性，有助于开发者正确使用。

* **`:has()` 的复杂用法错误:**  `:has()` 伪类允许根据后代元素的存在与否进行选择，其语法和行为可能比较复杂。测试用例 `TEST(CSSSelector, Specificity_Has)` 和 `TEST(CSSSelector, CheckHasArgumentMatchInShadowTreeFlag)` 覆盖了 `:has()` 的各种用法，有助于避免错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

虽然用户不会直接与这个 C++ 测试文件交互，但理解用户操作如何触发 CSS 选择器的匹配过程，可以帮助理解这个测试文件的意义。以下是一些可能的步骤：

1. **用户访问网页:**  当用户在浏览器中打开一个网页时，浏览器会下载 HTML、CSS 和 JavaScript 资源。
2. **浏览器解析 HTML 和 CSS:** 浏览器开始解析 HTML 构建 DOM 树，并解析 CSS 构建 CSSOM 树。在这个过程中，CSS 选择器会被解析并存储在内部的数据结构中，这正是 `css_selector_test.cc` 所测试的核心部分。
3. **样式计算和匹配:**  浏览器将 CSSOM 中的样式规则与 DOM 树中的元素进行匹配。这个匹配过程依赖于 `blink::CSSSelector` 类的实现。例如，当浏览器遇到一个 `<div>` 元素时，它会检查是否有 CSS 规则的选择器能够匹配这个 `<div>` 元素。
4. **动态样式更新 (例如，`:hover`):** 当用户与网页进行交互时，例如鼠标悬停在一个元素上，浏览器会重新计算样式。`:hover` 伪类的状态发生改变，浏览器需要重新评估哪些 CSS 规则适用。`TEST(CSSSelector, HasLinkOrVisited)` 中对包含 `:hover` 的选择器的测试，就与这种动态更新有关。
5. **JavaScript 操作 DOM 和样式:**  JavaScript 可以通过 `querySelectorAll` 等 API 使用 CSS 选择器来查询元素，或者动态地修改元素的类名、属性等，从而触发 CSS 选择器的重新匹配。
6. **Shadow DOM 的渲染:** 如果网页使用了 Shadow DOM，浏览器在渲染时需要考虑 Shadow DOM 的边界和选择器的穿透规则。`TEST(CSSSelector, Specificity_Host)` 等测试用例覆盖了与 Shadow DOM 相关的选择器。

**作为调试线索:**

如果前端开发者在开发过程中遇到 CSS 样式不生效的问题，很可能与 CSS 选择器有关。

* **使用浏览器开发者工具:**  开发者可以使用浏览器的开发者工具（例如 Chrome DevTools）查看元素的样式，以及哪些 CSS 规则匹配上了该元素，哪些没有匹配上。DevTools 会显示计算后的样式、规则的来源、以及选择器的特异性等信息。
* **检查 CSS 选择器语法:**  开发者需要仔细检查 CSS 选择器的语法是否正确，是否有拼写错误，是否符合 CSS 规范。
* **理解选择器的特异性:**  如果多个 CSS 规则都匹配同一个元素，特异性更高的规则会生效。开发者需要理解不同选择器的特异性权重，才能正确地覆盖样式。
* **考虑 Shadow DOM 的影响:**  如果样式问题出现在 Shadow DOM 内部或边界处，开发者需要了解 Shadow DOM 的选择器规则。

`css_selector_test.cc` 文件中测试的各种边界情况和复杂选择器，可以帮助开发者理解 CSS 选择器的内部工作原理，从而更好地进行调试。如果 Blink 引擎的这些测试都通过了，那么在正常情况下，浏览器对 CSS 选择器的处理应该是符合预期的。反之，如果这些测试失败，就意味着浏览器的 CSS 选择器实现存在 bug，可能会导致网页样式显示异常。

### 提示词
```
这是目录为blink/renderer/core/css/css_selector_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/rule_set.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

unsigned Specificity(const String& selector_text) {
  CSSSelectorList* selector_list =
      css_test_helpers::ParseSelectorList(selector_text);
  return selector_list->First()->Specificity();
}

bool HasLinkOrVisited(const String& selector_text) {
  CSSSelectorList* selector_list =
      css_test_helpers::ParseSelectorList(selector_text);
  return selector_list->First()->HasLinkOrVisited();
}

}  // namespace

TEST(CSSSelector, Representations) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  const char* css_rules =
      "summary::-webkit-details-marker { }"
      "* {}"
      "div {}"
      "#id {}"
      ".class {}"
      "[attr] {}"
      "div:hover {}"
      "div:nth-child(2){}"
      "div:nth-child(2n+1 of .a){}"
      ".class#id { }"
      "#id.class { }"
      "[attr]#id { }"
      "div[attr]#id { }"
      "div::first-line { }"
      ".a.b.c { }"
      "div:not(.a) { }"        // without class a
      "div:not(:visited) { }"  // without the visited pseudo class

      "[attr=\"value\"] { }"   // Exact equality
      "[attr~=\"value\"] { }"  // One of a space-separated list
      "[attr^=\"value\"] { }"  // Begins with
      "[attr$=\"value\"] { }"  // Ends with
      "[attr*=\"value\"] { }"  // Substring equal to
      "[attr|=\"value\"] { }"  // One of a hyphen-separated list

      ".a .b { }"    // .b is a descendant of .a
      ".a > .b { }"  // .b is a direct descendant of .a
      ".a ~ .b { }"  // .a precedes .b in sibling order
      ".a + .b { }"  // .a element immediately precedes .b in sibling order
      ".a, .b { }"   // matches .a or .b

      ".a.b .c {}";

  sheet.AddCSSRules(css_rules);
  EXPECT_EQ(30u,
            sheet.GetRuleSet().RuleCount());  // .a, .b counts as two rules.
#ifndef NDEBUG
  sheet.GetRuleSet().Show();
#endif
}

TEST(CSSSelector, OverflowRareDataMatchNth) {
  test::TaskEnvironment task_environment;
  int max_int = std::numeric_limits<int>::max();
  int min_int = std::numeric_limits<int>::min();
  CSSSelector selector;

  // Overflow count - b (max_int - -1 = max_int + 1)
  selector.SetNth(1, -1, /*sub_selector=*/nullptr);
  EXPECT_FALSE(selector.MatchNth(max_int));
  // 0 - (min_int) = max_int + 1
  selector.SetNth(1, min_int, /*sub_selector=*/nullptr);
  EXPECT_FALSE(selector.MatchNth(0));

  // min_int - 1
  selector.SetNth(-1, min_int, /*sub_selector=*/nullptr);
  EXPECT_FALSE(selector.MatchNth(1));

  // a shouldn't negate to itself (and min_int negates to itself).
  // Note: This test can only fail when using ubsan.
  selector.SetNth(min_int, 10, /*sub_selector=*/nullptr);
  EXPECT_FALSE(selector.MatchNth(2));
}

TEST(CSSSelector, Specificity_Is) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(Specificity(".a :is(.b, div.c)"), Specificity(".a div.c"));
  EXPECT_EQ(Specificity(".a :is(.c#d, .e)"), Specificity(".a .c#d"));
  EXPECT_EQ(Specificity(":is(.e+.f, .g>.b, .h)"), Specificity(".e+.f"));
  EXPECT_EQ(Specificity(".a :is(.e+.f, .g>.b, .h#i)"), Specificity(".a .h#i"));
  EXPECT_EQ(Specificity(".a+:is(.b+span.f, :is(.c>.e, .g))"),
            Specificity(".a+.b+span.f"));
  EXPECT_EQ(Specificity("div > :is(div:where(span:where(.b ~ .c)))"),
            Specificity("div > div"));
  EXPECT_EQ(Specificity(":is(.c + .c + .c, .b + .c:not(span), .b + .c + .e)"),
            Specificity(".c + .c + .c"));
}

TEST(CSSSelector, Specificity_Where) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(Specificity(".a :where(.b, div.c)"), Specificity(".a"));
  EXPECT_EQ(Specificity(".a :where(.c#d, .e)"), Specificity(".a"));
  EXPECT_EQ(Specificity(":where(.e+.f, .g>.b, .h)"), Specificity("*"));
  EXPECT_EQ(Specificity(".a :where(.e+.f, .g>.b, .h#i)"), Specificity(".a"));
  EXPECT_EQ(Specificity("div > :where(.b+span.f, :where(.c>.e, .g))"),
            Specificity("div"));
  EXPECT_EQ(Specificity("div > :where(div:is(span:is(.b ~ .c)))"),
            Specificity("div"));
  EXPECT_EQ(
      Specificity(":where(.c + .c + .c, .b + .c:not(span), .b + .c + .e)"),
      Specificity("*"));
}

TEST(CSSSelector, Specificity_Slotted) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(Specificity("::slotted(.a)"), Specificity(".a::first-line"));
  EXPECT_EQ(Specificity("::slotted(*)"), Specificity("::first-line"));
}

TEST(CSSSelector, Specificity_Host) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(Specificity(":host"), Specificity(".host"));
  EXPECT_EQ(Specificity(":host(.a)"), Specificity(".host .a"));
  EXPECT_EQ(Specificity(":host(div#a.b)"), Specificity(".host div#a.b"));
}

TEST(CSSSelector, Specificity_HostContext) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(Specificity(":host-context(.a)"), Specificity(".host-context .a"));
  EXPECT_EQ(Specificity(":host-context(div#a.b)"),
            Specificity(".host-context div#a.b"));
}

TEST(CSSSelector, Specificity_Not) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(Specificity(":not(div)"), Specificity(":is(div)"));
  EXPECT_EQ(Specificity(":not(.a)"), Specificity(":is(.a)"));
  EXPECT_EQ(Specificity(":not(div.a)"), Specificity(":is(div.a)"));
  EXPECT_EQ(Specificity(".a :not(.b, div.c)"),
            Specificity(".a :is(.b, div.c)"));
  EXPECT_EQ(Specificity(".a :not(.c#d, .e)"), Specificity(".a :is(.c#d, .e)"));
  EXPECT_EQ(Specificity(".a :not(.e+.f, .g>.b, .h#i)"),
            Specificity(".a :is(.e+.f, .g>.b, .h#i)"));
  EXPECT_EQ(Specificity(":not(.c + .c + .c, .b + .c:not(span), .b + .c + .e)"),
            Specificity(":is(.c + .c + .c, .b + .c:not(span), .b + .c + .e)"));
}

TEST(CSSSelector, Specificity_Has) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(Specificity(":has(div)"), Specificity("div"));
  EXPECT_EQ(Specificity(":has(div)"), Specificity("* div"));
  EXPECT_EQ(Specificity(":has(~ div)"), Specificity("* ~ div"));
  EXPECT_EQ(Specificity(":has(> .a)"), Specificity("* > .a"));
  EXPECT_EQ(Specificity(":has(+ div.a)"), Specificity("* + div.a"));
  EXPECT_EQ(Specificity(".a :has(.b, div.c)"), Specificity(".a div.c"));
  EXPECT_EQ(Specificity(".a :has(.c#d, .e)"), Specificity(".a .c#d"));
  EXPECT_EQ(Specificity(":has(.e+.f, .g>.b, .h)"), Specificity(".e+.f"));
  EXPECT_EQ(Specificity(".a :has(.e+.f, .g>.b, .h#i)"), Specificity(".a .h#i"));
  EXPECT_EQ(Specificity("div > :has(div, div:where(span:where(.b ~ .c)))"),
            Specificity("div > div"));
  EXPECT_EQ(Specificity(":has(.c + .c + .c, .b + .c:not(span), .b + .c + .e)"),
            Specificity(".c + .c + .c"));
}

TEST(CSSSelector, HasLinkOrVisited) {
  test::TaskEnvironment task_environment;
  EXPECT_FALSE(HasLinkOrVisited("tag"));
  EXPECT_FALSE(HasLinkOrVisited("visited"));
  EXPECT_FALSE(HasLinkOrVisited("link"));
  EXPECT_FALSE(HasLinkOrVisited(".a"));
  EXPECT_FALSE(HasLinkOrVisited("#a:is(visited)"));
  EXPECT_FALSE(HasLinkOrVisited(":not(link):hover"));
  EXPECT_FALSE(HasLinkOrVisited(":hover"));
  EXPECT_FALSE(HasLinkOrVisited(":is(:hover)"));
  EXPECT_FALSE(HasLinkOrVisited(":not(:is(:hover))"));

  EXPECT_TRUE(HasLinkOrVisited(":visited"));
  EXPECT_TRUE(HasLinkOrVisited(":link"));
  EXPECT_TRUE(HasLinkOrVisited(":visited:link"));
  EXPECT_TRUE(HasLinkOrVisited(":not(:visited)"));
  EXPECT_TRUE(HasLinkOrVisited(":not(:link)"));
  EXPECT_TRUE(HasLinkOrVisited(":not(:is(:link))"));
  EXPECT_TRUE(HasLinkOrVisited(":is(:link)"));
  EXPECT_TRUE(HasLinkOrVisited(":is(.a, .b, :is(:visited))"));
  EXPECT_TRUE(HasLinkOrVisited("::cue(:visited)"));
  EXPECT_TRUE(HasLinkOrVisited("::cue(:link)"));
  EXPECT_TRUE(HasLinkOrVisited(":host(:link)"));
  EXPECT_TRUE(HasLinkOrVisited(":host-context(:link)"));
}

TEST(CSSSelector, CueDefaultNamespace) {
  test::TaskEnvironment task_environment;
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(R"HTML(
    @namespace "http://www.w3.org/1999/xhtml";
    video::cue(b) {}
  )HTML");

  const CSSSelector& cue_selector =
      sheet.GetRuleSet().CuePseudoRules()[0].Selector();
  EXPECT_EQ(cue_selector.GetPseudoType(), CSSSelector::kPseudoCue);

  const CSSSelectorList* cue_arguments = cue_selector.SelectorList();
  ASSERT_TRUE(cue_arguments);
  const CSSSelector* vtt_type_selector = cue_arguments->First();
  ASSERT_TRUE(vtt_type_selector);
  EXPECT_EQ(vtt_type_selector->TagQName().LocalName(), "b");
  // Default namespace should not affect VTT node type selector.
  EXPECT_EQ(vtt_type_selector->TagQName().NamespaceURI(), g_star_atom);
}

TEST(CSSSelector, CopyInvalidList) {
  test::TaskEnvironment task_environment;
  CSSSelectorList* list = CSSSelectorList::Empty();
  EXPECT_FALSE(list->IsValid());
  EXPECT_FALSE(list->Copy()->IsValid());
}

TEST(CSSSelector, CopyValidList) {
  test::TaskEnvironment task_environment;
  CSSSelectorList* list = css_test_helpers::ParseSelectorList(".a");
  EXPECT_TRUE(list->IsValid());
  EXPECT_TRUE(list->Copy()->IsValid());
}

TEST(CSSSelector, FirstInInvalidList) {
  test::TaskEnvironment task_environment;
  CSSSelectorList* list = CSSSelectorList::Empty();
  EXPECT_FALSE(list->IsValid());
  EXPECT_FALSE(list->First());
}

TEST(CSSSelector, ImplicitPseudoDescendant) {
  test::TaskEnvironment task_environment;
  CSSSelector selector[2] = {
      CSSSelector(html_names::kDivTag,
                  /* is_implicit */ false),
      CSSSelector(AtomicString("scope"), /* is_implicit */ true)};
  selector[0].SetRelation(CSSSelector::kDescendant);
  selector[1].SetLastInComplexSelector(true);
  EXPECT_EQ("div", selector[0].SelectorText());
}

TEST(CSSSelector, ImplicitPseudoChild) {
  test::TaskEnvironment task_environment;
  CSSSelector selector[2] = {
      CSSSelector(html_names::kDivTag,
                  /* is_implicit */ false),
      CSSSelector(AtomicString("scope"), /* is_implicit */ true)};
  selector[0].SetRelation(CSSSelector::kChild);
  selector[1].SetLastInComplexSelector(true);
  EXPECT_EQ("> div", selector[0].SelectorText());
}

TEST(CSSSelector, NonImplicitPseudoChild) {
  test::TaskEnvironment task_environment;
  CSSSelector selector[2] = {
      CSSSelector(html_names::kDivTag,
                  /* is_implicit */ false),
      CSSSelector(AtomicString("scope"), /* is_implicit */ false)};
  selector[0].SetRelation(CSSSelector::kChild);
  selector[1].SetLastInComplexSelector(true);
  EXPECT_EQ(":scope > div", selector[0].SelectorText());
}

TEST(CSSSelector, ImplicitScopeSpecificity) {
  test::TaskEnvironment task_environment;
  CSSSelector selector[2] = {
      CSSSelector(html_names::kDivTag,
                  /* is_implicit */ false),
      CSSSelector(AtomicString("scope"), /* is_implicit */ true)};
  selector[0].SetRelation(CSSSelector::kChild);
  selector[1].SetLastInComplexSelector(true);
  EXPECT_EQ("> div", selector[0].SelectorText());
  EXPECT_EQ(CSSSelector::kTagSpecificity, selector[0].Specificity());
}

TEST(CSSSelector, ExplicitScopeSpecificity) {
  test::TaskEnvironment task_environment;
  CSSSelector selector[2] = {
      CSSSelector(html_names::kDivTag,
                  /* is_implicit */ false),
      CSSSelector(AtomicString("scope"), /* is_implicit */ false)};
  selector[0].SetRelation(CSSSelector::kChild);
  selector[1].SetLastInComplexSelector(true);
  EXPECT_EQ(":scope > div", selector[0].SelectorText());
  EXPECT_EQ(CSSSelector::kTagSpecificity | CSSSelector::kClassLikeSpecificity,
            selector[0].Specificity());
}

TEST(CSSSelector, CheckSelectorTextExpandingPseudoParent) {
  test::TaskEnvironment task_environment;

  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(
      ".a { .b { .c, &.c, .c:has(&) {} } }"
      ".d .e { .f:has(> &) {} }");
  RuleSet& rule_set = sheet.GetRuleSet();

  base::span<const RuleData> rules = rule_set.ClassRules(AtomicString("a"));
  ASSERT_EQ(1u, rules.size());
  const CSSSelector* selector = &rules[0].Selector();
  EXPECT_EQ(".a", selector->SelectorText());

  rules = rule_set.ClassRules(AtomicString("b"));
  ASSERT_EQ(1u, rules.size());
  selector = &rules[0].Selector();
  EXPECT_EQ("& .b", selector->SelectorText());
  EXPECT_EQ(":is(.a) .b", selector->SelectorTextExpandingPseudoParent());

  rules = rule_set.ClassRules(AtomicString("c"));
  ASSERT_EQ(3u, rules.size());
  selector = &rules[0].Selector();
  EXPECT_EQ("& .c", selector->SelectorText());
  EXPECT_EQ(":is(:is(.a) .b) .c",
            selector->SelectorTextExpandingPseudoParent());
  selector = &rules[1].Selector();
  EXPECT_EQ("&.c", selector->SelectorText());
  EXPECT_EQ(":is(:is(.a) .b).c", selector->SelectorTextExpandingPseudoParent());
  selector = &rules[2].Selector();
  EXPECT_EQ(".c:has(&)", selector->SelectorText());
  EXPECT_EQ(".c:has(:is(:is(.a) .b))",
            selector->SelectorTextExpandingPseudoParent());

  rules = rule_set.ClassRules(AtomicString("e"));
  ASSERT_EQ(1u, rules.size());
  selector = &rules[0].Selector();
  EXPECT_EQ(".d .e", selector->SelectorText());

  rules = rule_set.ClassRules(AtomicString("f"));
  ASSERT_EQ(1u, rules.size());
  selector = &rules[0].Selector();
  EXPECT_EQ(".f:has(> &)", selector->SelectorText());
  EXPECT_EQ(".f:has(> :is(.d .e))",
            selector->SelectorTextExpandingPseudoParent());
}

TEST(CSSSelector, CheckHasArgumentMatchInShadowTreeFlag) {
  test::TaskEnvironment task_environment;

  css_test_helpers::TestStyleSheet sheet;
  sheet.AddCSSRules(
      ":host:has(.a) {}"
      ":host:has(.a):has(.b) {}"
      ":host:has(.a) .b {}"
      ":host:has(.a):has(.b) .c {}"
      ":host :has(.a) {}"
      ":host :has(.a) .b {}"
      ":host:has(.a):host(.b):has(.c):host-context(.d):has(.e) :has(.f) {}");
  RuleSet& rule_set = sheet.GetRuleSet();

  base::span<const RuleData> rules = rule_set.ShadowHostRules();
  ASSERT_EQ(2u, rules.size());
  const CSSSelector* selector = &rules[0].Selector();
  EXPECT_EQ(":host:has(.a)", selector->SelectorText());
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());

  selector = &rules[1].Selector();
  EXPECT_EQ(":host:has(.a):has(.b)", selector->SelectorText());
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());

  rules = rule_set.ClassRules(AtomicString("b"));
  ASSERT_EQ(2u, rules.size());
  selector = &rules[0].Selector();
  EXPECT_EQ(":host:has(.a) .b", selector->SelectorText());
  selector = selector->NextSimpleSelector();
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());

  selector = &rules[1].Selector();
  EXPECT_EQ(":host :has(.a) .b", selector->SelectorText());
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_FALSE(selector->HasArgumentMatchInShadowTree());

  rules = rule_set.ClassRules(AtomicString("c"));
  ASSERT_EQ(1u, rules.size());
  selector = &rules[0].Selector();
  EXPECT_EQ(":host:has(.a):has(.b) .c", selector->SelectorText());
  selector = selector->NextSimpleSelector();
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());

  rules = rule_set.UniversalRules();
  ASSERT_EQ(2u, rules.size());
  selector = &rules[0].Selector();
  EXPECT_EQ(":host :has(.a)", selector->SelectorText());
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_FALSE(selector->HasArgumentMatchInShadowTree());

  selector = &rules[1].Selector();
  EXPECT_EQ(":host:has(.a):host(.b):has(.c):host-context(.d):has(.e) :has(.f)",
            selector->SelectorText());
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_FALSE(selector->HasArgumentMatchInShadowTree());
  selector = selector->NextSimpleSelector();
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());
  selector = selector->NextSimpleSelector();
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());
  selector = selector->NextSimpleSelector();
  selector = selector->NextSimpleSelector();
  EXPECT_EQ(selector->GetPseudoType(), CSSSelector::kPseudoHas);
  EXPECT_TRUE(selector->HasArgumentMatchInShadowTree());
}

}  // namespace blink
```