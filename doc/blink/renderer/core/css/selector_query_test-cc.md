Response:
The user wants to understand the functionality of the `selector_query_test.cc` file in the Chromium Blink engine. They are interested in its relation to web technologies like JavaScript, HTML, and CSS, and want examples of its usage, potential errors, and debugging context.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the core purpose of the file:** The file name `selector_query_test.cc` strongly suggests it's a test file for the `SelectorQuery` functionality. This is confirmed by the `#include "third_party/blink/renderer/core/css/selector_query.h"` and the use of `TEST` macros from `gtest`.

2. **Analyze the included headers:**  The headers provide clues about the tested functionality and its context. Key headers are:
    * `selector_query.h`: The core functionality being tested.
    * `css_parser.h`, `css_parser_context.h`: Indicates the parsing of CSS selectors is involved.
    * `document.h`, `element_traversal.h`, `shadow_root.h`, `static_node_list.h`:  Suggests the testing involves interacting with the DOM tree and shadow DOM.
    * `html_document.h`, `html_html_element.h`: Implies testing within an HTML context.

3. **Examine the test structure:** The file uses `gtest` for its structure. The `TEST(SelectorQueryTest, ...)` macros define individual test cases. The common pattern within each test is:
    * Setup: Creating a `Document` and often inserting HTML content.
    * Action: Using methods like `QuerySelector` and `QuerySelectorAll` on the document or elements.
    * Assertion: Using `EXPECT_EQ` or `EXPECT_NE` to verify the results (number of matching elements, specific element properties).

4. **Infer the functionality being tested:** Based on the test names and the actions performed within the tests, the file is testing:
    * Correctness of CSS selector matching (`querySelector`, `querySelectorAll`).
    * Performance and optimization (indicated by the `QueryStats`).
    * Handling of pseudo-elements (`::before`).
    * Behavior during parsing (`LastOfTypeNotFinishedParsing`).
    * Performance optimizations (fast paths) in standard mode.
    * Behavior within shadow DOM.
    * Handling of quirks mode (case-insensitive matching).
    * Functionality on disconnected DOM subtrees.
    * Complex selectors including `:has()` pseudo-class.

5. **Relate to JavaScript, HTML, and CSS:**
    * **JavaScript:** The `querySelector` and `querySelectorAll` methods being tested are the JavaScript APIs used to select elements in the DOM. The tests ensure the underlying engine implementation behaves as expected by these APIs.
    * **HTML:** The tests create and manipulate HTML structures. The selectors target elements based on their tags, IDs, classes, and attributes defined in HTML.
    * **CSS:** The core of the testing involves parsing and matching CSS selectors. The tests verify that the engine correctly interprets and applies CSS selector syntax.

6. **Provide concrete examples:** To illustrate the connection with web technologies, create scenarios that mimic how these APIs are used in web development. Use the test cases themselves as a source of inspiration for these examples.

7. **Illustrate logical reasoning (implicit in the tests):** The tests themselves are examples of logical reasoning. For instance, when testing a selector like `#A`, the expected output is one matching element. The reasoning is that IDs are unique, so there should be only one element with that ID. Explicitly stating the input (HTML snippet and selector) and expected output makes this clear.

8. **Identify potential user/programming errors:**  Consider common mistakes developers make when working with selectors. Examples include:
    * Incorrect selector syntax.
    * Case sensitivity issues (especially relevant in standard vs. quirks mode).
    * Forgetting about shadow DOM boundaries.
    * Misunderstanding the behavior of combinators.

9. **Explain the debugging context:** Describe how a developer might end up looking at this test file. This involves scenarios like:
    * Reporting a bug related to `querySelector`/`querySelectorAll`.
    * Contributing to the Blink rendering engine.
    * Investigating performance issues with selector queries.

10. **Structure the response:** Organize the information logically with clear headings and bullet points for readability. Start with a summary of the file's purpose and then delve into specific aspects.

11. **Review and refine:** Ensure the explanation is accurate, clear, and addresses all aspects of the user's request. Use precise language and avoid jargon where possible. Double-check the examples and reasoning. For instance, ensure the examples accurately reflect the test scenarios.
这个文件 `blink/renderer/core/css/selector_query_test.cc` 是 Chromium Blink 渲染引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `blink/renderer/core/css/selector_query.h` 中定义的 `SelectorQuery` 类的功能是否正确**。

`SelectorQuery` 类在 Blink 引擎中负责执行 CSS 选择器查询，这是浏览器中一个核心功能，用于根据 CSS 选择器在 DOM 树中查找匹配的元素。

下面我们来详细列举一下它的功能以及与 JavaScript, HTML, CSS 的关系：

**功能列举:**

1. **测试 CSS 选择器的解析和匹配:**  该文件通过编写各种测试用例，验证 `SelectorQuery` 类是否能正确解析各种复杂的 CSS 选择器，并准确地在模拟的 DOM 结构中找到匹配的元素。
2. **测试 `querySelector` 和 `querySelectorAll` 的实现:**  `SelectorQuery` 类是浏览器实现 JavaScript 中 `document.querySelector()` 和 `document.querySelectorAll()` 方法的关键部分。这个测试文件验证了这些方法在不同场景下的正确性。
3. **测试性能优化 (Fast Paths):**  为了提高选择器查询的效率，`SelectorQuery` 内部实现了一些性能优化，例如针对 ID、class 和标签名的快速查找路径。这个测试文件会验证这些优化是否正常工作，并且在应该触发的时候触发。
4. **测试 Shadow DOM 的支持:**  现代 Web 开发中使用了 Shadow DOM 来实现组件的封装。这个测试文件包含了针对 Shadow DOM 场景的选择器查询测试，确保 `SelectorQuery` 能正确处理 Shadow DOM 的边界。
5. **测试 Quirks 模式的支持:**  为了兼容老旧的网页，浏览器需要支持 Quirks 模式。在这个模式下，CSS 解析和匹配规则可能有所不同。这个测试文件包含了在 Quirks 模式下的选择器查询测试。
6. **测试断开连接的 DOM 子树:**  在某些情况下，我们可能需要在断开连接的 DOM 子树中进行选择器查询。这个测试文件验证了 `SelectorQuery` 在这种场景下的行为。
7. **测试 `:has()` 伪类:**  CSS `:has()` 伪类允许根据子元素的存在与否来选择父元素。这个测试文件包含了对 `:has()` 伪类的功能测试。
8. **收集查询统计信息:**  代码中包含 `#ifdef DCHECK_IS_ON() || defined(RELEASE_QUERY_STATS)` 的部分，说明在调试模式或者特定编译配置下，会收集选择器查询的统计信息，用于分析性能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关系到 JavaScript, HTML 和 CSS 的功能，因为它测试的是浏览器引擎中处理这三项核心技术的关键组件。

* **JavaScript:**
    * **举例:**  测试文件中使用了 `scope.QuerySelector(AtomicString(selector))` 和 `scope.QuerySelectorAll(AtomicString(selector))` 来模拟 JavaScript 中 `element.querySelector()` 和 `element.querySelectorAll()` 的行为。例如，测试用例 `{"#A", false, 1, {1, 1, 0, 0, 0, 0, 0}}` 验证了在 HTML 中存在 ID 为 "A" 的元素时，`querySelector("#A")` 应该返回一个元素。
    * **关系:**  `document.querySelector()` 和 `document.querySelectorAll()` 是 JavaScript 中操作 DOM 的核心 API，这个测试文件确保了 Blink 引擎正确地实现了这些 API 背后的选择器查询逻辑。

* **HTML:**
    * **举例:**  测试用例中会动态生成 HTML 结构，例如 `document->documentElement()->setInnerHTML(...)`，然后在其上执行选择器查询。例如，测试用例中创建了包含各种 `<span>` 和 `<div>` 元素的 HTML 结构，并用不同的 CSS 选择器来查找这些元素。
    * **关系:**  CSS 选择器是用来选取 HTML 元素的，这个测试文件通过在各种 HTML 结构上运行选择器查询来验证其正确性。

* **CSS:**
    * **举例:**  测试用例中的 `test_case.selector` 字段包含了各种 CSS 选择器，例如 `#A`, `.two`, `span`, `body #multiple`, `p:last-of-type`, `:has(> .a ~ .b)` 等。测试文件验证了 `SelectorQuery` 能否正确解析和匹配这些 CSS 选择器。
    * **关系:**  CSS 选择器定义了如何选取 HTML 元素以应用样式或进行 JavaScript 操作。这个测试文件确保了 Blink 引擎能够正确理解和执行 CSS 选择器的语义。

**逻辑推理的假设输入与输出:**

测试用例本质上就是在做逻辑推理。每个测试用例都包含一个假设的输入（HTML 结构和 CSS 选择器）以及期望的输出（匹配元素的数量）。

**假设输入 (来自 `StandardsModeFastPaths` 测试用例):**

```html
<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <span id=first class=A>
      <span id=a class=one></span>
      <span id=b class=two></span>
      <span id=c class=one></span>
      <div id=multiple class=two></div>
    </span>
    <div>
      <span id=second class=B>
        <span id=A class=one></span>
        <span id=B class=two></span>
        <span id=C class=one></span>
        <span id=multiple class=two></span>
      </span>
    </div>
  </body>
</html>
```

**CSS 选择器:** `"#multiple"`

**`query_all`:** `false` (意味着模拟 `querySelector`)

**期望输出:** `matches = 1` (应该匹配到一个 ID 为 "multiple" 的元素)

**假设输入 (来自 `StandardsModeFastPaths` 测试用例):**

```html
<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <span id=first class=A>
      <span id=a class=one></span>
      <span id=b class=two></span>
      <span id=c class=one></span>
      <div id=multiple class=two></div>
    </span>
    <div>
      <span id=second class=B>
        <span id=A class=one></span>
        <span id=B class=two></span>
        <span id=C class=one></span>
        <span id=multiple class=two></span>
      </span>
    </div>
  </body>
</html>
```

**CSS 选择器:** `"#multiple"`

**`query_all`:** `true` (意味着模拟 `querySelectorAll`)

**期望输出:** `matches = 2` (应该匹配到两个 ID 为 "multiple" 的元素)

**用户或编程常见的使用错误及举例说明:**

* **CSS 选择器语法错误:** 用户可能编写了错误的 CSS 选择器，例如拼写错误、缺少必要的符号等。
    * **举例:**  `querySelector("#fist")` (拼写错误，应该是 `first`)，会导致找不到元素。测试文件中的用例通过各种正确的选择器来验证引擎的功能，间接帮助开发者理解正确的语法。
* **大小写敏感性问题:**  在标准模式下，CSS 类名和 ID 是大小写敏感的，但在某些老旧浏览器或 Quirks 模式下可能不敏感。
    * **举例:**  `querySelector("#One")` 在标准模式下不会匹配到 `<div id="one">`。`QuirksModeSlowPath` 测试用例专门测试了 Quirks 模式下 ID 选择器的大小写不敏感性。
* **对 Shadow DOM 边界的理解不足:**  用户可能尝试使用选择器跨越 Shadow DOM 的边界进行选择，但这是不允许的，除非使用了特定的选择器或 API。
    * **举例:**  在一个包含 Shadow Root 的组件中，在主文档中使用 `querySelector("#element-in-shadow-dom")` 通常不会找到 Shadow DOM 内部的元素。`FastPathScoped` 测试用例验证了在 Shadow DOM 内和外的选择器查询行为。
* **误解选择器的优先级和特异性:**  复杂的 CSS 选择器可能会导致用户难以理解最终哪些样式会被应用。虽然这个测试文件不直接测试样式应用，但它验证了选择器的匹配机制，这对于理解样式优先级至关重要。
* **性能问题:**  编写低效的 CSS 选择器可能会导致页面性能问题，尤其是在大型 DOM 树上。测试文件中的 `QueryStats` 部分间接涉及到性能测试，帮助开发者了解哪些选择器执行效率更高。

**用户操作是如何一步步的到达这里，作为调试线索:**

一个开发者可能会因为以下原因查看或调试这个文件：

1. **报告了 `querySelector` 或 `querySelectorAll` 的 Bug:**  如果用户在使用 JavaScript 的选择器 API 时遇到了意外的行为，例如没有找到预期的元素，他们可能会报告一个 Bug。Chromium 的开发者可能会通过编写或修改 `selector_query_test.cc` 中的测试用例来重现和修复这个 Bug。
    * **用户操作:** 用户在一个特定的网页上使用 `document.querySelector()` 或 `document.querySelectorAll()`，发现结果不正确。
    * **调试线索:** 开发者会根据用户提供的 HTML 结构和 CSS 选择器，在测试文件中添加类似的测试用例，运行测试来定位问题。
2. **参与 Blink 渲染引擎的开发:**  如果开发者正在开发或维护 Blink 引擎的 CSS 选择器功能，他们会经常查看和修改这个测试文件，以确保新功能的正确性或修复现有的 Bug。
    * **用户操作:**  不涉及具体用户操作，而是开发者进行引擎内部的开发工作。
    * **调试线索:**  开发者在修改 `SelectorQuery` 相关的代码后，会运行所有的测试用例，确保没有引入新的问题。如果测试失败，他们会仔细分析失败的测试用例，找出代码中的错误。
3. **调查性能问题:**  如果开发者怀疑选择器查询是导致页面性能瓶颈的原因之一，他们可能会查看这个测试文件，了解 Blink 引擎是如何优化选择器查询的，或者添加性能测试用例来评估不同选择器的性能。
    * **用户操作:** 用户访问一个页面时，感觉页面加载或交互缓慢。
    * **调试线索:**  开发者可能会使用性能分析工具来定位瓶颈，如果怀疑是选择器查询的问题，他们可能会研究 `SelectorQuery` 的实现和相关的测试用例。
4. **理解 CSS 选择器的工作原理:**  对于想要深入了解浏览器如何处理 CSS 选择器的开发者来说，阅读这个测试文件可以提供很多细节信息，了解各种选择器在不同场景下的行为。
    * **用户操作:**  开发者正在学习或研究 CSS 选择器的工作原理。
    * **调试线索:**  测试用例提供了各种 CSS 选择器的示例以及预期的匹配结果，可以帮助开发者更直观地理解选择器的语义。

总而言之，`blink/renderer/core/css/selector_query_test.cc` 是 Blink 引擎中一个至关重要的测试文件，它确保了 CSS 选择器查询功能的正确性和性能，直接影响着浏览器处理 HTML、CSS 和 JavaScript 的能力。开发者通过编写和运行这些测试用例，可以有效地发现和修复 Bug，保证 Web 平台的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/core/css/selector_query_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/css/selector_query.h"

#include <memory>
#include <utility>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

// Uncomment to run the SelectorQueryTests for stats in a release build.
// #define RELEASE_QUERY_STATS

namespace blink {

namespace {
struct QueryTest {
  const char* selector;
  bool query_all;
  unsigned matches;
  // {totalCount, fastId, fastClass, fastTagName, fastScan, slowScan,
  //  slowTraversingShadowTreeScan}
  SelectorQuery::QueryStats stats;
};

template <unsigned length>
void RunTests(ContainerNode& scope, const QueryTest (&test_cases)[length]) {
  for (const auto& test_case : test_cases) {
    const char* selector = test_case.selector;
    SCOPED_TRACE(testing::Message()
                 << (test_case.query_all ? "querySelectorAll('"
                                         : "querySelector('")
                 << selector << "')");
    if (test_case.query_all) {
      StaticElementList* match_all =
          scope.QuerySelectorAll(AtomicString(selector));
      EXPECT_EQ(test_case.matches, match_all->length());
    } else {
      Element* match = scope.QuerySelector(AtomicString(selector));
      EXPECT_EQ(test_case.matches, match ? 1u : 0u);
    }
#if DCHECK_IS_ON() || defined(RELEASE_QUERY_STATS)
    SelectorQuery::QueryStats stats = SelectorQuery::LastQueryStats();
    EXPECT_EQ(test_case.stats.total_count, stats.total_count);
    EXPECT_EQ(test_case.stats.fast_id, stats.fast_id);
    EXPECT_EQ(test_case.stats.fast_class, stats.fast_class);
    EXPECT_EQ(test_case.stats.fast_tag_name, stats.fast_tag_name);
    EXPECT_EQ(test_case.stats.fast_scan, stats.fast_scan);
    EXPECT_EQ(test_case.stats.slow_scan, stats.slow_scan);
    EXPECT_EQ(test_case.stats.slow_traversing_shadow_tree_scan,
              stats.slow_traversing_shadow_tree_scan);
#endif
  }
}
}  // namespace

TEST(SelectorQueryTest, NotMatchingPseudoElement) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* html = MakeGarbageCollected<HTMLHtmlElement>(*document);
  document->AppendChild(html);
  document->documentElement()->setInnerHTML(
      "<body><style>span::before { content: 'X' }</style><span></span></body>");

  HeapVector<CSSSelector> arena;
  base::span<CSSSelector> selector_vector = CSSParser::ParseSelector(
      MakeGarbageCollected<CSSParserContext>(
          *document, NullURL(), true /* origin_clean */, Referrer()),
      CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
      /*is_within_scope=*/false, nullptr, "span::before", arena);
  CSSSelectorList* selector_list =
      CSSSelectorList::AdoptSelectorVector(selector_vector);
  std::unique_ptr<SelectorQuery> query = SelectorQuery::Adopt(selector_list);
  Element* elm = query->QueryFirst(*document);
  EXPECT_EQ(nullptr, elm);

  selector_vector = CSSParser::ParseSelector(
      MakeGarbageCollected<CSSParserContext>(
          *document, NullURL(), true /* origin_clean */, Referrer()),
      CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
      /*is_within_scope=*/false, nullptr, "span", arena);
  selector_list = CSSSelectorList::AdoptSelectorVector(selector_vector);
  query = SelectorQuery::Adopt(selector_list);
  elm = query->QueryFirst(*document);
  EXPECT_NE(nullptr, elm);
}

TEST(SelectorQueryTest, LastOfTypeNotFinishedParsing) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  auto* html = MakeGarbageCollected<HTMLHtmlElement>(*document);
  document->AppendChild(html);
  document->documentElement()->setInnerHTML(
      "<body><p></p><p id=last></p></body>", ASSERT_NO_EXCEPTION);

  document->body()->BeginParsingChildren();

  HeapVector<CSSSelector> arena;
  base::span<CSSSelector> selector_vector = CSSParser::ParseSelector(
      MakeGarbageCollected<CSSParserContext>(
          *document, NullURL(), true /* origin_clean */, Referrer()),
      CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
      /*is_within_scope=*/false, nullptr, "p:last-of-type", arena);
  CSSSelectorList* selector_list =
      CSSSelectorList::AdoptSelectorVector(selector_vector);
  std::unique_ptr<SelectorQuery> query = SelectorQuery::Adopt(selector_list);
  Element* elm = query->QueryFirst(*document);
  ASSERT_TRUE(elm);
  EXPECT_EQ("last", elm->IdForStyleResolution());
}

TEST(SelectorQueryTest, StandardsModeFastPaths) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <html>
      <head></head>
      <body>
        <span id=first class=A>
          <span id=a class=one></span>
          <span id=b class=two></span>
          <span id=c class=one></span>
          <div id=multiple class=two></div>
        </span>
        <div>
          <span id=second class=B>
            <span id=A class=one></span>
            <span id=B class=two></span>
            <span id=C class=one></span>
            <span id=multiple class=two></span>
          </span>
        </div>
      </body>
    </html>
  )HTML");
  static const struct QueryTest kTestCases[] = {
      // Id in right most selector fast path.
      {"#A", false, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"#multiple", false, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"#multiple.two", false, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"#multiple", true, 2, {2, 2, 0, 0, 0, 0, 0}},
      {"span#multiple", true, 1, {2, 2, 0, 0, 0, 0, 0}},
      {"#multiple.two", true, 2, {2, 2, 0, 0, 0, 0, 0}},
      {"body #multiple", false, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"body span#multiple", false, 1, {2, 2, 0, 0, 0, 0, 0}},
      {"body #multiple", true, 2, {2, 2, 0, 0, 0, 0, 0}},
      {"[id=multiple]", true, 2, {2, 2, 0, 0, 0, 0, 0}},
      {"body [id=multiple]", true, 2, {2, 2, 0, 0, 0, 0, 0}},

      // Single selector tag fast path.
      {"span", false, 1, {4, 0, 0, 4, 0, 0, 0}},
      {"span", true, 9, {14, 0, 0, 14, 0, 0, 0}},

      // Single selector class fast path.
      {".two", false, 1, {6, 0, 6, 0, 0, 0, 0}},
      {".two", true, 4, {14, 0, 14, 0, 0, 0, 0}},

      // Class in the right most selector fast path.
      {"body .two", false, 1, {6, 0, 6, 0, 0, 0, 0}},
      {"div .two", false, 1, {12, 0, 12, 0, 0, 0, 0}},

      // Classes in the right most selector for querySelectorAll use a fast
      // path.
      {"body .two", true, 4, {14, 0, 14, 0, 0, 0, 0}},
      {"div .two", true, 2, {14, 0, 14, 0, 0, 0, 0}},

      // TODO: We could use the fast class path to find the elements inside
      // the id scope instead of the fast scan.
      {"#second .two", false, 1, {3, 1, 0, 0, 2, 0, 0}},
      {"#second .two", true, 2, {5, 1, 0, 0, 4, 0, 0}},

      // We combine the class fast path with the fast scan mode when possible.
      {".B span", false, 1, {11, 0, 10, 0, 1, 0, 0}},
      {".B span", true, 4, {14, 0, 10, 0, 4, 0, 0}},

      // We expand the scope of id selectors when affected by an adjectent
      // combinator.
      {"#c + :last-child", false, 1, {5, 1, 0, 0, 4, 0, 0}},
      {"#a ~ :last-child", false, 1, {5, 1, 0, 0, 4, 0, 0}},
      {"#c + div", true, 1, {5, 1, 0, 0, 4, 0, 0}},
      {"#a ~ span", true, 2, {5, 1, 0, 0, 4, 0, 0}},

      // We only expand the scope for id selectors if they're directly affected
      // the adjacent combinator.
      {"#first span + span", false, 1, {3, 1, 0, 0, 2, 0, 0}},
      {"#first span ~ span", false, 1, {3, 1, 0, 0, 2, 0, 0}},
      {"#second span + span", true, 3, {5, 1, 0, 0, 4, 0, 0}},
      {"#second span ~ span", true, 3, {5, 1, 0, 0, 4, 0, 0}},

      // We disable the fast path for class selectors when affected by adjacent
      // combinator.
      {".one + :last-child", false, 1, {8, 0, 0, 0, 8, 0, 0}},
      {".A ~ :last-child", false, 1, {9, 0, 0, 0, 9, 0, 0}},
      {".A + div", true, 1, {14, 0, 0, 0, 14, 0, 0}},
      {".one ~ span", true, 5, {14, 0, 0, 0, 14, 0, 0}},

      // We re-enable the fast path for classes once past the selector directly
      // affected by the adjacent combinator.
      {".B span + span", true, 3, {14, 0, 10, 0, 4, 0, 0}},
      {".B span ~ span", true, 3, {14, 0, 10, 0, 4, 0, 0}},

      // Selectors with no classes or ids use the fast scan.
      {":scope", false, 1, {1, 0, 0, 0, 1, 0, 0}},
      {":scope", true, 1, {14, 0, 0, 0, 14, 0, 0}},
      {"foo bar", false, 0, {14, 0, 0, 0, 14, 0, 0}},

      // Multiple selectors always uses the slow path.
      // TODO(esprehn): We could make this fast if we sorted the output, not
      // sure it's worth it unless we're dealing with ids.
      {"#a, #b", false, 1, {5, 0, 0, 0, 0, 5, 0}},
      {"#a, #b", true, 2, {14, 0, 0, 0, 0, 14, 0}},
  };
  RunTests(*document, kTestCases);
}

TEST(SelectorQueryTest, FastPathScoped) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <html id=root-id class=root-class>
      <head></head>
      <body>
        <span id=first>
          <span id=A class='a child'></span>
          <span id=B class='a child'>
              <a class=first></a>
              <a class=second></a>
              <a class=third></a>
          </span>
          <span id=multiple class='b child'></span>
          <span id=multiple class='c child'></span>
        </span>
      </body>
    </html>
  )HTML");
  Element* scope = document->getElementById(AtomicString("first"));
  ASSERT_NE(nullptr, scope);
  ShadowRoot& shadowRoot =
      scope->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  // Make the inside the shadow root be identical to that of the outer document.
  shadowRoot.appendChild(document->documentElement()->cloneNode(/*deep*/ true));
  static const struct QueryTest kTestCases[] = {
      // Id in the right most selector.
      {"#first", false, 0, {0, 0, 0, 0, 0, 0, 0}},

      {"#B", false, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"#multiple", false, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"#multiple.c", false, 1, {2, 2, 0, 0, 0, 0, 0}},

      // Class in the right most selector.
      {".child", false, 1, {1, 0, 1, 0, 0, 0, 0}},
      {".child", true, 4, {7, 0, 7, 0, 0, 0, 0}},

      // If an ancestor has the class name we fast scan all the descendants of
      // the scope.
      {".root-class span", true, 4, {7, 0, 0, 0, 7, 0, 0}},

      // If an ancestor has the class name in the middle of the selector we fast
      // scan all the descendants of the scope.
      {".root-class span:nth-child(2)", false, 1, {2, 0, 0, 0, 2, 0, 0}},
      {".root-class span:nth-child(2)", true, 1, {7, 0, 0, 0, 7, 0, 0}},

      // If the id is an ancestor we scan all the descendants.
      {"#root-id span", true, 4, {8, 1, 0, 0, 7, 0, 0}},
  };

  {
    SCOPED_TRACE("Inside document");
    RunTests(*scope, kTestCases);
  }

  {
    // Run all the tests a second time but with a scope inside a shadow root,
    // all the fast paths should behave the same.
    SCOPED_TRACE("Inside shadow root");
    scope = shadowRoot.getElementById(AtomicString("first"));
    ASSERT_NE(nullptr, scope);
    RunTests(*scope, kTestCases);
  }
}

TEST(SelectorQueryTest, QuirksModeSlowPath) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <html>
      <head></head>
      <body>
        <span id=first>
          <span id=One class=Two></span>
          <span id=one class=tWo></span>
        </span>
      </body>
    </html>
  )HTML");
  static const struct QueryTest kTestCases[] = {
      // Quirks mode can't use the id fast path due to being case-insensitive.
      {"#one", false, 1, {5, 0, 0, 0, 5, 0, 0}},
      {"#One", false, 1, {5, 0, 0, 0, 5, 0, 0}},
      {"#ONE", false, 1, {5, 0, 0, 0, 5, 0, 0}},
      {"#ONE", true, 2, {6, 0, 0, 0, 6, 0, 0}},
      {"[id=One]", false, 1, {5, 0, 0, 0, 5, 0, 0}},
      {"[id=One]", true, 1, {6, 0, 0, 0, 6, 0, 0}},
      {"body #first", false, 1, {4, 0, 0, 0, 4, 0, 0}},
      {"body #one", true, 2, {6, 0, 0, 0, 6, 0, 0}},
      // Quirks can use the class and tag name fast paths though.
      {"span", false, 1, {4, 0, 0, 4, 0, 0, 0}},
      {"span", true, 3, {6, 0, 0, 6, 0, 0, 0}},
      {".two", false, 1, {5, 0, 5, 0, 0, 0, 0}},
      {".two", true, 2, {6, 0, 6, 0, 0, 0, 0}},
      {"body span", false, 1, {4, 0, 0, 0, 4, 0, 0}},
      {"body span", true, 3, {6, 0, 0, 0, 6, 0, 0}},
      {"body .two", false, 1, {5, 0, 5, 0, 0, 0, 0}},
      {"body .two", true, 2, {6, 0, 6, 0, 0, 0, 0}},
  };
  RunTests(*document, kTestCases);
}

TEST(SelectorQueryTest, DisconnectedSubtree) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  Element* scope = document->CreateRawElement(html_names::kDivTag);
  scope->setInnerHTML(R"HTML(
    <section>
      <span id=first>
        <span id=A class=A></span>
        <span id=B class=child></span>
        <span id=multiple class=child></span>
        <span id=multiple class=B></span>
      </span>
    </section>
  )HTML");
  static const struct QueryTest kTestCases[] = {
      {"#A", false, 1, {3, 0, 0, 0, 3, 0, 0}},
      {"#B", false, 1, {4, 0, 0, 0, 4, 0, 0}},
      {"#B", true, 1, {6, 0, 0, 0, 6, 0, 0}},
      {"#multiple", true, 2, {6, 0, 0, 0, 6, 0, 0}},
      {".child", false, 1, {4, 0, 4, 0, 0, 0, 0}},
      {".child", true, 2, {6, 0, 6, 0, 0, 0, 0}},
      {"#first span", false, 1, {3, 0, 0, 0, 3, 0, 0}},
      {"#first span", true, 4, {6, 0, 0, 0, 6, 0, 0}},
  };

  RunTests(*scope, kTestCases);
}

TEST(SelectorQueryTest, DisconnectedTreeScope) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  Element* host = document->CreateRawElement(html_names::kDivTag);
  ShadowRoot& shadowRoot =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadowRoot.setInnerHTML(R"HTML(
    <section>
      <span id=first>
        <span id=A class=A></span>
        <span id=B class=child></span>
        <span id=multiple class=child></span>
        <span id=multiple class=B></span>
      </span>
    </section>
  )HTML");
  static const struct QueryTest kTestCases[] = {
      {"#A", false, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"#B", false, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"#B", true, 1, {1, 1, 0, 0, 0, 0, 0}},
      {"#multiple", true, 2, {2, 2, 0, 0, 0, 0, 0}},
      {".child", false, 1, {4, 0, 4, 0, 0, 0, 0}},
      {".child", true, 2, {6, 0, 6, 0, 0, 0, 0}},
      {"#first span", false, 1, {2, 1, 0, 0, 1, 0, 0}},
      {"#first span", true, 4, {5, 1, 0, 0, 4, 0, 0}},
  };

  RunTests(shadowRoot, kTestCases);
}

TEST(SelectorQueryTest, QueryHasPseudoClass) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1 class=subject3>
        <div id=div2 class=a>
          <div id=div3 class=b></div>
        </div>
        <div id=div4 class='subject1 subject3 subject4'>
          <div id=div5 class='subject2 subject5 subject6'></div>
          <div id=div6 class=a>
            <div id=div7 class='subject1 subject4'>
              <div id=div8></div>
              <div id=div9 class=a></div>
              <div id=div10 class=b>
                <div id=div11 class=c></div>
              </div>
            </div>
            <div id=div12 class=b>
              <div id=div13 class=c></div>
            </div>
          </div>
          <div id=div14 class=b>
            <div id=div15 class='c d'></div>
          </div>
        </div>
        <div id=div16 class='subject1 subject3'>
          <div id=div17 class='subject2 subject5'></div>
          <div id=div18 class=a>
            <div id=div19 class='subject1 subject4'>
              <div id=div20 class='subject5 subject6'></div>
              <div id=div21 class=a></div>
              <div id=div22 class=b>
                <div id=div23 class='c d'></div>
              </div>
            </div>
            <div id=div24 class=b>
              <div id=div25 class=c></div>
            </div>
          </div>
          <div id=div26></div>
          <div id=div27 class=b>
            <div id=div28 class='c d'></div>
          </div>
          <div id=div29></div>
          <div id=div30>
            <div id=div31></div>
          </div>
        </div>
      </div>
    </main>
  )HTML");
  Element* scope = document->getElementById(AtomicString("main"));
  {
    StaticElementList* result =
        scope->QuerySelectorAll(AtomicString(":has(> .a ~ .b)"));
    ASSERT_EQ(4U, result->length());
    EXPECT_EQ(result->item(0)->GetIdAttribute(), "div4");
    EXPECT_TRUE(
        result->item(0)->ClassNames().Contains(AtomicString("subject1")));
    EXPECT_EQ(result->item(1)->GetIdAttribute(), "div7");
    EXPECT_TRUE(
        result->item(1)->ClassNames().Contains(AtomicString("subject1")));
    EXPECT_EQ(result->item(2)->GetIdAttribute(), "div16");
    EXPECT_TRUE(
        result->item(2)->ClassNames().Contains(AtomicString("subject1")));
    EXPECT_EQ(result->item(3)->GetIdAttribute(), "div19");
    EXPECT_TRUE(
        result->item(3)->ClassNames().Contains(AtomicString("subject1")));
  }

  {
    StaticElementList* result =
        scope->QuerySelectorAll(AtomicString(":has(+ .a > .b .c)"));
    ASSERT_EQ(2U, result->length());
    EXPECT_EQ(result->item(0)->GetIdAttribute(), "div5");
    EXPECT_TRUE(
        result->item(0)->ClassNames().Contains(AtomicString("subject2")));
    EXPECT_EQ(result->item(1)->GetIdAttribute(), "div17");
    EXPECT_TRUE(
        result->item(1)->ClassNames().Contains(AtomicString("subject2")));
  }

  {
    StaticElementList* result =
        scope->QuerySelectorAll(AtomicString(":has(> .a .b)"));
    ASSERT_EQ(3U, result->length());
    EXPECT_EQ(result->item(0)->GetIdAttribute(), "div1");
    EXPECT_TRUE(
        result->item(0)->ClassNames().Contains(AtomicString("subject3")));
    EXPECT_EQ(result->item(1)->GetIdAttribute(), "div4");
    EXPECT_TRUE(
        result->item(1)->ClassNames().Contains(AtomicString("subject3")));
    EXPECT_EQ(result->item(2)->GetIdAttribute(), "div16");
    EXPECT_TRUE(
        result->item(2)->ClassNames().Contains(AtomicString("subject3")));
  }

  {
    StaticElementList* result =
        scope->QuerySelectorAll(AtomicString(":has(> .a + .b .c)"));
    ASSERT_EQ(3U, result->length());
    EXPECT_EQ(result->item(0)->GetIdAttribute(), "div4");
    EXPECT_TRUE(
        result->item(0)->ClassNames().Contains(AtomicString("subject4")));
    EXPECT_EQ(result->item(1)->GetIdAttribute(), "div7");
    EXPECT_TRUE(
        result->item(1)->ClassNames().Contains(AtomicString("subject4")));
    EXPECT_EQ(result->item(2)->GetIdAttribute(), "div19");
    EXPECT_TRUE(
        result->item(2)->ClassNames().Contains(AtomicString("subject4")));
  }

  {
    StaticElementList* result =
        scope->QuerySelectorAll(AtomicString(":has(~ .a ~ .b .d)"));
    ASSERT_EQ(3U, result->length());
    EXPECT_EQ(result->item(0)->GetIdAttribute(), "div5");
    EXPECT_TRUE(
        result->item(0)->ClassNames().Contains(AtomicString("subject5")));
    EXPECT_EQ(result->item(1)->GetIdAttribute(), "div17");
    EXPECT_TRUE(
        result->item(1)->ClassNames().Contains(AtomicString("subject5")));
    EXPECT_EQ(result->item(2)->GetIdAttribute(), "div20");
    EXPECT_TRUE(
        result->item(2)->ClassNames().Contains(AtomicString("subject5")));
  }

  {
    StaticElementList* result =
        scope->QuerySelectorAll(AtomicString(":has(+ .a + .b .d)"));
    ASSERT_EQ(2U, result->length());
    EXPECT_EQ(result->item(0)->GetIdAttribute(), "div5");
    EXPECT_TRUE(
        result->item(0)->ClassNames().Contains(AtomicString("subject6")));
    EXPECT_EQ(result->item(1)->GetIdAttribute(), "div20");
    EXPECT_TRUE(
        result->item(1)->ClassNames().Contains(AtomicString("subject6")));
  }
}

}  // namespace blink
```