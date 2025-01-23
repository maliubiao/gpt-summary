Response:
The user wants to understand the functionality of the `element_rule_collector_test.cc` file in the Chromium Blink engine.

Here's a breakdown of how to address the request:

1. **Identify the core purpose:** The filename `element_rule_collector_test.cc` strongly suggests it's a test file for the `ElementRuleCollector` class. The `#include "third_party/blink/renderer/core/css/element_rule_collector.h"` confirms this.

2. **Analyze the tests:**  Go through each `TEST_F` function to understand what aspects of `ElementRuleCollector` are being tested. Look for patterns and key functionalities being exercised.

3. **Connect to web technologies (HTML, CSS, JavaScript):**  Relate the tested functionalities to how they impact rendering and styling of web pages. For example, tests involving selectors, `:visited`, and `:link` directly relate to CSS styling.

4. **Infer logical reasoning and provide examples:** When a test checks for a specific behavior (e.g., how `ElementRuleCollector` handles nested CSS rules),  formulate hypothetical inputs (CSS rules and HTML structure) and the expected output (which rules match).

5. **Consider user/developer errors:**  Think about common mistakes developers might make when writing CSS, and how `ElementRuleCollector` might handle these situations or how the tests reveal potential pitfalls.

6. **Explain the debugging perspective:**  Imagine a scenario where a developer is debugging CSS issues. How would the functionality tested in this file help in that process? How can a developer reach this part of the code during debugging?

7. **Structure the answer:**  Organize the findings into logical sections to provide a clear and comprehensive explanation.

**Detailed thought process for specific points:**

* **Functionality:** The tests use methods like `Match` and `GetAllMatchedRules`. This clearly indicates the `ElementRuleCollector`'s primary job is to determine which CSS rules apply to a given element.

* **Relation to HTML, CSS, JavaScript:**
    * **HTML:** The tests manipulate the DOM using `SetBodyInnerHTML` and `GetDocument().getElementById`. This shows the collector interacts with the HTML structure.
    * **CSS:** The tests define CSS rules as strings and parse them using `ParseRule` and `RuleSetFromSingleRule`. The tests on selectors like `:visited`, `:link`, `#id`, and class names demonstrate the collector's role in CSS matching. The nested rules test shows how it handles more complex CSS structures.
    * **JavaScript:** While this specific test file doesn't directly use JavaScript, the underlying `ElementRuleCollector` is used when the browser calculates styles, which can be triggered by JavaScript DOM manipulations or style changes.

* **Logical Reasoning and Examples:**
    * **Link Match Type:**  The tests for `:link` and `:visited` show the collector's ability to distinguish between visited and unvisited links. The example input is the HTML structure with the `<a>` tags and the CSS selectors. The output is the `LinkMatchMask` indicating which link state matches.
    * **Direct Nesting:** The nested CSS rule example (`#foo { ... &.a ... }`) demonstrates how the collector handles selectors that refer back to the parent selector. Input: the CSS and HTML; output: the list of matched rules.

* **User/Developer Errors:** The test about "Rule Not Starting with Ampersand" highlights a potential CSS nesting syntax error. The output shows the collector's behavior in such a case.

* **Debugging Perspective:**  If a developer has CSS rules that are not being applied as expected, understanding how `ElementRuleCollector` works and writing similar test cases can help pinpoint the issue. The explanation of how a user action leads to style recalculation provides context for when this code is invoked.

* **Code Snippets:** Include relevant code snippets from the test file to illustrate the points being made (e.g., the `Match` function).

By following this thought process, I can generate a comprehensive and informative answer that addresses all aspects of the user's request.
这是一个名为 `element_rule_collector_test.cc` 的 C++ 文件，属于 Chromium Blink 渲染引擎的一部分。从其名称和包含的头文件来看，它的主要功能是**测试 `ElementRuleCollector` 类的各种功能**。`ElementRuleCollector` 的核心职责是**收集并匹配适用于特定 HTML 元素的 CSS 规则**。

下面详细列举其功能以及与 JavaScript、HTML、CSS 的关系：

**主要功能:**

1. **测试 CSS 规则的匹配**: 该文件包含了一系列测试用例 (以 `TEST_F` 宏定义)，用于验证 `ElementRuleCollector` 是否能正确地将 CSS 规则与 HTML 元素进行匹配。这包括：
    * **基本的选择器匹配**: 测试各种 CSS 选择器 (例如：ID 选择器 `#id`, 类选择器 `.class`, 标签选择器 `div`) 的匹配情况。
    * **伪类匹配**: 特别关注与链接状态相关的伪类 `:link` 和 `:visited` 的匹配，以及 `:not`, `:is` 等其他结构性伪类的匹配。
    * **嵌套规则匹配**: 测试 CSS 嵌套规则 (使用 `&` 符号) 的匹配情况。
    * **媒体查询中的规则匹配**: 测试在 `@media` 查询中定义的嵌套规则的匹配情况。
    * **`:host-context` 伪类的匹配**: 测试在 Shadow DOM 中使用 `:host-context` 伪类时的匹配行为。
    * **非通用高亮伪类 (Non-Universal Highlights) 的匹配**:  测试针对特定命名空间下的高亮伪类 (例如 `::highlight(x)`) 的匹配。

2. **验证 `LinkMatchType`**:  通过 `Match` 函数，测试当元素本身或其祖先是链接 (`<a>` 标签) 时，`:link` 和 `:visited` 伪类是否能正确匹配。这对于确保链接样式的正确渲染至关重要。

3. **获取所有匹配的规则**: `GetAllMatchedRules` 函数用于获取与特定元素匹配的所有 CSS 规则，这有助于验证规则收集的完整性。

4. **获取匹配的 CSS 规则列表**: `GetMatchedCSSRuleList` 函数用于获取匹配的 `CSSStyleRule` 对象的列表，这在调试和理解样式计算过程时非常有用。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML**: 该测试文件通过 `SetBodyInnerHTML` 方法动态创建 HTML 结构，并使用 `GetDocument().getElementById` 等方法获取 HTML 元素。测试用例针对这些元素应用不同的 CSS 规则，并验证匹配结果。

    * **举例**:  在 `LinkMatchType` 测试中，创建了包含 `<div>` 和 `<a>` 元素的 HTML 结构：
      ```html
      <div id=foo></div>
      <a id=visited href="">
        <span id=visited_span></span>
      </a>
      <a id=link href="unvisited">
        <span id=unvisited_span></span>
      </a>
      <div id=bar></div>
      ```
      然后针对这些元素进行 CSS 规则的匹配测试。

* **CSS**:  该测试文件的核心就是测试 CSS 规则的匹配。它使用字符串来定义 CSS 规则，并通过 `ParseRule` 和 `RuleSetFromSingleRule` 函数将其解析为 Blink 内部的 CSS 对象。测试用例验证了各种 CSS 选择器和语法的匹配行为。

    * **举例**: `LinkMatchType` 测试中使用了如下 CSS 选择器：
      * `#bar` (ID 选择器)
      * `:visited` 和 `:link` (链接状态伪类)
      * `:not(:visited)` (否定伪类)
      * `body :link` (后代选择器)
      * `body > :link` (子选择器)
      * `:is(:link, :not(:link))` (逻辑组合伪类)
      * `:link + #bar` (相邻兄弟选择器)
      * `:host-context(a) div` (`:host-context` 伪类，用于 Shadow DOM)

    * **举例 (嵌套规则)**: `DirectNesting` 测试中定义了包含嵌套规则的 CSS：
      ```css
      #foo {
         color: green;
         &.a { color: red; }
         & > .b { color: navy; }
      }
      ```
      测试 `ElementRuleCollector` 能否正确匹配这些嵌套规则。

* **JavaScript**: 虽然该文件本身是 C++ 代码，但 `ElementRuleCollector` 的功能直接影响到 JavaScript 中与样式相关的操作。当 JavaScript 修改 DOM 结构或元素的类名等属性时，浏览器会重新计算样式，这时就会用到 `ElementRuleCollector` 来确定哪些 CSS 规则适用于修改后的元素。

    * **场景**:  假设一个 JavaScript 代码通过 `element.classList.add('active')` 给一个元素添加了一个类名。浏览器会触发样式重算，`ElementRuleCollector` 会被调用，检查是否有 `.active` 相关的 CSS 规则适用于该元素，并更新元素的样式。

**逻辑推理、假设输入与输出:**

* **假设输入 (LinkMatchType 测试)**:
    * **HTML**:  包含一个 ID 为 `visited` 的已访问链接和一个 ID 为 `link` 的未访问链接。
    * **CSS 规则**:  `#foo { color: green }`, `:visited { color: blue }`, `:link { color: red }`
    * **调用的 `Match` 函数**: `Match(visited, ":visited")`, `Match(link, ":link")`, `Match(foo, "#foo")`

* **输出**:
    * `Match(visited, ":visited")` 应该返回表示 `:visited` 匹配的特定标志 (例如 `CSSSelector::kMatchVisited`)。
    * `Match(link, ":link")` 应该返回表示 `:link` 匹配的特定标志 (例如 `CSSSelector::kMatchLink`)。
    * `Match(foo, "#foo")` 应该返回表示基本选择器匹配的标志 (例如 `CSSSelector::kMatchLink`，因为 `foo` 不是链接本身，但基本选择器始终匹配)。

* **假设输入 (DirectNesting 测试)**:
    * **HTML**:
      ```html
      <div id="foo" class="a">
        <div id="bar" class="b">
           <div id="baz" class="b">
           </div>
        </div>
      </div>
      ```
    * **CSS 规则**:
      ```css
      #foo {
         color: green;
         &.a { color: red; }
         & > .b { color: navy; }
      }
      ```
    * **调用的 `GetAllMatchedRules` 函数**: `GetAllMatchedRules(foo, rule_set)`, `GetAllMatchedRules(bar, rule_set)`, `GetAllMatchedRules(baz, rule_set)`

* **输出**:
    * `GetAllMatchedRules(foo, rule_set)` 应该返回包含两条匹配规则的列表：`#foo` 和 `&.a`。
    * `GetAllMatchedRules(bar, rule_set)` 应该返回包含一条匹配规则的列表：`& > .b`。
    * `GetAllMatchedRules(baz, rule_set)` 应该返回一个空列表，因为 `#baz` 不匹配任何规则。

**用户或编程常见的使用错误及举例说明:**

* **CSS 选择器错误**: 用户可能编写错误的 CSS 选择器，导致样式无法应用。例如，拼写错误的类名或 ID。`ElementRuleCollector` 的测试确保了在这些情况下不会出现意外的匹配。

    * **举例**: 如果用户错误地写了 `.fo` 而不是 `.foo`，`ElementRuleCollector` 将不会将该选择器与 class 为 `foo` 的元素匹配。

* **对链接伪类的误解**:  开发者可能不清楚 `:link` 和 `:visited` 的工作原理，例如，认为 `:visited` 可以匹配任何被访问过的元素，而实际上它只适用于 `<a>` 标签。`LinkMatchType` 测试验证了 `ElementRuleCollector` 在处理这些伪类时的正确行为。

    * **举例**: 如果用户尝试使用 `div:visited { ... }` 来设置访问过的 `div` 元素的样式，这将不会生效，因为 `:visited` 仅适用于链接。`ElementRuleCollector` 的逻辑会确保不会错误地匹配这种情况。

* **CSS 嵌套语法错误**:  用户可能错误地使用 CSS 嵌套，例如，在顶级作用域使用 `&` 符号。`NestingAtToplevelMatchesNothing` 测试验证了 `ElementRuleCollector` 在这种情况下不会匹配任何元素。

    * **举例**:  如果在 CSS 中直接写 `& { color: red; }`，它不会应用到任何元素，`ElementRuleCollector` 的测试确保了这一点。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个网页**: 这是最基本的操作，所有后续的样式计算都基于此。
2. **浏览器解析 HTML**:  浏览器会解析下载的 HTML 文档，构建 DOM 树。
3. **浏览器解析 CSS**: 浏览器会解析 `<style>` 标签中的 CSS 代码或外部 CSS 文件，构建 CSSOM (CSS Object Model)。
4. **样式计算 (Style Calculation)**:  浏览器需要确定每个 HTML 元素应该应用哪些 CSS 规则，最终计算出元素的最终样式。`ElementRuleCollector` 在这个阶段发挥关键作用。
    * **遍历 DOM 树**: 浏览器会遍历 DOM 树中的每个元素。
    * **构建 `ElementResolveContext`**:  对于每个元素，创建一个 `ElementResolveContext` 对象，提供元素相关的上下文信息。
    * **创建 `ElementRuleCollector`**:  创建一个 `ElementRuleCollector` 对象，传入 `ElementResolveContext` 和其他必要的参数。
    * **收集匹配的规则**:  `ElementRuleCollector` 会遍历 CSSOM 中的规则，并根据选择器匹配规则，找到适用于当前元素的 CSS 规则。
    * **处理嵌套规则**: 如果 CSS 中存在嵌套规则，`ElementRuleCollector` 会处理 `&` 符号，生成完整的选择器并进行匹配。
    * **处理链接伪类**: 如果元素是链接或在链接内部，`ElementRuleCollector` 会根据链接的访问状态 (已访问或未访问) 匹配 `:link` 或 `:visited` 伪类。
    * **处理其他伪类**:  `ElementRuleCollector` 也会处理其他伪类，如 `:hover`, `:active` 等。
    * **排序和应用规则**: 匹配到的规则会根据优先级 (specificity) 和来源 (origin) 进行排序，最终应用到元素上。
5. **渲染 (Rendering)**:  计算出的样式信息会被用于渲染网页，将 HTML 元素绘制到屏幕上。

**调试线索**:

如果开发者发现网页的样式不符合预期，例如：

* **某些 CSS 规则没有生效**: 可能是选择器写错了，或者优先级不够高。调试时可以查看浏览器的开发者工具中的 "Elements" 面板，查看元素的计算样式 (Computed)。
* **链接的 `:visited` 样式没有应用**:  可能是因为浏览器的隐私设置阻止了 `:visited` 样式的应用，或者选择器本身有问题。
* **嵌套的 CSS 规则没有生效**: 可能是嵌套的语法错误，或者父元素的选择器没有正确匹配。

在 Chromium 源码的开发或调试过程中，如果怀疑 `ElementRuleCollector` 的行为有问题，可以：

* **运行相关的单元测试**:  运行 `element_rule_collector_test.cc` 中的测试用例，验证 `ElementRuleCollector` 在各种情况下的行为是否符合预期。
* **设置断点**: 在 `ElementRuleCollector` 的关键方法中设置断点，例如 `CollectMatchingRules` 和 `SortAndTransferMatchedRules`，观察其执行过程，查看哪些规则被匹配，哪些没有被匹配，以及原因。
* **查看日志**:  Blink 引擎中可能存在与样式计算相关的日志输出，可以帮助理解 `ElementRuleCollector` 的工作过程。

总而言之，`element_rule_collector_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它确保了 CSS 规则能够被正确地匹配到 HTML 元素，这对于网页的正确渲染至关重要。理解这个文件的功能，有助于理解浏览器样式计算的核心机制，并为调试 CSS 相关问题提供线索。

### 提示词
```
这是目录为blink/renderer/core/css/element_rule_collector_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/element_rule_collector.h"

#include <optional>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/resolver/element_resolve_context.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/selector_filter.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

using css_test_helpers::ParseRule;

static RuleSet* RuleSetFromSingleRule(Document& document, const String& text) {
  auto* style_rule =
      DynamicTo<StyleRule>(css_test_helpers::ParseRule(document, text));
  if (style_rule == nullptr) {
    return nullptr;
  }
  RuleSet* rule_set = MakeGarbageCollected<RuleSet>();
  MediaQueryEvaluator* medium =
      MakeGarbageCollected<MediaQueryEvaluator>(document.GetFrame());
  rule_set->AddStyleRule(style_rule, /*parent_rule=*/nullptr, *medium,
                         kRuleHasNoSpecialState, /*within_mixin=*/false);
  return rule_set;
}

class ElementRuleCollectorTest : public PageTestBase {
 public:
  EInsideLink InsideLink(Element* element) {
    if (!element) {
      return EInsideLink::kNotInsideLink;
    }
    if (element->IsLink()) {
      ElementResolveContext context(*element);
      return context.ElementLinkState();
    }
    return InsideLink(DynamicTo<Element>(FlatTreeTraversal::Parent(*element)));
  }

  // Matches an element against a selector via ElementRuleCollector.
  //
  // Upon successful match, the combined CSSSelector::LinkMatchMask of
  // of all matched rules is returned, or std::nullopt if no-match.
  std::optional<unsigned> Match(Element* element,
                                const String& selector,
                                const ContainerNode* scope = nullptr) {
    ElementResolveContext context(*element);
    SelectorFilter filter;
    MatchResult result;
    ElementRuleCollector collector(context, StyleRecalcContext(), filter,
                                   result, InsideLink(element));

    String rule = selector + " { color: green }";
    RuleSet* rule_set = RuleSetFromSingleRule(GetDocument(), rule);
    if (!rule_set) {
      return std::nullopt;
    }

    MatchRequest request(rule_set, scope);

    collector.CollectMatchingRules(request, /*part_names*/ nullptr);
    collector.SortAndTransferMatchedRules(CascadeOrigin::kAuthor,
                                          /*is_vtt_embedded_style=*/false,
                                          /*tracker=*/nullptr);

    const MatchedPropertiesVector& vector = result.GetMatchedProperties();
    if (!vector.size()) {
      return std::nullopt;
    }

    // Either the normal rules matched, the visited dependent rules matched,
    // or both. There should be nothing else.
    DCHECK(vector.size() == 1 || vector.size() == 2);

    unsigned link_match_type = 0;
    for (const auto& matched_properties : vector) {
      link_match_type |= matched_properties.data_.link_match_type;
    }
    return link_match_type;
  }

  Vector<MatchedRule> GetAllMatchedRules(Element* element, RuleSet* rule_set) {
    ElementResolveContext context(*element);
    SelectorFilter filter;
    MatchResult result;
    ElementRuleCollector collector(context, StyleRecalcContext(), filter,
                                   result, InsideLink(element));

    MatchRequest request(rule_set, {});

    collector.CollectMatchingRules(request, /*part_names*/ nullptr);
    return Vector<MatchedRule>{collector.MatchedRulesForTest()};
  }

  RuleIndexList* GetMatchedCSSRuleList(Element* element,
                                       RuleSet* rule_set,
                                       const CSSStyleSheet* sheet) {
    ElementResolveContext context(*element);
    SelectorFilter filter;
    MatchResult result;
    ElementRuleCollector collector(context, StyleRecalcContext(), filter,
                                   result, InsideLink(element));

    MatchRequest request(rule_set, {}, sheet);

    collector.SetMode(SelectorChecker::kCollectingCSSRules);
    collector.CollectMatchingRules(request, /*part_names*/ nullptr);
    collector.SortAndTransferMatchedRules(CascadeOrigin::kAuthor,
                                          /*is_vtt_embedded_style=*/false,
                                          /*tracker=*/nullptr);

    return collector.MatchedCSSRuleList();
  }
};

TEST_F(ElementRuleCollectorTest, LinkMatchType) {
  SetBodyInnerHTML(R"HTML(
    <div id=foo></div>
    <a id=visited href="">
      <span id=visited_span></span>
    </a>
    <a id=link href="unvisited">
      <span id=unvisited_span></span>
    </a>
    <div id=bar></div>
  )HTML");
  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  Element* bar = GetDocument().getElementById(AtomicString("bar"));
  Element* visited = GetDocument().getElementById(AtomicString("visited"));
  Element* link = GetDocument().getElementById(AtomicString("link"));
  Element* unvisited_span =
      GetDocument().getElementById(AtomicString("unvisited_span"));
  Element* visited_span =
      GetDocument().getElementById(AtomicString("visited_span"));
  ASSERT_TRUE(foo);
  ASSERT_TRUE(bar);
  ASSERT_TRUE(visited);
  ASSERT_TRUE(link);
  ASSERT_TRUE(unvisited_span);
  ASSERT_TRUE(visited_span);

  ASSERT_EQ(EInsideLink::kInsideVisitedLink, InsideLink(visited));
  ASSERT_EQ(EInsideLink::kInsideVisitedLink, InsideLink(visited_span));
  ASSERT_EQ(EInsideLink::kNotInsideLink, InsideLink(foo));
  ASSERT_EQ(EInsideLink::kInsideUnvisitedLink, InsideLink(link));
  ASSERT_EQ(EInsideLink::kInsideUnvisitedLink, InsideLink(unvisited_span));
  ASSERT_EQ(EInsideLink::kNotInsideLink, InsideLink(bar));

  const auto kMatchLink = CSSSelector::kMatchLink;
  const auto kMatchVisited = CSSSelector::kMatchVisited;
  const auto kMatchAll = CSSSelector::kMatchAll;

  EXPECT_EQ(Match(foo, "#bar"), std::nullopt);
  EXPECT_EQ(Match(visited, "#foo"), std::nullopt);
  EXPECT_EQ(Match(link, "#foo"), std::nullopt);

  EXPECT_EQ(Match(foo, "#foo"), kMatchLink);
  EXPECT_EQ(Match(link, ":visited"), kMatchVisited);
  EXPECT_EQ(Match(link, ":link"), kMatchLink);
  // Note that for elements that are not inside links at all, we always
  // expect kMatchLink, since kMatchLink represents the regular (non-visited)
  // style.
  EXPECT_EQ(Match(foo, ":not(:visited)"), kMatchLink);
  EXPECT_EQ(Match(foo, ":not(:link)"), kMatchLink);
  EXPECT_EQ(Match(foo, ":not(:link):not(:visited)"), kMatchLink);

  EXPECT_EQ(Match(visited, ":link"), kMatchLink);
  EXPECT_EQ(Match(visited, ":visited"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":link:visited"), std::nullopt);
  EXPECT_EQ(Match(visited, ":visited:link"), std::nullopt);
  EXPECT_EQ(Match(visited, "#visited:visited"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":visited#visited"), kMatchVisited);
  EXPECT_EQ(Match(visited, "body :link"), kMatchLink);
  EXPECT_EQ(Match(visited, "body > :link"), kMatchLink);
  EXPECT_EQ(Match(visited_span, ":link span"), kMatchLink);
  EXPECT_EQ(Match(visited_span, ":visited span"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":not(:visited)"), kMatchLink);
  EXPECT_EQ(Match(visited, ":not(:link)"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":not(:link):not(:visited)"), std::nullopt);
  EXPECT_EQ(Match(visited, ":is(:not(:link))"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":is(:not(:visited))"), kMatchLink);
  EXPECT_EQ(Match(visited, ":is(:link, :not(:link))"), kMatchAll);
  EXPECT_EQ(Match(visited, ":is(:not(:visited), :not(:link))"), kMatchAll);
  EXPECT_EQ(Match(visited, ":is(:not(:visited):not(:link))"), std::nullopt);
  EXPECT_EQ(Match(visited, ":is(:not(:visited):link)"), kMatchLink);
  EXPECT_EQ(Match(visited, ":not(:is(:link))"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":not(:is(:visited))"), kMatchLink);
  EXPECT_EQ(Match(visited, ":not(:is(:not(:visited)))"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":not(:is(:link, :visited))"), std::nullopt);
  EXPECT_EQ(Match(visited, ":not(:is(:link:visited))"), kMatchAll);
  EXPECT_EQ(Match(visited, ":not(:is(:not(:link):visited))"), kMatchLink);
  EXPECT_EQ(Match(visited, ":not(:is(:not(:link):not(:visited)))"), kMatchAll);

  EXPECT_EQ(Match(visited, ":is(#visited)"), kMatchAll);
  EXPECT_EQ(Match(visited, ":is(#visited, :visited)"), kMatchAll);
  EXPECT_EQ(Match(visited, ":is(#visited, :link)"), kMatchAll);
  EXPECT_EQ(Match(visited, ":is(#unrelated, :link)"), kMatchLink);
  EXPECT_EQ(Match(visited, ":is(:visited, :is(#unrelated))"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":is(:visited, #visited)"), kMatchAll);
  EXPECT_EQ(Match(visited, ":is(:link, #visited)"), kMatchAll);
  EXPECT_EQ(Match(visited, ":is(:visited)"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":is(:link)"), kMatchLink);
  EXPECT_EQ(Match(visited, ":is(:link):is(:visited)"), std::nullopt);
  EXPECT_EQ(Match(visited, ":is(:link:visited)"), std::nullopt);
  EXPECT_EQ(Match(visited, ":is(:link, :link)"), kMatchLink);
  EXPECT_EQ(Match(visited, ":is(:is(:link))"), kMatchLink);
  EXPECT_EQ(Match(visited, ":is(:link, :visited)"), kMatchAll);
  EXPECT_EQ(Match(visited, ":is(:link, :visited):link"), kMatchLink);
  EXPECT_EQ(Match(visited, ":is(:link, :visited):visited"), kMatchVisited);
  EXPECT_EQ(Match(visited, ":link:is(:link, :visited)"), kMatchLink);
  EXPECT_EQ(Match(visited, ":visited:is(:link, :visited)"), kMatchVisited);

  // When using :link/:visited in a sibling selector, we expect special
  // behavior for privacy reasons.
  // https://developer.mozilla.org/en-US/docs/Web/CSS/Privacy_and_the_:visited_selector
  EXPECT_EQ(Match(bar, ":link + #bar"), kMatchLink);
  EXPECT_EQ(Match(bar, ":visited + #bar"), std::nullopt);
  EXPECT_EQ(Match(bar, ":is(:link + #bar)"), kMatchLink);
  EXPECT_EQ(Match(bar, ":is(:visited ~ #bar)"), std::nullopt);
  EXPECT_EQ(Match(bar, ":not(:is(:link + #bar))"), std::nullopt);
  EXPECT_EQ(Match(bar, ":not(:is(:visited ~ #bar))"), kMatchLink);
}

TEST_F(ElementRuleCollectorTest, LinkMatchTypeHostContext) {
  SetBodyInnerHTML(R"HTML(
    <a href=""><div id="visited_host"></div></a>
    <a href="unvisited"><div id="unvisited_host"></div></a>
  )HTML");

  Element* visited_host =
      GetDocument().getElementById(AtomicString("visited_host"));
  Element* unvisited_host =
      GetDocument().getElementById(AtomicString("unvisited_host"));
  ASSERT_TRUE(visited_host);
  ASSERT_TRUE(unvisited_host);

  ShadowRoot& visited_root =
      visited_host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  ShadowRoot& unvisited_root =
      unvisited_host->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  visited_root.setInnerHTML(R"HTML(
    <style id=style></style>
    <div id=div></div>
  )HTML");
  unvisited_root.setInnerHTML(R"HTML(
    <style id=style></style>
    <div id=div></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* visited_style = visited_root.getElementById(AtomicString("style"));
  Element* unvisited_style =
      unvisited_root.getElementById(AtomicString("style"));
  ASSERT_TRUE(visited_style);
  ASSERT_TRUE(unvisited_style);

  Element* visited_div = visited_root.getElementById(AtomicString("div"));
  Element* unvisited_div = unvisited_root.getElementById(AtomicString("div"));
  ASSERT_TRUE(visited_div);
  ASSERT_TRUE(unvisited_div);

  const auto kMatchLink = CSSSelector::kMatchLink;
  const auto kMatchVisited = CSSSelector::kMatchVisited;
  const auto kMatchAll = CSSSelector::kMatchAll;

  {
    Element* element = visited_div;
    const ContainerNode* scope = visited_style;

    EXPECT_EQ(Match(element, ":host-context(a) div", scope), kMatchAll);
    EXPECT_EQ(Match(element, ":host-context(:link) div", scope), kMatchLink);
    EXPECT_EQ(Match(element, ":host-context(:visited) div", scope),
              kMatchVisited);
    EXPECT_EQ(Match(element, ":host-context(:is(:visited, :link)) div", scope),
              kMatchAll);

    // :host-context(:not(:visited/link)) matches the host itself.
    EXPECT_EQ(Match(element, ":host-context(:not(:visited)) div", scope),
              kMatchAll);
    EXPECT_EQ(Match(element, ":host-context(:not(:link)) div", scope),
              kMatchAll);
  }

  {
    Element* element = unvisited_div;
    const ContainerNode* scope = unvisited_style;

    EXPECT_EQ(Match(element, ":host-context(a) div", scope), kMatchAll);
    EXPECT_EQ(Match(element, ":host-context(:link) div", scope), kMatchLink);
    EXPECT_EQ(Match(element, ":host-context(:visited) div", scope),
              kMatchVisited);
    EXPECT_EQ(Match(element, ":host-context(:is(:visited, :link)) div", scope),
              kMatchAll);
  }
}

TEST_F(ElementRuleCollectorTest, MatchesNonUniversalHighlights) {
  String markup =
      "<html xmlns='http://www.w3.org/1999/xhtml'><body class='foo'>"
      "<none xmlns=''/>"
      "<bar xmlns='http://example.org/bar'/>"
      "<default xmlns='http://example.org/default'/>"
      "</body></html>";
  SegmentedBuffer data;
  data.Append(markup.Utf8().data(), markup.length());
  GetFrame().ForceSynchronousDocumentInstall(AtomicString("text/xml"),
                                             std::move(data));

  // Creates a StyleSheetContents with selector and optional default @namespace,
  // matches rules for originating element, then returns the non-universal flag
  // for ::highlight(x) or the given PseudoId.
  auto run = [&](Element& element, String selector,
                 std::optional<AtomicString> defaultNamespace) {
    auto* parser_context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    auto* sheet = MakeGarbageCollected<StyleSheetContents>(parser_context);
    sheet->ParserAddNamespace(AtomicString("bar"),
                              AtomicString("http://example.org/bar"));
    if (defaultNamespace) {
      sheet->ParserAddNamespace(g_null_atom, *defaultNamespace);
    }
    MediaQueryEvaluator* medium =
        MakeGarbageCollected<MediaQueryEvaluator>(GetDocument().GetFrame());
    RuleSet& rules = sheet->EnsureRuleSet(*medium);
    auto* rule = To<StyleRule>(CSSParser::ParseRule(
        sheet->ParserContext(), sheet, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        selector + " { color: green }"));
    rules.AddStyleRule(rule, /*parent_rule=*/nullptr, *medium,
                       kRuleHasNoSpecialState, /*within_mixin=*/false);

    MatchResult result;
    ElementResolveContext context{element};
    ElementRuleCollector collector(context, StyleRecalcContext(),
                                   SelectorFilter(), result,
                                   EInsideLink::kNotInsideLink);
    collector.CollectMatchingRules(MatchRequest{&sheet->GetRuleSet(), nullptr},
                                   /*part_names*/ nullptr);

    // Pretty-print the arguments for debugging.
    StringBuilder args{};
    args.Append("(<");
    args.Append(element.ToString());
    args.Append(">, ");
    args.Append(selector);
    args.Append(", ");
    if (defaultNamespace) {
      args.Append(String("\"" + *defaultNamespace + "\""));
    } else {
      args.Append("{}");
    }
    args.Append(")");

    return result.HasNonUniversalHighlightPseudoStyles();
  };

  Element& body = *GetDocument().body();
  Element& none = *body.QuerySelector(AtomicString("none"));
  Element& bar = *body.QuerySelector(AtomicString("bar"));
  Element& def = *body.QuerySelector(AtomicString("default"));
  AtomicString defNs("http://example.org/default");

  // Cases that only make sense without a default @namespace.
  // ::selection kSubSelector :window-inactive
  EXPECT_TRUE(run(body, "::selection:window-inactive", {}));
  EXPECT_TRUE(run(body, "body::highlight(x)", {}));    // body::highlight(x)
  EXPECT_TRUE(run(body, ".foo::highlight(x)", {}));    // .foo::highlight(x)
  EXPECT_TRUE(run(body, "* ::highlight(x)", {}));      // ::highlight(x) *
  EXPECT_TRUE(run(body, "* body::highlight(x)", {}));  // body::highlight(x) *

  // Cases that depend on whether there is a default @namespace.
  EXPECT_FALSE(run(def, "::highlight(x)", {}));     // ::highlight(x)
  EXPECT_FALSE(run(def, "*::highlight(x)", {}));    // ::highlight(x)
  EXPECT_TRUE(run(def, "::highlight(x)", defNs));   // null|*::highlight(x)
  EXPECT_TRUE(run(def, "*::highlight(x)", defNs));  // null|*::highlight(x)

  // Cases that are independent of whether there is a default @namespace.
  for (auto& ns : Vector<std::optional<AtomicString>>{{}, defNs}) {
    // no default ::highlight(x), default *|*::highlight(x)
    EXPECT_FALSE(run(body, "*|*::highlight(x)", ns));
    // no default .foo::highlight(x), default *|*.foo::highlight(x)
    EXPECT_TRUE(run(body, "*|*.foo::highlight(x)", ns));
    EXPECT_TRUE(run(none, "|*::highlight(x)", ns));    // empty|*::highlight(x)
    EXPECT_TRUE(run(bar, "bar|*::highlight(x)", ns));  // bar|*::highlight(x)
  }
}

TEST_F(ElementRuleCollectorTest, DirectNesting) {
  SetBodyInnerHTML(R"HTML(
    <div id="foo" class="a">
      <div id="bar" class="b">
         <div id="baz" class="b">
         </div>
      </div>
    </div>
  )HTML");
  String rule = R"CSS(
    #foo {
       color: green;
       &.a { color: red; }
       & > .b { color: navy; }
    }
  )CSS";
  RuleSet* rule_set = RuleSetFromSingleRule(GetDocument(), rule);
  ASSERT_NE(nullptr, rule_set);

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  Element* bar = GetDocument().getElementById(AtomicString("bar"));
  Element* baz = GetDocument().getElementById(AtomicString("baz"));
  ASSERT_NE(nullptr, foo);
  ASSERT_NE(nullptr, bar);
  ASSERT_NE(nullptr, baz);

  Vector<MatchedRule> foo_rules = GetAllMatchedRules(foo, rule_set);
  ASSERT_EQ(2u, foo_rules.size());
  EXPECT_EQ("#foo", foo_rules[0].GetRuleData()->Selector().SelectorText());
  EXPECT_EQ("&.a", foo_rules[1].GetRuleData()->Selector().SelectorText());

  Vector<MatchedRule> bar_rules = GetAllMatchedRules(bar, rule_set);
  ASSERT_EQ(1u, bar_rules.size());
  EXPECT_EQ("& > .b", bar_rules[0].GetRuleData()->Selector().SelectorText());

  Vector<MatchedRule> baz_rules = GetAllMatchedRules(baz, rule_set);
  ASSERT_EQ(0u, baz_rules.size());
}

TEST_F(ElementRuleCollectorTest, RuleNotStartingWithAmpersand) {
  SetBodyInnerHTML(R"HTML(
    <div id="foo"></div>
    <div id="bar"></div>
  )HTML");
  String rule = R"CSS(
    #foo {
       color: green;
       :not(&) { color: red; }
    }
  )CSS";
  RuleSet* rule_set = RuleSetFromSingleRule(GetDocument(), rule);
  ASSERT_NE(nullptr, rule_set);

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  Element* bar = GetDocument().getElementById(AtomicString("bar"));
  ASSERT_NE(nullptr, foo);
  ASSERT_NE(nullptr, bar);

  Vector<MatchedRule> foo_rules = GetAllMatchedRules(foo, rule_set);
  ASSERT_EQ(1u, foo_rules.size());
  EXPECT_EQ("#foo", foo_rules[0].GetRuleData()->Selector().SelectorText());

  Vector<MatchedRule> bar_rules = GetAllMatchedRules(bar, rule_set);
  ASSERT_EQ(1u, bar_rules.size());
  EXPECT_EQ(":not(&)", bar_rules[0].GetRuleData()->Selector().SelectorText());
}

TEST_F(ElementRuleCollectorTest, NestingAtToplevelMatchesNothing) {
  SetBodyInnerHTML(R"HTML(
    <div id="foo"></div>
  )HTML");
  String rule = R"CSS(
    & { color: red; }
  )CSS";
  RuleSet* rule_set = RuleSetFromSingleRule(GetDocument(), rule);
  ASSERT_NE(nullptr, rule_set);

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  ASSERT_NE(nullptr, foo);

  Vector<MatchedRule> foo_rules = GetAllMatchedRules(foo, rule_set);
  EXPECT_EQ(0u, foo_rules.size());
}

TEST_F(ElementRuleCollectorTest, NestedRulesInMediaQuery) {
  SetBodyInnerHTML(R"HTML(
    <div id="foo"><div id="bar" class="c"></div></div>
    <div id="baz"></div>
  )HTML");
  String rule = R"CSS(
    #foo {
        color: oldlace;
        @media screen {
            & .c { color: palegoldenrod; }
        }
    }
  )CSS";
  RuleSet* rule_set = RuleSetFromSingleRule(GetDocument(), rule);
  ASSERT_NE(nullptr, rule_set);

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  Element* bar = GetDocument().getElementById(AtomicString("bar"));
  Element* baz = GetDocument().getElementById(AtomicString("baz"));
  ASSERT_NE(nullptr, foo);
  ASSERT_NE(nullptr, bar);
  ASSERT_NE(nullptr, baz);

  Vector<MatchedRule> foo_rules = GetAllMatchedRules(foo, rule_set);
  ASSERT_EQ(1u, foo_rules.size());
  EXPECT_EQ("#foo", foo_rules[0].GetRuleData()->Selector().SelectorText());

  Vector<MatchedRule> bar_rules = GetAllMatchedRules(bar, rule_set);
  ASSERT_EQ(1u, bar_rules.size());
  EXPECT_EQ("& .c", bar_rules[0].GetRuleData()->Selector().SelectorText());

  Vector<MatchedRule> baz_rules = GetAllMatchedRules(baz, rule_set);
  EXPECT_EQ(0u, baz_rules.size());
}

TEST_F(ElementRuleCollectorTest, FindStyleRuleWithNesting) {
  SetBodyInnerHTML(R"HTML(
    <style id="style">
      #foo {
        color: green;
        &.a { color: red; }
        & > .b { color: navy; }
      }
    </style>
    <div id="foo" class="a">
      <div id="bar" class="b">
      </div>
    </div>
  )HTML");
  CSSStyleSheet* sheet =
      To<HTMLStyleElement>(GetDocument().getElementById(AtomicString("style")))
          ->sheet();

  RuleSet* rule_set = &sheet->Contents()->GetRuleSet();
  ASSERT_NE(nullptr, rule_set);

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  Element* bar = GetDocument().getElementById(AtomicString("bar"));
  ASSERT_NE(nullptr, foo);
  ASSERT_NE(nullptr, bar);

  RuleIndexList* foo_css_rules = GetMatchedCSSRuleList(foo, rule_set, sheet);
  ASSERT_EQ(2u, foo_css_rules->size());
  CSSRule* foo_css_rule_1 = foo_css_rules->at(0).first;
  EXPECT_EQ("#foo", DynamicTo<CSSStyleRule>(foo_css_rule_1)->selectorText());
  CSSRule* foo_css_rule_2 = foo_css_rules->at(1).first;
  EXPECT_EQ("&.a", DynamicTo<CSSStyleRule>(foo_css_rule_2)->selectorText());

  RuleIndexList* bar_css_rules = GetMatchedCSSRuleList(bar, rule_set, sheet);
  ASSERT_EQ(1u, bar_css_rules->size());
  CSSRule* bar_css_rule_1 = bar_css_rules->at(0).first;
  EXPECT_EQ("& > .b", DynamicTo<CSSStyleRule>(bar_css_rule_1)->selectorText());
}

}  // namespace blink
```