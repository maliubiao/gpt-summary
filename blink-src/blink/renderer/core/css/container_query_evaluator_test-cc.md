Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan of the code, looking for recognizable keywords and patterns. I see:

* `#include`:  Indicates dependencies on other parts of the Blink engine (CSS, DOM, etc.).
* `namespace blink`:  Confirms this is Blink-specific code.
* `class ContainerQueryEvaluatorTest`:  Clearly this is a test suite for a class named `ContainerQueryEvaluator`.
* `public PageTestBase`:  Suggests this test relies on a framework for setting up and managing a test page environment.
* `SetUp()`:  A common setup function in testing frameworks, likely used to initialize the test environment. The `setInnerHTML` call immediately tells me it manipulates the DOM.
* `ContainerElement()`: A helper function to get a specific element by ID.
* `ParseContainer()`:  Parses a string representing a CSS `@container` rule. This is a crucial hint about the file's purpose.
* `CreateEvaluatorForType()`: Creates an instance of the `ContainerQueryEvaluator`, hinting at different container types.
* `Eval()`:  Multiple `Eval` functions suggest different ways to evaluate container queries, likely based on size or custom properties. The return type `bool` signifies a true/false result.
* `SizeContainerChanged()`, `StickyContainerChanged()`, `SnapContainerChanged()`, `StyleContainerChanged()`: These function names clearly indicate the types of changes the `ContainerQueryEvaluator` is designed to handle.
* `EvalAndAdd()`:  Evaluates a query and potentially adds it to a collection of results.
* `GetResults()`:  Retrieves the collection of evaluation results.
* `ClearSizeResults()`, `ClearStyleResults()`:  Functions to clear cached evaluation results.
* `TEST_F()`:  A standard macro in Google Test, indicating individual test cases. The names of these tests (`ContainmentMatch`, `SizeContainerChanged`, etc.) provide valuable clues about what aspects of the evaluator are being tested.

**2. Identifying the Core Functionality:**

Based on the keywords and function names, the core functionality of this test file quickly becomes apparent: **testing the `ContainerQueryEvaluator` class**. More specifically, it seems to focus on:

* **Parsing and evaluating CSS container queries.** The `ParseContainer` and `Eval` functions are key here.
* **Handling different types of container queries:** Size queries (`min-width`, `min-height`), style queries (`style(--...)`), and scroll-state queries (`scroll-state(...)`).
* **Reacting to changes in the container:** Size changes, sticky state changes, snap point changes, and style changes (custom properties).
* **Caching and clearing evaluation results.** The `GetResults`, `ClearSizeResults`, and `ClearStyleResults` functions point to this.
* **Integration with the Blink rendering engine:** The `#include` statements and the use of classes like `ComputedStyle`, `Element`, and `Document` confirm this.

**3. Relating to Web Technologies (HTML, CSS, JavaScript):**

The connection to web technologies is clear:

* **CSS:** The file directly deals with parsing and evaluating CSS `@container` rules and related properties (`container-type`, custom properties).
* **HTML:** The `SetUp` function manipulates the HTML DOM to create a test structure. The queries themselves target elements within this structure.
* **JavaScript:** While this file is C++, the functionality it tests is directly related to how container queries will behave when used in web pages. JavaScript can dynamically manipulate styles and trigger the conditions that these tests are verifying.

**4. Inferring Logical Reasoning and Examples:**

The test cases themselves provide examples of logical reasoning. For instance, the `ContainmentMatch` test checks various combinations of `min-width`, `min-height`, and container types to ensure the evaluator correctly determines if a query matches. I can see the direct input (the query string, width, height, container type) and the expected output (true or false).

For instance, in `ContainmentMatch`:

* **Input:** `query = "(min-width: 100px)"`, `width = 100.0`, `container_type = type_size`, `contained_axes = horizontal`
* **Expected Output:** `true`

Similarly, the `SizeContainerChanged` test shows the evaluator's behavior when the container's size changes. It demonstrates the caching mechanism and how changes invalidate cached results.

**5. Identifying Potential User/Programming Errors:**

By looking at the test cases and the evaluator's responsibilities, I can infer potential errors:

* **Incorrect CSS syntax in `@container` rules:** The `ParseContainer` function likely handles this, but invalid syntax would prevent proper evaluation.
* **Misunderstanding the behavior of different container types:**  Using `container-type: inline-size` when expecting block-level size containment, for example.
* **Incorrectly specifying units in container queries:** Forgetting units or using incorrect units.
* **Not understanding the invalidation logic:**  Being surprised when a seemingly unrelated style change triggers a re-evaluation of container queries.

**6. Tracing User Operations:**

The test setup provides a basic structure. A user would typically:

1. **Write HTML:** Define elements and their initial structure.
2. **Write CSS:** Include `@container` rules to apply styles based on the container's characteristics. Set `container-type` and potentially `container-name`.
3. **Browser loads the page:** The Blink engine parses the HTML and CSS.
4. **Layout and Style Calculation:** The engine calculates the initial layout and applies styles, including those based on container queries. The `ContainerQueryEvaluator` is invoked during this process.
5. **User interactions or JavaScript:** May cause changes to the container's size, scroll position, or custom properties, triggering re-evaluation by the `ContainerQueryEvaluator`.

The test file simulates these steps by setting up a basic HTML structure and then triggering simulated changes (size changes, style changes) and checking the evaluator's response.

**7. Summarizing Functionality (for Part 1):**

Finally, based on the analysis, I can summarize the file's purpose for the "Part 1" prompt. It's crucial to focus on what the *code* is doing, not just what it's testing.

This thought process combines code analysis, understanding of web technologies, and logical deduction to comprehensively understand the purpose and functionality of the given test file.
这是 Chromium Blink 引擎中 `blink/renderer/core/css/container_query_evaluator_test.cc` 文件的第一部分，它主要的功能是 **测试 `ContainerQueryEvaluator` 类的功能**。

`ContainerQueryEvaluator` 负责评估 CSS 容器查询 (Container Queries) 的条件是否成立。容器查询允许开发者根据父容器的尺寸或其他特性（如样式、滚动状态）来应用不同的 CSS 样式。

**具体功能归纳如下：**

1. **创建和初始化 `ContainerQueryEvaluator` 对象:**  测试如何为特定的容器元素创建评估器。
2. **解析容器查询:** 测试如何解析 CSS 容器查询字符串，并将其转换为 `ContainerQuery` 对象。
3. **评估尺寸相关的容器查询:** 测试当容器的尺寸（宽度、高度）发生变化时，`ContainerQueryEvaluator` 如何判断尺寸相关的查询条件是否满足，例如 `(min-width: 100px)` 或 `(max-height: 200px)`。
4. **评估样式相关的容器查询:** 测试当容器的自定义 CSS 属性 (CSS Custom Properties) 发生变化时，`ContainerQueryEvaluator` 如何判断样式相关的查询条件是否满足，例如 `style(--my-variable: value)`。
5. **评估滚动状态相关的容器查询:** 测试当容器的滚动状态（例如是否吸顶/吸底，是否吸附到滚动捕捉点）发生变化时，`ContainerQueryEvaluator` 如何判断滚动状态相关的查询条件是否满足，例如 `scroll-state(stuck: top)` 或 `scroll-state(snapped: block)`。
6. **缓存和清除评估结果:** 测试 `ContainerQueryEvaluator` 如何缓存已评估的查询结果，以及如何在容器属性发生变化时清除这些缓存，以便重新评估。
7. **处理不同类型的容器:** 测试针对不同类型的容器（例如 `container-type: size`，`container-type: inline-size`，`container-type: scroll-state`）的查询评估。
8. **处理容器轴向的包含关系:** 测试当容器指定了 `container-type: size` 时，只有在容器包含特定轴向 (水平或垂直) 的尺寸时，尺寸相关的查询才会生效。
9. **处理容器的显示状态:** 测试当容器的 `display` 属性为 `none` 时，评估器的行为。
10. **处理打印场景:** 测试在打印场景下，容器查询的评估是否正确。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:** 该文件直接测试了 CSS 容器查询的核心功能。
    * **例子:**  `ParseContainer("(min-width: 100px)")`  解析了一个 CSS 尺寸相关的容器查询。
    * **例子:**  `ParseContainer("style(--my-prop: value)")` 解析了一个 CSS 样式相关的容器查询。
    * **例子:**  `Eval(query, 100.0, 100.0, type_size, horizontal)`  模拟容器尺寸变化，并评估 CSS 查询。

* **HTML:**  测试用例通过 HTML 创建了容器元素，这是容器查询应用的基础。
    * **例子:**  `GetDocument().body()->setInnerHTML(R"HTML(...)HTML");`  在测试开始时设置了 HTML 结构，包含了被测试的容器元素。
    * **例子:**  `ContainerElement()`  方法获取了 HTML 中 ID 为 "container" 的元素。

* **JavaScript:** 虽然这个文件是 C++ 代码，但它测试的功能最终会影响到 JavaScript 与 CSS 的交互。当 JavaScript 修改容器的尺寸、样式或滚动状态时，会触发容器查询的重新评估，从而可能改变元素的样式。
    * **例子:**  在实际应用中，JavaScript 可以通过修改元素的 `style` 属性或添加/移除类名来改变容器的尺寸，这些操作会间接地触发 `ContainerQueryEvaluator` 的工作。

**逻辑推理的假设输入与输出：**

* **假设输入 (尺寸查询):**
    * `query`: "(min-width: 200px)"
    * `width`: 250px
    * `height`: 150px
    * `container_type`: `type_size` (表示容器包含尺寸信息)
    * `contained_axes`: `horizontal` (表示容器包含水平方向的尺寸)
* **预期输出:** `Eval()` 函数返回 `true`，因为容器的宽度 (250px) 大于等于 200px。

* **假设输入 (样式查询):**
    * `query`: "style(--theme-color: dark)"
    * `custom_property_name`: "--theme-color"
    * `custom_property_value`: "dark"
* **预期输出:** `Eval()` 函数返回 `true`，因为容器的自定义属性 `--theme-color` 的值是 "dark"。

**用户或编程常见的使用错误举例说明：**

* **错误使用 `container-type`:**  用户可能错误地设置了 `container-type`，导致尺寸查询无法生效。例如，如果容器设置了 `container-type: inline-size`，而查询的是 `(min-height: 100px)`，则该查询可能不会按预期工作，除非容器也包含了垂直方向的尺寸信息。
* **CSS 语法错误:**  在 `@container` 规则中编写了错误的 CSS 语法，导致解析失败。例如 `(@container min-width: 100px) {}` (缺少了括号)。
* **误解单位:**  在容器查询中使用了错误的单位或者忘记了添加单位。例如 `(min-width: 100)` (缺少单位 `px`)。
* **自定义属性名称拼写错误:** 在样式查询中，自定义属性的名称拼写错误，导致查询无法匹配。例如 `style(--tehme-color: dark)` (应该为 `--theme-color`)。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **开发者编写 HTML 和 CSS 代码:**  开发者创建了一个包含容器的 HTML 结构，并使用 CSS 的 `@container` 规则定义了基于容器特性的样式。
2. **浏览器加载页面并解析 CSS:** 当浏览器加载该页面时，Blink 引擎的 CSS 解析器会解析 CSS 代码，包括 `@container` 规则，并创建相应的内部数据结构 (`CSSContainerRule`, `ContainerQuery` 等)。
3. **布局和样式计算:** 在布局和样式计算阶段，Blink 引擎需要确定哪些样式规则应该应用到哪些元素上。当遇到使用了容器查询的样式规则时，`ContainerQueryEvaluator` 会被创建并用于评估容器查询的条件是否满足。
4. **容器属性变化:**  如果容器的尺寸、样式或滚动状态发生变化（例如通过 JavaScript 操作，或者窗口大小调整），Blink 引擎会通知 `ContainerQueryEvaluator`，使其重新评估相关的容器查询。
5. **样式更新:**  根据 `ContainerQueryEvaluator` 的评估结果，元素的样式会被更新。

如果开发者在调试容器查询相关的问题，他们可能会在以下情况下查看或涉及 `ContainerQueryEvaluatorTest`:

* **容器查询样式未按预期生效:** 开发者发现容器查询的条件应该满足，但样式却没有应用，这可能意味着 `ContainerQueryEvaluator` 的评估逻辑存在问题。
* **性能问题:**  大量的容器查询可能会影响性能，开发者可能需要了解 `ContainerQueryEvaluator` 的工作原理和优化方法。
* **理解容器查询的具体行为:** 开发者想要深入了解 Blink 引擎是如何处理容器查询的，例如不同类型的容器查询是如何评估的，缓存机制是如何工作的等。

**总结 (针对第 1 部分):**

`blink/renderer/core/css/container_query_evaluator_test.cc` 的第一部分主要用于测试 `ContainerQueryEvaluator` 类的核心功能，包括解析和评估尺寸、样式和滚动状态相关的 CSS 容器查询，并验证其在不同容器类型和场景下的行为。它确保了 Blink 引擎能够正确地根据容器的特性应用相应的 CSS 样式。

Prompt: 
```
这是目录为blink/renderer/core/css/container_query_evaluator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/container_query_evaluator.h"

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/core/css/container_query.h"
#include "third_party/blink/renderer/core/css/css_container_rule.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/match_result.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class ContainerQueryEvaluatorTest : public PageTestBase {
 public:
  void SetUp() override {
    PageTestBase::SetUp();
    GetDocument().body()->setInnerHTML(R"HTML(
      <div id="container-parent">
        <div id="container"></div>
      </div>
    )HTML");
  }

  Element& ContainerElement() {
    return *GetDocument().getElementById(AtomicString("container"));
  }

  ContainerQuery* ParseContainer(String query) {
    String rule = "@container " + query + " {}";
    auto* style_rule = DynamicTo<StyleRuleContainer>(
        css_test_helpers::ParseRule(GetDocument(), rule));
    if (!style_rule) {
      return nullptr;
    }
    return &style_rule->GetContainerQuery();
  }

  ContainerQueryEvaluator* CreateEvaluatorForType(unsigned container_type) {
    ComputedStyleBuilder builder(
        *GetDocument().GetStyleResolver().InitialStyleForElement());
    builder.SetContainerType(container_type);
    ContainerElement().SetComputedStyle(builder.TakeStyle());
    return MakeGarbageCollected<ContainerQueryEvaluator>(ContainerElement());
  }

  bool Eval(String query,
            double width,
            double height,
            unsigned container_type,
            PhysicalAxes contained_axes) {
    ContainerQuery* container_query = ParseContainer(query);
    DCHECK(container_query);
    ContainerQueryEvaluator* evaluator = CreateEvaluatorForType(container_type);
    evaluator->SizeContainerChanged(
        PhysicalSize(LayoutUnit(width), LayoutUnit(height)), contained_axes);
    return evaluator->Eval(*container_query).value;
  }

  bool Eval(String query,
            String custom_property_name,
            String custom_property_value) {
    const CSSParserContext* context =
        StrictCSSParserContext(SecureContextMode::kSecureContext);
    CSSUnparsedDeclarationValue* value =
        CSSVariableParser::ParseDeclarationValue(custom_property_value, false,
                                                 *context);
    DCHECK(value);

    ComputedStyleBuilder builder =
        GetDocument().GetStyleResolver().InitialStyleBuilderForElement();
    builder.SetVariableData(AtomicString(custom_property_name),
                            value->VariableDataValue(), false);
    ContainerElement().SetComputedStyle(builder.TakeStyle());

    auto* evaluator =
        MakeGarbageCollected<ContainerQueryEvaluator>(ContainerElement());
    evaluator->SizeContainerChanged(
        PhysicalSize(LayoutUnit(100), LayoutUnit(100)),
        PhysicalAxes{kPhysicalAxesNone});

    ContainerQuery* container_query = ParseContainer(query);
    return evaluator->Eval(*container_query).value;
  }

  using Change = ContainerQueryEvaluator::Change;

  Change SizeContainerChanged(ContainerQueryEvaluator* evaluator,
                              PhysicalSize size,
                              unsigned container_type,
                              PhysicalAxes axes) {
    ComputedStyleBuilder builder(
        *GetDocument().GetStyleResolver().InitialStyleForElement());
    builder.SetContainerType(container_type);
    ContainerElement().SetComputedStyle(builder.TakeStyle());
    return evaluator->SizeContainerChanged(size, axes);
  }

  Change StickyContainerChanged(ContainerQueryEvaluator* evaluator,
                                ContainerStuckPhysical stuck_horizontal,
                                ContainerStuckPhysical stuck_vertical,
                                unsigned container_type) {
    ComputedStyleBuilder builder(
        *GetDocument().GetStyleResolver().InitialStyleForElement());
    builder.SetContainerType(container_type);
    ContainerElement().SetComputedStyle(builder.TakeStyle());
    return evaluator->StickyContainerChanged(stuck_horizontal, stuck_vertical);
  }

  Change SnapContainerChanged(ContainerQueryEvaluator* evaluator,
                              ContainerSnappedFlags snapped,
                              unsigned container_type) {
    ComputedStyleBuilder builder(
        *GetDocument().GetStyleResolver().InitialStyleForElement());
    builder.SetContainerType(container_type);
    ContainerElement().SetComputedStyle(builder.TakeStyle());
    return evaluator->SnapContainerChanged(snapped);
  }

  Change StyleContainerChanged(ContainerQueryEvaluator* evaluator) {
    return evaluator->StyleContainerChanged();
  }

  bool EvalAndAdd(ContainerQueryEvaluator* evaluator,
                  const ContainerQuery& query,
                  Change change = Change::kNearestContainer) {
    MatchResult dummy_result;
    return evaluator->EvalAndAdd(query, change, dummy_result);
  }

  using Result = ContainerQueryEvaluator::Result;
  const HeapHashMap<Member<const ContainerQuery>, Result>& GetResults(
      ContainerQueryEvaluator* evaluator) const {
    return evaluator->results_;
  }

  unsigned GetUnitFlags(ContainerQueryEvaluator* evaluator) const {
    return evaluator->unit_flags_;
  }

  void ClearSizeResults(ContainerQueryEvaluator* evaluator,
                        Change change) const {
    return evaluator->ClearResults(change,
                                   ContainerQueryEvaluator::kSizeContainer);
  }

  void ClearStyleResults(ContainerQueryEvaluator* evaluator,
                         Change change) const {
    return evaluator->ClearResults(change,
                                   ContainerQueryEvaluator::kStyleContainer);
  }

  const PhysicalAxes none{kPhysicalAxesNone};
  const PhysicalAxes both{kPhysicalAxesBoth};
  const PhysicalAxes horizontal{kPhysicalAxesHorizontal};
  const PhysicalAxes vertical{kPhysicalAxesVertical};

  const unsigned type_normal = kContainerTypeNormal;
  const unsigned type_size = kContainerTypeSize;
  const unsigned type_inline_size = kContainerTypeInlineSize;
  const unsigned type_scroll_state = kContainerTypeScrollState;
};

TEST_F(ContainerQueryEvaluatorTest, ContainmentMatch) {
  {
    String query = "(min-width: 100px)";
    EXPECT_TRUE(Eval(query, 100.0, 100.0, type_size, horizontal));
    EXPECT_TRUE(Eval(query, 100.0, 100.0, type_size, both));
    EXPECT_TRUE(Eval(query, 100.0, 100.0, type_inline_size, horizontal));
    EXPECT_TRUE(Eval(query, 100.0, 100.0, type_inline_size, both));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_size, vertical));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_size, none));
    EXPECT_FALSE(Eval(query, 99.0, 100.0, type_size, horizontal));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_normal, both));
  }

  {
    String query = "(min-height: 100px)";
    EXPECT_TRUE(Eval(query, 100.0, 100.0, type_size, vertical));
    EXPECT_TRUE(Eval(query, 100.0, 100.0, type_size, both));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_size, horizontal));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_size, none));
    EXPECT_FALSE(Eval(query, 100.0, 99.0, type_size, vertical));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_normal, both));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_inline_size, both));
  }

  {
    String query = "((min-width: 100px) and (min-height: 100px))";
    EXPECT_TRUE(Eval(query, 100.0, 100.0, type_size, both));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_size, vertical));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_size, horizontal));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_size, none));
    EXPECT_FALSE(Eval(query, 100.0, 99.0, type_size, both));
    EXPECT_FALSE(Eval(query, 99.0, 100.0, type_size, both));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_normal, both));
    EXPECT_FALSE(Eval(query, 100.0, 100.0, type_inline_size, both));
  }
}

TEST_F(ContainerQueryEvaluatorTest, SizeContainerChanged) {
  PhysicalSize size_50(LayoutUnit(50), LayoutUnit(50));
  PhysicalSize size_100(LayoutUnit(100), LayoutUnit(100));
  PhysicalSize size_200(LayoutUnit(200), LayoutUnit(200));

  ContainerQuery* container_query_50 = ParseContainer("(min-width: 50px)");
  ContainerQuery* container_query_100 = ParseContainer("(min-width: 100px)");
  ContainerQuery* container_query_200 = ParseContainer("(min-width: 200px)");
  ASSERT_TRUE(container_query_50);
  ASSERT_TRUE(container_query_100);
  ASSERT_TRUE(container_query_200);

  ContainerQueryEvaluator* evaluator = CreateEvaluatorForType(type_inline_size);
  SizeContainerChanged(evaluator, size_100, type_size, horizontal);

  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_100));
  EXPECT_FALSE(EvalAndAdd(evaluator, *container_query_200));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Calling SizeContainerChanged with the values we already have should not
  // produce a Change.
  EXPECT_EQ(Change::kNone,
            SizeContainerChanged(evaluator, size_100, type_size, horizontal));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // EvalAndAdding the same queries again is allowed.
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_100));
  EXPECT_FALSE(EvalAndAdd(evaluator, *container_query_200));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Resize from 100px to 200px.
  EXPECT_EQ(Change::kNearestContainer,
            SizeContainerChanged(evaluator, size_200, type_size, horizontal));
  EXPECT_EQ(0u, GetResults(evaluator).size());

  // Now both 100px and 200px queries should return true.
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_100));
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_200));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Calling SizeContainerChanged with the values we already have should not
  // produce a Change.
  EXPECT_EQ(Change::kNone,
            SizeContainerChanged(evaluator, size_200, type_size, horizontal));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Still valid to EvalAndAdd the same queries again.
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_100));
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_200));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Setting contained_axes=vertical should invalidate the queries, since
  // they query width.
  EXPECT_EQ(Change::kNearestContainer,
            SizeContainerChanged(evaluator, size_200, type_size, vertical));
  EXPECT_EQ(0u, GetResults(evaluator).size());

  EXPECT_FALSE(EvalAndAdd(evaluator, *container_query_100));
  EXPECT_FALSE(EvalAndAdd(evaluator, *container_query_200));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Switching back to horizontal.
  EXPECT_EQ(Change::kNearestContainer,
            SizeContainerChanged(evaluator, size_100, type_size, horizontal));
  EXPECT_EQ(0u, GetResults(evaluator).size());

  // Resize to 200px.
  EXPECT_EQ(Change::kNone,
            SizeContainerChanged(evaluator, size_200, type_size, horizontal));
  EXPECT_EQ(0u, GetResults(evaluator).size());

  // Add a query of each Change type.
  EXPECT_TRUE(
      EvalAndAdd(evaluator, *container_query_100, Change::kNearestContainer));
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_200,
                         Change::kDescendantContainers));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Resize to 50px should cause both queries to change their evaluation.
  // `ContainerChanged` should return the biggest `Change`.
  EXPECT_EQ(Change::kDescendantContainers,
            SizeContainerChanged(evaluator, size_50, type_size, horizontal));
}

TEST_F(ContainerQueryEvaluatorTest, StyleContainerChanged) {
  PhysicalSize size_100(LayoutUnit(100), LayoutUnit(100));

  Element& container_element = ContainerElement();
  ComputedStyleBuilder builder(
      *GetDocument().GetStyleResolver().InitialStyleForElement());
  builder.SetContainerType(type_inline_size);
  const ComputedStyle* style = builder.TakeStyle();
  container_element.SetComputedStyle(style);

  ContainerQueryEvaluator* evaluator = CreateEvaluatorForType(type_inline_size);
  EXPECT_EQ(Change::kNone,
            evaluator->SizeContainerChanged(size_100, horizontal));

  ContainerQuery* foo_bar_query = ParseContainer("style(--foo: bar)");
  ContainerQuery* size_bar_foo_query =
      ParseContainer("(inline-size = 100px) and style(--bar: foo)");
  ContainerQuery* no_match_query =
      ParseContainer("(inline-size > 1000px) and style(--no: match)");
  ASSERT_TRUE(foo_bar_query);
  ASSERT_TRUE(size_bar_foo_query);
  ASSERT_TRUE(no_match_query);

  auto eval_and_add_all = [&]() {
    EvalAndAdd(evaluator, *foo_bar_query);
    EvalAndAdd(evaluator, *size_bar_foo_query);
    EvalAndAdd(evaluator, *no_match_query);
  };

  eval_and_add_all();

  // Calling StyleContainerChanged without changing the style should not produce
  // a change.
  EXPECT_EQ(Change::kNone, StyleContainerChanged(evaluator));
  EXPECT_EQ(3u, GetResults(evaluator).size());

  const bool inherited = true;

  // Set --no: match. Should not cause change because size query part does not
  // match.
  builder = ComputedStyleBuilder(*style);
  builder.SetVariableData(AtomicString("--no"),
                          css_test_helpers::CreateVariableData("match"),
                          inherited);
  style = builder.TakeStyle();
  container_element.SetComputedStyle(style);
  EXPECT_EQ(Change::kNone, StyleContainerChanged(evaluator));
  EXPECT_EQ(3u, GetResults(evaluator).size());

  // Set --foo: bar. Should trigger change.
  builder = ComputedStyleBuilder(*style);
  builder.SetVariableData(AtomicString("--foo"),
                          css_test_helpers::CreateVariableData("bar"),
                          inherited);
  style = builder.TakeStyle();
  container_element.SetComputedStyle(style);
  EXPECT_EQ(Change::kNearestContainer, StyleContainerChanged(evaluator));
  EXPECT_EQ(0u, GetResults(evaluator).size());

  // Set --bar: foo. Should trigger change because size part also matches.
  eval_and_add_all();
  builder = ComputedStyleBuilder(*style);
  builder.SetVariableData(AtomicString("--bar"),
                          css_test_helpers::CreateVariableData("foo"),
                          inherited);
  style = builder.TakeStyle();
  container_element.SetComputedStyle(style);
  EXPECT_EQ(Change::kNearestContainer, StyleContainerChanged(evaluator));
  EXPECT_EQ(0u, GetResults(evaluator).size());
}

TEST_F(ContainerQueryEvaluatorTest, StickyContainerChanged) {
  ContainerQuery* container_query_left =
      ParseContainer("scroll-state(stuck: left)");
  ContainerQuery* container_query_bottom =
      ParseContainer("scroll-state(stuck: bottom)");
  ASSERT_TRUE(container_query_left);
  ASSERT_TRUE(container_query_bottom);

  ContainerQueryEvaluator* evaluator =
      CreateEvaluatorForType(type_scroll_state);
  StickyContainerChanged(evaluator, ContainerStuckPhysical::kLeft,
                         ContainerStuckPhysical::kNo, type_scroll_state);

  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_left));
  EXPECT_FALSE(EvalAndAdd(evaluator, *container_query_bottom));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Calling StickyContainerChanged with the values we already have should not
  // produce a Change.
  EXPECT_EQ(Change::kNone, StickyContainerChanged(
                               evaluator, ContainerStuckPhysical::kLeft,
                               ContainerStuckPhysical::kNo, type_scroll_state));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // EvalAndAdding the same queries again is allowed.
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_left));
  EXPECT_FALSE(EvalAndAdd(evaluator, *container_query_bottom));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Set vertically stuck to bottom.
  EXPECT_EQ(Change::kNearestContainer,
            StickyContainerChanged(evaluator, ContainerStuckPhysical::kLeft,
                                   ContainerStuckPhysical::kBottom,
                                   type_scroll_state));
  EXPECT_EQ(0u, GetResults(evaluator).size());

  // Now both left and bottom queries should return true.
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_left));
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_bottom));
  EXPECT_EQ(2u, GetResults(evaluator).size());
}

TEST_F(ContainerQueryEvaluatorTest, SnapContainerChanged) {
  ContainerQuery* container_query_snap_block =
      ParseContainer("scroll-state(snapped: block)");
  ContainerQuery* container_query_snap_inline =
      ParseContainer("scroll-state(snapped: inline)");
  ASSERT_TRUE(container_query_snap_block);
  ASSERT_TRUE(container_query_snap_inline);

  ContainerQueryEvaluator* evaluator =
      CreateEvaluatorForType(type_scroll_state);
  SnapContainerChanged(evaluator,
                       static_cast<ContainerSnappedFlags>(ContainerSnapped::kY),
                       type_scroll_state);

  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_snap_block));
  EXPECT_FALSE(EvalAndAdd(evaluator, *container_query_snap_inline));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Calling SnapContainerChanged with the values we already have should not
  // produce a Change.
  EXPECT_EQ(
      Change::kNone,
      SnapContainerChanged(
          evaluator, static_cast<ContainerSnappedFlags>(ContainerSnapped::kY),
          type_scroll_state));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // EvalAndAdding the same queries again is allowed.
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_snap_block));
  EXPECT_FALSE(EvalAndAdd(evaluator, *container_query_snap_inline));
  EXPECT_EQ(2u, GetResults(evaluator).size());

  // Add inline snapped.
  EXPECT_EQ(Change::kNearestContainer,
            SnapContainerChanged(
                evaluator,
                static_cast<ContainerSnappedFlags>(ContainerSnapped::kX) |
                    static_cast<ContainerSnappedFlags>(ContainerSnapped::kY),
                type_scroll_state));
  EXPECT_EQ(0u, GetResults(evaluator).size());

  // Now both block and inline queries should return true.
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_snap_block));
  EXPECT_TRUE(EvalAndAdd(evaluator, *container_query_snap_inline));
  EXPECT_EQ(2u, GetResults(evaluator).size());
}

TEST_F(ContainerQueryEvaluatorTest, ClearResults) {
  PhysicalSize size_100(LayoutUnit(100), LayoutUnit(100));

  ContainerQuery* container_query_px = ParseContainer("(min-width: 50px)");
  ContainerQuery* container_query_em = ParseContainer("(min-width: 10em)");
  ContainerQuery* container_query_vh = ParseContainer("(min-width: 10vh)");
  ContainerQuery* container_query_cqw = ParseContainer("(min-width: 10cqw)");
  ContainerQuery* container_query_style = ParseContainer("style(--foo: bar)");
  ContainerQuery* container_query_size_and_style =
      ParseContainer("(width > 0px) and style(--foo: bar)");
  ASSERT_TRUE(container_query_px);
  ASSERT_TRUE(container_query_em);
  ASSERT_TRUE(container_query_vh);
  ASSERT_TRUE(container_query_cqw);
  ASSERT_TRUE(container_query_style);
  ASSERT_TRUE(container_query_size_and_style);

  ContainerQueryEvaluator* evaluator = CreateEvaluatorForType(type_inline_size);
  SizeContainerChanged(evaluator, size_100, type_size, horizontal);

  EXPECT_EQ(0u, GetResults(evaluator).size());

  using UnitFlags = MediaQueryExpValue::UnitFlags;

  // EvalAndAdd (min-width: 50px), nearest.
  EvalAndAdd(evaluator, *container_query_px, Change::kNearestContainer);
  ASSERT_EQ(1u, GetResults(evaluator).size());
  EXPECT_EQ(Change::kNearestContainer,
            GetResults(evaluator).at(container_query_px).change);
  EXPECT_EQ(UnitFlags::kNone,
            GetResults(evaluator).at(container_query_px).unit_flags);
  EXPECT_EQ(UnitFlags::kNone, GetUnitFlags(evaluator));

  // EvalAndAdd (min-width: 10em), descendant
  EvalAndAdd(evaluator, *container_query_em, Change::kDescendantContainers);
  ASSERT_EQ(2u, GetResults(evaluator).size());
  EXPECT_EQ(Change::kDescendantContainers,
            GetResults(evaluator).at(container_query_em).change);
  EXPECT_EQ(UnitFlags::kFontRelative,
            GetResults(evaluator).at(container_query_em).unit_flags);
  EXPECT_EQ(UnitFlags::kFontRelative, GetUnitFlags(evaluator));

  // EvalAndAdd (min-width: 10vh), nearest
  EvalAndAdd(evaluator, *container_query_vh, Change::kNearestContainer);
  ASSERT_EQ(3u, GetResults(evaluator).size());
  EXPECT_EQ(Change::kNearestContainer,
            GetResults(evaluator).at(container_query_vh).change);
  EXPECT_EQ(UnitFlags::kStaticViewport,
            GetResults(evaluator).at(container_query_vh).unit_flags);
  EXPECT_EQ(static_cast<unsigned>(UnitFlags::kFontRelative |
                                  UnitFlags::kStaticViewport),
            GetUnitFlags(evaluator));

  // EvalAndAdd (min-width: 10cqw), descendant
  EvalAndAdd(evaluator, *container_query_cqw, Change::kDescendantContainers);
  ASSERT_EQ(4u, GetResults(evaluator).size());
  EXPECT_EQ(Change::kDescendantContainers,
            GetResults(evaluator).at(container_query_cqw).change);
  EXPECT_EQ(UnitFlags::kContainer,
            GetResults(evaluator).at(container_query_cqw).unit_flags);
  EXPECT_EQ(
      static_cast<unsigned>(UnitFlags::kFontRelative |
                            UnitFlags::kStaticViewport | UnitFlags::kContainer),
      GetUnitFlags(evaluator));

  // Make sure clearing style() results does not clear any size results.
  ClearStyleResults(evaluator, Change::kDescendantContainers);
  ASSERT_EQ(4u, GetResults(evaluator).size());

  // Clearing kNearestContainer should leave all information originating
  // from kDescendantContainers.
  ClearSizeResults(evaluator, Change::kNearestContainer);
  ASSERT_EQ(2u, GetResults(evaluator).size());
  EXPECT_EQ(Change::kDescendantContainers,
            GetResults(evaluator).at(container_query_em).change);
  EXPECT_EQ(Change::kDescendantContainers,
            GetResults(evaluator).at(container_query_cqw).change);
  EXPECT_EQ(UnitFlags::kFontRelative,
            GetResults(evaluator).at(container_query_em).unit_flags);
  EXPECT_EQ(UnitFlags::kContainer,
            GetResults(evaluator).at(container_query_cqw).unit_flags);
  EXPECT_EQ(
      static_cast<unsigned>(UnitFlags::kFontRelative | UnitFlags::kContainer),
      GetUnitFlags(evaluator));

  // Clearing Change::kDescendantContainers should clear everything.
  ClearSizeResults(evaluator, Change::kDescendantContainers);
  ASSERT_EQ(0u, GetResults(evaluator).size());
  EXPECT_EQ(UnitFlags::kNone, GetUnitFlags(evaluator));

  // Add everything again, to ensure that
  // ClearResults(Change::kDescendantContainers, ...) also clears
  // Change::kNearestContainer.
  EvalAndAdd(evaluator, *container_query_px, Change::kNearestContainer);
  EvalAndAdd(evaluator, *container_query_em, Change::kDescendantContainers);
  EvalAndAdd(evaluator, *container_query_vh, Change::kNearestContainer);
  EvalAndAdd(evaluator, *container_query_cqw, Change::kDescendantContainers);
  ASSERT_EQ(4u, GetResults(evaluator).size());
  EXPECT_EQ(
      static_cast<unsigned>(UnitFlags::kFontRelative |
                            UnitFlags::kStaticViewport | UnitFlags::kContainer),
      GetUnitFlags(evaluator));
  ClearSizeResults(evaluator, Change::kDescendantContainers);
  ASSERT_EQ(0u, GetResults(evaluator).size());
  EXPECT_EQ(UnitFlags::kNone, GetUnitFlags(evaluator));

  // Clearing style() results
  EvalAndAdd(evaluator, *container_query_px, Change::kNearestContainer);
  EvalAndAdd(evaluator, *container_query_style, Change::kDescendantContainers);
  EvalAndAdd(evaluator, *container_query_size_and_style,
             Change::kNearestContainer);

  EXPECT_EQ(3u, GetResults(evaluator).size());
  ClearStyleResults(evaluator, Change::kNearestContainer);
  EXPECT_EQ(2u, GetResults(evaluator).size());

  EvalAndAdd(evaluator, *container_query_px, Change::kNearestContainer);
  EvalAndAdd(evaluator, *container_query_style, Change::kDescendantContainers);
  EvalAndAdd(evaluator, *container_query_size_and_style,
             Change::kNearestContainer);

  EXPECT_EQ(3u, GetResults(evaluator).size());
  ClearStyleResults(evaluator, Change::kDescendantContainers);
  EXPECT_EQ(1u, GetResults(evaluator).size());

  ClearSizeResults(evaluator, Change::kNearestContainer);
  EXPECT_EQ(0u, GetResults(evaluator).size());
}

TEST_F(ContainerQueryEvaluatorTest, SizeInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #container {
        container-type: size;
        width: 500px;
        height: 500px;
      }
      @container (min-width: 500px) {
        div { z-index:1; }
      }
    </style>
    <div id=container>
      <div id=div></div>
      <div id=div></div>
      <div id=div></div>
      <div id=div></div>
      <div id=div></div>
      <div id=div></div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);
  ASSERT_TRUE(container->GetContainerQueryEvaluator());

  {
    // Causes re-layout, but the size does not change
    container->SetInlineStyleProperty(CSSPropertyID::kFloat, "left");

    unsigned before_count = GetStyleEngine().StyleForElementCount();

    UpdateAllLifecyclePhasesForTest();

    unsigned after_count = GetStyleEngine().StyleForElementCount();

    // Only #container should be affected. In particular, we should not
    // recalc any style for <div> children of #container.
    EXPECT_EQ(1u, after_count - before_count);
  }

  {
    // The size of the container changes, but it does not matter for
    // the result of the query (min-width: 500px).
    container->SetInlineStyleProperty(CSSPropertyID::kWidth, "600px");

    unsigned before_count = GetStyleEngine().StyleForElementCount();

    UpdateAllLifecyclePhasesForTest();

    unsigned after_count = GetStyleEngine().StyleForElementCount();

    // Only #container should be affected. In particular, we should not
    // recalc any style for <div> children of #container.
    EXPECT_EQ(1u, after_count - before_count);
  }
}

TEST_F(ContainerQueryEvaluatorTest, DependentQueries) {
  PhysicalSize size_100(LayoutUnit(100), LayoutUnit(100));
  PhysicalSize size_150(LayoutUnit(150), LayoutUnit(150));
  PhysicalSize size_200(LayoutUnit(200), LayoutUnit(200));
  PhysicalSize size_300(LayoutUnit(300), LayoutUnit(300));
  PhysicalSize size_400(LayoutUnit(400), LayoutUnit(400));

  ContainerQuery* query_min_200px = ParseContainer("(min-width: 200px)");
  ContainerQuery* query_max_300px = ParseContainer("(max-width: 300px)");
  ASSERT_TRUE(query_min_200px);

  ContainerQueryEvaluator* evaluator = CreateEvaluatorForType(type_inline_size);
  SizeContainerChanged(evaluator, size_100, type_size, horizontal);

  EvalAndAdd(evaluator, *query_min_200px);
  EvalAndAdd(evaluator, *query_max_300px);
  // Updating with the same size as we initially had should not invalidate
  // any query results.
  EXPECT_EQ(Change::kNone,
            SizeContainerChanged(evaluator, size_100, type_size, horizontal));

  // Makes no difference for either of (min-width: 200px), (max-width: 300px):
  EXPECT_EQ(Change::kNone,
            SizeContainerChanged(evaluator, size_150, type_size, horizontal));

  // (min-width: 200px) becomes true:
  EXPECT_EQ(Change::kNearestContainer,
            SizeContainerChanged(evaluator, size_200, type_size, horizontal));

  EvalAndAdd(evaluator, *query_min_200px);
  EvalAndAdd(evaluator, *query_max_300px);
  EXPECT_EQ(Change::kNone,
            SizeContainerChanged(evaluator, size_200, type_size, horizontal));

  // Makes no difference for either of (min-width: 200px), (max-width: 300px):
  EXPECT_EQ(Change::kNone,
            SizeContainerChanged(evaluator, size_300, type_size, horizontal));

  // (max-width: 300px) becomes false:
  EXPECT_EQ(Change::kNearestContainer,
            SizeContainerChanged(evaluator, size_400, type_size, horizontal));
}

TEST_F(ContainerQueryEvaluatorTest, EvaluatorDisplayNone) {
  SetBodyInnerHTML(R"HTML(
    <style>
      main {
        display: block;
        container-type: size;
        width: 500px;
        height: 500px;
      }
      main.none {
        display: none;
      }
      @container (min-width: 500px) {
        div { --x:test; }
      }
    </style>
    <main id=outer>
      <div>
        <main id=inner>
          <div></div>
        </main>
      </div>
    </main>
  )HTML");

  // Inner container
  Element* inner = GetDocument().getElementById(AtomicString("inner"));
  ASSERT_TRUE(inner);
  EXPECT_TRUE(inner->GetContainerQueryEvaluator());

  inner->classList().Add(AtomicString("none"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(inner->GetContainerQueryEvaluator());

  inner->classList().Remove(AtomicString("none"));
  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(inner->GetContainerQueryEvaluator());

  // Outer container
  Element* outer = GetDocument().getElementById(AtomicString("outer"));
  ASSERT_TRUE(outer);
  EXPECT_TRUE(outer->GetContainerQueryEvaluator());
  EXPECT_TRUE(inner->GetContainerQueryEvaluator());

  outer->classList().Add(AtomicString("none"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(outer->GetContainerQueryEvaluator());
  EXPECT_FALSE(inner->GetContainerQueryEvaluator());

  outer->classList().Remove(AtomicString("none"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(outer->GetContainerQueryEvaluator());
  EXPECT_TRUE(inner->GetContainerQueryEvaluator());
}

TEST_F(ContainerQueryEvaluatorTest, Printing) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @page { size: 400px 400px; }
      body { margin: 0; }
      #container {
        container-type: size;
        width: 50vw;
      }

      @container (width = 200px) {
        #target { color: green; }
      }
    </style>
    <div id="container">
      <span id="target"></span>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_NE(
      target->ComputedStyleRef().VisitedDependentColor(GetCSSPropertyColor()),
      Color(0, 128, 0));

  constexpr gfx::SizeF initial_page_size(400, 400);
  GetDocument().GetFrame()->StartPrinting(WebPrintParams(initial_page_size));
  GetDocument().View()->UpdateLifecyclePhasesForPrinting();

  EXPECT_EQ(
      target->ComputedStyleRef().VisitedDependentColor(GetCSSPropertyColor()),
      Color(0, 128, 0));
}

TEST_F(ContainerQueryEvaluatorTest, CustomPropertyStyleQuery) {
  EXPECT_FALSE(Eval("style(--my-prop)", "--my-prop", "10px"));
  EXPECT_FALSE(Eval("style(--my-prop:)", "--my-prop", "10px"));
  EXPECT_FALSE(Eval("style(--my-prop: )", "--my-prop", "10px"));

  EXPECT_FALSE(Eval("style(--my-prop)", "--my-prop", ""));
  EXPECT_TRUE(Eval("style(--my-prop:)", "--my-prop", ""));
  EXPECT_TRUE(Eval("style(--my-prop: )", "--my-prop", ""));

  EXPECT_TRUE(Eval("style(--my-prop:10px)", "--my-prop", "10px"));
  EXPECT_TRUE(Eval("style(--my-prop: 10px)", "--my-prop", "10px"));
  EXPECT_TRUE(Eval("style(--my-prop:10px )", "--my-prop", "10px"));
  EXPECT_TRUE(Eval("style(--my-prop: 10px )", "--my-prop", "10px"));
}

TEST_F(ContainerQueryEvaluatorTest, FindContainer) {
  SetBodyInnerHTML(R"HTML(
    <div style="container-name:outer;container-type:size">
      <div style="container-name:outer">
        <div style="container-type: size">
          <div>
            <div></div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateA
"""


```