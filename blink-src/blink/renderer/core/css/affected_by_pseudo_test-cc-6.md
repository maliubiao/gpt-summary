Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. I need to:

1. **Identify the core purpose:** Analyze the code to determine what it's testing. The presence of `TEST_F` suggests unit tests. The names of the tests and functions like `CheckAffectedByFlagsForHas` point towards testing how CSS `:has()` pseudo-class affects style invalidation.

2. **Relate to web technologies:** Explain how this C++ code interacts with JavaScript, HTML, and CSS. This will involve understanding how CSS selectors (especially `:has()`) trigger style recalculations when the DOM changes.

3. **Illustrate with examples:** Provide concrete examples of HTML, CSS, and JavaScript code that relate to the test scenarios.

4. **Infer logic and provide input/output:**  Based on the test cases, deduce the logic being tested. This involves understanding how changes in the DOM (like adding/removing elements or changing attributes) affect the "affected by" flags for elements when the `:has()` pseudo-class is involved. I'll need to consider the initial state and the impact of DOM manipulations.

5. **Highlight common errors:** Identify potential mistakes developers might make when working with `:has()` selectors that could lead to unexpected behavior or performance issues.

6. **Describe the user's journey:**  Explain the steps a user might take in a web browser that would eventually trigger this code. This involves connecting user interactions (like hovering, clicking, or page loading) to the underlying style calculation mechanism.

7. **Summarize the functionality:** Given this is part 7 of 8, I need to provide a concise summary of the code's purpose.

**Mental Sandbox:**

* **Parsing the tests:**  I see various tests focused on `:has()`. Some tests check initial "affected by" flags. Others simulate DOM manipulations (attribute changes, adding/removing elements) and verify how these flags change and how many style recalculations are triggered.
* **Key concepts:** The core idea seems to be testing the correctness and efficiency of the style invalidation system when using `:has()`. It's checking which elements need their styles recalculated after DOM changes.
* **`CheckAffectedByFlagsForHas`:** This function seems to be the central verification mechanism. It takes an element ID and expected boolean flags as input.
* **DOM manipulation:**  The tests use methods like `setAttribute`, `SetHovered`, `RemoveChild` to simulate user actions or JavaScript-driven DOM updates.
* **`UpdateAllLifecyclePhasesForTest`:**  This likely triggers a style recalculation.
* **`GetStyleEngine().StyleForElementCount()`:** This seems to be a way to track the number of elements whose styles are recalculated.
* **User actions:**  User actions like hovering over elements, or JavaScript modifying the DOM, could lead to these style recalculations.

**Constraint Checklist & Confidence:**

* List the functionalities? Yes.
* Relation to JS/HTML/CSS? Yes.
* Examples? Yes.
* Logic and I/O? Yes, I can infer the logic and represent it with simplified input/output scenarios based on the test structure.
* Common errors? Yes.
* User journey? Yes.
* Summarize functionality? Yes.
* Part 7 of 8? Yes, I need to keep the summary focused on the provided snippet.

Confidence Score: 5/5

Strategizing complete. I will now proceed with generating the response based on the above analysis.
这是 `blink/renderer/core/css/affected_by_pseudo_test.cc` 文件的第 7 部分，它属于 Chromium Blink 引擎的测试代码。这个文件的主要功能是**测试 CSS 中 `:has()` 伪类对元素样式影响的跟踪和更新机制，特别是当 DOM 结构发生变化时的情况。**

更具体地说，这部分代码主要关注以下几个方面：

1. **`:has()` 伪类对祖先元素和兄弟元素的影响:**  测试当 `:has()` 伪类匹配的元素发生变化（例如被移除）时，哪些祖先元素和兄弟元素的样式需要重新计算。
2. **DOM 移除操作的影响:**  测试在不同的 DOM 结构下，移除元素（特别是被 `:has()` 伪类引用的元素）后，样式系统如何正确地标记和更新受影响的元素。
3. **性能优化：最小化样式重算:**  通过断言 `GetStyleEngine().StyleForElementCount()` 的变化，来验证样式系统是否只重新计算了真正需要更新的元素的样式，从而提高性能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这个测试文件直接针对 CSS 的 `:has()` 伪类。`:has()` 允许我们选择器匹配包含指定元素的父元素或前兄弟元素。测试验证了当 `:has()` 的条件发生变化时，样式系统能否正确地识别受影响的元素。
    * **例子:**  CSS 规则 `.a:has(.b)` 会选择所有包含子元素 `.b` 的 `.a` 元素。这个测试会验证当 `.b` 元素被移除时，`.a` 元素的样式是否需要更新。

* **HTML:**  测试用例通过 `SetHtmlInnerHTML` 方法设置不同的 HTML 结构，来模拟各种场景。这些 HTML 结构包含了不同的元素嵌套和兄弟关系，用于测试 `:has()` 在不同上下文下的行为。
    * **例子:**  HTML 代码 `<div id='div1' class='a'><div class='b'></div></div>` 定义了一个 `.a` 元素，它包含一个 `.b` 元素。测试会操作这个结构，例如移除 `.b`，然后验证 `.a` 的样式更新情况。

* **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，但它模拟了 JavaScript 操作 DOM 的行为。例如，`GetElementById(...)->RemoveChild(...)` 模拟了 JavaScript 中常用的 `removeChild()` 方法。当 JavaScript 动态地修改 DOM 时，CSS 样式需要相应地更新，这个测试验证了 Blink 引擎在这方面的正确性。
    * **例子:**  JavaScript 代码 `document.getElementById('div1').removeChild(document.querySelector('.b'));` 会移除 ID 为 `div1` 的元素下的 `.b` 子元素。这个测试模拟了这种操作，并检查了样式系统的反应。

**逻辑推理、假设输入与输出:**

让我们以 `AffectedByHasAfterRemoval1` 测试用例的一部分为例进行逻辑推理：

**假设输入:**

```html
<style>
  .a:has(.b) { color: green }
</style>
<div id=div1 class='a'>
  <div id=div11></div>
  <div id=div12 class='b'>
    <div id=div121 class='b'></div>
  </div>
  <div id=div13 class='b'></div>
  <div id=div14 class='b'></div>
  <div id=div15></div>
</div>
```

**初始状态:**  `div1` 因为包含 `.b` 子元素，所以其 `kAffectedBySubjectHas` 和 `kAncestorsOrAncestorSiblingsAffectedByHas` 标志为 `true`。其他元素的标志根据它们与 `:has()` 选择器的关系而设置。

**操作:**  移除 `div12` 的子元素 `div121`。

**预期输出:**  由于 `div1` 仍然包含 `.b` 元素（`div12` 和 `div13`，`div14`），移除 `div121` 不会影响 `div1` 的 `:has(.b)` 匹配，因此 `div1` 的受影响标志应该保持不变，样式重算计数应该为 0。

**代码中的验证:**

```c++
  GetDocument()
      .getElementById(AtomicString("div12"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div121")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
```

**用户或编程常见的使用错误及举例说明:**

* **过度使用 `:has()` 导致性能问题:**  `:has()` 是一种强大的选择器，但它的计算成本相对较高。在复杂的页面中使用过多的 `:has()` 可能会导致性能问题，因为每次 DOM 变化都需要重新评估这些选择器。
    * **例子:**  如果一个大型网站的 CSS 中有大量的类似于 `body :has(.active .menu-item:hover)` 的规则，当用户在菜单项上悬停时，可能需要检查整个 `body` 下的元素，导致延迟。
* **对 `:has()` 的行为理解不足:** 开发者可能不清楚 `:has()` 会影响哪些元素的样式更新。例如，可能会错误地认为只有直接匹配 `:has()` 选择器的元素才会受到影响。
    * **例子:**  一个开发者可能认为只有 `.a:has(.b)` 中的 `.a` 元素会在 `.b` 元素变化时更新样式，而忽略了其他祖先或兄弟元素可能也会受到影响。这个测试文件帮助验证了这些情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载网页:** 当用户在 Chrome 浏览器中打开一个包含使用 `:has()` 伪类的 CSS 规则的网页时，Blink 引擎会解析这些 CSS 规则。
2. **DOM 构建和样式计算:** Blink 引擎会根据 HTML 构建 DOM 树，并根据 CSS 规则计算每个元素的样式。对于包含 `:has()` 的规则，引擎会记录哪些元素可能受到影响。
3. **用户交互或 JavaScript 操作:**  当用户与网页交互（例如鼠标悬停、点击）或 JavaScript 代码修改 DOM 结构时（例如添加、删除元素或修改属性），Blink 引擎会触发样式的重新计算。
4. **`:has()` 的评估:**  当 DOM 发生变化时，Blink 引擎会重新评估包含 `:has()` 的选择器，判断哪些元素的样式需要更新。
5. **`affected_by_pseudo_test.cc` 的作用:**  当 Blink 引擎的开发者修改了与 `:has()` 相关的代码时，他们会运行像 `affected_by_pseudo_test.cc` 这样的测试用例，以确保修改没有引入 bug，并且样式更新机制仍然能够正确高效地工作。如果测试失败，开发者可以通过调试来追踪问题，例如查看哪些元素的受影响标志设置不正确，或者样式重算次数超出了预期。

**归纳一下它的功能 (作为第 7 部分):**

作为 `affected_by_pseudo_test.cc` 的第 7 部分，这段代码专注于**测试在元素被移除后，`:has()` 伪类对相关元素样式影响的追踪和更新是否正确。**  它通过模拟不同的 DOM 移除场景，并检查受影响元素的标志位和样式重算次数，来验证 Blink 引擎在处理这类情况时的正确性和性能。  这部分特别强调了 DOM 移除操作对 `:has()` 匹配状态以及由此引发的样式更新的影响。

Prompt: 
```
这是目录为blink/renderer/core/css/affected_by_pseudo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共8部分，请归纳一下它的功能

"""
                       {{kAffectedBySubjectHas, true},
                              {kAffectedByLogicalCombinationsInHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div121",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div1211",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div11")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a b"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div11")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div11")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a invalid"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0U, GetStyleEngine().StyleForElementCount() - start_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div12")->setAttribute(html_names::kClassAttr,
                                        AtomicString("d e"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0U, GetStyleEngine().StyleForElementCount() - start_count);
}

TEST_F(AffectedByPseudoTest,
       AncestorsOrSiblingsAffectedByHoverInHasWithFastRejection) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(nonexistent), .a:has(.b:hover) { color: green }
    </style>
    <div id=div1 class='a'>
      <div id=div11></div>
      <div id=div12 class='b'></div>
      <div id=div13></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, true},
               {kAffectedByPseudoInHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                {kAncestorsOrSiblingsAffectedByHoverInHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div13")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div13")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div12")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div12")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterRemoval1) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(.b) { color: green }
    </style>
    <div id=div1 class='a'>
      <div id=div11></div>
      <div id=div12 class='b'>
        <div id=div121 class='b'></div>
      </div>
      <div id=div13 class='b'></div>
      <div id=div14 class='b'></div>
      <div id=div15></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div14", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div15", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div12"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div121")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div14", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div12")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div14", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div14")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div13")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterRemoval2) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(> .b > .c) { color: green }
    </style>
    <div id=div1 class='a'>
      <div id=div11></div>
      <div id=div12 class='b'>
        <div id=div121 class='c'></div>
        <div id=div122 class='c'></div>
      </div>
      <div id=div13 class='b'>
        <div id=div131 class='c'></div>
        <div id=div132 class='c'></div>
        <div id=div133 class='c'></div>
        <div id=div134></div>
      </div>
      <div id=div14></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div122", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div131", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div132", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div133", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div134", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div14", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div14")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div13"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div134")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div13"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div131")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div13"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div133")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div122", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div132", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div13")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div122", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div12"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div121")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterRemoval3) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(~ .b) { color: green }
    </style>
    <div id=div1>
      <div id=div11 class='a'>
        <div id=div111 class='a'></div>
        <div id=div112 class='b'></div>
        <div id=div113 class='b'></div>
        <div id=div114></div>
      </div>
      <div id=div12>
        <div id=div121 class='b'></div>
        <div id=div122 class='b'></div>
      </div>
      <div id=div13>
        <div id=div131></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, true},
                {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div111", {{kAffectedBySubjectHas, true},
                 {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div112", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div114", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div122", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div131", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div114")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div112")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div113")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div12"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div122")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div13")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div12")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterRemoval4) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(+ .b + .c) { color: green }
    </style>
    <div id=div1>
      <div id=div11 class='a'>
        <div id=div111 class='a'></div>
        <div id=div112 class='b'></div>
        <div id=div113 class='c'></div>
        <div id=div114 class='c'></div>
        <div id=div115 class='c'></div>
        <div id=div116></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, true},
                {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div111", {{kAffectedBySubjectHas, true},
                 {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div112", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div114", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div115", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div116", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div115")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div113")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div114", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div116", {{kAffectedBySubjectHas, false},
                 {kSiblingsAffectedByHasForSiblingRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div116")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div114")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterRemoval5) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(~ .b .c) { color: green }
    </style>
    <div id=div1>
      <div id=div11 class='a'>
        <div id=div111 class='c'></div>
      </div>
      <div id=div12>
        <div id=div121></div>
        <div id=div122 class='c'></div>
      </div>
      <div id=div13>
        <div id=div131 class='c'></div>
      </div>
      <div id=div14 class='b'>
        <div id=div141></div>
        <div id=div142 class='c'></div>
        <div id=div143 class='c'></div>
      </div>
      <div id=div15 class='b'>
        <div id=div151 class='c'></div>
        <div id=div152></div>
      </div>
      <div id=div16 class='b'>
        <div id=div161 class='c'></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div111",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div121",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div122",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div131",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div14",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div141",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div142",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div143",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div15",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div151",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div152",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div16",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div161",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div111")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div12"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div122")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div12")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div13")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div14",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div141",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div142",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div143",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div15",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div151",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div152",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div16",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div161",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div16")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div143",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div15",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div151",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div152",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div15"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div152")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div15"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div151")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div14",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div141",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div142",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAnc
"""


```