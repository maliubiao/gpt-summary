Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Understanding of the File's Purpose:**

The file name `affected_by_pseudo_test.cc` immediately suggests that it's testing how certain CSS pseudo-classes affect elements. The presence of "has" in the code confirms the focus on the `:has()` pseudo-class. The "AffectedByFlags" further indicates that it's about tracking how the presence of `:has()` impacts the styling and layout calculations for various elements.

**2. Deconstructing the Tests:**

The code is structured as a series of `TEST_F` blocks. Each test appears to focus on a specific scenario involving the `:has()` pseudo-class. The `SetHtmlInnerHTML` function suggests the tests are manipulating the DOM (Document Object Model) and checking how styles are applied based on the `:has()` selector.

**3. Identifying Key Functions:**

* **`SetHtmlInnerHTML(...)`:** This function clearly sets up the HTML structure for the test. It's the starting point for each test case.
* **`UpdateAllLifecyclePhasesForTest()`:**  This is crucial. It indicates that after modifying the DOM, the test forces a re-calculation of styles and layout. This is where the `:has()` logic is likely triggered.
* **`CheckAffectedByFlagsForHas(element_id, expected_flags)`:** This is the core assertion function. It verifies the internal state of the Blink rendering engine regarding how an element is affected by `:has()`. The `expected_flags` are key-value pairs indicating whether the element is affected by subject/non-subject `:has()`, ancestor/sibling `:has()`, etc.
* **`GetElementById(...)`:**  Standard DOM manipulation for accessing specific elements.
* **`GetComputedStyle()`:**  Retrieves the final computed style of an element, after all CSS rules have been applied.
* **`VisitedDependentColor(GetCSSPropertyColor())`:** This hints at testing how `:has()` affects properties that can be influenced by pseudo-classes like `:visited`.

**4. Analyzing the Test Cases (Example: `AffectedByHasAfterInsertion5`):**

* **Initial Setup:** The test starts with a specific HTML structure and a CSS rule: `.a:has(~ .b .c) { color: green; }`. This rule selects elements with class 'a' that have a sibling which is followed by an element with class 'b' that contains an element with class 'c'.
* **Assertions Before Insertion:** The test uses `CheckAffectedByFlagsForHas` to verify the initial "affected by" status of various elements based on the initial DOM. This establishes a baseline.
* **DOM Manipulation (Insertion):** The code then uses JavaScript-like DOM manipulation (`MakeGarbageCollected<HTMLDivElement>`, `setAttribute`, `setInnerHTML`, `AppendChild`) to insert new elements into the existing structure. This simulates dynamic changes in a web page.
* **Assertions After Insertion:**  Crucially, *after* each insertion and `UpdateAllLifecyclePhasesForTest()`, the test *again* uses `CheckAffectedByFlagsForHas` to verify how the insertion has changed the "affected by" status of elements. It also checks the computed style of an element (`GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(...)`) to see if the CSS rule is now applied.
* **Repeating the Process:** The test repeats this pattern of insertion and assertion multiple times, testing different insertion points and element types.

**5. Connecting to Web Technologies:**

* **HTML:** The tests directly manipulate HTML elements and their structure. The `SetHtmlInnerHTML` function defines the initial HTML, and the subsequent insertion operations change it.
* **CSS:** The CSS rule (`.a:has(~ .b .c) { color: green; }`) is the driving force behind the tests. The `:has()` pseudo-class is the central feature being tested. The assertions verify whether this CSS rule correctly affects elements based on the presence or absence of matching elements within the `:has()` selector.
* **JavaScript (Indirectly):** While the test itself is in C++, the DOM manipulation methods (`AppendChild`, `setAttribute`, `setInnerHTML`) are very similar to their JavaScript counterparts. This suggests that this test is verifying the correctness of the rendering engine's behavior when the DOM is manipulated dynamically, as it often is through JavaScript on real web pages.

**6. Inferring Functionality and Logic:**

Based on the structure and the names of the functions and flags, we can infer that this test file is designed to:

* **Verify the correctness of the `:has()` pseudo-class implementation.**
* **Test how changes to the DOM (especially element insertion) affect the application of styles defined using `:has()`.**
* **Track which elements are considered "affected" by a `:has()` rule, even if the rule doesn't currently apply to them.** This "affected by" status is likely an optimization or internal mechanism to efficiently re-evaluate styles when the DOM changes.
* **Test various combinations of selectors within the `:has()` pseudo-class (e.g., descendant selectors, sibling selectors).**

**7. Identifying Potential User/Programming Errors:**

The tests, by their nature, help catch errors in the Blink rendering engine's implementation. From a user/programmer perspective, these tests indirectly highlight potential misunderstandings or edge cases related to the `:has()` pseudo-class, such as:

* **Not understanding how DOM manipulation affects `:has()` selectors.**  A developer might expect a style to apply immediately after inserting an element, but the rendering engine might need to perform a style re-calculation.
* **Incorrectly assuming the scope of the `:has()` selector.**  For example, not understanding the difference between direct child selectors (`>`) and descendant selectors (space).
* **Overlooking the performance implications of complex `:has()` selectors**, which might require more extensive DOM traversal.

**8. Debugging Scenario and User Operations:**

Imagine a user reports that a certain element's style isn't updating correctly after they dynamically add some content to the page using JavaScript. A developer debugging this might:

1. **Examine the relevant CSS rules**, looking for `:has()` selectors that might be involved.
2. **Use browser developer tools** to inspect the element's styles and see which rules are being applied.
3. **Step through the JavaScript code** that manipulates the DOM to understand the exact sequence of changes.
4. **Potentially write a simplified test case** that mirrors the user's scenario to reproduce the bug. This test case might look similar to the ones in `affected_by_pseudo_test.cc`.
5. **If working on the Blink engine itself**, they might run these existing tests or add new ones to pinpoint the issue in the style calculation logic.

**9. Summarizing Functionality (Part 6):**

Given the specific code in part 6, its main function is to **test how the rendering engine correctly identifies elements affected by the `:has()` pseudo-class after new elements are inserted into the DOM**. It focuses on scenarios involving sibling selectors (`~` and `+`) within the `:has()` argument and verifies the internal "affected by" flags for different elements before and after insertion. It also checks if the expected styles are applied based on the `:has()` condition. The tests are structured to cover various insertion points and complexities of the `:has()` selector.
```cpp
TEST_F(AffectedByPseudoTest, AffectedByLogicalCombinationsInHas) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(:is(.b .c)) { color: green; }
      .d:has(:is(.e)) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'>
        <div id=div111>
          <div id=div1111 class='c'></div>
        </div>
      </div>
      <div id=div12 class='d'>
        <div id=div121>
          <div id=div1211></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByLogicalCombinationsInHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByLogicalCombinationsInHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div1111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div12",
```

**功能归纳 (第 6 部分):**

这部分代码主要的功能是**测试 `:has()` 伪类选择器与逻辑组合器（例如 `:is()`）结合使用时，渲染引擎如何判断元素是否受到影响**。 具体来说，它测试了以下场景：

* **`:has(:is(.b .c))`**:  检查当 `:has()` 中使用 `:is()` 匹配后代选择器时，哪些元素会被标记为受到影响。
* **`:has(:is(.e))`**: 检查当 `:has()` 中使用 `:is()` 匹配简单的类选择器时，哪些元素会被标记为受到影响。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这部分代码直接测试 CSS 的 `:has()` 伪类和 `:is()` 逻辑组合器。
    * **例子:**  CSS 规则 `.a:has(:is(.b .c)) { color: green; }` 的意思是：选择所有拥有后代元素同时具有类名 `b` 和 `c` 的元素（祖先元素）且自身类名为 `a` 的元素，并将其文本颜色设置为绿色。

* **HTML:** 代码通过 `SetHtmlInnerHTML` 设置 HTML 结构，并在结构中定义了用于测试的元素及其类名和 ID。
    * **例子:** `<div id=div11 class='a'><div id=div111><div id=div1111 class='c'></div></div></div>` 这个 HTML 片段定义了一个 `div` 元素，其 ID 为 `div11`，类名为 `a`。它内部嵌套了两个 `div` 元素，最内层的 `div` 元素类名为 `c`。

* **JavaScript:** 虽然这段代码本身是用 C++ 编写的，属于 Blink 引擎的测试代码，但它测试的是当页面中的元素和样式被 JavaScript 动态修改后，CSS 引擎的反应是否正确。JavaScript 可以动态添加、删除或修改 HTML 元素及其属性，这会触发 CSS 样式的重新计算和应用。
    * **例子:**  假设在网页加载后，JavaScript 代码动态地给 `div111` 添加了类名 `b`，那么根据 CSS 规则 `.a:has(:is(.b .c))`，`div11` 应该会被应用 `color: green;` 的样式。这个测试的目标就是验证引擎在这种情况下的行为是否正确。

**逻辑推理及假设输入与输出:**

* **假设输入:**  以下 HTML 结构和 CSS 规则：
    ```html
    <style>
      .a:has(:is(.b .c)) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'>
        <div id=div111 class='b'>
          <div id=div1111 class='c'></div>
        </div>
      </div>
    </div>
    ```
* **预期输出 (基于测试代码):**
    * `div1` 不会被标记为受到 `:has` 的影响 (没有直接匹配的规则)。
    * `div11` 会被标记为受到 `kAffectedBySubjectHas` 和 `kAffectedByLogicalCombinationsInHas` 的影响，因为它自身匹配 `.a`，并且 `:has` 中的条件 `:is(.b .c)` 在其后代中得到满足。
    * `div111` 和 `div1111` 会被标记为受到 `kAncestorsOrAncestorSiblingsAffectedByHas` 的影响，因为它们是满足 `:has` 条件的元素，其祖先元素 `div11` 因此受到影响。

**用户或编程常见的使用错误:**

* **混淆后代选择器和子选择器:** 用户可能错误地认为 `.a:has(:is(.b > .c))` 会匹配上述的 HTML 结构，但实际上只有当 `div111` 的直接子元素是 `div1111` 且类名为 `c` 时才会匹配。理解 CSS 选择器的精确含义对于正确使用 `:has()` 非常重要。
* **忽略 `:is()` 的作用域:**  `:is()` 本身不会改变选择器的匹配范围，它只是提供了一种更清晰地组织选择器的方式。用户可能会误认为 `:is(.b .c)` 只会匹配直接子元素，但实际上它仍然匹配所有后代元素。
* **对 `:has()` 性能的潜在影响认识不足:**  复杂的 `:has()` 选择器可能会导致浏览器进行更多的 DOM 搜索，从而影响性能。用户在编写大量或复杂的 `:has()` 规则时需要注意这一点。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户报告样式问题:** 用户在浏览器中发现，某个元素的样式没有按照预期的方式应用。例如，一个应该变绿色的 `div` 元素并没有变绿。
2. **开发者检查 CSS 规则:** 开发者查看相关的 CSS 代码，发现其中使用了 `:has()` 伪类，例如 `.my-container:has(.error-message) { border: 1px solid red; }`。
3. **开发者检查 HTML 结构:** 开发者检查了该元素及其相关的 HTML 结构，查看是否满足 `:has()` 中的条件。
4. **怀疑 `:has()` 的行为:**  如果 HTML 结构看起来符合条件，但样式没有应用，开发者可能会怀疑浏览器对 `:has()` 的实现有问题。
5. **查看 Blink 引擎测试:** 为了验证或排除这个怀疑，开发者（特别是 Chromium 开发者）可能会查看 Blink 引擎中与 `:has()` 相关的测试代码，比如 `affected_by_pseudo_test.cc`。
6. **定位到相关测试用例:** 开发者可能会在测试文件中搜索与 `:is()` 或包含复杂选择器的 `:has()` 用例，例如本例中的 `AffectedByLogicalCombinationsInHas`。
7. **分析测试代码:** 开发者会分析测试代码的 HTML 结构、CSS 规则以及对 `CheckAffectedByFlagsForHas` 的断言，来理解 Blink 引擎是如何处理这类情况的，并尝试找到他们遇到的问题的根源。

**总结:**

这第 6 部分的 `affected_by_pseudo_test.cc` 文件专注于测试 Blink 引擎在处理带有 `:is()` 逻辑组合器的 `:has()` 伪类选择器时的行为，验证引擎是否正确地标记了受到这些复杂选择器影响的元素。这对于确保浏览器能够按照 CSS 规范正确渲染页面至关重要，尤其是在涉及到动态内容和复杂的选择器时。

### 提示词
```
这是目录为blink/renderer/core/css/affected_by_pseudo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
{kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div24",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div25", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterInsertion5) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(~ .b .c) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'></div>
    </div>
    <div id=div2>
      <div id=div21 class='a'></div>
      <div id=div22 class='b'>
        <div id=div221></div>
        <div id=div222>
          <div id=div2221></div>
          <div id=div2223></div>
          <div id=div2224 class='b'>
            <div id=div22241 class='c'></div>
          </div>
          <div id=div2225></div>
        </div>
      </div>
      <div id=div25></div>
    </div>
    <div id=div3>
      <div id=div31></div>
      <div id=div32></div>
      <div id=div33>
        <div id=div331></div>
      </div>
      <div id=div34></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div22",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div221", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div222",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2221", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2223", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2224",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div22241",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2225",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div25",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div31", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div32", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div33", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div331", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div34", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div12"));
  subtree_root->setInnerHTML(String::FromUTF8(R"HTML(
      <div id=div121>
        <div id=div1211></div>
        <div id=div1212></div>
      </div>
  )HTML"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(subtree_root);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(4U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div121",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1211",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1212",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  start_count = GetStyleEngine().StyleForElementCount();
  subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div13"));
  subtree_root->setAttribute(html_names::kClassAttr, AtomicString("b"));
  subtree_root->setInnerHTML(String::FromUTF8(R"HTML(
      <div id=div131>
        <div id=div1311 class='c'></div>
        <div id=div1312></div>
      </div>
  )HTML"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(subtree_root);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(5U, GetStyleEngine().StyleForElementCount() - start_count);

  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div121",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1211",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1212",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div131",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1311",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1312",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div2222"));
  subtree_root->setAttribute(html_names::kClassAttr, AtomicString("a"));
  subtree_root->setInnerHTML(
      String::FromUTF8(R"HTML(<div id=div22221></div>)HTML"));
  GetDocument()
      .getElementById(AtomicString("div222"))
      ->InsertBefore(subtree_root,
                     GetDocument().getElementById(AtomicString("div2223")));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div2221", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2222",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div22221",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div2223",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div2224",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas("div22241",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2225",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterInsertion6) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(+ .b + .c .d) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'></div>
    </div>
    <div id=div2>
      <div id=div21></div>
      <div id=div22></div>
      <div id=div23 class='b'></div>
      <div id=div24 class='c'></div>
      <div id=div25>
        <div id=div251></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div23", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div24", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div25", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div251", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div12"));
  subtree_root->setInnerHTML(String::FromUTF8(R"HTML(
      <div id=div121></div>
  )HTML"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(subtree_root);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div121",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div13"));
  subtree_root->setInnerHTML(String::FromUTF8(R"HTML(
      <div id=div131></div>
  )HTML"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(subtree_root);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div131",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // There can be some inefficiency for fixed adjacent distance :has() argument
  start_count = GetStyleEngine().StyleForElementCount();
  subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div14"));
  subtree_root->setInnerHTML(String::FromUTF8(R"HTML(
      <div id=div141 class='d'></div>
  )HTML"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(subtree_root);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3U, GetStyleEngine().StyleForElementCount() - start_count);

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  CheckAffectedByFlagsForHas(
      "div14",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div141",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div22")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div23",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div24",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div25", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div251", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div22")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // There can be some inefficiency for fixed adjacent distance :has() argument
  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div23")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div231 class='d'></div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div23",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div231",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div22")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div24")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div241>
          <div id=div2411 class='d'></div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div24",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div241",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div2411",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetElementById("div22")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterWiping) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(.b) { color: green; }
    </style>
    <div id='div1' class='a'>
      <div id='div11'>
        div11 <div id='div111' class='b'></div>
      </div>
      <div id='div12'>
        div12 <div id='div121' class='b'></div>
      </div>
    </div>
    <div id='div2'>
      div2 <div id='div21' class='b'></div>
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
      "div111", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div11"))
      ->setInnerHTML(String::FromUTF8(R"HTML(div11)HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0U, GetStyleEngine().StyleForElementCount() - start_count);

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
                 {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div12"))
      ->setInnerHTML(String::FromUTF8(R"HTML(div12)HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div2"))
      ->setInnerHTML(String::FromUTF8(R"HTML(div2)HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByLogicalCombinationsInHas) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(:is(.b .c)) { color: green; }
      .d:has(:is(.e)) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'>
        <div id=div111>
          <div id=div1111 class='c'></div>
        </div>
      </div>
      <div id=div12 class='d'>
        <div id=div121>
          <div id=div1211></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByLogicalCombinationsInHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByLogicalCombinationsInHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div1111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div12",
```