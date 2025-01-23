Response:
The user wants a summary of the provided C++ code, which is a test file for the Blink rendering engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename `affected_by_pseudo_test.cc` and the presence of `TEST_F` macros immediately indicate this is a test file. The "affected_by_pseudo" part suggests it's testing how changes related to CSS pseudo-classes (specifically `:has()`) affect the styling of elements.

2. **Analyze the test structure:** The code consists of multiple test cases, each setting up an HTML structure and then performing actions (like adding or removing classes) to see how the `:has()` selector behaves. The `CheckAffectedByFlagsForHas` function is central, as it verifies specific flags related to how the `:has()` selector impacts styling.

3. **Interpret `CheckAffectedByFlagsForHas`:** This function takes an element ID and a list of flags as input. The flags (`kAffectedBySubjectHas`, `kAffectedByNonSubjectHas`, etc.) represent different ways a `:has()` selector can influence the styling of an element. The boolean values associated with each flag in the test cases indicate whether that specific influence is expected for the given element.

4. **Connect to web technologies:**  The code manipulates HTML elements (using IDs and classes) and CSS selectors (specifically `:has()`). Changes in the HTML structure or class attributes trigger re-styling, which is the core functionality being tested. JavaScript is mentioned as a possible user action that could lead to these changes.

5. **Infer the testing scenarios:** The different test case names (`AffectedByNonSubjectHasComplexCase1`, `AffectedBySelectorQuery`, `AffectedByHasAfterInsertion1`, etc.) hint at the specific aspects of `:has()` being tested. For example, "AfterInsertion" likely tests how `:has()` behaves when elements are dynamically added to the DOM.

6. **Identify key functions:** Besides `CheckAffectedByFlagsForHas`, `SetHtmlInnerHTML`, `GetElementById`, and `UpdateAllLifecyclePhasesForTest` are crucial. They set up the initial HTML, manipulate elements, and trigger style recalculations, respectively.

7. **Consider user errors and debugging:**  A common user error would be incorrect CSS syntax for the `:has()` selector. The test file itself can be a debugging aid, showing expected behavior for various scenarios. Following the step-by-step actions in the tests can help track down style issues.

8. **Focus on the specific section:** The prompt asks for a summary of the *provided* code snippet. Therefore, the summary should focus on the test cases within that snippet, even though the overall file likely contains more.

9. **Structure the summary:** Organize the information logically, covering the file's purpose, how it relates to web technologies, and the specific functionality being tested in the provided section.

10. **Address all parts of the prompt:**  Make sure to explicitly address the relationships with JavaScript, HTML, and CSS, provide examples (even if they are based on the test code itself), discuss user errors, and outline the debugging process.

11. **Refine and clarify:** Review the summary for clarity and accuracy. Ensure the language is accessible and avoids overly technical jargon where possible. For example, instead of just saying "tests the invalidation of style," explain that it checks *which* elements need to be restyled when changes occur.
好的，这是对提供的代码片段的功能归纳：

**功能归纳：**

这段代码是 `affected_by_pseudo_test.cc` 文件的一部分，专门用于测试 CSS `:has()` 伪类选择器对元素样式影响的边界情况和复杂场景。  它重点关注当`:has()`选择器中的非主体部分（即`:has()`括号内的选择器）匹配到元素时，哪些其他元素会被标记为“受影响”，需要重新计算样式。

**具体功能点：**

* **测试 `:has()` 伪类对兄弟节点的影响:**  `AffectedByNonSubjectHasComplexCase1` 和 `AffectedByNonSubjectHasComplexCase2` 测试了当`:has()`选择器匹配到一个元素时，其兄弟节点是否会被标记为受影响。这些测试用例通过添加或移除兄弟节点的类名来触发样式重新计算，并验证预期受影响的元素。

* **测试 `:has()` 伪类对祖先和祖先兄弟节点的影响:**  这些测试用例也涵盖了 `:has()` 匹配的元素如何影响其祖先元素以及祖先元素的兄弟节点。

* **测试 `:has()` 伪类的复杂组合选择器:**  `AffectedByNonSubjectHasComplexCase3` 使用了更复杂的 `:has()` 选择器 `~ .b > .c > .d`，并测试了当匹配发生时，哪些元素会受到影响。这旨在验证引擎在处理复杂`:has()`选择器时的正确性。

* **测试通过 JavaScript 进行的动态修改对 `:has()` 影响的计算:**  代码中使用了 `GetElementById()->setAttribute()` 来模拟 JavaScript 修改元素属性的操作。这部分测试了当通过 JavaScript 修改 DOM 结构或元素属性时，`:has()` 选择器是否能正确地识别并标记受影响的元素。

* **断言受影响元素的数量和标志位:**  `ASSERT_EQ(1U, element_count);`  这类断言用于验证在特定操作后，预期需要重新计算样式的元素数量是否正确。`CheckAffectedByFlagsForHas()` 函数则用于检查特定元素的“受影响”标志位是否符合预期。这些标志位 (`kAffectedBySubjectHas`, `kAffectedByNonSubjectHas`, 等)  精确地指示了元素因 `:has()` 伪类而受到何种程度的影响。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  这段代码的核心是测试 CSS 的 `:has()` 伪类选择器。它验证了在各种 HTML 结构和 CSS 规则下，`:has()` 是否能正确地识别需要更新样式的元素。例如，CSS 规则 `.a:has(~ .b > .c > .d) ~ .e { background-color: lime; }`  定义了当类名为 `a` 的元素拥有一个满足 `~ .b > .c > .d` 选择器的兄弟节点时，类名为 `e` 的兄弟节点应该应用特定的样式。

* **HTML:** 测试用例通过 `SetHtmlInnerHTML()` 设置了不同的 HTML 结构，用于模拟各种场景。例如，使用了嵌套的 `div` 元素，并赋予不同的 `id` 和 `class` 属性，来构建测试 `:has()` 行为的上下文。

* **JavaScript:** 虽然这段代码本身是 C++ 写的测试，但它模拟了 JavaScript 可以触发的 DOM 操作，比如修改元素的 `class` 属性。 例如，`GetElementById("div4")->setAttribute(html_names::kClassAttr, AtomicString("d"));`  模拟了 JavaScript 代码 `document.getElementById('div4').setAttribute('class', 'd')` 的行为。  这些操作会触发浏览器的样式重新计算，而测试代码会验证 `:has()` 相关的计算是否正确。

**逻辑推理与假设输入/输出：**

以 `AffectedByNonSubjectHasComplexCase1` 的部分代码为例：

**假设输入：**

```html
<style>
  .a:has(+ .b) { color: green; }
</style>
<div id=div1 class='a'></div>
<div id=div2></div>
<div id=div3 class='b'></div>
```

**初始状态输出 (通过 `CheckAffectedByFlagsForHas` 验证):**

* `div1`: `kAffectedBySubjectHas`: false, `kAffectedByNonSubjectHas`: false, ...
* `div2`: ...
* `div3`: ...

**操作:**

```c++
GetElementById("div2")->setAttribute(html_names::kClassAttr, AtomicString("b"));
UpdateAllLifecyclePhasesForTest();
```

**预期输出 (通过 `CheckAffectedByFlagsForHas` 验证):**

* `div1`: `kAffectedBySubjectHas`: false, `kAffectedByNonSubjectHas`: true, `kSiblingsAffectedByHas`: true, ... (因为 `div1` 现在拥有一个紧邻的类名为 `b` 的兄弟节点 `div2`)
* `div2`: ...
* `div3`: ...

**用户或编程常见的使用错误：**

* **CSS 选择器错误：** 用户可能会写出不正确的 `:has()` 选择器语法，例如，在 `:has()` 内部使用了不被允许的选择器组合。
* **对 `:has()` 影响范围的误解：** 开发者可能不清楚 `:has()` 会影响到哪些元素的样式重算。 例如，可能会错误地认为只有 `:has()` 的主体元素（选择器前半部分匹配的元素）会受到影响，而忽略了非主体部分匹配的元素及其相关的祖先和兄弟节点。
* **JavaScript 动态修改 DOM 后样式未及时更新：**  开发者可能在 JavaScript 中修改了 DOM 结构或属性，但没有正确地触发浏览器的样式重新计算，导致页面显示不符合预期。

**用户操作到达这里的调试线索：**

假设用户在浏览网页时发现某个元素的样式没有按照预期应用。作为 Chromium 开发者，在调试时可能会遵循以下步骤：

1. **检查 CSS 规则：**  首先查看相关的 CSS 规则，特别是涉及到 `:has()` 伪类的规则，确认选择器是否正确，样式属性是否定义正确。
2. **检查 HTML 结构：**  查看元素的 HTML 结构，确认是否存在满足 `:has()` 选择器内部条件的目标元素。
3. **使用开发者工具：** 使用浏览器的开发者工具（Elements 面板）查看元素的 computed styles 和 applied styles，确认是否有相关的 CSS 规则被应用，以及是否有其他规则覆盖了预期的样式。
4. **断点调试渲染引擎代码：** 如果通过开发者工具无法定位问题，可能需要深入到 Chromium 的渲染引擎代码进行调试。 可能会在以下地方设置断点：
    * **StyleRecalc 类:**  查看样式重新计算的流程。
    * **Selector Matching 代码:**  查看选择器匹配的逻辑，特别是 `:has()` 相关的匹配代码。
    * **`affected_by_pseudo_test.cc` 中的测试用例：**  如果怀疑是 `:has()` 的行为不符合预期，可以参考或运行这个测试文件中的相关用例，来验证引擎的实现是否正确。开发者可能会修改这个测试文件，添加新的测试用例来复现和定位 bug。
5. **分析 "Affected By" 标志位：**  测试文件中使用的 `CheckAffectedByFlagsForHas` 函数所检查的标志位，在渲染引擎内部被用来跟踪哪些元素因为特定的 CSS 规则而需要重新计算样式。 调试时，查看这些标志位的状态可以帮助理解样式更新的流程。

**总结这段代码的功能：**

总而言之，这段代码是 Chromium Blink 引擎中用于测试 CSS `:has()` 伪类选择器行为的单元测试。它通过构建各种复杂的 HTML 结构和 CSS 规则，并模拟 JavaScript 的 DOM 操作，来验证引擎是否能够正确地识别和标记因 `:has()` 选择器而受到影响的元素，确保浏览器的样式计算逻辑的正确性。 它是保证浏览器正确渲染使用了 `:has()` 伪类的网页的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/css/affected_by_pseudo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
edBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div8", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->setAttribute(html_names::kClassAttr,
                                       AtomicString("d"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div9")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByNonSubjectHasComplexCase3) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(~ .b > .c > .d) ~ .e { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
      </div>
      <div id=div4>
        <div id=div5>
          <div id=div6></div>
        </div>
      </div>
      <div id=div7 class='b'>
        <div id=div8 class='c'>
          <div id=div9 class='d'>
            <div id=div10></div>
          </div>
        </div>
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
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div8", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div10", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->setAttribute(html_names::kClassAttr,
                                       AtomicString("e"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div10", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div8")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div10", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedBySelectorQuery) {
  SetHtmlInnerHTML(R"HTML(
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
      </div>
      <div id=div4 class='e'>
        <div id=div5>
          <div id=div6></div>
        </div>
      </div>
      <div id=div7 class='b'>
        <div id=div8 class='c'>
          <div id=div9 class='d'>
            <div id=div10></div>
          </div>
        </div>
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
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div8", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div10", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  StaticElementList* result = GetDocument().QuerySelectorAll(
      AtomicString(".a:has(~ .b > .c > .d) ~ .e"));
  ASSERT_EQ(1U, result->length());
  EXPECT_EQ(result->item(0)->GetIdAttribute(), "div4");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div8", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div10", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterInsertion1) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(.b) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'></div>
    </div>
    <div id=div2>
      <div id=div21>
        <div id=div211>
          <div id=div2111></div>
        </div>
        <div id=div212 class='b'>
          <div id=div2121></div>
        </div>
      </div>
      <div id=div22></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
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
      "div211", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2111", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div212", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2121", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div21")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div21",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div211", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2111", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div212",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2121",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  auto* subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div12"));
  subtree_root->setInnerHTML(
      String::FromUTF8(R"HTML(<div id=div121></div>)HTML"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(subtree_root);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div11")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div111>
          <div id=div1111></div>
          <div id=div1112></div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3U, GetStyleEngine().StyleForElementCount() - start_count);

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
  CheckAffectedByFlagsForHas("div1112",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div1112")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div11121>
          <div id=div111211></div>
          <div id=div111212 class='b'>
            <div id=div1112121></div>
          </div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(5U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas("div11121",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div111211",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div111212",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div1112121",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div2111")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div21111>
          <div id=div211111></div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div21111", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div211111", {{kAffectedBySubjectHas, false},
                    {kAffectedByNonSubjectHas, false},
                    {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                    {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div2121")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div21211>
          <div id=div212111></div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas("div21211",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div212111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterInsertion2) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(> .b > .c) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'></div>
    </div>
    <div id=div2>
      <div id=div21>
        <div id=div211 class='b'>
          <div id=div2111 class='c'>
            <div id=div21111></div>
          </div>
        </div>
        <div id=div212></div>
```