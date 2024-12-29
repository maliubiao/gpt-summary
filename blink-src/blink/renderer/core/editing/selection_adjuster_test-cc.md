Response:
Let's break down the thought process for analyzing the `selection_adjuster_test.cc` file.

1. **Understand the Core Purpose:** The filename itself, `selection_adjuster_test.cc`, strongly suggests this file contains tests for a component named `SelectionAdjuster`. The `.cc` extension indicates C++ source code.

2. **Identify Key Functionality from Includes:** The `#include` directives at the beginning are crucial:
    * `"third_party/blink/renderer/core/editing/selection_adjuster.h"`: This is the header file for the `SelectionAdjuster` class being tested. It confirms the core subject.
    * `"third_party/blink/renderer/core/editing/selection_template.h"`:  This suggests `SelectionAdjuster` likely works with some form of selection representation (a "template" for selections).
    * `"third_party/blink/renderer/core/editing/testing/editing_test_base.h"`: This indicates the file uses a testing framework specific to Blink's editing components. We can infer it provides utility functions for setting up test scenarios.
    * `"third_party/blink/renderer/core/html/forms/text_control_element.h"`: This suggests interactions with form elements like `<input>`, which are often involved in text selection scenarios.

3. **Examine the Test Structure:**  The code defines a test fixture `SelectionAdjusterTest` inheriting from `EditingTestBase`. This confirms the file's purpose is testing. The `TEST_F` macro indicates individual test cases within this fixture.

4. **Analyze Individual Test Cases (Iterative Process):**  Go through each `TEST_F` block and try to understand what it's testing. Look for patterns and recurring themes.

    * **Shadow Boundary Tests:** The first two tests (`AdjustShadowToCollpasedInDOMTree`, `AdjustShadowToCollpasedInFlatTree`) explicitly mention "Shadow boundary adjustment". They set up scenarios with `<template>` (for shadow DOM) and `<input>` elements and check how selections are adjusted at shadow boundaries.

    * **Editing Boundary Tests:**  Several tests (`DeleteNonEditableRange`, `FormatBlockContentEditableFalse`, `NestedContentEditableElements`, etc.) focus on how selections are adjusted around elements with `contenteditable` attributes. The names often suggest specific scenarios (deleting, formatting).

    * **Shadow Root as Boundary:**  Tests like `ShadowRootAsRootBoundaryElement` and `ShadowRootAsRootBoundaryElementEditable` specifically examine how the shadow root itself acts as a boundary for selection.

    * **Distributed Nodes:** Tests like `ShadowDistributedNodesWithoutEditingBoundary` and `ShadowDistributedNodesWithEditingBoundary` involve `<slot>` elements and how selections behave when nodes are distributed within shadow DOM.

    * **Combined Scenarios:**  Some tests (`EditingBoundaryOutsideOfShadowTree`, `EditingBoundaryInsideOfShadowTree`, `ShadowHostAndShadowTreeAreEditable`) combine shadow DOM and `contenteditable` scenarios to test more complex interactions.

    * **Type Adjustment:** `AdjustSelectionTypeWithShadow` and `AdjustSelectionWithNextNonEditableNode` test a different aspect: adjusting the *type* of selection, possibly to handle edge cases.

5. **Connect to Web Technologies:**  As the test cases are analyzed, connect them to the corresponding web technologies:

    * **JavaScript:** While this specific test file is C++, the functionality it tests directly impacts JavaScript's `Selection` API. JavaScript code uses this API to get and set selections, and the `SelectionAdjuster` ensures these selections are valid and meaningful within the DOM and shadow DOM.

    * **HTML:** The test cases heavily rely on HTML structures (spans, divs, templates, inputs, contenteditable attributes, shadow hosts, slots). The tests verify how selections behave in these HTML contexts.

    * **CSS:** While not explicitly tested here, CSS influences the *rendering* of selections. The `SelectionAdjuster` works with the logical structure of the DOM, and the resulting selection will be visually represented according to CSS styles.

6. **Infer Logical Reasoning and Examples:** Based on the test names and the HTML structures, deduce the likely input and output of the `SelectionAdjuster` in different scenarios. For instance, when a selection crosses a `contenteditable="false"` boundary, the adjuster will likely move the selection endpoints to avoid including the non-editable content.

7. **Consider User and Programmer Errors:** Think about common mistakes users or developers might make related to selections and editing:

    * Trying to select text across non-editable regions.
    * Unexpected selection behavior when using shadow DOM.
    * Issues with selections in nested `contenteditable` elements.

8. **Trace User Actions:**  Imagine the sequence of user interactions that could lead to the scenarios tested:

    * Dragging the mouse to select text.
    * Using keyboard shortcuts (Shift + arrow keys) for selection.
    * Programmatically setting the selection using JavaScript.

9. **Formulate the Explanation:**  Organize the findings into a clear and structured explanation, covering the file's purpose, its relationship to web technologies, logical reasoning, potential errors, and debugging clues. Use the test case names and the provided HTML snippets as concrete examples.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file tests selection functionality."  *Refinement:* "Specifically, it tests the `SelectionAdjuster` component."
* **Initial thought:** "It deals with how selections are moved." *Refinement:* "It adjusts selections to respect boundaries like shadow DOM and `contenteditable` regions."
* **Struggling to understand a test:** "What's the point of `AdjustSelectionTypeWithShadow`?" *Realization:* "It's likely testing how the *type* of selection (e.g., range vs. caret) is handled in the presence of shadow DOM, possibly to prevent crashes or unexpected behavior."
* **Overlooking a connection:** "Does this have anything to do with CSS?" *Consideration:* "While not directly tested, the *visual outcome* of the adjusted selection is affected by CSS."

By following this iterative and analytical process, incorporating domain knowledge about web technologies and the Blink rendering engine, you can arrive at a comprehensive understanding of the `selection_adjuster_test.cc` file.
这是一个 Chromium Blink 引擎的 C++ 源代码文件，其主要功能是**测试 `SelectionAdjuster` 类的各种选择调整逻辑**。 `SelectionAdjuster` 的作用是根据特定的规则（例如，避免跨越 shadow DOM 边界或 `contenteditable` 边界）调整给定的文本选择。

以下是该文件功能的详细列举和与 JavaScript、HTML、CSS 的关系说明：

**主要功能:**

1. **Shadow Boundary 调整测试:**
   - 测试 `SelectionAdjuster::AdjustSelectionToAvoidCrossingShadowBoundaries` 函数。
   - 验证在 DOM 树和 Flat 树两种视图下，当选择跨越 shadow DOM 边界时，选择是如何被调整的，通常会被调整到边界的折叠位置。

2. **编辑边界调整测试:**
   - 测试 `SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries` 函数。
   - 验证当选择跨越 `contenteditable` 属性不同的元素边界时，选择是如何被调整的。通常，选择会被调整到非 `contenteditable` 区域的边缘。这确保了在编辑操作时不会意外地修改到不可编辑的内容。

3. **测试不同场景下的选择调整:**
   - 嵌套的 `contenteditable` 元素。
   - Shadow root 作为编辑边界。
   - 可编辑的 shadow root。
   - 包含 slot 的 shadow DOM 场景，包括可编辑和不可编辑的情况。
   - 编辑边界位于 shadow DOM 外部或内部。
   - shadow host 和 shadow tree 都是可编辑的情况。

4. **测试选择类型的调整:**
   - 测试 `SelectionAdjuster::AdjustSelectionType` 函数。
   - 验证在特定情况下（例如，涉及到 shadow DOM），选择的类型是否需要调整以保持一致性和避免崩溃。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    - JavaScript 代码可以使用 `Selection` API 来获取和设置当前页面的文本选择。
    - `SelectionAdjuster` 的调整逻辑会影响到 JavaScript `Selection` API 返回的结果。例如，如果 JavaScript 代码获取到一个跨越不可编辑区域的选择，Blink 引擎内部的 `SelectionAdjuster` 可能会对其进行调整，最终 JavaScript 获取到的选择会是调整后的结果。
    - **举例:** 假设用户通过 JavaScript 代码 `window.getSelection()` 获取到的选择跨越了一个 `contenteditable="false"` 的元素。`SelectionAdjuster` 会调整这个选择，使得它的起始或结束位置落在不可编辑区域的边界上。

* **HTML:**
    - **`contenteditable` 属性:**  该测试文件大量涉及到 `contenteditable` 属性，这是 HTML 中用于指定元素内容是否可编辑的属性。 `SelectionAdjuster` 的一个核心功能就是处理跨越具有不同 `contenteditable` 属性的元素的选择。
    - **Shadow DOM:**  测试文件也大量使用 `<template>` 元素和 `attachShadow` 方法来创建 shadow DOM。`SelectionAdjuster` 负责处理跨越 shadow DOM 边界的选择。
    - **`<slot>` 元素:**  测试了在 shadow DOM 中使用 `<slot>` 元素进行内容分发时，选择的调整行为。
    - **HTML 结构:** 测试用例通过构建不同的 HTML 结构来模拟各种选择场景。

    - **举例 (基于测试用例 `DeleteNonEditableRange`):**
        - **HTML 结构:** 一个可编辑的 `div` 包含一个 `blockquote` 和一个 `contenteditable="false"` 的 `span`，`span` 内部还有一个可编辑的 `span` 和一个 `ol`。
        - **用户操作:** 用户可能尝试从 `blockquote` 中的 "foo" 选中到 `contenteditable="false"` 的 `span` 内部。
        - **`SelectionAdjuster` 的作用:** 当用户进行这样的选择时，`SelectionAdjuster` 会调整选择的结束位置，使其落在 `contenteditable="false"` 的 `span` 之前，防止选择包含不可编辑的内容。

* **CSS:**
    - CSS 本身不会直接影响 `SelectionAdjuster` 的逻辑。`SelectionAdjuster` 关注的是 DOM 结构和 `contenteditable` 属性。
    - 然而，CSS 会影响选择的视觉呈现（例如，选择的背景色）。 `SelectionAdjuster` 确保了逻辑上的选择是合理的，而 CSS 则负责渲染这个选择。
    - **间接关系:** CSS 可以通过控制元素的显示和布局来影响用户进行选择的行为，但 `SelectionAdjuster` 的调整逻辑不受 CSS 直接控制。

**逻辑推理、假设输入与输出 (基于测试用例):**

**测试用例:** `AdjustShadowToCollpasedInDOMTree`

**假设输入 (HTML):**
```html
<span><template data-mode="open">abc</template></span>
```
**假设输入 (Selection):**  选择 "b" 和 "c" (标记为 `|` 在 "b" 前，`^` 在 "c" 后):
```html
<span><template data-mode="open">a|bc^</template></span>
```

**逻辑推理:**  选择跨越了 open 模式的 shadow DOM 的边界。`AdjustSelectionToAvoidCrossingShadowBoundaries` 应该将选择调整到 shadow host 的边界并折叠。

**预期输出 (调整后的 Selection):**
```html
<span>|</span>
```

**测试用例:** `DeleteNonEditableRange`

**假设输入 (HTML):**
```html
<div contenteditable>
  <blockquote>
    <span>foo<br></span>
    barbarbar
  </blockquote>
  <span contenteditable="false">
    <span></span>
    <ol>bar</ol>
  </span>
</div>
```
**假设输入 (Selection):**  从 "foo" 的开始位置选中到 `contenteditable="false"` span 的开始位置 (标记为 `^` 和 `|`):
```html
<div contenteditable>
  <blockquote>
    <span>^foo<br></span>
    barbarbar
  </blockquote>
  <span contenteditable="false">
    <span>|</span>
    <ol>bar</ol>
  </span>
</div>
```

**逻辑推理:** 选择跨越了 `contenteditable="false"` 的边界。`AdjustSelectionToAvoidCrossingEditingBoundaries` 应该将选择的结束位置调整到非可编辑区域的边缘。

**预期输出 (调整后的 Selection):**
```html
<div contenteditable>
  <blockquote>
    <span>^foo<br></span>
    barbarbar
  </blockquote>
  |<span contenteditable="false">
    <span></span>
    <ol>bar</ol>
  </span>
</div>
```

**用户或编程常见的使用错误:**

1. **假设选择可以随意跨越 `contenteditable` 边界:** 开发者可能会编写 JavaScript 代码，假设用户可以选择从一个可编辑区域跨越到不可编辑区域，然后尝试对这个选择进行操作。`SelectionAdjuster` 的存在就是为了规范这种行为，防止意外的修改。

2. **不理解 shadow DOM 的边界限制:**  开发者在处理包含 shadow DOM 的页面时，可能会错误地认为选择可以无缝地跨越 shadow host 和 shadow tree。 `SelectionAdjuster` 强制选择落在这些边界上。

3. **在 JavaScript 中手动设置超出边界的选择:**  开发者可能尝试通过 JavaScript 代码手动创建一个跨越编辑或 shadow DOM 边界的选择。虽然可以设置，但后续的操作可能会受到 `SelectionAdjuster` 的影响，导致行为不符合预期。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中与包含 `contenteditable` 元素或 shadow DOM 的网页进行交互。**
2. **用户通过鼠标拖拽或键盘操作 (如 Shift + 方向键) 来选择文本。**
3. **用户的选择操作可能会尝试跨越以下边界:**
   - `contenteditable` 属性从 `true` 到 `false` 或反之的元素边界。
   - shadow host 和 shadow tree 之间的边界。
4. **当选择发生变化时，Blink 引擎会更新选择状态。**
5. **在更新选择状态的过程中，`SelectionAdjuster` 类会被调用。**
6. **`SelectionAdjuster` 会根据预定义的规则 (例如，不能跨越不可编辑区域) 检查并调整当前的选择。**
7. **如果需要调整，`SelectionAdjuster` 会修改选择的起始和结束位置。**
8. **最终，用户通过 JavaScript 的 `window.getSelection()` 获取到的选择，或者浏览器内部用于编辑操作的选择，将是经过 `SelectionAdjuster` 调整后的结果。**

**调试线索:**

- 如果在调试过程中发现 JavaScript 获取到的选择与用户实际拖拽的选择范围不一致，可以考虑 `SelectionAdjuster` 是否在起作用。
- 当处理涉及 `contenteditable` 或 shadow DOM 的编辑功能时，如果出现选择异常行为，可以关注 `SelectionAdjuster` 的调整逻辑是否符合预期。
- 可以通过在 `SelectionAdjuster` 的相关函数中添加断点或日志输出来跟踪选择是如何被调整的。
- 分析测试用例可以帮助理解 `SelectionAdjuster` 在各种边界条件下的行为。

总而言之，`selection_adjuster_test.cc` 是一个非常重要的测试文件，它确保了 Blink 引擎在处理文本选择时能够正确地处理各种复杂的边界情况，从而保证了网页编辑功能的稳定性和一致性。 它与 JavaScript, HTML 的交互非常密切，因为它的目标就是规范用户在 HTML 结构中进行的选择行为，并最终影响 JavaScript 可以获取到的选择结果。

Prompt: 
```
这是目录为blink/renderer/core/editing/selection_adjuster_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/selection_adjuster.h"

#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"

namespace blink {

class SelectionAdjusterTest : public EditingTestBase {};

// ------------ Shadow boundary adjustment tests --------------
TEST_F(SelectionAdjusterTest, AdjustShadowToCollpasedInDOMTree) {
  const SelectionInDOMTree& selection = SetSelectionTextToBody(
      "<span><template data-mode=\"open\">a|bc</template></span>^");
  const SelectionInDOMTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingShadowBoundaries(
          selection);
  EXPECT_EQ("<span></span>|", GetSelectionTextFromBody(result));
}

TEST_F(SelectionAdjusterTest, AdjustShadowToCollpasedInFlatTree) {
  SetBodyContent("<input value=abc>");
  const auto& input =
      ToTextControl(*GetDocument().QuerySelector(AtomicString("input")));
  const SelectionInFlatTree& selection =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::AfterNode(input))
          .Extend(
              PositionInFlatTree(*input.InnerEditorElement()->firstChild(), 1))
          .Build();
  const SelectionInFlatTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingShadowBoundaries(
          selection);
  EXPECT_EQ("<input value=\"abc\"><div>abc</div></input>|",
            GetSelectionTextInFlatTreeFromBody(result));
}

// ------------ Editing boundary adjustment tests --------------
// Extracted the related part from delete-non-editable-range-crash.html here,
// because the final result in that test was not WAI.
TEST_F(SelectionAdjusterTest, DeleteNonEditableRange) {
  const SelectionInDOMTree& selection = SetSelectionTextToBody(R"HTML(
      <div contenteditable>
        <blockquote>
          <span>^foo<br></span>
          barbarbar
        </blockquote>
        <span contenteditable="false">
          <span contenteditable>|</span>
          <ol>bar</ol>
        </span>
      </div>)HTML");

  const SelectionInDOMTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);

  EXPECT_EQ(R"HTML(
      <div contenteditable>
        <blockquote>
          <span>^foo<br></span>
          barbarbar
        </blockquote>
        |<span contenteditable="false">
          <span contenteditable></span>
          <ol>bar</ol>
        </span>
      </div>)HTML",
            GetSelectionTextFromBody(result));
}

// Extracted the related part from format-block-contenteditable-false.html here,
// because the final result in that test was not WAI.
TEST_F(SelectionAdjusterTest, FormatBlockContentEditableFalse) {
  const SelectionInDOMTree& selection = SetSelectionTextToBody(R"HTML(
      <div contenteditable>
        <h1><i>^foo</i><br><i>baz</i></h1>
        <div contenteditable="false">|bar</div>
      </div>)HTML");

  const SelectionInDOMTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);

  EXPECT_EQ(R"HTML(
      <div contenteditable>
        <h1><i>^foo</i><br><i>baz</i></h1>
        |<div contenteditable="false">bar</div>
      </div>)HTML",
            GetSelectionTextFromBody(result));
}

TEST_F(SelectionAdjusterTest, NestedContentEditableElements) {
  // Select from bar to foo.
  const SelectionInDOMTree& selection = SetSelectionTextToBody(R"HTML(
      <div contenteditable>
        <div contenteditable="false">
          <div contenteditable>
            |foo
          </div>
        </div>
        <br>
        bar^
      </div>)HTML");

  const SelectionInDOMTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);

  EXPECT_EQ(R"HTML(
      <div contenteditable>
        <div contenteditable="false">
          <div contenteditable>
            foo
          </div>
        </div>|
        <br>
        bar^
      </div>)HTML",
            GetSelectionTextFromBody(result));
}

TEST_F(SelectionAdjusterTest, ShadowRootAsRootBoundaryElement) {
  const char* body_content = "<div id='host'></div>";
  const char* shadow_content = "<div id='foo'>foo</div><div id='bar'>bar</div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Element* foo = shadow_root->QuerySelector(AtomicString("#foo"));
  Element* bar = shadow_root->QuerySelector(AtomicString("#bar"));

  // DOM tree selection.
  const SelectionInDOMTree& selection =
      SelectionInDOMTree::Builder()
          .Collapse(Position::FirstPositionInNode(*foo))
          .Extend(Position::LastPositionInNode(*bar))
          .Build();
  const SelectionInDOMTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);

  EXPECT_EQ(Position::FirstPositionInNode(*foo), result.Anchor());
  EXPECT_EQ(Position::LastPositionInNode(*bar), result.Focus());

  // Flat tree selection.
  const SelectionInFlatTree& selection_in_flat_tree =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*foo))
          .Extend(PositionInFlatTree::LastPositionInNode(*bar))
          .Build();
  const SelectionInFlatTree& result_in_flat_tree =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection_in_flat_tree);

  EXPECT_EQ(PositionInFlatTree::FirstPositionInNode(*foo),
            result_in_flat_tree.Anchor());
  EXPECT_EQ(PositionInFlatTree::LastPositionInNode(*bar),
            result_in_flat_tree.Focus());
}

TEST_F(SelectionAdjusterTest, ShadowRootAsRootBoundaryElementEditable) {
  const char* body_content = "<div id='host'></div>";
  const char* shadow_content =
      "foo"
      "<div id='bar' contenteditable>bar</div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  const Node* foo = shadow_root->firstChild();
  const Element* bar = shadow_root->QuerySelector(AtomicString("#bar"));

  // Select from foo to bar in DOM tree.
  const SelectionInDOMTree& selection =
      SelectionInDOMTree::Builder()
          .Collapse(Position::FirstPositionInNode(*foo))
          .Extend(Position::LastPositionInNode(*bar))
          .Build();
  const SelectionInDOMTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);

  EXPECT_EQ(Position::FirstPositionInNode(*foo), result.Anchor());
  EXPECT_EQ(Position::BeforeNode(*bar), result.Focus());

  // Select from foo to bar in flat tree.
  const SelectionInFlatTree& selection_in_flat_tree =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*foo))
          .Extend(PositionInFlatTree::LastPositionInNode(*bar))
          .Build();
  const SelectionInFlatTree& result_in_flat_tree =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection_in_flat_tree);

  EXPECT_EQ(PositionInFlatTree::FirstPositionInNode(*foo),
            result_in_flat_tree.Anchor());
  EXPECT_EQ(PositionInFlatTree::BeforeNode(*bar), result_in_flat_tree.Focus());

  // Select from bar to foo in DOM tree.
  const SelectionInDOMTree& selection2 =
      SelectionInDOMTree::Builder()
          .Collapse(Position::LastPositionInNode(*bar))
          .Extend(Position::FirstPositionInNode(*foo))
          .Build();
  const SelectionInDOMTree& result2 =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection2);

  EXPECT_EQ(Position::LastPositionInNode(*bar), result2.Anchor());
  EXPECT_EQ(Position::FirstPositionInNode(*bar), result2.Focus());

  // Select from bar to foo in flat tree.
  const SelectionInFlatTree& selection_in_flat_tree2 =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::LastPositionInNode(*bar))
          .Extend(PositionInFlatTree::FirstPositionInNode(*foo))
          .Build();
  const SelectionInFlatTree& result_in_flat_tree2 =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection_in_flat_tree2);

  EXPECT_EQ(PositionInFlatTree::LastPositionInNode(*bar),
            result_in_flat_tree2.Anchor());
  EXPECT_EQ(PositionInFlatTree::FirstPositionInNode(*bar),
            result_in_flat_tree2.Focus());
}

TEST_F(SelectionAdjusterTest, ShadowDistributedNodesWithoutEditingBoundary) {
  const char* body_content = R"HTML(
      <div id=host>
        <div id=foo slot=foo>foo</div>
        <div id=bar slot=bar>bar</div>
      </div>)HTML";
  const char* shadow_content = R"HTML(
      <div>
        <div id=s1>111</div>
        <slot name=foo></slot>
        <div id=s2>222</div>
        <slot name=bar></slot>
        <div id=s3>333</div>
      </div>)HTML";
  SetBodyContent(body_content);
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(shadow_content);

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  Element* s1 = shadow_root.QuerySelector(AtomicString("#s1"));

  // Select from 111 to foo.
  const SelectionInFlatTree& selection =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*s1))
          .Extend(PositionInFlatTree::LastPositionInNode(*foo))
          .Build();
  const SelectionInFlatTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);
  EXPECT_EQ(R"HTML(
      <div id="host">
      <div>
        <div id="s1">^111</div>
        <slot name="foo"><div id="foo" slot="foo">foo|</div></slot>
        <div id="s2">222</div>
        <slot name="bar"><div id="bar" slot="bar">bar</div></slot>
        <div id="s3">333</div>
      </div></div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result));

  // Select from foo to 111.
  const SelectionInFlatTree& selection2 =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::LastPositionInNode(*foo))
          .Extend(PositionInFlatTree::FirstPositionInNode(*s1))
          .Build();
  const SelectionInFlatTree& result2 =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection2);
  EXPECT_EQ(R"HTML(
      <div id="host">
      <div>
        <div id="s1">|111</div>
        <slot name="foo"><div id="foo" slot="foo">foo^</div></slot>
        <div id="s2">222</div>
        <slot name="bar"><div id="bar" slot="bar">bar</div></slot>
        <div id="s3">333</div>
      </div></div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result2));
}

// This test is just recording the behavior of current implementation, can be
// changed.
TEST_F(SelectionAdjusterTest, ShadowDistributedNodesWithEditingBoundary) {
  const char* body_content = R"HTML(
      <div contenteditable id=host>
        <div id=foo slot=foo>foo</div>
        <div id=bar slot=bar>bar</div>
      </div>)HTML";
  const char* shadow_content = R"HTML(
      <div>
        <div id=s1>111</div>
        <slot name=foo></slot>
        <div id=s2>222</div>
        <slot name=bar></slot>
        <div id=s3>333</div>
      </div>)HTML";
  SetBodyContent(body_content);
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(shadow_content);

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  Element* bar = GetDocument().getElementById(AtomicString("bar"));
  Element* s1 = shadow_root.QuerySelector(AtomicString("#s1"));
  Element* s2 = shadow_root.QuerySelector(AtomicString("#s2"));

  // Select from 111 to foo.
  const SelectionInFlatTree& selection =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*s1))
          .Extend(PositionInFlatTree::LastPositionInNode(*foo))
          .Build();
  const SelectionInFlatTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);
  EXPECT_EQ(R"HTML(
      <div contenteditable id="host">
      <div>
        <div id="s1">^111</div>
        <slot name="foo">|<div id="foo" slot="foo">foo</div></slot>
        <div id="s2">222</div>
        <slot name="bar"><div id="bar" slot="bar">bar</div></slot>
        <div id="s3">333</div>
      </div></div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result));

  // Select from foo to 111.
  const SelectionInFlatTree& selection2 =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::LastPositionInNode(*foo))
          .Extend(PositionInFlatTree::FirstPositionInNode(*s1))
          .Build();
  const SelectionInFlatTree& result2 =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection2);
  EXPECT_EQ(R"HTML(
      <div contenteditable id="host">
      <div>
        <div id="s1">111</div>
        <slot name="foo"><div id="foo" slot="foo">|foo^</div></slot>
        <div id="s2">222</div>
        <slot name="bar"><div id="bar" slot="bar">bar</div></slot>
        <div id="s3">333</div>
      </div></div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result2));

  // Select from 111 to 222.
  const SelectionInFlatTree& selection3 =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*s1))
          .Extend(PositionInFlatTree::LastPositionInNode(*s2))
          .Build();
  const SelectionInFlatTree& result3 =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection3);
  EXPECT_EQ(R"HTML(
      <div contenteditable id="host">
      <div>
        <div id="s1">^111</div>
        <slot name="foo"><div id="foo" slot="foo">foo</div></slot>
        <div id="s2">222|</div>
        <slot name="bar"><div id="bar" slot="bar">bar</div></slot>
        <div id="s3">333</div>
      </div></div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result3));

  // Select from foo to bar.
  const SelectionInFlatTree& selection4 =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*foo))
          .Extend(PositionInFlatTree::LastPositionInNode(*bar))
          .Build();
  const SelectionInFlatTree& result4 =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection4);
  EXPECT_EQ(R"HTML(
      <div contenteditable id="host">
      <div>
        <div id="s1">111</div>
        <slot name="foo"><div id="foo" slot="foo">^foo|</div></slot>
        <div id="s2">222</div>
        <slot name="bar"><div id="bar" slot="bar">bar</div></slot>
        <div id="s3">333</div>
      </div></div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result4));
}

TEST_F(SelectionAdjusterTest, EditingBoundaryOutsideOfShadowTree) {
  SetBodyContent(R"HTML(
    <div>
      <div id=base>base</div>
      <div id=div1 contenteditable>
        55
        <div id=host></div>
      </div>
    </div>)HTML");
  ShadowRoot* shadow_root =
      SetShadowContent("<div id=extent>extent</div>", "host");
  Element* base = GetDocument().getElementById(AtomicString("base"));
  Element* extent = shadow_root->QuerySelector(AtomicString("#extent"));

  const SelectionInFlatTree& selection =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*base))
          .Extend(PositionInFlatTree::LastPositionInNode(*extent))
          .Build();
  const SelectionInFlatTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);
  EXPECT_EQ(R"HTML(
    <div>
      <div id="base">^base</div>
      |<div contenteditable id="div1">
        55
        <div id="host"><div id="extent">extent</div></div>
      </div>
    </div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result));
}

TEST_F(SelectionAdjusterTest, EditingBoundaryInsideOfShadowTree) {
  SetBodyContent(R"HTML(
    <div>
      <div id=base>base</div>
      <div id=host>foo</div>
    </div>)HTML");
  ShadowRoot* shadow_root = SetShadowContent(R"HTML(
    <div>
      <div>bar</div>
      <div contenteditable id=extent>extent</div>
      <div>baz</div>
    </div>)HTML",
                                             "host");

  Element* base = GetDocument().getElementById(AtomicString("base"));
  Element* extent = shadow_root->QuerySelector(AtomicString("#extent"));

  const SelectionInFlatTree& selection =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*base))
          .Extend(PositionInFlatTree::LastPositionInNode(*extent))
          .Build();
  const SelectionInFlatTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);
  EXPECT_EQ(R"HTML(
    <div>
      <div id="base">^base</div>
      <div id="host">
    <div>
      <div>bar</div>
      |<div contenteditable id="extent">extent</div>
      <div>baz</div>
    </div></div>
    </div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result));
}

// The current behavior of shadow host and shadow tree are editable is we can't
// cross the shadow boundary.
TEST_F(SelectionAdjusterTest, ShadowHostAndShadowTreeAreEditable) {
  SetBodyContent(R"HTML(
    <div contenteditable>
      <div id=foo>foo</div>
      <div id=host></div>
    </div>)HTML");
  ShadowRoot* shadow_root =
      SetShadowContent("<div contenteditable id=bar>bar</div>", "host");

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  Element* bar = shadow_root->QuerySelector(AtomicString("#bar"));

  // Select from foo to bar.
  const SelectionInFlatTree& selection =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::FirstPositionInNode(*foo))
          .Extend(PositionInFlatTree::LastPositionInNode(*bar))
          .Build();
  const SelectionInFlatTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);
  EXPECT_EQ(R"HTML(
    <div contenteditable>
      <div id="foo">^foo</div>
      <div id="host">|<div contenteditable id="bar">bar</div></div>
    </div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result));

  // Select from bar to foo.
  const SelectionInFlatTree& selection2 =
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::LastPositionInNode(*bar))
          .Extend(PositionInFlatTree::FirstPositionInNode(*foo))
          .Build();
  const SelectionInFlatTree& result2 =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection2);
  EXPECT_EQ(R"HTML(
    <div contenteditable>
      <div id="foo">foo</div>
      <div id="host"><div contenteditable id="bar">|bar^</div></div>
    </div>)HTML",
            GetSelectionTextInFlatTreeFromBody(result2));
}

TEST_F(SelectionAdjusterTest, AdjustSelectionTypeWithShadow) {
  SetBodyContent("<p id='host'>foo</p>");
  SetShadowContent("bar<slot></slot>", "host");

  Element* host = GetDocument().getElementById(AtomicString("host"));
  const Position& base = Position(host->firstChild(), 0);
  const Position& extent = Position(host, 0);
  const SelectionInDOMTree& selection =
      SelectionInDOMTree::Builder().Collapse(base).Extend(extent).Build();

  // Should not crash
  const SelectionInDOMTree& adjusted =
      SelectionAdjuster::AdjustSelectionType(selection);

  EXPECT_EQ(base, adjusted.Anchor());
  EXPECT_EQ(extent, adjusted.Focus());
}

TEST_F(SelectionAdjusterTest, AdjustShadowWithRootAndHost) {
  SetBodyContent("<div id='host'></div>");
  ShadowRoot* shadow_root = SetShadowContent("", "host");

  Element* host = GetDocument().getElementById(AtomicString("host"));
  const SelectionInDOMTree& selection = SelectionInDOMTree::Builder()
                                            .Collapse(Position(shadow_root, 0))
                                            .Extend(Position(host, 0))
                                            .Build();

  // Should not crash
  const SelectionInDOMTree& result =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingShadowBoundaries(
          selection);

  EXPECT_EQ(Position(shadow_root, 0), result.Anchor());
  EXPECT_EQ(Position(shadow_root, 0), result.Focus());
}

// http://crbug.com/1371268
TEST_F(SelectionAdjusterTest, AdjustSelectionWithNextNonEditableNode) {
  SetBodyContent(R"HTML(
    <div contenteditable=true>
      <div id="one">Paragraph 1</div>
      <div id="two" contenteditable=false>
        <div contenteditable=true>Paragraph 2</div>
      </div>
    </div>)HTML");

  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));
  const SelectionInDOMTree& selection = SelectionInDOMTree::Builder()
                                            .Collapse(Position(one, 0))
                                            .Extend(Position(two, 0))
                                            .Build();
  const SelectionInDOMTree& editing_selection =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
          selection);
  EXPECT_EQ(editing_selection.Anchor(), selection.Anchor());
  EXPECT_EQ(editing_selection.Focus(), Position::BeforeNode(*two));

  const SelectionInDOMTree& adjusted_selection =
      SelectionAdjuster::AdjustSelectionType(editing_selection);
  EXPECT_EQ(adjusted_selection.Anchor(),
            Position::FirstPositionInNode(*one->firstChild()));
  EXPECT_EQ(adjusted_selection.Focus(), editing_selection.Focus());
}

}  // namespace blink

"""

```