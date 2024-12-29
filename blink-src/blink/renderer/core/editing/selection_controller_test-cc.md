Response:
Let's break down the thought process to analyze the provided C++ test file.

1. **Identify the Core Subject:** The file name `selection_controller_test.cc` immediately tells us the focus is on testing the `SelectionController` class within the Blink rendering engine.

2. **Understand the Context (Blink/Chromium):**  Knowing this is part of Blink/Chromium is crucial. This means the code interacts with web page rendering, DOM manipulation, and user input events. The tests will likely simulate user actions and verify the `SelectionController`'s behavior.

3. **Analyze the Includes:** The included headers provide clues about the functionalities being tested:
    * `selection_controller.h`:  The class under test.
    * `frame_selection.h`, `selection_template.h`, `visible_selection.h`: Related classes dealing with selection management. "Visible" likely means user-perceived selection.
    * `editing_test_base.h`:  Indicates this is a unit test setup with helper functions for creating and manipulating a test DOM.
    * `local_frame.h`, `local_frame_view.h`, `settings.h`:  Core classes for the browsing context, suggesting the tests might involve frame-level interactions and settings.
    * `event_handler.h`:  Crucial for handling user input (mouse clicks, keyboard presses) that lead to selection changes.
    * `layout_object.h`:  Deals with the rendered representation of the DOM, hinting that the tests might consider layout when determining selections.
    * `core_unit_test_helper.h`: More general testing utilities.

4. **Examine the Test Class (`SelectionControllerTest`):**
    * It inherits from `EditingTestBase`, confirming the test setup.
    * It provides helper methods like `Controller()`, `HitTestResultAtLocation()`, `GetPositionFromHitTestResult()`, `VisibleSelectionInDOMTree()`, and `GetVisibleSelectionInFlatTree()`. These simplify interacting with the `SelectionController` and inspecting the selection state.
    * It defines type aliases like `AppendTrailingWhitespace` and `SelectInputEventType`, indicating these are important parameters for some `SelectionController` methods.

5. **Analyze Individual Test Cases (`TEST_F`):**  Each `TEST_F` macro represents a specific scenario being tested. Read the names and the code within each test:
    * `setNonDirectionalSelectionIfNeeded`: Tests how the selection is handled when the anchor and focus points are set independently, particularly across shadow DOM boundaries.
    * `setCaretAtHitTestResult`: Focuses on setting the caret (insertion point) based on where the user clicks. It includes tests for scenarios where the hit-tested position might be null or disconnected due to script manipulation.
    * `AdjustSelectionWithTrailingWhitespace`: Tests how the selection is adjusted around elements with trailing whitespace, potentially involving `user-select: none`.
    * `SelectClosestWordFromHitTestResultAtEndOfLine1/2`: Checks word selection behavior at the end of lines, distinguishing between mouse and touch input.
    * `SelectWordToEndOfLine`: Tests selecting a word and then extending the selection to the end of the line using Shift+Click.
    * `SelectWordToEndOfTableCell`: Similar to the previous test, but specifically within table cells.
    * `Scroll`: Tests how hit-testing and position determination work within a scrollable container, even with elements having padding, borders, and margins. This checks if the hit-test logic correctly identifies the underlying text content.
    * `AdjustSelectionByUserSelectWithInput/Span/Comment`:  These tests examine how the `user-select` CSS property affects selection behavior, especially when dealing with nested elements and comments.

6. **Identify Key Functionalities Tested:** Based on the test cases, the primary functions of `SelectionController` being tested are:
    * Setting and managing the selection (caret, range).
    * Handling different ways of setting the selection (direct setting, hit-testing).
    * Adjusting the selection based on various factors (whitespace, `user-select` property, DOM structure).
    * Handling edge cases and potential issues (null or disconnected positions, script interference).
    * Differentiating between mouse and touch input for selection.
    * Correctly identifying positions within scrollable containers and around different box model properties.

7. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The tests show how JavaScript can interact with and modify the selection (e.g., `window.getSelection()`, `range.surroundContents()`). The tests also simulate how JavaScript event listeners (`selectstart`) might interfere with the selection process.
    * **HTML:** The tests use various HTML elements (`span`, `div`, `input`, `pre`, `table`) to create different content structures and test selection behavior within these structures. The use of Shadow DOM is also evident.
    * **CSS:** The `user-select` property is directly tested, demonstrating its influence on what parts of the page can be selected. The tests also use CSS for styling (margins, padding, fonts, borders, `display: inline-block`) to create specific layout scenarios that might affect hit-testing.

8. **Infer Logical Reasoning and Scenarios:** For each test, consider:
    * **Input:** The HTML content, the simulated user action (mouse click, double-click, shift-click, long press), and the specific coordinates of the click.
    * **Expected Output:** The resulting selection (start and end points, anchor and focus nodes/offsets). The tests use `EXPECT_EQ` to verify this.

9. **Consider User/Programming Errors:**
    * **User Errors:**  The tests indirectly cover user errors like trying to select content marked with `user-select: none`.
    * **Programming Errors:**  The tests that check for null or disconnected positions highlight potential errors in Blink's selection logic or in how JavaScript manipulates the DOM. The test involving the `selectstart` event demonstrates how poorly written JavaScript can interfere with the browser's default selection behavior.

10. **Trace User Actions (Debugging):**  Imagine a user interacting with a web page and encountering unexpected selection behavior. This test file provides examples of how a developer might try to reproduce and debug such issues:
    * **Clicking/Tapping:** Tests simulate these basic interactions.
    * **Double-clicking:**  Simulates word selection.
    * **Shift-clicking:** Simulates extending a selection.
    * **Long press:**  Simulates a context menu or text selection initiation on touch devices.
    * **Interacting with specific elements:** The tests target different HTML elements and CSS properties.

By following these steps, we can systematically analyze the test file and extract the relevant information about its functionality and its relationship to web technologies and potential user/programming errors.
这个文件 `selection_controller_test.cc` 是 Chromium Blink 引擎中用于测试 `SelectionController` 类的单元测试文件。 `SelectionController` 类负责管理网页中的文本和元素的选中状态。

以下是该文件的主要功能和它与 JavaScript, HTML, CSS 的关系，以及相关的例子、逻辑推理和常见错误：

**主要功能:**

1. **测试文本选择:** 验证在各种场景下文本选择是否按照预期工作，包括鼠标拖拽、双击、三击等操作引起的文本选择。
2. **测试元素选择:** 验证是否能正确选中元素，例如图片、链接等。
3. **测试不同类型的选择:** 包括光标（caret）的定位、范围选择（range selection）等。
4. **测试与用户交互相关的选择:** 模拟用户的鼠标和键盘操作，测试选择行为的正确性。
5. **测试在复杂 DOM 结构下的选择:** 包括 shadow DOM、iframe 等场景。
6. **测试与编辑相关的选择:**  验证在可编辑区域 (`contenteditable`) 内的选择行为。
7. **测试在不同 CSS 样式影响下的选择:** 例如 `user-select: none` 对选择的影响。
8. **测试在滚动容器中的选择:** 验证在滚动区域内的选择位置是否正确。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **功能关系:** JavaScript 可以通过 `window.getSelection()` API 获取和修改当前的选择。`SelectionController` 的行为直接影响了这个 API 返回的结果。
    * **举例说明:**  测试用例 `setCaretAtHitTestResult` 中使用了 JavaScript 代码来监听 `onselectstart` 事件，并尝试在选择开始时移除元素。这模拟了 JavaScript 如何与选择操作进行交互，并测试 `SelectionController` 在这种情况下是否能正常工作。
    * **假设输入与输出:**
        * **假设输入:** JavaScript 代码调用 `window.getSelection().collapse(node, offset)` 将选择折叠到指定位置。
        * **输出:** `SelectionController` 内部状态更新，光标被定位到指定的 `node` 的 `offset` 位置。

* **HTML:**
    * **功能关系:** HTML 结构定义了网页的内容和布局，`SelectionController` 需要根据 HTML 结构来确定可选中的文本和元素。
    * **举例说明:** 测试用例中使用了各种 HTML 结构，例如 `<span id=top>top</span><span id=host></span>` 和 shadow DOM 的结合，来测试跨越不同 DOM 树的选择行为。  `AdjustSelectionWithTrailingWhitespace` 使用了 `<input type=checkbox>` 和 `<div>` 来测试在特定 HTML 元素附近的选择调整。
    * **假设输入与输出:**
        * **假设输入:**  HTML 包含文本节点 "Hello World"。
        * **输出:** 用户通过鼠标拖拽选中 "Hello"。 `SelectionController` 将记录选区的起始和结束位置对应于 "Hello" 在 DOM 树中的位置。

* **CSS:**
    * **功能关系:** CSS 样式可以影响元素的可选择性，例如 `user-select: none` 会阻止用户选中元素内的文本。 `SelectionController` 需要考虑这些 CSS 属性。
    * **举例说明:** 测试用例 `setCaretAtHitTestResultWithNullPosition` 使用了 CSS `user-select: none` 来设置一个 `div` 不可选中，并测试在点击该 `div` 前面的伪元素时，选择是否正确地被忽略。`AdjustSelectionByUserSelectWithInput` 等测试用例也关注 `user-select` 属性对选择边界的影响。
    * **假设输入与输出:**
        * **假设输入:** 一个 `<div>` 元素的 CSS 样式设置为 `user-select: none;`。
        * **输出:** 用户尝试在该 `<div>` 内进行选择，`SelectionController` 应该阻止选择操作，或者选择范围不会包含该 `<div>` 内的文本。

**逻辑推理的假设输入与输出:**

* **测试用例 `setNonDirectionalSelectionIfNeeded`:**
    * **假设输入:**  HTML 结构包含两个 `<span>` 元素，一个在主 DOM 树，一个在 shadow DOM 中。调用 `SetNonDirectionalSelectionIfNeeded` 设置一个从主 DOM 树的文本节点到 shadow DOM 的文本节点的选择。
    * **输出:**  `VisibleSelectionInDOMTree()` 和 `GetVisibleSelectionInFlatTree()` 返回的选区信息分别反映了在 DOM 树和扁平树中的正确起始和结束位置。

* **测试用例 `SelectClosestWordFromHitTestResultAtEndOfLine1`:**
    * **假设输入:** HTML 包含 `<pre>(1)\n(2)</pre>`。 用户点击在 "(1)" 之后，换行符之前的位置。
    * **输出 (鼠标):** 调用 `SelectClosestWordFromHitTestResult` 后，整个单词 "(1)" 被选中。
    * **输出 (触摸):** 调用 `SelectClosestWordFromHitTestResult` 后，选择不发生变化（因为触摸可能触发其他手势）。

**涉及用户或者编程常见的使用错误及举例说明:**

* **用户错误:**
    * **尝试选择 `user-select: none` 的内容:** 用户可能尝试选中设置了 `user-select: none` 属性的文本，期望能够复制或操作，但实际上是无法选中的。测试用例覆盖了这种情况，确保 `SelectionController` 的行为符合预期。
* **编程错误:**
    * **在 `selectstart` 事件中修改 DOM 结构导致选择状态混乱:**  测试用例 `setCaretAtHitTestResult` 展示了在 `selectstart` 事件中移除元素的极端情况。如果开发者在选择开始时意外地修改了 DOM 结构，可能会导致 `SelectionController` 的状态不一致，甚至崩溃。
    * **错误地计算或设置选择的起始和结束位置:** 开发者在使用 JavaScript 操作选择时，可能会错误地计算节点的偏移量或者使用错误的 API，导致选择范围不正确。这些测试用例可以帮助发现 Blink 引擎在处理这些错误输入时的健壮性。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在网页上进行选择操作:**  用户可以使用鼠标拖拽、双击、三击等方式选中网页上的文本或元素。
2. **浏览器接收到用户输入事件:** 用户的鼠标按下、移动、抬起等操作会触发浏览器事件。
3. **事件被传递到渲染引擎:** 浏览器将这些事件传递给 Blink 渲染引擎的事件处理模块 (`EventHandler`)。
4. **`EventHandler` 调用 `SelectionController` 的方法:**  根据接收到的事件类型和位置，`EventHandler` 会调用 `SelectionController` 相应的方法来更新选择状态，例如 `SetCaretAtHitTestResult`，`SelectClosestWordFromHitTestResult` 等。
5. **`SelectionController` 根据 DOM 结构、CSS 样式等信息进行计算:** `SelectionController` 内部会根据当前的 DOM 树结构、元素的 CSS 样式（如 `user-select`），以及用户的操作位置，计算出新的选择范围。
6. **更新选择状态并通知其他模块:** `SelectionController` 更新内部的选择状态，并可能通知其他需要知道选择变化的模块，例如文本输入框、上下文菜单等。

作为调试线索，当用户报告选择相关的 bug 时，开发者可以：

* **重现用户的操作步骤:** 尝试在测试环境中模拟用户的操作，例如点击、拖拽的位置和方式。
* **查看 `SelectionController` 的相关日志:**  在 Blink 引擎的开发版本中，可以添加日志来跟踪 `SelectionController` 的执行流程和内部状态。
* **运行相关的单元测试:** 运行 `selection_controller_test.cc` 中的相关测试用例，看是否能复现 bug。如果可以，则表示问题可能出在 `SelectionController` 的逻辑中。
* **编写新的测试用例:** 如果现有的测试用例没有覆盖到 bug 的场景，可以编写新的测试用例来专门测试该场景。这有助于定位和修复问题，并防止未来出现相同的 bug。
* **使用调试工具:** 使用 GDB 等调试工具来单步执行 `SelectionController` 的代码，查看变量的值和执行流程，以便更深入地理解问题的原因。

总而言之，`selection_controller_test.cc` 是 Blink 引擎中至关重要的测试文件，它确保了文本和元素选择功能的正确性和健壮性，并且覆盖了各种用户交互场景、DOM 结构和 CSS 样式的影响。 理解这个文件的功能有助于理解浏览器如何处理用户的选择操作，以及如何调试和修复相关的 bug。

Prompt: 
```
这是目录为blink/renderer/core/editing/selection_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/selection_controller.h"

#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class SelectionControllerTest : public EditingTestBase {
 public:
  SelectionControllerTest(const SelectionControllerTest&) = delete;
  SelectionControllerTest& operator=(const SelectionControllerTest&) = delete;

 protected:
  using AppendTrailingWhitespace =
      SelectionController::AppendTrailingWhitespace;
  using SelectInputEventType = SelectionController::SelectInputEventType;

  SelectionControllerTest() = default;

  SelectionController& Controller() {
    return GetFrame().GetEventHandler().GetSelectionController();
  }

  HitTestResult HitTestResultAtLocation(const HitTestLocation& location) {
    return GetFrame().GetEventHandler().HitTestResultAtLocation(location);
  }

  HitTestResult HitTestResultAtLocation(int x, int y) {
    HitTestLocation location(gfx::Point(x, y));
    return HitTestResultAtLocation(location);
  }

  static PositionWithAffinity GetPositionFromHitTestResult(
      const HitTestResult& hit_test_result) {
    return hit_test_result.GetPosition();
  }

  VisibleSelection VisibleSelectionInDOMTree() const {
    return Selection().ComputeVisibleSelectionInDOMTree();
  }

  VisibleSelectionInFlatTree GetVisibleSelectionInFlatTree() const {
    return Selection().ComputeVisibleSelectionInFlatTree();
  }

  bool SelectClosestWordFromHitTestResult(
      const HitTestResult& result,
      AppendTrailingWhitespace append_trailing_whitespace,
      SelectInputEventType select_input_event_type);
  void SetCaretAtHitTestResult(const HitTestResult&);
  void SetNonDirectionalSelectionIfNeeded(const SelectionInFlatTree&,
                                          TextGranularity);
};

bool SelectionControllerTest::SelectClosestWordFromHitTestResult(
    const HitTestResult& result,
    AppendTrailingWhitespace append_trailing_whitespace,
    SelectInputEventType select_input_event_type) {
  return Controller().SelectClosestWordFromHitTestResult(
      result, append_trailing_whitespace, select_input_event_type);
}

void SelectionControllerTest::SetCaretAtHitTestResult(
    const HitTestResult& hit_test_result) {
  GetFrame().GetEventHandler().GetSelectionController().SetCaretAtHitTestResult(
      hit_test_result);
}

void SelectionControllerTest::SetNonDirectionalSelectionIfNeeded(
    const SelectionInFlatTree& new_selection,
    TextGranularity granularity) {
  GetFrame()
      .GetEventHandler()
      .GetSelectionController()
      .SetNonDirectionalSelectionIfNeeded(
          new_selection,
          SetSelectionOptions::Builder().SetGranularity(granularity).Build(),
          SelectionController::kDoNotAdjustEndpoints);
}

TEST_F(SelectionControllerTest, setNonDirectionalSelectionIfNeeded) {
  const char* body_content = "<span id=top>top</span><span id=host></span>";
  const char* shadow_content = "<span id=bottom>bottom</span>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* top = GetDocument().getElementById(AtomicString("top"))->firstChild();
  Node* bottom =
      shadow_root->getElementById(AtomicString("bottom"))->firstChild();

  // top to bottom
  SetNonDirectionalSelectionIfNeeded(SelectionInFlatTree::Builder()
                                         .Collapse(PositionInFlatTree(top, 1))
                                         .Extend(PositionInFlatTree(bottom, 3))
                                         .Build(),
                                     TextGranularity::kCharacter);
  EXPECT_EQ(VisibleSelectionInDOMTree().Start(),
            VisibleSelectionInDOMTree().Anchor());
  EXPECT_EQ(VisibleSelectionInDOMTree().End(),
            VisibleSelectionInDOMTree().Focus());
  EXPECT_EQ(Position(top, 1), VisibleSelectionInDOMTree().Start());
  EXPECT_EQ(Position(top, 3), VisibleSelectionInDOMTree().End());

  EXPECT_EQ(PositionInFlatTree(top, 1),
            GetVisibleSelectionInFlatTree().Anchor());
  EXPECT_EQ(PositionInFlatTree(bottom, 3),
            GetVisibleSelectionInFlatTree().Focus());
  EXPECT_EQ(PositionInFlatTree(top, 1),
            GetVisibleSelectionInFlatTree().Start());
  EXPECT_EQ(PositionInFlatTree(bottom, 3),
            GetVisibleSelectionInFlatTree().End());

  // bottom to top
  SetNonDirectionalSelectionIfNeeded(
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree(bottom, 3))
          .Extend(PositionInFlatTree(top, 1))
          .Build(),
      TextGranularity::kCharacter);
  EXPECT_EQ(VisibleSelectionInDOMTree().End(),
            VisibleSelectionInDOMTree().Anchor());
  EXPECT_EQ(VisibleSelectionInDOMTree().Start(),
            VisibleSelectionInDOMTree().Focus());
  EXPECT_EQ(Position(bottom, 0), VisibleSelectionInDOMTree().Start());
  EXPECT_EQ(Position(bottom, 3), VisibleSelectionInDOMTree().End());

  EXPECT_EQ(PositionInFlatTree(bottom, 3),
            GetVisibleSelectionInFlatTree().Anchor());
  EXPECT_EQ(PositionInFlatTree(top, 1),
            GetVisibleSelectionInFlatTree().Focus());
  EXPECT_EQ(PositionInFlatTree(top, 1),
            GetVisibleSelectionInFlatTree().Start());
  EXPECT_EQ(PositionInFlatTree(bottom, 3),
            GetVisibleSelectionInFlatTree().End());
}

TEST_F(SelectionControllerTest, setCaretAtHitTestResult) {
  const char* body_content = "<div id='sample' contenteditable>sample</div>";
  SetBodyContent(body_content);
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "var sample = document.getElementById('sample');"
      "sample.addEventListener('onselectstart', "
      "  event => elem.parentNode.removeChild(elem));");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();
  HitTestLocation location((gfx::Point(8, 8)));
  GetFrame().GetEventHandler().GetSelectionController().HandleGestureLongPress(
      GetFrame().GetEventHandler().HitTestResultAtLocation(location));
}

// For http://crbug.com/704827
TEST_F(SelectionControllerTest, setCaretAtHitTestResultWithNullPosition) {
  SetBodyContent(
      "<style>"
      "#sample:before {content: '&nbsp;'}"
      "#sample { user-select: none; }"
      "</style>"
      "<div id=sample></div>");
  UpdateAllLifecyclePhasesForTest();

  // Hit "&nbsp;" in before pseudo element of "sample".
  HitTestLocation location((gfx::Point(10, 10)));
  SetCaretAtHitTestResult(
      GetFrame().GetEventHandler().HitTestResultAtLocation(location));

  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
}

// For http://crbug.com/759971
TEST_F(SelectionControllerTest,
       SetCaretAtHitTestResultWithDisconnectedPosition) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.designMode = 'on';"
      "const selection = window.getSelection();"
      "const html = document.getElementsByTagName('html')[0];"
      "selection.collapse(html);"
      "const range = selection.getRangeAt(0);"

      "function selectstart() {"
      "  const body = document.getElementsByTagName('body')[0];"
      "  range.surroundContents(body);"
      "  range.deleteContents();"
      "}"
      "document.addEventListener('selectstart', selectstart);");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Simulate a tap somewhere in the document
  blink::WebMouseEvent mouse_event(
      blink::WebInputEvent::Type::kMouseDown,
      blink::WebInputEvent::kIsCompatibilityEventForTouch,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  // Frame scale defaults to 0, which would cause a divide-by-zero problem.
  mouse_event.SetFrameScale(1);
  HitTestLocation location((gfx::Point(0, 0)));
  GetFrame().GetEventHandler().GetSelectionController().HandleMousePressEvent(
      MouseEventWithHitTestResults(
          mouse_event, location,
          GetFrame().GetEventHandler().HitTestResultAtLocation(location)));

  // The original bug was that this test would cause
  // TextSuggestionController::HandlePotentialMisspelledWordTap() to crash. So
  // the primary thing this test cases tests is that we can get here without
  // crashing.

  // Verify no selection was set.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
}

// For http://crbug.com/700368
TEST_F(SelectionControllerTest, AdjustSelectionWithTrailingWhitespace) {
  SetBodyContent(
      "<input type=checkbox>"
      "<div style='user-select:none'>abc</div>");
  Element* const input = GetDocument().QuerySelector(AtomicString("input"));

  const SelectionInFlatTree& selection = ExpandWithGranularity(
      SelectionInFlatTree::Builder()
          .Collapse(PositionInFlatTree::BeforeNode(*input))
          .Extend(PositionInFlatTree::AfterNode(*input))
          .Build(),
      TextGranularity::kWord);
  const SelectionInFlatTree& result =
      AdjustSelectionWithTrailingWhitespace(selection);

  EXPECT_EQ(PositionInFlatTree::BeforeNode(*input),
            result.ComputeStartPosition());
  EXPECT_EQ(PositionInFlatTree::AfterNode(*input), result.ComputeEndPosition());
}

// For http://crbug.com/974569
TEST_F(SelectionControllerTest,
       SelectClosestWordFromHitTestResultAtEndOfLine1) {
  InsertStyleElement("body { margin: 0; padding: 0; font: 10px monospace; }");
  SetBodyContent("<pre>(1)\n(2)</pre>");

  // Click/Tap after "(1)"
  HitTestLocation location(gfx::Point(40, 10));
  HitTestResult result =
      GetFrame().GetEventHandler().HitTestResultAtLocation(location);
  ASSERT_EQ("<pre>(1)|\n(2)</pre>",
            GetSelectionTextFromBody(
                SelectionInDOMTree::Builder()
                    .Collapse(GetPositionFromHitTestResult(result))
                    .Build()));

  // Select word by mouse
  EXPECT_TRUE(SelectClosestWordFromHitTestResult(
      result, AppendTrailingWhitespace::kDontAppend,
      SelectInputEventType::kMouse));
  EXPECT_EQ("<pre>(1)^\n|(2)</pre>", GetSelectionTextFromBody());

  // Select word by tap
  EXPECT_FALSE(SelectClosestWordFromHitTestResult(
      result, AppendTrailingWhitespace::kDontAppend,
      SelectInputEventType::kTouch));
  EXPECT_EQ("<pre>(1)^\n|(2)</pre>", GetSelectionTextFromBody())
      << "selection isn't changed";
}

TEST_F(SelectionControllerTest,
       SelectClosestWordFromHitTestResultAtEndOfLine2) {
  InsertStyleElement("body { margin: 0; padding: 0; font: 10px monospace; }");
  SetBodyContent("<pre>ab:\ncd</pre>");

  // Click/Tap after "(1)"
  HitTestLocation location(gfx::Point(40, 10));
  HitTestResult result =
      GetFrame().GetEventHandler().HitTestResultAtLocation(location);
  ASSERT_EQ("<pre>ab:|\ncd</pre>",
            GetSelectionTextFromBody(
                SelectionInDOMTree::Builder()
                    .Collapse(GetPositionFromHitTestResult(result))
                    .Build()));

  // Select word by mouse
  EXPECT_TRUE(SelectClosestWordFromHitTestResult(
      result, AppendTrailingWhitespace::kDontAppend,
      SelectInputEventType::kMouse));
  EXPECT_EQ("<pre>ab:^\n|cd</pre>", GetSelectionTextFromBody());

  // Select word by tap
  EXPECT_FALSE(SelectClosestWordFromHitTestResult(
      result, AppendTrailingWhitespace::kDontAppend,
      SelectInputEventType::kTouch));
  EXPECT_EQ("<pre>ab:^\n|cd</pre>", GetSelectionTextFromBody())
      << "selection isn't changed";
}

// For http://crbug.com/1092554
TEST_F(SelectionControllerTest, SelectWordToEndOfLine) {
  LoadAhem();
  InsertStyleElement("body { margin: 0; padding: 0; font: 10px/10px Ahem; }");
  SetBodyContent("<div>abc def<br/>ghi</div>");

  // Select foo
  blink::WebMouseEvent double_click(
      blink::WebMouseEvent::Type::kMouseDown, 0,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  // Frame scale defaults to 0, which would cause a divide-by-zero problem.
  double_click.SetFrameScale(1);
  HitTestLocation location((gfx::Point(20, 5)));
  double_click.button = blink::WebMouseEvent::Button::kLeft;
  double_click.click_count = 2;
  HitTestResult result =
      GetFrame().GetEventHandler().HitTestResultAtLocation(location);
  GetFrame().GetEventHandler().GetSelectionController().HandleMousePressEvent(
      MouseEventWithHitTestResults(double_click, location, result));
  ASSERT_EQ("<div>ab|c def<br>ghi</div>",
            GetSelectionTextFromBody(
                SelectionInDOMTree::Builder()
                    .Collapse(GetPositionFromHitTestResult(result))
                    .Build()));

  // Select word by mouse
  EXPECT_TRUE(SelectClosestWordFromHitTestResult(
      result, AppendTrailingWhitespace::kDontAppend,
      SelectInputEventType::kMouse));
  EXPECT_EQ("<div>^abc| def<br>ghi</div>", GetSelectionTextFromBody());

  // Select to end of line
  blink::WebMouseEvent single_shift_click(
      blink::WebMouseEvent::Type::kMouseDown,
      blink::WebInputEvent::Modifiers::kShiftKey,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  // Frame scale defaults to 0, which would cause a divide-by-zero problem.
  single_shift_click.SetFrameScale(1);
  HitTestLocation single_click_location((gfx::Point(400, 5)));
  single_shift_click.button = blink::WebMouseEvent::Button::kLeft;
  single_shift_click.click_count = 1;
  HitTestResult single_click_result =
      GetFrame().GetEventHandler().HitTestResultAtLocation(
          single_click_location);
  GetFrame().GetEventHandler().GetSelectionController().HandleMousePressEvent(
      MouseEventWithHitTestResults(single_shift_click, single_click_location,
                                   single_click_result));
  EXPECT_EQ("<div>^abc def<br>|ghi</div>", GetSelectionTextFromBody());
}

// For http://crbug.com/892750
TEST_F(SelectionControllerTest, SelectWordToEndOfTableCell) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0; padding: 0; font: 10px/10px Ahem; } td {width: "
      "200px}");
  SetBodyContent("<table><td>foo</td><td>bar</td></table>");

  // Select foo
  blink::WebMouseEvent double_click(
      blink::WebMouseEvent::Type::kMouseDown, 0,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  // Frame scale defaults to 0, which would cause a divide-by-zero problem.
  double_click.SetFrameScale(1);
  HitTestLocation location((gfx::Point(20, 5)));
  double_click.button = WebMouseEvent::Button::kLeft;
  double_click.click_count = 2;
  HitTestResult result =
      GetFrame().GetEventHandler().HitTestResultAtLocation(location);
  GetFrame().GetEventHandler().GetSelectionController().HandleMousePressEvent(
      MouseEventWithHitTestResults(double_click, location, result));
  ASSERT_EQ("<table><tbody><tr><td>fo|o</td><td>bar</td></tr></tbody></table>",
            GetSelectionTextFromBody(
                SelectionInDOMTree::Builder()
                    .Collapse(GetPositionFromHitTestResult(result))
                    .Build()));
  // Select word by mouse
  EXPECT_TRUE(SelectClosestWordFromHitTestResult(
      result, AppendTrailingWhitespace::kDontAppend,
      SelectInputEventType::kMouse));
  EXPECT_EQ("<table><tbody><tr><td>^foo|</td><td>bar</td></tr></tbody></table>",
            GetSelectionTextFromBody());

  // Select to end of cell 1
  blink::WebMouseEvent cell1_single_shift_click(
      blink::WebMouseEvent::Type::kMouseDown,
      blink::WebInputEvent::Modifiers::kShiftKey,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  // Frame scale defaults to 0, which would cause a divide-by-zero problem.
  cell1_single_shift_click.SetFrameScale(1);
  HitTestLocation cell1_single_click_location((gfx::Point(175, 5)));
  cell1_single_shift_click.button = blink::WebMouseEvent::Button::kLeft;
  cell1_single_shift_click.click_count = 1;
  HitTestResult cell1_single_click_result =
      GetFrame().GetEventHandler().HitTestResultAtLocation(
          cell1_single_click_location);
  GetFrame().GetEventHandler().GetSelectionController().HandleMousePressEvent(
      MouseEventWithHitTestResults(cell1_single_shift_click,
                                   cell1_single_click_location,
                                   cell1_single_click_result));
  EXPECT_EQ("<table><tbody><tr><td>^foo|</td><td>bar</td></tr></tbody></table>",
            GetSelectionTextFromBody());

  // Select to end of cell 2
  blink::WebMouseEvent cell2_single_shift_click(
      blink::WebMouseEvent::Type::kMouseDown,
      blink::WebInputEvent::Modifiers::kShiftKey,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  // Frame scale defaults to 0, which would cause a divide-by-zero problem.
  cell2_single_shift_click.SetFrameScale(1);
  HitTestLocation cell2_single_click_location((gfx::Point(375, 5)));
  cell2_single_shift_click.button = blink::WebMouseEvent::Button::kLeft;
  cell2_single_shift_click.click_count = 1;
  HitTestResult cell2_single_click_result =
      GetFrame().GetEventHandler().HitTestResultAtLocation(
          cell2_single_click_location);
  GetFrame().GetEventHandler().GetSelectionController().HandleMousePressEvent(
      MouseEventWithHitTestResults(cell2_single_shift_click,
                                   cell2_single_click_location,
                                   cell2_single_click_result));
  EXPECT_EQ("<table><tbody><tr><td>^foo</td><td>bar|</td></tr></tbody></table>",
            GetSelectionTextFromBody());
}

TEST_F(SelectionControllerTest, Scroll) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      font-size: 50px;
      line-height: 2;
    }
    #scroller {
      width: 400px;
      height: 600px;
      overflow: scroll;
    }
    </style>
    <div id="scroller">
      <span>line1</span><br>
      <span>line2</span><br>
      <span>line3</span><br>
      <span>line4</span><br>
      <span style="padding-left: 100px">line5</span><br>
      <span style="border-left: 100px solid blue">line6</span><br>
      <span style="margin-left: 100px">line7</span><br>
      <span style="display: inline-block; width: 100px; height: 1em; line-height: 1">x</span>line8<br>
      <span>line9</span><br>
    </div>
  )HTML");

  // Scroll #scroller by 2 lines. "line3" should be at the top.
  Element* scroller = GetElementById("scroller");
  scroller->setScrollTop(200);

  // Hit-test on the first visible line. This should be "line3".
  HitTestResult line3_result = HitTestResultAtLocation(5, 50);
  EXPECT_EQ(line3_result.LocalPoint(), PhysicalOffset(5, 50));
  PositionWithAffinity line3 = line3_result.GetPosition();
  Node* line3_node = line3.AnchorNode();
  EXPECT_EQ(line3_node->nodeName(), "#text");
  EXPECT_EQ(line3_node->textContent(), "line3");

  // Then hit-test beyond the end of the first visible line. This should snap to
  // the end of the "line3".
  //
  // +------------
  // |line3   x <-- Click here
  // |line4
  HitTestResult line3_end_result = HitTestResultAtLocation(300, 50);
  EXPECT_EQ(line3_end_result.LocalPoint(), PhysicalOffset(300, 50));
  PositionWithAffinity line3_end = line3_end_result.GetPosition();
  Node* line3_end_node = line3_end.AnchorNode();
  EXPECT_EQ(line3_end_node->nodeName(), "#text");
  EXPECT_EQ(line3_end_node->textContent(), "line3");

  // At the line-gap between line3 and line4.
  // There is no |LayoutText| here, but it should snap to line4.
  HitTestResult line4_over_result = HitTestResultAtLocation(5, 101);
  EXPECT_EQ(line4_over_result.LocalPoint(), PhysicalOffset(5, 101));
  PositionWithAffinity line4_over = line4_over_result.GetPosition();
  Node* line4_over_node = line4_over.AnchorNode();
  EXPECT_EQ(line4_over_node->nodeName(), "#text");
  EXPECT_EQ(line4_over_node->textContent(), "line4");

  // At the padding of an inline box.
  HitTestResult line5_result = HitTestResultAtLocation(5, 250);
  EXPECT_EQ(line5_result.LocalPoint(), PhysicalOffset(5, 250));
  PositionWithAffinity line5 = line5_result.GetPosition();
  Node* line5_node = line5.AnchorNode();
  EXPECT_EQ(line5_node->nodeName(), "#text");
  EXPECT_EQ(line5_node->textContent(), "line5");

  // At the border of an inline box.
  HitTestResult line6_result = HitTestResultAtLocation(5, 350);
  EXPECT_EQ(line6_result.LocalPoint(), PhysicalOffset(5, 350));
  PositionWithAffinity line6 = line6_result.GetPosition();
  Node* line6_node = line6.AnchorNode();
  EXPECT_EQ(line6_node->nodeName(), "#text");
  EXPECT_EQ(line6_node->textContent(), "line6");

  // At the margin of an inline box.
  HitTestResult line7_result = HitTestResultAtLocation(5, 450);
  EXPECT_EQ(line7_result.LocalPoint(), PhysicalOffset(5, 450));
  PositionWithAffinity line7 = line7_result.GetPosition();
  Node* line7_node = line7.AnchorNode();
  EXPECT_EQ(line7_node->nodeName(), "#text");
  EXPECT_EQ(line7_node->textContent(), "line7");

  // At the inline-block.
  HitTestResult line8_result = HitTestResultAtLocation(5, 550);
  EXPECT_EQ(line8_result.LocalPoint(), PhysicalOffset(5, 25));
  PositionWithAffinity line8 = line8_result.GetPosition();
  Node* line8_node = line8.AnchorNode();
  EXPECT_EQ(line8_node->nodeName(), "#text");
  EXPECT_EQ(line8_node->textContent(), "x");
}

// http://crbug.com/1372847
TEST_F(SelectionControllerTest, AdjustSelectionByUserSelectWithInput) {
  SetBodyContent(R"HTML(
    <div style="user-select: none;">
      <div id="one" style="user-select: text;">11</div>
      <input type="text" value="input"/>
    </div>
    <div id="two">22</div>)HTML");

  Element* one = GetDocument().getElementById(AtomicString("one"));
  const SelectionInFlatTree& selection =
      ExpandWithGranularity(SelectionInFlatTree::Builder()
                                .Collapse(PositionInFlatTree(one, 0))
                                .Build(),
                            TextGranularity::kParagraph);
  SelectionInFlatTree adjust_selection =
      AdjustSelectionByUserSelect(one, selection);
  EXPECT_EQ(adjust_selection.Anchor(), selection.Anchor());
  EXPECT_EQ(adjust_selection.Focus(), PositionInFlatTree(one->parentNode(), 2));
}

// http://crbug.com/1410448
TEST_F(SelectionControllerTest, AdjustSelectionByUserSelectWithSpan) {
  SetBodyContent(R"HTML(
    <div id="div" style="user-select:none">
      <span id="one" style="user-select:text">
        <span style="user-select:text">Hel</span>lo
      </span>
      <span style="user-select:text"> lo </span>
      <span id="two" style="user-select:text">there</span></div>)HTML");

  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));

  const SelectionInFlatTree& selection =
      ExpandWithGranularity(SelectionInFlatTree::Builder()
                                .Collapse(PositionInFlatTree(one, 0))
                                .Build(),
                            TextGranularity::kParagraph);
  SelectionInFlatTree adjust_selection =
      AdjustSelectionByUserSelect(one, selection);
  EXPECT_EQ(adjust_selection.Anchor(), selection.Anchor());
  EXPECT_EQ(adjust_selection.Focus(),
            PositionInFlatTree::LastPositionInNode(*two->firstChild()));
}

// http://crbug.com/1487484
TEST_F(SelectionControllerTest, AdjustSelectionByUserSelectWithComment) {
  SetBodyContent(R"HTML(
    <div id="div">
      <span id="one">Hello World!</span>
      <b>before comment</b><!---->
      <span id="two">after comment Hello World!</span>
    </div>)HTML");

  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));

  const SelectionInFlatTree& selection =
      ExpandWithGranularity(SelectionInFlatTree::Builder()
                                .Collapse(PositionInFlatTree(one, 0))
                                .Build(),
                            TextGranularity::kParagraph);
  SelectionInFlatTree adjust_selection =
      AdjustSelectionByUserSelect(one, selection);
  EXPECT_EQ(adjust_selection.Anchor(), selection.Anchor());
  EXPECT_EQ(adjust_selection.Anchor(),
            PositionInFlatTree::FirstPositionInNode(*one->firstChild()));
  EXPECT_EQ(adjust_selection.Focus(), selection.Focus());
  EXPECT_EQ(adjust_selection.Focus(),
            PositionInFlatTree::LastPositionInNode(*two->firstChild()));
}

}  // namespace blink

"""

```