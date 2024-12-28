Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. This is the second part of a two-part request. Since it's the second part, I need to synthesize the information from *this* snippet and infer the overall purpose by combining it with the likely content of the *first* part (which I don't have access to, so I'll make reasonable assumptions).

**Part 1 - Likely Content and its purpose:**

Based on the file name (`frame_selection_test.cc`), it's highly probable that the first part of the file contains setup code for the tests, including:

*   **Test fixture definition:** A class inheriting from a testing framework's base class (like `testing::Test` or a Blink-specific base). This fixture likely provides methods for creating a test environment (e.g., setting up a `Document`, `Frame`), helper functions for setting content, and potentially utility functions for interacting with the selection.
*   **Basic test cases:** Tests covering the initial states of selection, like no selection, hidden selection, etc.
*   **Focus-related tests:** Tests covering the basic interaction of focus with selection (e.g., focusing a simple element).

**Part 2 - Current Snippet Analysis:**

This snippet contains a series of `TEST_F` blocks, indicating individual test cases. Each test case seems to focus on specific scenarios involving:

*   **Selection types:** Caret selections (single insertion point) and range selections (highlighted text).
*   **DOM elements:**  Input fields (`<input>`), editable divs (`<div contenteditable>`), links (`<a>`), textareas (`<textarea>`), and general divs.
*   **Shadow DOM:** Interactions with selection inside shadow roots.
*   **Focus:** How focusing different elements affects the selection (visibility, focus state).
*   **Read-only/disabled elements:** Special cases for text controls.
*   **Parent element focus:**  Impact of focusing parent elements (both editable and non-editable) on selections within child elements.
*   **Scrolling and scaling:**  Testing how scrolling and page scaling affect the reported selection bounds.
*   **Bi-directional text:** Testing selection boundaries with mixed text directions.
*   **Clipboard operations:** Testing the text content copied to the clipboard.
*   **Flat tree vs. DOM tree:** Testing selection behavior in the context of the flat tree representation of the DOM.
*   **Painting:** Testing that selection data is correctly recorded during painting, even when selection handles are hidden.

**Connecting to Web Technologies:**

The tests directly interact with HTML elements and their attributes (`id`, `value`, `contenteditable`, `readonly`, `disabled`, `dir`). They also simulate user interactions like focusing and selecting text, which are core features of web browsers and rely on JavaScript APIs (like `focus()`, `select()`, and the `Selection` API) and CSS for styling the selection.

**Hypothesized Workflow and User Actions:**

A user might reach this code by:

1. **Experiencing a bug related to text selection:**  For instance, a caret not appearing when an input field is focused, or selected text disappearing unexpectedly when another element is focused.
2. **Reporting the bug:**  Providing steps to reproduce the issue.
3. **A Chromium developer investigating the bug:** They would look at the reported steps, identify the involved DOM elements and interactions, and then write a new test case (or modify an existing one) in `frame_selection_test.cc` to reproduce the bug and verify the fix.

**Overall Functionality (Combining Part 1 & 2):**

The entire `frame_selection_test.cc` file serves as a comprehensive suite of unit tests for the Blink rendering engine's selection management logic. It verifies the correct behavior of text selection in various scenarios, including different DOM structures, user interactions (focus, clicks), and element states (editable, read-only, disabled). It ensures that the selection is correctly maintained, displayed (or hidden), and interacts as expected with other browser features like focus and clipboard operations.

**Final Plan:**

1. Summarize the functionality of this specific snippet.
2. Explain its relationship to JavaScript, HTML, and CSS, providing examples from the code.
3. Give an example of logical reasoning with input and output based on a test case.
4. Illustrate a common user/programming error and how this test file can help prevent it.
5. Describe how a user's actions can lead to the need for these tests.
6. Combine this information into a concise summary of the file's overall function.
这是`blink/renderer/core/editing/frame_selection_test.cc`文件的第二部分，延续了第一部分的功能，专注于对Blink引擎中关于Frame Selection的各种场景进行单元测试。

**归纳一下它的功能:**

这部分代码主要用于测试在各种复杂的DOM结构和用户交互下，Blink引擎的文本选择 (Frame Selection) 功能是否正确工作。  它涵盖了以下几个核心方面：

1. **焦点与选区的关系:** 测试焦点移动 (例如，通过点击链接或调用 `focus()` 方法) 如何影响文本选区的状态 (是否存在，是否有焦点，是否可见)。
2. **不同类型元素的选区行为:** 针对 `input`, `textarea`, 可编辑 `div`, Shadow DOM 中的节点等不同类型的元素，测试选区的创建、修改、以及在焦点变化时的行为。
3. **只读和禁用元素的选区行为:**  测试只读 (`readonly`) 和禁用 (`disabled`) 的文本控件中的选区行为，例如是否允许创建选区，焦点变化的影响。
4. **父元素对子元素选区的影响:** 测试当焦点移动到可编辑或不可编辑的父元素时，子元素中的选区状态如何变化。
5. **选区的可见性:**  测试在各种情况下，选区 (无论是光标还是范围选区) 是否应该可见 (`IsHidden()` 返回 `false`) 或隐藏 (`IsHidden()` 返回 `true`)。
6. **选区的边界计算:** 测试在滚动和页面缩放的情况下，选区的绝对边界 (`AbsoluteUnclippedBounds()`) 和相对边界 (`ComputeAbsoluteBounds()`) 的计算是否正确。
7. **双向文本 (Bidi) 的选区:** 测试在包含从右到左 (`rtl`) 和从左到右 (`ltr`) 文本的场景下，选区是否能正确包含边界。
8. **剪贴板操作:** 测试在特定场景下 (例如，选区包含 `input` 元素)，复制到剪贴板的文本内容是否符合预期 (`SelectedTextForClipboard()`).
9. **Flat Tree 与 DOM Tree 的选区关系:** 测试在 Shadow DOM 等场景下，选区在 Flat Tree 和 DOM Tree 中的连接状态，以及如何影响选区的文本内容。
10. **绘制 (Painting) 时的选区记录:** 测试在绘制过程中，即使禁用了选区控制柄，选区信息是否仍然被正确记录。

**与javascript, html, css的功能的关系举例说明:**

*   **HTML:** 测试用例通过 `SetBodyContent()` 方法设置 HTML 结构，例如 `<input id='field'>`, `<div contenteditable id='ce'>blabla</div>`。这些 HTML 元素是测试选区行为的基础。
*   **JavaScript:** 测试用例模拟 JavaScript 的 `focus()` 和 `blur()` 方法来改变元素的焦点，例如 `field->Focus()`，`field->blur()`。  `Selection().SelectAll()` 模拟了 JavaScript 中选择所有文本的操作。这些操作直接影响了页面的交互和选区的状态。
*   **CSS:** 测试用例中使用了 `<style>` 标签来定义 CSS 样式，例如设置 `margin`, `height`, `font-size` 等，这些样式影响了元素的布局和大小，从而影响了选区边界的计算。例如，在 `TEST_F(FrameSelectionTest, SelectionBounds)` 中，CSS 用于创建一个具有特定高度和溢出行为的 `div`，以便测试选区边界在滚动时的表现。

**逻辑推理的假设输入与输出:**

**假设输入:**  HTML 内容为 `<input id='test' value='hello'>`，然后通过 JavaScript 代码模拟焦点到该 `input` 元素。

**逻辑推理:**

1. 初始状态下，没有元素获得焦点，选区应该是 `None`，没有焦点，并且隐藏。
2. 当 `input` 元素获得焦点后，选区应该变为 `Caret` (光标)，拥有焦点，并且可见。

**对应的测试代码:**

```c++
TEST_F(FrameSelectionTest, CaretInInput) {
  SetBodyContent("<input id='test' value='hello'>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const input_element = GetDocument().getElementById(AtomicString("test"));
  input_element->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());
}
```

**用户或编程常见的使用错误举例说明:**

一个常见的用户操作是**在只读的文本框中尝试选择文本并期望能够编辑**。

**测试用例模拟:** `TEST_F(FrameSelectionTest, FocusingButtonHidesRangeInReadOnlyTextControl)`

**代码片段:**

```c++
TEST_F(FrameSelectionTest, FocusingButtonHidesRangeInReadOnlyTextControl) {
  SetBodyContent(
      "<textarea readonly>Berlin</textarea>"
      "<input type='submit' value='Submit'>");
  // ... (选择文本框并选择所有内容) ...
  Element* const submit = GetDocument().QuerySelector(AtomicString("input"));
  submit->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());
}
```

**说明:**  这个测试用例验证了即使在只读的文本框中选择了文本，当焦点移动到其他可聚焦元素 (例如按钮) 时，文本框的选区仍然存在 (`IsRange()` 为真)，但失去了焦点 (`SelectionHasFocus()` 为假)，并且可能被隐藏 (`IsHidden()` 为真)。 这反映了用户无法编辑只读文本框的预期行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户报告了一个与文本选择相关的 bug:** 例如，用户发现在一个特定的网页上，当他们在一个 `<input>` 元素中选择了一些文本后，点击页面上的一个链接，选中的文本仍然高亮显示，但实际上已经失去了焦点，并且无法进行复制等操作。
2. **开发者尝试重现该 bug:** 开发者会按照用户的操作步骤，在本地环境中加载该网页，并尝试重现该问题。
3. **开发者定位到 `frame_selection_test.cc`:**  由于该 bug 涉及到文本选区的行为，开发者可能会搜索相关的测试文件，`frame_selection_test.cc` 就是一个很可能包含相关测试的候选文件。
4. **开发者查找或编写新的测试用例:** 开发者可能会在文件中搜索已有的类似场景的测试用例，或者编写一个新的测试用例来精确地复现用户报告的问题。 例如，`TEST_F(FrameSelectionTest, FocusingLinkHidesRangeInTextControl)` 这个测试用例很可能就是为了解决类似 "在文本框中选择文本后点击链接，选区显示异常" 的问题而编写的。
5. **运行测试用例并进行调试:** 开发者会运行相关的测试用例，如果测试失败，他们会使用调试工具来分析代码执行流程，找出导致选区行为异常的原因，并最终修复 bug。

总而言之，`blink/renderer/core/editing/frame_selection_test.cc` 的这部分代码通过大量的单元测试，确保了 Blink 引擎在各种复杂的场景下能够正确地管理和呈现文本选区，保证了用户在浏览器中进行文本选择和编辑时的行为符合预期。 这些测试覆盖了各种 HTML 元素、用户交互以及焦点变化，有效地防止了与文本选择相关的 bug 的出现。

Prompt: 
```
这是目录为blink/renderer/core/editing/frame_selection_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
n().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Caret is now hidden.
}

TEST_F(FrameSelectionTest, CaretInTextControl) {
  SetBodyContent("<input id='field'>");  // <input> hosts a shadow tree.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const field = GetDocument().getElementById(AtomicString("field"));
  field->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  field->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Caret is now hidden.
}

TEST_F(FrameSelectionTest, RangeInShadowTree) {
  SetBodyContent("<p id='host'></p>");
  ShadowRoot* shadow_root = SetShadowContent("hey", "host");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Node* text_node = shadow_root->firstChild();
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text_node, 0), Position(text_node, 3))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("hey");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  GetDocument().body()->Focus();  // Move focus to document body.
  EXPECT_EQ_SELECTED_TEXT("hey");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());
}

TEST_F(FrameSelectionTest, RangeInTextControl) {
  SetBodyContent("<input id='field' value='hola'>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const field = GetDocument().getElementById(AtomicString("field"));
  field->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  field->blur();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());
}

// crbug.com/692898
TEST_F(FrameSelectionTest, FocusingLinkHidesCaretInTextControl) {
  SetBodyContent(
      "<input id='field'>"
      "<a href='www' id='alink'>link</a>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const field = GetDocument().getElementById(AtomicString("field"));
  field->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Element* const alink = GetDocument().getElementById(AtomicString("alink"));
  alink->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());
}

// crbug.com/692898
TEST_F(FrameSelectionTest, FocusingLinkHidesRangeInTextControl) {
  SetBodyContent(
      "<input id='field' value='hola'>"
      "<a href='www' id='alink'>link</a>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const field = GetDocument().getElementById(AtomicString("field"));
  field->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Element* const alink = GetDocument().getElementById(AtomicString("alink"));
  alink->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());
}

TEST_F(FrameSelectionTest, FocusingButtonHidesRangeInReadOnlyTextControl) {
  SetBodyContent(
      "<textarea readonly>Berlin</textarea>"
      "<input type='submit' value='Submit'>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  textarea->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Element* const submit = GetDocument().QuerySelector(AtomicString("input"));
  submit->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());
}

TEST_F(FrameSelectionTest, FocusingButtonHidesRangeInDisabledTextControl) {
  SetBodyContent(
      "<textarea disabled>Berlin</textarea>"
      "<input type='submit' value='Submit'>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  textarea->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());

  // We use a double click to create the selection [Berlin].
  // FrameSelection::SelectAll (= textarea.select() in JavaScript) would have
  // been shorter, but currently that doesn't work on a *disabled* text control.
  const gfx::Rect elem_bounds = textarea->BoundsInWidget();
  WebMouseEvent double_click(WebMouseEvent::Type::kMouseDown, 0,
                             WebInputEvent::GetStaticTimeStampForTests());
  double_click.SetPositionInWidget(elem_bounds.x(), elem_bounds.y());
  double_click.SetPositionInScreen(elem_bounds.x(), elem_bounds.y());
  double_click.button = WebMouseEvent::Button::kLeft;
  double_click.click_count = 2;
  double_click.SetFrameScale(1);

  GetFrame().GetEventHandler().HandleMousePressEvent(double_click);
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Element* const submit = GetDocument().QuerySelector(AtomicString("input"));
  submit->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());
}

// crbug.com/713051
TEST_F(FrameSelectionTest, FocusingNonEditableParentHidesCaretInTextControl) {
  SetBodyContent(
      "<div tabindex='-1' id='parent'>"
      "  <input id='field'>"
      "</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const field = GetDocument().getElementById(AtomicString("field"));
  field->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  // Here the selection belongs to <input>'s shadow tree and that tree has a
  // non-editable parent that is focused.
  Element* const parent = GetDocument().getElementById(AtomicString("parent"));
  parent->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Focus is outside <input>
                                        // so caret should not be visible.

  parent->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Caret is still hidden.
}

// crbug.com/713051
TEST_F(FrameSelectionTest, FocusingNonEditableParentHidesRangeInTextControl) {
  SetBodyContent(
      "<div tabindex='-1' id='parent'>"
      "  <input id='field' value='hola'>"
      "</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const field = GetDocument().getElementById(AtomicString("field"));
  field->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  // Here the selection belongs to <input>'s shadow tree and that tree has a
  // non-editable parent that is focused.
  Element* const parent = GetDocument().getElementById(AtomicString("parent"));
  parent->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Focus is outside <input>
                                        // so range should not be visible.

  parent->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Range is still hidden.
}

TEST_F(FrameSelectionTest, CaretInEditableDiv) {
  SetBodyContent("<div contenteditable id='ce'>blabla</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const ce = GetDocument().getElementById(AtomicString("ce"));
  ce->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  ce->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Caret is now hidden.
}

TEST_F(FrameSelectionTest, RangeInEditableDiv) {
  SetBodyContent("<div contenteditable id='ce'>blabla</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const ce = GetDocument().getElementById(AtomicString("ce"));
  ce->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  ce->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Range is still visible.
}

TEST_F(FrameSelectionTest, RangeInEditableDivInShadowTree) {
  SetBodyContent("<p id='host'></p>");
  ShadowRoot* shadow_root =
      SetShadowContent("<div id='ce' contenteditable>foo</div>", "host");

  Element* const ce = shadow_root->getElementById(AtomicString("ce"));
  ce->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  ce->blur();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Range is still visible.
}

TEST_F(FrameSelectionTest, FocusingLinkHidesCaretInContentEditable) {
  SetBodyContent(
      "<div contenteditable id='ce'>blabla</div>"
      "<a href='www' id='alink'>link</a>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const ce = GetDocument().getElementById(AtomicString("ce"));
  ce->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Element* const alink = GetDocument().getElementById(AtomicString("alink"));
  alink->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());
}

TEST_F(FrameSelectionTest, FocusingLinkKeepsRangeInContentEditable) {
  SetBodyContent(
      "<div contenteditable id='ce'>blabla</div>"
      "<a href='www' id='alink'>link</a>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const ce = GetDocument().getElementById(AtomicString("ce"));
  ce->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Element* const alink = GetDocument().getElementById(AtomicString("alink"));
  alink->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());
}

TEST_F(FrameSelectionTest, FocusingEditableParentKeepsEditableCaret) {
  SetBodyContent(
      "<div contenteditable tabindex='-1' id='parent'>"
      "<div contenteditable id='ce'>blabla</div>"
      "</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  // TODO(editing-dev): Blink should be able to focus the inner <div>.
  //  Element* const ce = GetDocument().getElementById(AtomicString("ce"));
  //  ce->Focus();
  //  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  //  EXPECT_FALSE(Selection().IsHidden());

  Element* const parent = GetDocument().getElementById(AtomicString("parent"));
  parent->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Focus is within editing boundary,
                                         // caret should be visible.

  parent->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Focus is outside editing boundary
                                        // so caret should be hidden.
}

TEST_F(FrameSelectionTest, FocusingEditableParentKeepsEditableRange) {
  SetBodyContent(
      "<div contenteditable tabindex='-1' id='parent'>"
      "<div contenteditable id='ce'>blabla</div>"
      "</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  // TODO(editing-dev): Blink should be able to focus the inner <div>.
  //  Element* const ce = GetDocument().getElementById(AtomicString("ce"));
  //  ce->Focus();
  //  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  //  EXPECT_FALSE(Selection().IsHidden());

  //  Selection().SelectAll();
  //  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  //  EXPECT_FALSE(Selection().IsHidden());

  Element* const parent = GetDocument().getElementById(AtomicString("parent"));
  parent->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Focus is within editing boundary,
                                         // range should be visible.

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  parent->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Focus is outside editing boundary
                                         // but range should still be visible.
}

TEST_F(FrameSelectionTest, FocusingNonEditableParentHidesEditableCaret) {
  SetBodyContent(
      "<div tabindex='-1' id='parent'>"
      "<div contenteditable id='ce'>blabla</div>"
      "</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const ce = GetDocument().getElementById(AtomicString("ce"));
  ce->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  // Here the selection belongs to <div>'s shadow tree and that tree has a
  // non-editable parent that is focused.
  Element* const parent = GetDocument().getElementById(AtomicString("parent"));
  parent->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Focus is outside editing boundary
                                        // so caret should be hidden.

  parent->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());  // Caret is still hidden.
}

TEST_F(FrameSelectionTest, FocusingNonEditableParentKeepsEditableRange) {
  SetBodyContent(
      "<div tabindex='-1' id='parent'>"
      "<div contenteditable id='ce'>blabla</div>"
      "</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const ce = GetDocument().getElementById(AtomicString("ce"));
  ce->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Selection().SelectAll();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  // Here the selection belongs to <div>'s shadow tree and that tree has a
  // non-editable parent that is focused.
  Element* const parent = GetDocument().getElementById(AtomicString("parent"));
  parent->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Focus is outside editing boundary
                                         // but range should still be visible.

  parent->blur();  // Move focus to document body.
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Range is still visible.
}

// crbug.com/707143
TEST_F(FrameSelectionTest, RangeContainsFocus) {
  SetBodyContent(
      "<div>"
      "  <div>"
      "    <span id='start'>start</span>"
      "  </div>"
      "  <a href='www' id='alink'>link</a>"
      "  <div>line 1</div>"
      "  <div>line 2</div>"
      "  <div>line 3</div>"
      "  <div>line 4</div>"
      "  <span id='end'>end</span>"
      "  <div></div>"
      "</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const start = GetDocument().getElementById(AtomicString("start"));
  Element* const end = GetDocument().getElementById(AtomicString("end"));
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(start, 0), Position(end, 1))
          .Build(),
      SetSelectionOptions());
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Element* const alink = GetDocument().getElementById(AtomicString("alink"));
  alink->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Range still visible.
}

// crbug.com/707143
TEST_F(FrameSelectionTest, RangeOutsideFocus) {
  // Here the selection sits on a sub tree that hasn't the focused element.
  // This test case is the reason why we separate FrameSelection::HasFocus() and
  // FrameSelection::IsHidden(). Even when the selection's DOM nodes are
  // completely disconnected from the focused node, we still want the selection
  // to be visible (not hidden).
  SetBodyContent(
      "<a href='www' id='alink'>link</a>"
      "<div>"
      "  <div>"
      "    <span id='start'>start</span>"
      "  </div>"
      "  <div>line 1</div>"
      "  <div>line 2</div>"
      "  <div>line 3</div>"
      "  <div>line 4</div>"
      "  <span id='end'>end</span>"
      "  <div></div>"
      "</div>");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const start = GetDocument().getElementById(AtomicString("start"));
  Element* const end = GetDocument().getElementById(AtomicString("end"));
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(start, 0), Position(end, 1))
          .Build(),
      SetSelectionOptions());
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  Element* const alink = GetDocument().getElementById(AtomicString("alink"));
  alink->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());  // Range still visible.
}

// crbug.com/725457
TEST_F(FrameSelectionTest, InconsistentVisibleSelectionNoCrash) {
  SetBodyContent("foo<div id=host><span id=anchor>bar</span></div>baz");
  SetShadowContent("shadow", "host");

  Element* anchor = GetDocument().getElementById(AtomicString("anchor"));

  // |start| and |end| are valid Positions in DOM tree, but do not participate
  // in flat tree. They should be canonicalized to null VisiblePositions, but
  // are currently not. See crbug.com/729636 for details.
  const Position& start = Position::BeforeNode(*anchor);
  const Position& end = Position::AfterNode(*anchor);
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(start).Extend(end).Build(),
      SetSelectionOptions());

  // Shouldn't crash inside.
  EXPECT_FALSE(Selection().SelectionHasFocus());
}

TEST_F(FrameSelectionTest, SelectionBounds) {
  SetBodyContent(
      "<style>"
      "  * { margin: 0; } "
      "  html, body { height: 2000px; }"
      "  div {"
      "    width: 20px;"
      "    height: 1000px;"
      "    font-size: 30px;"
      "    overflow: hidden;"
      "    margin-top: 2px;"
      "  }"
      "</style>"
      "<div>"
      "  a<br>b<br>c<br>d<br>e<br>f<br>g<br>h<br>i<br>j<br>k<br>l<br>m<br>n<br>"
      "  a<br>b<br>c<br>d<br>e<br>f<br>g<br>h<br>i<br>j<br>k<br>l<br>m<br>n<br>"
      "  a<br>b<br>c<br>d<br>e<br>f<br>g<br>h<br>i<br>j<br>k<br>l<br>m<br>n<br>"
      "</div>");
  Selection().SelectAll();

  const int node_width = 20;
  const int node_height = 1000;
  const int node_margin_top = 2;
  // The top of the node should be visible but the bottom should be outside
  // by the viewport. The unclipped selection bounds should not be clipped.
  EXPECT_EQ(PhysicalRect(0, node_margin_top, node_width, node_height),
            Selection().AbsoluteUnclippedBounds());

  // Scroll 500px down so the top of the node is outside the viewport and the
  // bottom is visible. The unclipped selection bounds should not be clipped.
  const int scroll_offset = 500;
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_offset), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_EQ(PhysicalRect(0, node_margin_top, node_width, node_height),
            frame_view->FrameToDocument(Selection().AbsoluteUnclippedBounds()));

  // Adjust the page scale factor which changes the selection bounds as seen
  // through the viewport. The unclipped selection bounds should not be clipped.
  const int page_scale_factor = 2;
  GetPage().SetPageScaleFactor(page_scale_factor);
  EXPECT_EQ(PhysicalRect(0, node_margin_top, node_width, node_height),
            frame_view->FrameToDocument(Selection().AbsoluteUnclippedBounds()));
}

TEST_F(FrameSelectionTest, AbosluteSelectionBoundsAfterScroll) {
  SetBodyContent(
      "<style>"
      "  html, body { height: 2000px; }"
      "</style>"
      "<div style='height:1000px;'>"
      "  <p style='margin-top:100px; font-size:30px'>text</p>"
      "</div>");
  Selection().SelectAll();

  gfx::Rect initial_anchor, initial_focus;
  Selection().ComputeAbsoluteBounds(initial_anchor, initial_focus);

  // Scroll 50px down.
  const int scroll_offset = 50;
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_offset), mojom::blink::ScrollType::kProgrammatic);

  // Check absolute selection bounds are updated.
  gfx::Rect anchor_after_scroll, focus_after_scroll;
  Selection().ComputeAbsoluteBounds(anchor_after_scroll, focus_after_scroll);
  EXPECT_EQ(anchor_after_scroll,
            initial_anchor - gfx::Vector2d(0, scroll_offset));
  EXPECT_EQ(focus_after_scroll,
            initial_focus - gfx::Vector2d(0, scroll_offset));
}

TEST_F(FrameSelectionTest, SelectionContainsBidiBoundary) {
  InsertStyleElement("div{font:10px/10px Ahem}");
  // Rendered as abcFED
  Selection().SetSelection(
      SetSelectionTextToBody("<div dir=ltr>^abc<bdo dir=trl>DEF|</bdo></div>"),
      SetSelectionOptions());

  // Check the right half of 'c'
  const PhysicalOffset c_right(35, 13);
  EXPECT_TRUE(Selection().Contains(c_right));

  // Check the left half of "F"
  const PhysicalOffset f_left(45, 13);
  EXPECT_TRUE(Selection().Contains(f_left));
}

// This is a regression test for https://crbug.com/927394 where 'copy' operation
// stopped copying content from inside text controls.
// Note that this is a non-standard behavior.
TEST_F(FrameSelectionTest, SelectedTextForClipboardEntersTextControls) {
  Selection().SetSelection(
      SetSelectionTextToBody("^foo<input value=\"bar\">baz|"),
      SetSelectionOptions());
  EXPECT_EQ("foo\nbar\nbaz", Selection().SelectedTextForClipboard());
}

// For https://crbug.com/1177295
TEST_F(FrameSelectionTest, PositionDisconnectedInFlatTree) {
  SetBodyContent("<div id=host>x</div>y");
  SetShadowContent("", "host");
  Element* host = GetElementById("host");
  Node* text = host->firstChild();
  Position positions[] = {
      Position::BeforeNode(*host),         Position::FirstPositionInNode(*host),
      Position::LastPositionInNode(*host), Position::AfterNode(*host),
      Position::BeforeNode(*text),         Position::FirstPositionInNode(*text),
      Position::LastPositionInNode(*text), Position::AfterNode(*text)};
  for (const Position& base : positions) {
    EXPECT_TRUE(base.IsConnected());
    bool flat_base_is_connected = ToPositionInFlatTree(base).IsConnected();
    EXPECT_EQ(base.AnchorNode() == host, flat_base_is_connected);
    for (const Position& extent : positions) {
      const SelectionInDOMTree& selection =
          SelectionInDOMTree::Builder().SetBaseAndExtent(base, extent).Build();
      Selection().SetSelection(selection, SetSelectionOptions());
      EXPECT_TRUE(extent.IsConnected());
      bool flat_extent_is_connected =
          ToPositionInFlatTree(selection.Focus()).IsConnected();
      EXPECT_EQ(flat_base_is_connected || flat_extent_is_connected
                    ? "<div id=\"host\"></div>|y"
                    : "<div id=\"host\"></div>y",
                GetSelectionTextInFlatTreeFromBody(
                    GetVisibleSelectionInFlatTree().AsSelection()));
    }
  }
}

TEST_F(FrameSelectionTest, PaintCaretRecordsSelectionWithNoSelectionHandles) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      blink::features::kHiddenSelectionBounds);

  Text* text = AppendTextNode("Hello, World!");
  UpdateAllLifecyclePhasesForTest();

  GetDocument().body()->setContentEditable("true", ASSERT_NO_EXCEPTION);
  GetDocument().body()->Focus();
  EXPECT_TRUE(GetDocument().body()->IsFocused());

  Selection().SetCaretEnabled(true);
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(text, 0)).Build(),
      SetSelectionOptions());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(Selection().ComputeVisibleSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().ShouldPaintCaret(
      *To<LayoutBlock>(GetDocument().body()->GetLayoutObject())));

  PaintController paint_controller;
  {
    GraphicsContext context(paint_controller);
    paint_controller.UpdateCurrentPaintChunkProperties(
        root_paint_chunk_id_, *root_paint_property_client_,
        PropertyTreeState::Root());
    Selection().PaintCaret(context, PhysicalOffset());
  }
  auto& paint_artifact = paint_controller.CommitNewDisplayItems();

  const PaintChunk& chunk = paint_artifact.GetPaintChunks()[0];
  EXPECT_THAT(chunk.layer_selection_data, Not(IsNull()));
  LayerSelectionData* selection_data = chunk.layer_selection_data;
  EXPECT_TRUE(selection_data->start.has_value());
  EXPECT_EQ(gfx::SelectionBound::HIDDEN, selection_data->start->type);
  EXPECT_TRUE(selection_data->end.has_value());
  EXPECT_EQ(gfx::SelectionBound::HIDDEN, selection_data->end->type);
}

}  // namespace blink

"""


```