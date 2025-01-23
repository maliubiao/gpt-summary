Response:
My thought process for analyzing the `editing_utilities_test.cc` file goes like this:

1. **Identify the Core Purpose:** The filename itself, `editing_utilities_test.cc`, strongly suggests this file contains *tests* for a set of *editing utilities*. This is my starting point.

2. **Scan the Includes:** The included headers provide crucial context:
    * `editing_utilities.h`: This confirms the existence of a corresponding source file with the actual utility functions being tested.
    * `dom/static_node_list.h`, `dom/text.h`:  Indicates interactions with the DOM, particularly nodes and text content.
    * `editing/position_with_affinity.h`, `editing/visible_position.h`:  Points to functionalities related to text cursors and their visual representation within the document.
    * `editing/testing/editing_test_base.h`:  Confirms this is a testing file and that it uses a base class for editing-related tests.
    * `html/forms/html_input_element.h`:  Suggests specific testing of how these utilities interact with form input elements.
    * `layout/...`:  Indicates tests involving the layout of the document and how elements are positioned and rendered.
    * `testing/core_unit_test_helper.h`: A general helper for unit tests within Chromium.

3. **Analyze the Test Class Structure:** The `EditingUtilitiesTest` class inherits from `EditingTestBase`. This tells me:
    * There's likely setup and teardown logic in `EditingTestBase` for creating a test environment (e.g., setting up a Document).
    * The tests within `EditingUtilitiesTest` will operate within this controlled environment.

4. **Examine Individual Tests (Iterative Process):** I go through each `TEST_F` block and try to understand what it's testing:
    * **Look for Setup:**  `SetBodyContent()` is a common function, indicating the test is setting up a specific HTML structure. `SetShadowContent()` indicates tests involving Shadow DOM.
    * **Identify the Function Under Test:** The test name often hints at the utility function being tested (e.g., `ComputePositionForNodeRemoval`, `DirectionOfEnclosingBlockOf`). The code within the test will usually call this function.
    * **Understand the Assertions:** `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` are key. They show what the test expects the utility function to return given the setup.
    * **Infer Functionality from Tests:**  By looking at what each test asserts, I can deduce the behavior of the corresponding utility function. For example, `ComputePositionForNodeRemoval` seems to calculate the correct position after a node is removed. `DirectionOfEnclosingBlockOf` determines the text direction of an element's container.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  As I understand the functionality of each test, I consider how it relates to web development:
    * **HTML:** The `SetBodyContent()` function directly manipulates the HTML structure. Tests involving elements like `<p>`, `<div>`, `<img>`, `<input>`, `<table>`, `<span>`, `<hr>` show how the utilities interact with these HTML elements. Shadow DOM tests involve `<slot>`.
    * **CSS:** Tests involving `dir=rtl` (right-to-left text direction) directly relate to CSS styling. The tests involving `pointer-events: none` and `text-transform: uppercase` also demonstrate interactions with CSS properties. The `<style>` tag within `SetBodyContent` shows CSS being applied.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, it underlies the browser's rendering engine. The tested utilities are used by the browser to handle editing actions initiated by JavaScript or user interaction. For example, when a user types in an `<input>` or deletes text, these utilities are involved in updating the DOM and the cursor position.

6. **Identify Logical Reasoning and Input/Output:** For tests that perform calculations or comparisons, I can often infer the logic and the expected input/output. For example, in `ComputePositionForNodeRemoval`, the input is a `Position` and the node to be removed, and the output is the adjusted `Position`.

7. **Consider User/Programming Errors:**  Some tests implicitly reveal potential errors:
    * Tests around editable positions highlight the complexities of determining where the cursor can be placed. Incorrect logic in these areas could lead to unexpected cursor behavior.
    * Tests involving read-only inputs demonstrate how the editing utilities should handle cases where direct modification is not allowed.

8. **Think About User Actions and Debugging:** I consider how a user might trigger the code being tested:
    * Selecting text, deleting content, moving the cursor with arrow keys, clicking to place the cursor, interacting with form fields – these are all user actions that might rely on the tested utilities. The Hit Testing tests are a prime example of simulating mouse clicks. Knowing this helps in debugging issues related to these actions.

9. **Address the "TODO" and "DISABLED" Comments:** These comments are important. They indicate known issues or areas where the tests might be failing under certain conditions (like the absence of Shadow DOM v0).

10. **Synthesize and Summarize:** Finally, I combine my observations into a concise summary of the file's functionality, highlighting its role in testing core editing utilities within the Blink rendering engine and its connection to web technologies. I specifically call out the Shadow DOM related tests and the issues mentioned in the TODOs as instructed.
This is the first part of a two-part description of the Chromium Blink engine source code file `blink/renderer/core/editing/editing_utilities_test.cc`. This part focuses on summarizing the file's functionalities based on the provided code.

**Overall Functionality of `editing_utilities_test.cc` (Part 1):**

This file contains unit tests for various utility functions located in `blink/renderer/core/editing/editing_utilities.h`. These utility functions are crucial for handling editing operations within the Blink rendering engine. The tests cover a range of scenarios and edge cases related to text editing, cursor positioning, and DOM manipulation in the context of editing.

Here's a breakdown of the specific functionalities being tested in this first part:

* **Calculating Positions After Node Removal:**
    * `ComputePositionForNodeRemoval`: Tests how the engine determines the correct cursor position after a node is removed from the DOM. It handles cases where the selection is either after a child node or after the node itself that's being removed.

* **Determining the Direction of Enclosing Blocks:**
    * `DirectionOfEnclosingBlockOf`: Tests the ability to identify the text direction (Left-to-Right or Right-to-Left) of the block-level element that contains a given position. This is important for correct text rendering and cursor movement in different locales.

* **Finding the First Editable Position:**
    * `firstEditablePositionAfterPositionInRoot`:  Tests the logic for finding the first editable position within a given root element, starting from a specified position. This is crucial for focusing the cursor correctly when entering editable areas. The tests also consider the impact of Shadow DOM.

* **Identifying Enclosing Blocks and Nodes of a Specific Type:**
    * `enclosingBlock`: Tests the function that finds the nearest ancestor element that is a block-level element for a given position.
    * `enclosingNodeOfType`: Tests the ability to find the nearest ancestor node of a specific type (in this case, block-level elements) for a given position.

* **Checking if a Position is Editable:**
    * `IsEditablePosition`: Tests various scenarios to determine if a given DOM position is within an editable area. This includes cases with:
        * `<hr>` elements.
        * `<span>` elements with `contenteditable`.
        * Elements marked as `inert` (which should not be editable, even within a `contenteditable` parent).

* **Handling Editable Positions in Tables:**
    * Tests that certain positions within a table structure are not considered editable.

* **Adjusting Positions Respecting Editing Boundaries:**
    * `PositionRespectingEditingBoundary`: Tests how the engine adjusts a given position based on hit-testing results and whether the position falls within an editable boundary. This is particularly relevant for:
        * `<input>` elements with `readonly` attribute.
        * `<input>` elements within `contenteditable` areas.
        * `<input>` elements with `pointer-events: none` CSS style. This simulates scenarios like dragging the cursor over a non-interactive input.

* **Repeating Strings:**
    * `RepeatString`: Tests a simple utility function that repeats a given string a specified number of times.

* **Finding Table Elements Just Before a Position:**
    * `TableElementJustBefore`: Tests the ability to locate a table element that immediately precedes a given visible position.

* **Finding the Last Editable Position:**
    * `lastEditablePositionBeforePositionInRoot`: Tests the logic for finding the last editable position within a given root element before a specified position. Similar to finding the first editable position, this considers Shadow DOM.

* **Moving to the Next Position:**
    * `NextNodeIndex`: Tests the functionality for moving to the next position based on grapheme clusters. This is important for correct cursor movement across different character sets.

* **Finding the Next Visually Distinct Candidate Position:**
    * `NextVisuallyDistinctCandidate`: Tests the function that finds the next position that represents a visually distinct point in the document. This is relevant for operations like selection and cursor movement.

* **Calculating Previous and Next Grapheme Boundaries:**
    * `uncheckedPreviousNextOffset_FirstLetter`, `uncheckedPreviousNextOffset_textTransform`, `uncheckedPreviousNextOffset`: Tests the functions responsible for finding the boundaries of grapheme clusters (user-perceived characters) within a text node. This includes handling:
        * `::first-letter` pseudo-elements.
        * `text-transform` CSS property.
        * Various Unicode grapheme breaking rules (CR, LF, Control characters, Hangul syllables, Regional Indicators).

**Relationship to JavaScript, HTML, and CSS:**

This test file directly relates to how the browser's rendering engine handles editing interactions within web pages defined by HTML, styled by CSS, and potentially manipulated by JavaScript.

* **HTML:** The tests heavily rely on setting up specific HTML structures using `SetBodyContent` and `SetShadowContent`. They test interactions with various HTML elements like `<div>`, `<p>`, `<img>`, `<input>`, `<span>`, `<hr>`, `<table>`, `<slot>`, and their attributes like `contenteditable`, `readonly`, and `inert`.

    * **Example:** The test `IsEditablePositionWithHr` directly tests how the editing engine considers the positions around an `<hr>` element with `contenteditable`.

* **CSS:** Several tests demonstrate the influence of CSS on editing behavior:
    * **Text Direction:** The `DirectionOfEnclosingBlockOf` test implicitly involves CSS's influence on text direction through the `dir` attribute.
    * **`pointer-events: none`:** The `PositionRespectingEditingBoundaryWithPointerEventNone` test explicitly uses CSS to make an input non-interactive and checks how position adjustments are handled.
    * **`text-transform: uppercase` and `::first-letter`:** The `uncheckedPreviousNextOffset_textTransform` and `uncheckedPreviousNextOffset_FirstLetter` tests show how CSS styling affects the calculation of grapheme boundaries.

    * **Example:** The `PositionRespectingEditingBoundaryWithPointerEventNone` test sets up HTML with an `<input>` element and then applies the CSS `pointer-events: none;` to it. The test then verifies that when a hit test occurs over this input, the position is adjusted correctly to the placeholder text.

* **JavaScript:** While this is a C++ test file, the underlying functionality being tested is what enables JavaScript editing APIs and user interactions that modify the DOM. For example, when JavaScript code uses methods to insert or delete text, the `editing_utilities` being tested are involved in calculating the correct positions and boundaries.

    * **Example:** When a user interacts with a contenteditable element (which could be controlled by JavaScript event listeners), the browser uses the logic tested here to determine where the cursor should be placed or where text should be inserted.

**Logical Reasoning, Assumptions, and Input/Output Examples:**

* **`ComputePositionForNodeRemoval`:**
    * **Assumption:** The input `position` is within or after a node that is a descendant of the `node_to_remove`.
    * **Input (Test Case 1):** `position` is the last position in the `<img>` tag, `node_to_remove` is the `<p>` tag.
    * **Output (Test Case 1):** The position should be at the beginning of the parent `<div>`.
    * **Input (Test Case 2):** `position` is after the `<img>` tag, `node_to_remove` is the `<p>` tag.
    * **Output (Test Case 2):** The position should be at the beginning of the parent `<div>`.

* **`DirectionOfEnclosingBlockOf`:**
    * **Assumption:** The position is within a text node or an element.
    * **Input:** A `Position` object pointing to a location within the `<b>` element with `id='one'`.
    * **Output (without FlatTree):**  The direction of the enclosing `<p>` element, which is LTR by default.
    * **Output (with FlatTree):** The direction of the enclosing block within the shadow DOM, which is RTL due to `dir=rtl` on a `<p>` inside the shadow root.

* **`IsEditablePositionWithVisibleInertElement`:**
    * **Assumption:** An element with the `inert` attribute should not be editable, even if it's inside a `contenteditable` element.
    * **Input:** A `Position` before the inert `<span>` and a `Position` inside the inert `<span>`.
    * **Output:** The position before the inert element is editable (`true`), the position inside is not (`false`).

**User or Programming Common Usage Errors:**

* **Incorrectly assuming positions within `inert` elements are editable:** Developers might mistakenly try to programmatically insert content into elements marked as `inert` if they are inside a `contenteditable` container. The tests highlight that `inert` effectively disables editing within that subtree.
* **Not considering Shadow DOM boundaries when calculating editable positions:** The tests with Shadow DOM demonstrate that the concept of "editable position" needs to account for the encapsulation provided by Shadow DOM. Incorrectly traversing the DOM without considering shadow boundaries can lead to errors in editing operations.
* **Misunderstanding how `pointer-events: none` affects hit testing and position resolution:** Developers might be surprised that elements with `pointer-events: none` still participate in the layout and can affect where the browser resolves clicks or drags. The `PositionRespectingEditingBoundaryWithPointerEventNone` test illustrates this.

**User Operations Leading to This Code:**

These tests are executed as part of the Chromium development process to ensure the correctness of the editing engine. However, the functionalities being tested are triggered by various user actions within a web browser:

1. **Typing text in editable areas:** When a user types in a `<textarea>` or an element with `contenteditable`, the browser uses the logic tested here to insert the text at the correct position.
2. **Deleting text:**  Pressing the Backspace or Delete key triggers the node removal and position calculation logic tested by `ComputePositionForNodeRemoval`.
3. **Moving the cursor:** Using arrow keys or clicking with the mouse relies on the functions tested for finding editable positions and grapheme boundaries.
4. **Selecting text:**  Dragging the mouse to select text involves hit testing and the logic for determining visually distinct candidate positions.
5. **Interacting with form fields:** Clicking or focusing on input fields triggers logic related to editable positions within those fields, including handling `readonly` attributes.
6. **Using right-to-left languages:** When editing text in RTL languages, the `DirectionOfEnclosingBlockOf` functionality is crucial for correct cursor movement and text rendering.
7. **Working with web components and Shadow DOM:**  When a user interacts with editable content within a web component that uses Shadow DOM, the tests related to Shadow DOM become relevant.

**Summary of Functionalities (as requested by "请归纳一下它的功能"):**

This file tests core editing utilities in the Blink rendering engine, covering:

* **Positioning and Navigation:** Calculating positions after DOM changes, finding editable positions, navigating through text (grapheme boundaries), and identifying visually distinct points.
* **DOM Structure and Boundaries:** Understanding the structure of the DOM (including Shadow DOM), identifying enclosing blocks, and respecting editing boundaries (like `readonly` inputs and `inert` elements).
* **Text Rendering Context:** Determining the text direction of elements.
* **Basic String Manipulation:**  Testing a utility for repeating strings.

These tests ensure the robustness and correctness of the browser's text editing capabilities across various HTML structures, CSS styles, and user interactions.

### 提示词
```
这是目录为blink/renderer/core/editing/editing_utilities_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/editing_utilities.h"

#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class EditingUtilitiesTest : public EditingTestBase {};

TEST_F(EditingUtilitiesTest, ComputePositionForNodeRemovalAfterChildren) {
  SetBodyContent("<div id=a><p id=b><img id=c></p></div>");
  const Position position = Position::LastPositionInNode(*GetElementById("c"));
  // Simulate <p> will be removed.
  EXPECT_EQ(Position(*GetElementById("a"), 0),
            ComputePositionForNodeRemoval(position, *GetElementById("b")));
}

TEST_F(EditingUtilitiesTest, ComputePositionForNodeRemovalAfterNode) {
  // "editing/deleting/delete-start-block.html" hits this case.
  SetBodyContent("<div id=a><p id=b><img id=c></p></div>");
  const Position position = Position::AfterNode(*GetElementById("c"));
  // Simulate <p> will be removed.
  EXPECT_EQ(Position(*GetElementById("a"), 0),
            ComputePositionForNodeRemoval(position, *GetElementById("b")));
}

TEST_F(EditingUtilitiesTest, DirectionOfEnclosingBlockOf) {
  const char* body_content =
      "<p id='host'><b slot='#one' id='one'></b><b slot='#two' "
      "id='two'>22</b></p>";
  const char* shadow_content =
      "<slot name=#two></slot><p dir=rtl><slot name=#one></slot><p>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  Node* one = GetDocument().getElementById(AtomicString("one"));

  EXPECT_EQ(TextDirection::kLtr, DirectionOfEnclosingBlockOf(Position(one, 0)));
  EXPECT_EQ(TextDirection::kRtl,
            DirectionOfEnclosingBlockOf(PositionInFlatTree(one, 0)));
}

// TODO(crbug.com/1157146): This test breaks without Shadow DOM v0.
TEST_F(EditingUtilitiesTest,
       DISABLED_firstEditablePositionAfterPositionInRoot) {
  const char* body_content =
      "<p id='host' contenteditable><b slot='#one' id='one'>1</b><b "
      "slot='#two' id='two'>22</b></p>";
  const char* shadow_content =
      "<slot name=#two></slot><slot name=#one></slot><b id='three'>333</b>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  Node* one = GetDocument().getElementById(AtomicString("one"));
  Node* two = GetDocument().getElementById(AtomicString("two"));
  Node* three = shadow_root->getElementById(AtomicString("three"));

  EXPECT_EQ(Position(one, 0),
            FirstEditablePositionAfterPositionInRoot(Position(one, 0), *host));
  // TODO(crbug.com/1157146): This returns the beginning of "1" instead of the
  // end of "22".
  EXPECT_EQ(Position(two->firstChild(), 2),
            CreateVisiblePosition(FirstEditablePositionAfterPositionInRoot(
                                      Position(one, 0), *host))
                .DeepEquivalent());

  EXPECT_EQ(PositionInFlatTree(one, 0),
            FirstEditablePositionAfterPositionInRoot(PositionInFlatTree(one, 0),
                                                     *host));
  // TODO(crbug.com/1157146): This returns the beginning of "1" instead of the
  // end of "22".
  EXPECT_EQ(PositionInFlatTree(two->firstChild(), 2),
            CreateVisiblePosition(FirstEditablePositionAfterPositionInRoot(
                                      PositionInFlatTree(one, 0), *host))
                .DeepEquivalent());

  EXPECT_EQ(
      Position::FirstPositionInNode(*host),
      FirstEditablePositionAfterPositionInRoot(Position(three, 0), *host));
  // TODO(crbug.com/1157146): This returns the beginning of "1" instead of the
  // beginning of "22".
  EXPECT_EQ(Position(two->firstChild(), 0),
            CreateVisiblePosition(FirstEditablePositionAfterPositionInRoot(
                                      Position(three, 0), *host))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree::AfterNode(*host),
            FirstEditablePositionAfterPositionInRoot(
                PositionInFlatTree(three, 0), *host));
  EXPECT_EQ(PositionInFlatTree::LastPositionInNode(*host),
            CreateVisiblePosition(FirstEditablePositionAfterPositionInRoot(
                                      PositionInFlatTree(three, 0), *host))
                .DeepEquivalent());
}

TEST_F(EditingUtilitiesTest, enclosingBlock) {
  const char* body_content = "<p id='host'><b slot='#one' id='one'>11</b></p>";
  const char* shadow_content =
      "<slot name=#two></slot><div id='three'><slot name=#one></slot></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");
  Node* host = GetDocument().getElementById(AtomicString("host"));
  Node* one = GetDocument().getElementById(AtomicString("one"));
  Node* three = shadow_root->getElementById(AtomicString("three"));

  EXPECT_EQ(host,
            EnclosingBlock(Position(one, 0), kCannotCrossEditingBoundary));
  EXPECT_EQ(three, EnclosingBlock(PositionInFlatTree(one, 0),
                                  kCannotCrossEditingBoundary));
}

TEST_F(EditingUtilitiesTest, enclosingNodeOfType) {
  const char* body_content = "<p id='host'><b slot='#one' id='one'>11</b></p>";
  const char* shadow_content =
      "<slot name=#two></slot><div id='three'><slot name=#one></div></slot>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");
  Node* host = GetDocument().getElementById(AtomicString("host"));
  Node* one = GetDocument().getElementById(AtomicString("one"));
  Node* three = shadow_root->getElementById(AtomicString("three"));

  EXPECT_EQ(host, EnclosingNodeOfType(Position(one, 0), IsEnclosingBlock));
  EXPECT_EQ(three,
            EnclosingNodeOfType(PositionInFlatTree(one, 0), IsEnclosingBlock));
}

// http://crbug.com/873088
TEST_F(EditingUtilitiesTest, IsEditablePositionWithHr) {
  SetBodyContent("<hr contenteditable id=target>");
  Element& target = *GetDocument().getElementById(AtomicString("target"));
  EXPECT_FALSE(IsEditablePosition(Position::BeforeNode(target)));
  EXPECT_TRUE(IsEditablePosition(Position(target, 0)));
}

// http://crbug.com/873088
TEST_F(EditingUtilitiesTest, IsEditablePositionWithSpan) {
  SetBodyContent("<span contenteditable id=target>abc</span>");
  Element& target = *GetDocument().getElementById(AtomicString("target"));
  EXPECT_FALSE(IsEditablePosition(Position::BeforeNode(target)));
  EXPECT_TRUE(IsEditablePosition(Position(target, 0)));
}

// https://issues.chromium.org/issues/41490809
TEST_F(EditingUtilitiesTest, IsEditablePositionWithVisibleInertElement) {
  SetBodyContent(
      R"(<div contenteditable><span inert id="target">abc</span></div>)");
  Element& target = *GetElementById("target");
  EXPECT_TRUE(IsEditablePosition(Position::BeforeNode(target)));
  EXPECT_FALSE(IsEditablePosition(Position(target.firstChild(), 0)));
}

// https://issues.chromium.org/issues/41490809
TEST_F(EditingUtilitiesTest, IsEditablePositionWithInVisibleInertElement) {
  SetBodyContent(
      R"(<div contenteditable>
        <span inert id="target" style="display: none;">abc</span></div>)");
  Element& target = *GetElementById("target");
  EXPECT_TRUE(IsEditablePosition(Position::BeforeNode(target)));
  EXPECT_FALSE(IsEditablePosition(Position(target.firstChild(), 0)));
}

TEST_F(EditingUtilitiesTest, isEditablePositionWithTable) {
  // We would like to have below DOM tree without HTML, HEAD and BODY element.
  //   <table id=table><caption>foo</caption></table>
  // However, |setBodyContent()| automatically creates HTML, HEAD and BODY
  // element. So, we build DOM tree manually.
  // Note: This is unusual HTML taken from http://crbug.com/574230
  Element* table = GetDocument().CreateRawElement(html_names::kTableTag);
  table->setInnerHTML("<caption>foo</caption>");
  while (GetDocument().firstChild())
    GetDocument().firstChild()->remove();
  GetDocument().AppendChild(table);
  GetDocument().setDesignMode("on");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(IsEditablePosition(Position(table, 0)));
}

// http://crbug.com/1185089
// See also PositionRespectingEditingBoundaryWithInputReadWrite
TEST_F(EditingUtilitiesTest,
       PositionRespectingEditingBoundaryWithInputReadOnly) {
  LoadAhem();
  InsertStyleElement("body { font: 10px/15px Ahem; margin: 0px; }");
  SetBodyContent(
      "<div id=sample>012"
      "<input value=abc placeholder=xyz readonly>"
      "345</div>");
  const auto& sample = *GetElementById("sample");
  const auto& text_012 = *To<Text>(sample.firstChild());
  const auto& input =
      ToTextControl(*GetDocument().QuerySelector(AtomicString("input")));
  const auto& inner_editor = *input.InnerEditorElement();
  const auto& text_abc = *To<Text>(inner_editor.firstChild());

  const HitTestRequest hit_request(HitTestRequest::kActive);
  const HitTestLocation hit_location(PhysicalOffset(0, 0));
  HitTestResult hit_result(hit_request, hit_location);
  ASSERT_TRUE(
      GetDocument().View()->GetLayoutView()->HitTest(hit_location, hit_result));
  ASSERT_EQ(PositionWithAffinity(Position(text_012, 0)),
            hit_result.GetPosition());

  EXPECT_EQ(
      PositionWithAffinity(Position(text_abc, 0)),
      PositionRespectingEditingBoundary(Position(text_abc, 1), hit_result))
      << "Adjust to outside of <input> to inside of <input>";
  EXPECT_EQ(PositionWithAffinity(Position(text_012, 0)),
            PositionRespectingEditingBoundary(Position::BeforeNode(input),
                                              hit_result))
      << "No adjustment because both position are in same enclosing element";
}

// http://crbug.com/1185089
TEST_F(EditingUtilitiesTest,
       PositionRespectingEditingBoundaryWithInputReadOnlyInEditable) {
  LoadAhem();
  InsertStyleElement("body { font: 10px/15px Ahem; margin: 0px; }");
  SetBodyContent(
      "<div contenteditable id=sample>012"
      "<input value=abc placeholder=xyz readonly>"
      "345</div>");
  const auto& sample = *GetElementById("sample");
  const auto& text_012 = *To<Text>(sample.firstChild());
  const auto& input =
      ToTextControl(*GetDocument().QuerySelector(AtomicString("input")));
  const auto& inner_editor = *input.InnerEditorElement();
  const auto& text_abc = *To<Text>(inner_editor.firstChild());

  const HitTestRequest hit_request(HitTestRequest::kActive);
  const HitTestLocation hit_location(PhysicalOffset(5, 5));
  HitTestResult hit_result(hit_request, hit_location);
  ASSERT_TRUE(
      GetDocument().View()->GetLayoutView()->HitTest(hit_location, hit_result));
  ASSERT_EQ(PositionWithAffinity(Position(text_012, 0)),
            hit_result.GetPosition());

  EXPECT_EQ(
      PositionWithAffinity(Position(text_abc, 0)),
      PositionRespectingEditingBoundary(Position(text_abc, 1), hit_result))
      << "Adjust to outside of <input> to inside of <input>";
  EXPECT_EQ(PositionWithAffinity(Position(text_012, 0)),
            PositionRespectingEditingBoundary(Position::BeforeNode(input),
                                              hit_result))
      << "No adjustment because both position are in same enclosing element";
}

// http://crbug.com/1185089
// See also PositionRespectingEditingBoundaryWithInputReadOnly
TEST_F(EditingUtilitiesTest,
       PositionRespectingEditingBoundaryWithInputReadWrite) {
  LoadAhem();
  InsertStyleElement("body { font: 10px/15px Ahem; margin: 0px; }");
  SetBodyContent(
      "<div id=sample>012"
      "<input value=abc placeholder=xyz>"
      "345</div>");
  const auto& sample = *GetElementById("sample");
  const auto& text_012 = *To<Text>(sample.firstChild());
  const auto& input =
      ToTextControl(*GetDocument().QuerySelector(AtomicString("input")));
  const auto& inner_editor = *input.InnerEditorElement();
  const auto& text_abc = *To<Text>(inner_editor.firstChild());

  const HitTestRequest hit_request(HitTestRequest::kActive);
  const HitTestLocation hit_location(PhysicalOffset(5, 5));
  HitTestResult hit_result(hit_request, hit_location);
  ASSERT_TRUE(
      GetDocument().View()->GetLayoutView()->HitTest(hit_location, hit_result));
  ASSERT_EQ(PositionWithAffinity(Position(text_012, 0)),
            hit_result.GetPosition());

  EXPECT_EQ(
      PositionWithAffinity(Position(text_abc, 0)),
      PositionRespectingEditingBoundary(Position(text_abc, 1), hit_result))
      << "Adjust to outside of <input> to inside of <input>";
  EXPECT_EQ(PositionWithAffinity(Position(text_012, 0)),
            PositionRespectingEditingBoundary(Position::BeforeNode(input),
                                              hit_result))
      << "No adjustment because both position are in same enclosing element";
}

// http://crbug.com/1249655 and http://crbug.com/1252377
TEST_F(EditingUtilitiesTest,
       PositionRespectingEditingBoundaryWithPointerEventNone) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 10px/15px Ahem; margin: 0px; }"
      "input { pointer-events: none; }");
  SetBodyContent("<div>012 <input id=target placeholder=abc> 345</div>");
  const auto& target = *To<TextControlElement>(GetElementById("target"));
  const auto& text_abc = *To<Text>(target.PlaceholderElement()->firstChild());

  const HitTestRequest hit_request(HitTestRequest::kActive);
  const HitTestLocation hit_location(PhysicalOffset(50, 5));
  HitTestResult hit_result(hit_request, hit_location);
  ASSERT_TRUE(
      GetDocument().View()->GetLayoutView()->HitTest(hit_location, hit_result));
  ASSERT_EQ(PositionWithAffinity(Position(text_abc, 1)),
            hit_result.GetPosition());
  // Simulates drag from "abc"@2 to "abc@1"
  EXPECT_EQ(
      PositionWithAffinity(Position(text_abc, 1)),
      PositionRespectingEditingBoundary(Position(text_abc, 2), hit_result));
}

TEST_F(EditingUtilitiesTest, RepeatString) {
  EXPECT_EQ("", RepeatString("xyz", 0));
  EXPECT_EQ("xyz", RepeatString("xyz", 1));
  EXPECT_EQ("xyzxyz", RepeatString("xyz", 2));
  EXPECT_EQ("xyzxyzxyz", RepeatString("xyz", 3));
}

// TODO(crbug.com/1157146): This test breaks without Shadow DOM v0.
TEST_F(EditingUtilitiesTest, DISABLED_tableElementJustBefore) {
  const char* body_content =
      "<div contenteditable id=host><table slot=#table "
      "id=table><tr><td>1</td></tr></table><b slot=#two id=two>22</b></div>";
  const char* shadow_content =
      "<slot name=#two></slot><slot name=#table></slot>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  Node* host = GetDocument().getElementById(AtomicString("host"));
  Node* table = GetDocument().getElementById(AtomicString("table"));

  EXPECT_EQ(table, TableElementJustBefore(VisiblePosition::AfterNode(*table)));
  // TODO(crbug.com/1157146): This returns null instead of the table.
  EXPECT_EQ(table, TableElementJustBefore(
                       VisiblePositionInFlatTree::AfterNode(*table)));

  EXPECT_EQ(table, TableElementJustBefore(
                       VisiblePosition::LastPositionInNode(*table)));
  // TODO(crbug.com/1157146): This returns null instead of the table.
  EXPECT_EQ(table, TableElementJustBefore(CreateVisiblePosition(
                       PositionInFlatTree::LastPositionInNode(*table))));

  EXPECT_EQ(nullptr,
            TableElementJustBefore(CreateVisiblePosition(Position(host, 2))));
  // TODO(crbug.com/1157146): This returns null instead of the table.
  EXPECT_EQ(table, TableElementJustBefore(
                       CreateVisiblePosition(PositionInFlatTree(host, 2))));

  EXPECT_EQ(nullptr, TableElementJustBefore(VisiblePosition::AfterNode(*host)));
  EXPECT_EQ(nullptr, TableElementJustBefore(
                         VisiblePositionInFlatTree::AfterNode(*host)));

  EXPECT_EQ(nullptr,
            TableElementJustBefore(VisiblePosition::LastPositionInNode(*host)));
  // TODO(crbug.com/1157146): This returns null instead of the table.
  EXPECT_EQ(table, TableElementJustBefore(CreateVisiblePosition(
                       PositionInFlatTree::LastPositionInNode(*host))));
}

// TODO(crbug.com/1157146): This test breaks without Shadow DOM v0.
TEST_F(EditingUtilitiesTest,
       DISABLED_lastEditablePositionBeforePositionInRoot) {
  const char* body_content =
      "<p id='host' contenteditable><b slot=#one id='one'>1</b><b slot=#two "
      "id='two'>22</b></p>";
  const char* shadow_content =
      "<slot name=#two></slot><slot name=#one></slot><b "
      "id='three'>333</b>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  Node* one = GetDocument().getElementById(AtomicString("one"));
  Node* two = GetDocument().getElementById(AtomicString("two"));
  Node* three = shadow_root->getElementById(AtomicString("three"));

  EXPECT_EQ(Position(one, 0),
            LastEditablePositionBeforePositionInRoot(Position(one, 0), *host));
  // TODO(crbug.com/1157146): This returns the beginning of "1" instead of the
  // end of "22".
  EXPECT_EQ(Position(two->firstChild(), 2),
            CreateVisiblePosition(LastEditablePositionBeforePositionInRoot(
                                      Position(one, 0), *host))
                .DeepEquivalent());

  EXPECT_EQ(PositionInFlatTree(one, 0),
            LastEditablePositionBeforePositionInRoot(PositionInFlatTree(one, 0),
                                                     *host));
  // TODO(crbug.com/1157146): This returns the beginning of "1" instead of the
  // end of "22".
  EXPECT_EQ(PositionInFlatTree(two->firstChild(), 2),
            CreateVisiblePosition(LastEditablePositionBeforePositionInRoot(
                                      PositionInFlatTree(one, 0), *host))
                .DeepEquivalent());

  EXPECT_EQ(
      Position::FirstPositionInNode(*host),
      LastEditablePositionBeforePositionInRoot(Position(three, 0), *host));
  // TODO(crbug.com/1157146): This returns the beginning of "1" instead of the
  // beginning of "22".
  EXPECT_EQ(Position(two->firstChild(), 0),
            CreateVisiblePosition(LastEditablePositionBeforePositionInRoot(
                                      Position(three, 0), *host))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree::FirstPositionInNode(*host),
            LastEditablePositionBeforePositionInRoot(
                PositionInFlatTree(three, 0), *host));
  // TODO(crbug.com/1157146): This returns nullptr instead of the beginning of
  // "22".
  EXPECT_EQ(PositionInFlatTree(two->firstChild(), 0),
            CreateVisiblePosition(LastEditablePositionBeforePositionInRoot(
                                      PositionInFlatTree(three, 0), *host))
                .DeepEquivalent());
}

// TODO(crbug.com/1157146): This test breaks without Shadow DOM v0.
TEST_F(EditingUtilitiesTest, DISABLED_NextNodeIndex) {
  const char* body_content =
      "<p id='host'>00<b slot='#one' id='one'>11</b><b slot='#two' "
      "id='two'>22</b>33</p>";
  const char* shadow_content = "<slot name=#two></slot><slot name=#one></slot>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  Node* host = GetDocument().getElementById(AtomicString("host"));
  Node* two = GetDocument().getElementById(AtomicString("two"));

  EXPECT_EQ(
      Position(host, 3),
      NextPositionOf(Position(two, 1), PositionMoveType::kGraphemeCluster));
  // TODO(crbug.com/1157146): This returns the slot instead of the <p>.
  EXPECT_EQ(PositionInFlatTree(host, 1),
            NextPositionOf(PositionInFlatTree(two, 1),
                           PositionMoveType::kGraphemeCluster));
}

TEST_F(EditingUtilitiesTest, NextVisuallyDistinctCandidate) {
  const char* body_content =
      "<p id='host'>00<b slot='#one' id='one'>11</b><b slot='#two' "
      "id='two'>22</b><b slot='#three' id='three'>33</b></p>";
  const char* shadow_content =
      "<slot name=#two></slot><slot name=#one></slot><slot name=#three></slot>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  Node* one = GetDocument().getElementById(AtomicString("one"));
  Node* two = GetDocument().getElementById(AtomicString("two"));
  Node* three = GetDocument().getElementById(AtomicString("three"));

  EXPECT_EQ(Position(two->firstChild(), 0),
            NextVisuallyDistinctCandidate(Position(one, 1)));
  EXPECT_EQ(PositionInFlatTree(three->firstChild(), 1),
            NextVisuallyDistinctCandidate(PositionInFlatTree(one, 1)));
}

TEST_F(EditingUtilitiesTest, uncheckedPreviousNextOffset_FirstLetter) {
  SetBodyContent(
      "<style>p::first-letter {color:red;}</style><p id='target'>abc</p>");
  const Node& node =
      *GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(node, 3));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(node, 2));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(node, 0));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(node, 1));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(node, 2));

  UpdateAllLifecyclePhasesForTest();
  EXPECT_NE(nullptr, node.GetLayoutObject());
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(node, 3));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(node, 2));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(node, 0));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(node, 1));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(node, 2));
}

TEST_F(EditingUtilitiesTest, uncheckedPreviousNextOffset_textTransform) {
  SetBodyContent(
      "<style>p {text-transform:uppercase}</style><p id='target'>abc</p>");
  const Node& node =
      *GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(node, 3));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(node, 2));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(node, 0));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(node, 1));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(node, 2));

  UpdateAllLifecyclePhasesForTest();
  EXPECT_NE(nullptr, node.GetLayoutObject());
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(node, 3));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(node, 2));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(node, 0));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(node, 1));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(node, 2));
}

// Following breaking rules come from http://unicode.org/reports/tr29/
// Note that some of rules are in draft. Also see
// http://www.unicode.org/reports/tr29/proposed.html
TEST_F(EditingUtilitiesTest, uncheckedPreviousNextOffset) {
  // GB1: Break at the start of text.
  SetBodyContent("<p id='target'>a</p>");
  Node* node =
      GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));

  // GB2: Break at the end of text.
  SetBodyContent("<p id='target'>a</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));

  // GB3: Do not break between CR and LF.
  SetBodyContent("<p id='target'>a&#x0D;&#x0A;b</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));

  // GB4,GB5: Break before and after CR/LF/Control.
  SetBodyContent("<p id='target'>a&#x0D;b</p>");  // CR
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 2));
  SetBodyContent("<p id='target'>a&#x0A;b</p>");  // LF
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 2));
  // U+00AD(SOFT HYPHEN) has Control property.
  SetBodyContent("<p id='target'>a&#xAD;b</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 2));

  // GB6: Don't break Hangul sequence.
  const std::string l =
      "&#x1100;";  // U+1100 (HANGUL CHOSEONG KIYEOK) has L property.
  const std::string v =
      "&#x1160;";  // U+1160 (HANGUL JUNGSEONG FILLER) has V property.
  const std::string lv =
      "&#xAC00;";  // U+AC00 (HANGUL SYLLABLE GA) has LV property.
  const std::string lvt =
      "&#xAC01;";  // U+AC01 (HANGUL SYLLABLE GAG) has LVT property.
  const std::string t =
      "&#x11A8;";  // U+11A8 (HANGUL JONGSEONG KIYEOK) has T property.
  SetBodyContent("<p id='target'>a" + l + l + "b</p>");  // L x L
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  SetBodyContent("<p id='target'>a" + l + v + "b</p>");  // L x V
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  SetBodyContent("<p id='target'>a" + l + lv + "b</p>");  // L x LV
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  SetBodyContent("<p id='target'>a" + l + lvt + "b</p>");  // L x LVT
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));

  // GB7: Don't break Hangul sequence.
  SetBodyContent("<p id='target'>a" + lv + v + "b</p>");  // LV x V
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  SetBodyContent("<p id='target'>a" + lv + t + "b</p>");  // LV x T
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  SetBodyContent("<p id='target'>a" + v + v + "b</p>");  // V x V
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  SetBodyContent("<p id='target'>a" + v + t + "b</p>");  // V x T
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));

  // GB8: Don't break Hangul sequence.
  SetBodyContent("<p id='target'>a" + lvt + t + "b</p>");  // LVT x T
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  SetBodyContent("<p id='target'>a" + t + t + "b</p>");  // T x T
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));

  // Break other Hangul syllable combination. See test of GB999.

  // GB12: Don't break between regional indicator if there are even numbered
  // regional indicator symbols before.
  // U+1F1FA is REGIONAL INDICATOR SYMBOL LETTER U.
  // U+1F1F8 is REGIONAL INDICATOR SYMBOL LETTER S.
  const std::string flag = "&#x1F1FA;&#x1F1F8;";  // US flag.
  // ^(RI RI)* RI x RI
  SetBodyContent("<p id='target'>" + flag + flag + flag + flag + "a</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(16, PreviousGraphemeBoundaryOf(*node, 17));
  EXPECT_EQ(12, PreviousGraphemeBoundaryOf(*node, 16));
  EXPECT_EQ(8, PreviousGraphemeBoundaryOf(*node, 12));
  EXPECT_EQ(4, PreviousGraphemeBoundaryOf(*node, 8));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(8, NextGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(12, NextGraphemeBoundaryOf(*node, 8));
  EXPECT_EQ(16, NextGraphemeBoundaryOf(*node, 12));
  EXPECT_EQ(17, NextGraphemeBoundaryOf(*node, 16));

  // GB8c: Don't break between regional indicator if there are even numbered
  // regional indicator symbols before.
  // [^RI] (RI RI)* RI x RI
  SetBodyContent("<p id='target'>a" + flag + flag + flag + flag + "b</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(17, PreviousGraphemeBoundaryOf(*node, 18));
  EXPECT_EQ(13, PreviousGraphemeBoundaryOf(*node, 17));
  EXPECT_EQ(9, PreviousGraphemeBoundaryOf(*node, 13));
  EXPECT_EQ(5, PreviousGraphemeBoundaryOf(*node, 9));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(5, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(9, NextGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(13, NextGraphemeBoundaryOf(*node, 9));
  EXPECT_EQ(17, NextGraphemeBoundaryOf(*node, 13));
  EXPECT_EQ(18, NextGraphem
```