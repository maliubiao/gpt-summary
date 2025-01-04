Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ test file (`selection_bounds_recorder_test.cc`) and explain its functionality in relation to web technologies (JavaScript, HTML, CSS), provide examples, and discuss debugging aspects.

2. **Initial Skim for Keywords:** Quickly read through the code looking for relevant keywords and patterns. Words like `Selection`, `Paint`, `Bounds`, `Test`, `HTML`, `CSS`, `JavaScript` (though not directly present) suggest the file is related to how text selections are rendered in the browser. The `TEST_F` macros clearly indicate these are unit tests.

3. **Identify the Core Class Under Test:** The `SelectionBoundsRecorderTest` class name strongly suggests this file tests the functionality of something that records the boundaries of a text selection during the painting process.

4. **Analyze Individual Tests:**  Examine each `TEST_F` function. Each test seems to focus on a specific scenario:

    * `SelectAll`:  Focuses on the "Select All" functionality.
    * `SelectAllInVerticalRl`, `SelectAllInVerticalLr`, `SelectAllInSidewaysRl`, `SelectAllInSidewaysLr`:  These variations test "Select All" in different writing modes (vertical-rl, vertical-lr, sideways-rl, sideways-lr), which are CSS properties. This immediately links the test to CSS.
    * `SelectMultiline`: Tests selections that span multiple lines.
    * `SelectMultilineEmptyStartEnd`: Tests selections where the start or end of the selection is at the beginning or end of a line (potentially an empty space).
    * `InvalidationForEmptyBounds`: This is a more complex test involving moving a selection and checking if the rendering invalidation happens correctly.

5. **Connect to Web Technologies:**

    * **HTML:** The `SetBodyInnerHTML` calls within the tests directly manipulate the HTML content of the page being tested. This is a fundamental connection.
    * **CSS:** The tests involving `writing-mode` directly demonstrate the interaction with CSS properties. The `style` tags within `SetBodyInnerHTML` further emphasize this connection.
    * **JavaScript:** While no explicit JavaScript code is present in the *test file*, the functionality being tested (text selection) is heavily influenced and controlled by JavaScript in a real browser environment. JavaScript APIs are used to make selections, and this test verifies the *rendering* of those selections. Therefore, there's an indirect relationship.

6. **Explain Functionality in Plain Language:**  Summarize the purpose of the test file: to verify that the selection boundaries are correctly calculated and recorded during the painting process, especially in different layout scenarios.

7. **Provide Concrete Examples:**

    * **HTML/CSS Interaction:** Use the `SelectAllInVerticalRl` test as an example, highlighting how the CSS `writing-mode` affects the expected coordinates of the selection bounds.
    * **JavaScript Interaction:** Explain that JavaScript would be the mechanism to trigger the "Select All" action or to programmatically set a specific selection.

8. **Logical Reasoning (Assumptions and Outputs):** For each test, outline:

    * **Assumptions/Input:** The initial HTML and CSS setup, and the selection action performed (e.g., `SelectAll()`, `SetSelection()`).
    * **Expected Output:** Focus on the `EXPECT_EQ` assertions, particularly the `edge_start` and `edge_end` coordinates of the `PaintedSelectionBound`. Explain what these coordinates represent (the visual bounds of the selection).

9. **Common Usage Errors:** Think about how developers might misuse or misunderstand the selection functionality:

    * Incorrectly calculating selection boundaries manually.
    * Not considering different writing modes.
    * Assuming selection coordinates are always in a specific direction.

10. **Debugging Clues:**  Explain how the tests themselves serve as debugging clues. If a bug occurs in selection rendering:

    * The tests might fail, pinpointing the area of the problem.
    * Developers can modify the test cases or add new ones to isolate the issue.
    * Stepping through the code during test execution (`gdb` or similar) can help understand the calculation of selection bounds.
    * Examining the `ContentPaintChunks` data structure can reveal if the recorded selection information is correct.

11. **Structure and Refine:** Organize the information logically with clear headings and bullet points. Ensure the language is clear and concise. Avoid overly technical jargon where possible. Review and refine the explanation for clarity and accuracy. For instance, initially, I might have focused too much on the C++ aspects, but I'd then adjust to emphasize the connections to web technologies as per the prompt's requirements. I'd also ensure the "User Operations" section clearly explains the browser UI actions that lead to this code being executed.
This C++ source code file, `selection_bounds_recorder_test.cc`, within the Chromium Blink engine, focuses on **testing the functionality of the `SelectionBoundsRecorder`**. The `SelectionBoundsRecorder` is a component responsible for recording the visual boundaries of text selections during the paint (rendering) process.

Here's a breakdown of its functionality and its relation to web technologies:

**Core Functionality:**

* **Verifying Selection Boundary Recording:** The primary purpose of this test file is to ensure that when text is selected in a web page, the `SelectionBoundsRecorder` accurately captures the start and end points of that selection. This includes the coordinates (`edge_start`, `edge_end`) and the type of boundary (e.g., `LEFT`, `RIGHT`).
* **Testing Different Selection Scenarios:** The tests cover various selection scenarios, including:
    * **Selecting all content (`SelectAll`)**:  Checks if the boundaries are correctly recorded when the entire content of an element is selected.
    * **Selections in different writing modes (`SelectAllInVerticalRl`, `SelectAllInVerticalLr`, `SelectAllInSidewaysRl`, `SelectAllInSidewaysLr`)**:  Crucially, it tests how selection boundaries are recorded when the text flows vertically or sideways, which are features controlled by CSS's `writing-mode` property.
    * **Multiline selections (`SelectMultiline`)**:  Verifies the recording of boundaries when the selection spans across multiple lines of text.
    * **Selections starting or ending at line breaks (`SelectMultilineEmptyStartEnd`)**: Examines cases where the selection begins or ends immediately before or after a line break.
    * **Invalidation of empty bounds (`InvalidationForEmptyBounds`)**: Tests the more complex scenario of how the recording and invalidation of selection boundaries work when a selection moves, potentially having empty start or end points in different paint chunks.

**Relationship to JavaScript, HTML, and CSS:**

* **HTML:** The tests directly manipulate the HTML content of the page being tested using `SetBodyInnerHTML`. This sets up the structure of the text and elements on which selections will be made. For example:
    ```c++
    SetBodyInnerHTML("<span>A<br>B<br>C</span>");
    ```
    This creates a simple HTML structure with a `span` containing line breaks.

* **CSS:** The tests explicitly use CSS to influence the layout and rendering of the text, particularly through the `writing-mode` property. For example:
    ```c++
    SetBodyInnerHTML(R"HTML(
        <style>body {
          writing-mode: vertical-rl;
          font: 20px Ahem;
        }</style><span>AB<br>C</span>)HTML");
    ```
    This sets the `writing-mode` to `vertical-rl` (vertical, right-to-left), which drastically alters the text flow and, consequently, the expected selection boundaries. This highlights how the `SelectionBoundsRecorder` needs to be aware of CSS properties.

* **JavaScript (Indirectly):** While the test file itself is C++, the functionality it tests is deeply intertwined with JavaScript. In a real browser environment, JavaScript is the primary way users and web developers interact with text selections:
    * **User Interaction:**  Dragging the mouse to select text triggers JavaScript events that update the browser's selection state.
    * **Programmatic Selection:** JavaScript APIs (like `window.getSelection()`, `Selection.setBaseAndExtent()`, `Selection.selectAll()`) allow developers to programmatically create and manipulate text selections.
    The `SelectionBoundsRecorder` is the underlying mechanism that captures the visual representation of these JavaScript-driven selections for rendering. The test file simulates these selection actions programmatically using Blink's internal APIs.

**Examples and Logical Reasoning (Hypothesized Input and Output):**

Let's take the `SelectAll` test as an example:

**Hypothesized Input:**

* **HTML:** `<span>A<br>B<br>C</span>`
* **CSS (Default):**  Standard horizontal, left-to-right text flow.
* **JavaScript Equivalent Action:** `document.execCommand('selectAll')` or a user dragging the mouse to select all the text.
* **Blink Internal Action:** `local_frame->Selection().SelectAll();`

**Logical Reasoning:**

1. The text will be laid out horizontally, one letter per line due to the `<br>` tags.
2. The selection will start at the beginning of "A" and end at the end of "C".
3. The `SelectionBoundsRecorder` will capture the visual position of the start and end of this selection.

**Expected Output (from the test):**

* `start.type` will be `gfx::SelectionBound::LEFT` (indicating the start of the selection).
* `start.edge_start` will be approximately `gfx::Point(8, 8)` and `start.edge_end` will be approximately `gfx::Point(8, 9)`. These coordinates represent the top-left and bottom-left of the visual start of the selection highlight.
* `end.type` will be `gfx::SelectionBound::RIGHT` (indicating the end of the selection).
* `end.edge_start` will be approximately `gfx::Point(9, 10)` and `end.edge_end` will be approximately `gfx::Point(9, 11)`. These coordinates represent the top-right and bottom-right of the visual end of the selection highlight.

The exact pixel values might vary slightly depending on font rendering and default styles, but the relative positions and the `LEFT`/`RIGHT` types are crucial.

**User or Programming Common Usage Errors:**

* **Incorrectly assuming selection boundaries in different writing modes:** A common mistake for web developers would be to assume that selection boundaries always behave the same way as in standard horizontal text flow. For instance, when `writing-mode` is `vertical-rl`, the "start" of the selection might visually be on the right side. This test helps ensure the browser handles this correctly.
* **Manually calculating selection highlights:** Developers should generally rely on the browser's built-in selection mechanisms. Trying to manually draw selection highlights using JavaScript and knowing the exact pixel coordinates can be error-prone, especially when considering different writing modes, text orientations, and zooming levels. The `SelectionBoundsRecorder` within the browser engine handles these complexities.
* **Not accounting for line breaks and empty lines:**  The `SelectMultilineEmptyStartEnd` test highlights the importance of correctly handling selections that begin or end at line breaks. Developers might make errors when trying to determine the exact character or DOM node at the start or end of such selections.

**User Operation Steps to Reach This Code (as a Debugging Clue):**

Imagine a user reports a bug where the text selection highlight appears incorrectly in a webpage using vertical writing mode. A developer might use this test file as a debugging tool:

1. **User Action:** The user opens a webpage with content styled using `writing-mode: vertical-rl;` (or another non-standard writing mode).
2. **User Action:** The user attempts to select text on this page by dragging their mouse.
3. **Browser Internal:** The browser's JavaScript engine detects the mouse drag and updates the selection state (start and end points of the selection).
4. **Browser Internal:** During the paint lifecycle, the `SelectionBoundsRecorder` is invoked to determine the visual boundaries of the current selection.
5. **Potential Bug:** If the selection highlight is drawn incorrectly, the issue might lie within the `SelectionBoundsRecorder`'s logic for handling vertical writing modes.
6. **Debugging:** A Chromium developer might:
    * **Run the existing tests in `selection_bounds_recorder_test.cc`**, especially the `SelectAllInVerticalRl` test, to see if they are failing. This would immediately indicate a problem in this area.
    * **Modify existing tests or add new test cases** to specifically reproduce the user's reported scenario. They might create a test with the exact HTML and CSS structure of the problematic webpage.
    * **Step through the code in `SelectionBoundsRecorder::RecordBoundsFor...` (and related functions)** using a debugger to understand how the selection boundaries are calculated for the specific elements and writing mode. They would inspect the intermediate values and calculations to pinpoint the source of the error.
    * **Examine the `ContentPaintChunks` data structure** (as seen in the tests) to see the recorded selection boundary information and compare it to the expected values.

In essence, this test file acts as a critical safeguard to ensure the correct visual representation of text selections across various web content layouts and user interactions. It provides a structured way to verify the logic of the `SelectionBoundsRecorder` and helps prevent and diagnose rendering bugs related to text selection highlights.

Prompt: 
```
这是目录为blink/renderer/core/paint/selection_bounds_recorder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"

using testing::ElementsAre;

namespace blink {

class SelectionBoundsRecorderTest : public PaintControllerPaintTestBase {};

TEST_F(SelectionBoundsRecorderTest, SelectAll) {
  SetBodyInnerHTML("<span>A<br>B<br>C</span>");

  LocalFrame* local_frame = GetDocument().GetFrame();
  local_frame->Selection().SetHandleVisibleForTesting();
  local_frame->GetPage()->GetFocusController().SetFocusedFrame(local_frame);
  local_frame->Selection().SelectAll();
  UpdateAllLifecyclePhasesForTest();

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 1u);
  EXPECT_TRUE(chunks[0].layer_selection_data->start.has_value());
  EXPECT_TRUE(chunks[0].layer_selection_data->end.has_value());
  PaintedSelectionBound start = chunks[0].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(8, 8));
  EXPECT_EQ(start.edge_end, gfx::Point(8, 9));

  PaintedSelectionBound end = chunks[0].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  EXPECT_EQ(end.edge_start, gfx::Point(9, 10));
  EXPECT_EQ(end.edge_end, gfx::Point(9, 11));
}

TEST_F(SelectionBoundsRecorderTest, SelectAllInVerticalRl) {
  LocalFrame* local_frame = GetDocument().GetFrame();
  LoadAhem(*local_frame);
  SetBodyInnerHTML(R"HTML(
      <style>body {
        writing-mode: vertical-rl;
        font: 20px Ahem;
      }</style><span>AB<br>C</span>)HTML");

  local_frame->Selection().SetHandleVisibleForTesting();
  local_frame->GetPage()->GetFocusController().SetFocusedFrame(local_frame);
  local_frame->Selection().SelectAll();
  UpdateAllLifecyclePhasesForTest();

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 1u);
  EXPECT_TRUE(chunks[0].layer_selection_data->start.has_value());
  EXPECT_TRUE(chunks[0].layer_selection_data->end.has_value());
  PaintedSelectionBound start = chunks[0].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(772, 8));
  EXPECT_EQ(start.edge_end, gfx::Point(792, 8));

  PaintedSelectionBound end = chunks[0].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  EXPECT_EQ(end.edge_start, gfx::Point(772, 28));
  EXPECT_EQ(end.edge_end, gfx::Point(752, 28));
}

TEST_F(SelectionBoundsRecorderTest, SelectAllInVerticalLr) {
  LocalFrame* local_frame = GetDocument().GetFrame();
  LoadAhem(*local_frame);
  SetBodyInnerHTML(R"HTML(
      <style>body {
        writing-mode: vertical-lr;
        font: 20px Ahem;
      }</style><span>AB<br>C</span>)HTML");

  local_frame->Selection().SetHandleVisibleForTesting();
  local_frame->GetPage()->GetFocusController().SetFocusedFrame(local_frame);
  local_frame->Selection().SelectAll();
  UpdateAllLifecyclePhasesForTest();

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 1u);
  EXPECT_TRUE(chunks[0].layer_selection_data->start.has_value());
  EXPECT_TRUE(chunks[0].layer_selection_data->end.has_value());
  PaintedSelectionBound start = chunks[0].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(28, 8));
  EXPECT_EQ(start.edge_end, gfx::Point(8, 8));

  PaintedSelectionBound end = chunks[0].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  EXPECT_EQ(end.edge_start, gfx::Point(28, 28));
  EXPECT_EQ(end.edge_end, gfx::Point(48, 28));
}

TEST_F(SelectionBoundsRecorderTest, SelectAllInSidewaysRl) {
  LocalFrame* local_frame = GetDocument().GetFrame();
  LoadAhem(*local_frame);
  SetBodyInnerHTML(R"HTML(
      <style>body {
        writing-mode: sideways-rl;
        font: 20px Ahem;
      }</style><span>AB<br>C</span>)HTML");

  local_frame->Selection().SetHandleVisibleForTesting();
  local_frame->GetPage()->GetFocusController().SetFocusedFrame(local_frame);
  local_frame->Selection().SelectAll();
  UpdateAllLifecyclePhasesForTest();

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 1u);
  EXPECT_TRUE(chunks[0].layer_selection_data->start.has_value());
  EXPECT_TRUE(chunks[0].layer_selection_data->end.has_value());
  PaintedSelectionBound start = chunks[0].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(772, 8));
  EXPECT_EQ(start.edge_end, gfx::Point(792, 8));

  PaintedSelectionBound end = chunks[0].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  EXPECT_EQ(end.edge_start, gfx::Point(772, 28));
  EXPECT_EQ(end.edge_end, gfx::Point(752, 28));
}

TEST_F(SelectionBoundsRecorderTest, SelectAllInSidewaysLr) {
  LocalFrame* local_frame = GetDocument().GetFrame();
  LoadAhem(*local_frame);
  SetBodyInnerHTML(R"HTML(
      <style>body {
        writing-mode: sideways-lr;
        font: 20px Ahem;
      }</style><span>AB<br>C</span>)HTML");

  local_frame->Selection().SetHandleVisibleForTesting();
  local_frame->GetPage()->GetFocusController().SetFocusedFrame(local_frame);
  local_frame->Selection().SelectAll();
  UpdateAllLifecyclePhasesForTest();

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 1u);
  EXPECT_TRUE(chunks[0].layer_selection_data->start.has_value());
  EXPECT_TRUE(chunks[0].layer_selection_data->end.has_value());
  PaintedSelectionBound start = chunks[0].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(8, 592));
  EXPECT_EQ(start.edge_end, gfx::Point(28, 592));

  PaintedSelectionBound end = chunks[0].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  EXPECT_EQ(end.edge_start, gfx::Point(28, 572));
  EXPECT_EQ(end.edge_end, gfx::Point(48, 572));
}

TEST_F(SelectionBoundsRecorderTest, SelectMultiline) {
  LocalFrame* local_frame = GetDocument().GetFrame();
  LoadAhem(*local_frame);

  local_frame->Selection().SetSelection(
      SelectionSample::SetSelectionText(GetDocument().body(),
                                        R"HTML(
          <style>
            div { white-space:pre; font-family: Ahem; }
          </style>
          <div>f^oo\nbar\nb|az</div>
      )HTML"),
      SetSelectionOptions());

  local_frame->Selection().SetHandleVisibleForTesting();
  local_frame->GetPage()->GetFocusController().SetFocusedFrame(local_frame);
  UpdateAllLifecyclePhasesForTest();

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 1u);
  EXPECT_TRUE(chunks[0].layer_selection_data->start.has_value());
  EXPECT_TRUE(chunks[0].layer_selection_data->end.has_value());
  PaintedSelectionBound start = chunks[0].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(9, 8));
  EXPECT_EQ(start.edge_end, gfx::Point(9, 9));

  PaintedSelectionBound end = chunks[0].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  EXPECT_EQ(end.edge_start, gfx::Point(19, 8));
  EXPECT_EQ(end.edge_end, gfx::Point(19, 9));
}

TEST_F(SelectionBoundsRecorderTest, SelectMultilineEmptyStartEnd) {
  LocalFrame* local_frame = GetDocument().GetFrame();
  LoadAhem(*local_frame);
  local_frame->Selection().SetSelection(
      SelectionSample::SetSelectionText(GetDocument().body(),
                                        R"HTML(
          <style>
            body { margin: 0; }
            * { font: 10px/1 Ahem; }
          </style>
          <div>foo^<br>bar<br>|baz</div>
      )HTML"),
      SetSelectionOptions());
  local_frame->Selection().SetHandleVisibleForTesting();
  local_frame->GetPage()->GetFocusController().SetFocusedFrame(local_frame);
  UpdateAllLifecyclePhasesForTest();

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 1u);
  EXPECT_TRUE(chunks[0].layer_selection_data->start.has_value());
  EXPECT_TRUE(chunks[0].layer_selection_data->end.has_value());
  PaintedSelectionBound start = chunks[0].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(30, 0));
  EXPECT_EQ(start.edge_end, gfx::Point(30, 10));

  PaintedSelectionBound end = chunks[0].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  EXPECT_EQ(end.edge_start, gfx::Point(0, 20));
  EXPECT_EQ(end.edge_end, gfx::Point(0, 30));
}

TEST_F(SelectionBoundsRecorderTest, InvalidationForEmptyBounds) {
  LocalFrame* local_frame = GetDocument().GetFrame();
  LoadAhem(*local_frame);

  // Set a selection that has empty start and end in separate paint chunks.
  // We'll move these empty endpoints into the middle div and make sure
  // everything is invalidated/re-painted/recorded correctly.
  local_frame->Selection().SetSelection(
      SelectionSample::SetSelectionText(GetDocument().body(),
                                        R"HTML(
          <style>
            body { margin: 0; }
            div { will-change: transform; }
            * { font: 10px/1 Ahem; }
          </style>
          <div>foo^</div><div id=target>bar</div><div>|baz</div>
      )HTML"),
      SetSelectionOptions());
  local_frame->Selection().SetHandleVisibleForTesting();
  local_frame->GetPage()->GetFocusController().SetFocusedFrame(local_frame);
  UpdateAllLifecyclePhasesForTest();

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 4u);

  // Skip the root chunk to get to the first div.
  EXPECT_TRUE(chunks[1].layer_selection_data->start.has_value());
  PaintedSelectionBound start = chunks[1].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(30, 0));
  EXPECT_EQ(start.edge_end, gfx::Point(30, 10));

  // Skip the middle div as well to get to the third div where the end of the
  // selection is.
  EXPECT_TRUE(chunks[3].layer_selection_data->end.has_value());
  PaintedSelectionBound end = chunks[3].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  // Coordinates are chunk-relative, so they should start at 0 y coordinate.
  EXPECT_EQ(end.edge_start, gfx::Point(0, 0));
  EXPECT_EQ(end.edge_end, gfx::Point(0, 10));

  // Move the selection around the start and end of the second div.
  local_frame->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position(GetElementById("target")->firstChild(), 0))
          .Extend(Position(GetElementById("target")->firstChild(), 3))
          .Build(),
      SetSelectionOptions());

  // Ensure the handle will be visible for the next paint (previous call to
  // SetSelection will clear the bit).
  local_frame->Selection().SetHandleVisibleForTesting();

  UpdateAllLifecyclePhasesForTest();

  chunks = ContentPaintChunks();
  ASSERT_EQ(chunks.size(), 4u);

  // Skip the root chunk to get to the first div, which should no longer have
  // a recorded value.
  EXPECT_FALSE(chunks[1].layer_selection_data);

  // Validate start/end in second div.
  EXPECT_TRUE(chunks[2].layer_selection_data->start.has_value());
  EXPECT_TRUE(chunks[2].layer_selection_data->end.has_value());
  start = chunks[2].layer_selection_data->start.value();
  EXPECT_EQ(start.type, gfx::SelectionBound::LEFT);
  EXPECT_EQ(start.edge_start, gfx::Point(0, 0));
  EXPECT_EQ(start.edge_end, gfx::Point(0, 10));

  end = chunks[2].layer_selection_data->end.value();
  EXPECT_EQ(end.type, gfx::SelectionBound::RIGHT);
  EXPECT_EQ(end.edge_start, gfx::Point(30, 0));
  EXPECT_EQ(end.edge_end, gfx::Point(30, 10));

  // Third div's chunk should no longer have an end value.
  EXPECT_FALSE(chunks[3].layer_selection_data);
}

}  // namespace blink

"""

```