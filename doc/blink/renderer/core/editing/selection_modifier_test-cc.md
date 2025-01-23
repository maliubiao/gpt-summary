Response:
Let's break down the thought process for analyzing the `selection_modifier_test.cc` file.

1. **Understand the Goal:** The core request is to understand the *purpose* of this test file and its relation to web technologies (JavaScript, HTML, CSS), common errors, and debugging.

2. **Identify the Core Class Under Test:** The filename `selection_modifier_test.cc` and the `#include "third_party/blink/renderer/core/editing/selection_modifier.h"` clearly indicate that this file tests the `SelectionModifier` class.

3. **Infer the `SelectionModifier`'s Functionality:** Based on its name and the included headers (`editing_behavior.h`, `editor.h`, `frame_selection.h`, `visible_position.h`), we can deduce that `SelectionModifier` is responsible for *modifying* the current text selection in the Blink rendering engine. The terms "move," "extend," and the different granularities (character, word, line, etc.) further reinforce this idea.

4. **Analyze the Test Structure:** The file uses the `TEST_F` macro, which is a standard Google Test (gtest) construct. This tells us each `TEST_F` block represents a specific test case for the `SelectionModifier` class.

5. **Examine Individual Test Cases:**  Now, we go through the tests one by one, looking for patterns and specific functionalities being tested.

   * **Basic Movement Tests (`ExtendForwardByWordNone`, `MoveForwardByWordNone`):** These seem to be testing edge cases where no initial selection exists. The comments highlight a past bug fix (crbug.com/832061), suggesting the tests prevent regressions.

   * **Line-Based Movement (`MoveByLineBlockInInline`, `MoveByLineHorizontal`, `MoveByLineMultiColumnSingleText`, `MoveByLineVertical`):** These tests set up specific HTML structures (with `<div>`, `<p>`, `<br>`, CSS styling for layout and writing modes) and then use `MoveForwardByLine` and `MoveBackwardByLine` to verify that the selection moves correctly across lines. This is a key function of text editing.

   * **Handling Hidden Content (`PreviousLineWithDisplayNone`):** This test checks how the selection behaves when encountering elements with `display: none`. It ensures the selection skips over these hidden parts.

   * **Null/Invalid Positions (`PreviousSentenceWithNull`, `StartOfSentenceWithNull`):** These tests seem to be defensive, ensuring the `SelectionModifier` handles cases with invalid or null starting positions gracefully without crashing.

   * **Shadow DOM Interactions (`MoveCaretWithShadow`):** This is a significant test case that deals with how the selection moves *through* and *across* Shadow DOM boundaries. It tests character-by-character, word-by-word, and line-by-line movement. This highlights the engine's ability to handle complex DOM structures.

   * **Object Element (`PreviousParagraphOfObject`):**  This tests selection behavior around `<object>` elements, which can represent embedded content.

   * **Flat Tree and Disconnected Positions (`PositionDisconnectedInFlatTree1`, `PositionDisconnectedInFlatTree2`):** These tests are related to Blink's "flat tree" representation and how selection works when elements are logically present but might be considered "disconnected" in certain contexts (especially with Shadow DOM).

   * **Complex Inline Elements (`OptgroupAndTable`):** This test deals with how the selection interacts with elements like `<optgroup>` and `<table>` that have complex rendering and internal structures (including Shadow DOM for `<optgroup>`).

   * **Editable Video (`EditableVideo`):**  This is another defensive test, checking that basic selection movement operations don't crash when dealing with editable `<video>` elements, even with different editing behaviors.

6. **Identify Connections to Web Technologies:**

   * **HTML:**  The test cases heavily rely on creating and manipulating HTML structures (`<div>`, `<p>`, `<br>`, `<b>`, `<object>`, `<video>`, Shadow DOM elements, etc.). The `SetBodyContent` and `SetSelectionTextToBody` methods are key to setting up the HTML context.
   * **CSS:**  CSS is used to control the layout and rendering of the HTML, directly influencing how "lines," "words," and "paragraphs" are visually determined. Examples include `font`, `padding`, `writing-mode`, `column-count`, `display: none`, `display: block`, `display: inline-table`, and `appearance`.
   * **JavaScript (Indirect):**  While this is a C++ test file, the functionality being tested (text selection) is directly exposed and used by JavaScript through the browser's DOM APIs (e.g., `window.getSelection()`, `document.getSelection()`, `Selection` object methods). The behavior tested here underpins how JavaScript can manipulate selections.

7. **Infer Logical Reasoning (Assumptions and Outputs):**  Each test case has implicit assumptions about how the selection *should* move. We can extract these by looking at the input HTML and the expected output (the final selection). For instance, in `MoveByLineHorizontal`, we assume that a `<br>` tag will define a line break.

8. **Identify Potential User/Programming Errors:**  The tests themselves reveal potential error scenarios:
   * **Incorrectly Handling Empty Selections:** The initial "None" tests highlight the need to avoid crashes when operating on no selection.
   * **Issues with Hidden Content:** The `display: none` test shows a potential error if selection logic naively traverses hidden content.
   * **Problems with Complex DOM Structures:** The Shadow DOM tests demonstrate the complexity of handling selection across shadow boundaries, where naive traversal could lead to incorrect behavior.
   * **Edge Cases with Specific Elements:** The `<object>` and `<video>` tests show the importance of handling different types of HTML elements correctly.

9. **Trace User Operations (Debugging Clues):**  Think about how a user's actions could lead to the execution paths being tested:
   * **Keyboard Navigation:** Arrow keys (up, down, left, right) combined with modifier keys (Shift, Ctrl/Cmd, Alt) directly trigger selection modifications being tested (moving by character, word, line, etc.).
   * **Mouse Dragging:** Selecting text with the mouse also uses the underlying selection mechanisms.
   * **Double-Click/Triple-Click:** These actions select words and paragraphs, respectively, and the tests for word and paragraph granularity are relevant here.
   * **Context Menus and Copy/Paste:** While not directly tested here, the selection mechanism is fundamental to copy/paste functionality.
   * **JavaScript Manipulation:** JavaScript code can programmatically change the selection, and the tested logic is what the browser engine uses to implement those changes.

10. **Structure the Answer:** Finally, organize the information gathered into a clear and structured answer, addressing each part of the original request. Use headings and bullet points for readability. Provide concrete examples for the relationships with JavaScript, HTML, and CSS, and clearly state the assumptions and outputs for the logical reasoning.
This C++ source file, `selection_modifier_test.cc`, is part of the Blink rendering engine, specifically focusing on **testing the `SelectionModifier` class**. The `SelectionModifier` class is responsible for **programmatically modifying the current text selection** in a web page. This includes actions like moving the selection start/end point, extending the selection, and doing so at various granularities (character, word, line, etc.).

Here's a breakdown of its functionalities and relationships:

**Core Functionality:**

* **Testing Selection Modification:** The primary goal is to ensure the `SelectionModifier` class behaves correctly under various conditions. This includes:
    * **Moving the selection:**  Testing movement forward and backward by character, word, line, sentence, and paragraph.
    * **Extending the selection:** Testing how the selection expands in different directions and granularities.
    * **Handling different HTML structures:** Testing selection modification in simple text, nested elements, elements with specific CSS properties (like `display: none`, `writing-mode`, `column-count`), and elements within Shadow DOM.
    * **Edge case handling:** Testing scenarios with no initial selection, null positions, and interactions with specific elements like `<object>` and editable `<video>`.

**Relationship with JavaScript, HTML, and CSS:**

The `SelectionModifier` class is a core part of the browser's editing functionality, which is directly exposed and utilized by JavaScript, influenced by HTML structure, and affected by CSS styling.

* **JavaScript:**
    * **Direct API Usage:** JavaScript can directly interact with the browser's selection through the `window.getSelection()` or `document.getSelection()` APIs. The `SelectionModifier` class provides the underlying logic for operations that JavaScript can trigger. For example, when a user presses the arrow keys while holding Shift, JavaScript might call browser functions that internally use `SelectionModifier` to extend the selection.
    * **Event Handling:** JavaScript event listeners for keyboard events (`keydown`, `keyup`) often trigger actions that lead to selection modifications. The logic within `SelectionModifier` is what executes when these events are handled.
    * **Example:** A JavaScript code snippet like `window.getSelection().modify('move', 'forward', 'word');` would internally rely on logic similar to what's being tested in `selection_modifier_test.cc` with `SelectionModifyAlteration::kMove` and `TextGranularity::kWord`.

* **HTML:**
    * **Document Structure:** The HTML structure of the page heavily influences how selection works. The tests in this file explicitly create various HTML structures using `SetBodyContent` and `InsertStyleElement` to simulate real-world scenarios. For example, tests involving `<br>` tags, `<div>` elements, and Shadow DOM directly test how selection behaves across different HTML boundaries.
    * **Contenteditable Attribute:** The `contenteditable` attribute makes elements editable, and the `SelectionModifier` is crucial for handling selection within these editable regions. The test with `<video contenteditable>` is an example of this.

* **CSS:**
    * **Visual Layout:** CSS properties like `writing-mode`, `column-count`, `display`, and font properties directly impact how text is laid out and how the browser defines "lines," "words," and "paragraphs." The tests use CSS to set up specific visual contexts to ensure selection modification behaves correctly under different layouts. For example, the `MoveByLineHorizontal` and `MoveByLineVertical` tests use `writing-mode` to test line movement in different orientations.
    * **`display: none`:** The `PreviousLineWithDisplayNone` test specifically checks how selection movement behaves around elements that are not visually rendered due to `display: none`.

**Logical Reasoning (Hypothetical Input & Output):**

Let's take the `TEST_F(SelectionModifierTest, MoveByLineHorizontal)` test as an example:

* **Hypothetical Input:**
    * **HTML:** `<p>ab|c<br>d<br><br>ghi</p>` (The `|` represents the cursor position).
    * **Operation:** Call `MoveForwardByLine` on the `SelectionModifier`.
* **Logical Steps within `MoveForwardByLine` (simplified):**
    1. Identify the current selection point.
    2. Determine the next line break based on the HTML structure and CSS layout.
    3. Move the selection point to the beginning of the next line.
* **Expected Output:** `<p>abc<br>d|<br><br>ghi</p>` (The cursor moves to the start of the next line).

Similarly, for `MoveBackwardByLine`, the logic would involve finding the previous line break.

**User or Programming Common Usage Errors:**

* **Incorrectly assuming line breaks:** Programmers might assume that a newline character (`\n`) always creates a line break in HTML. However, in HTML, `<br>` tags or block-level elements typically define line breaks. The tests with `<br>` highlight this.
* **Not considering CSS layout:**  Developers might write JavaScript that manipulates selection based purely on the text content without considering how CSS affects the visual layout. This could lead to unexpected selection behavior, especially with properties like `column-count` or `writing-mode`. The `MoveByLineMultiColumnSingleText` and `MoveByLineVertical` tests address this.
* **Issues with hidden content:**  Trying to programmatically select or move the selection within elements that are hidden using `display: none` might lead to unexpected results if not handled correctly. The `PreviousLineWithDisplayNone` test prevents regressions in this area.
* **Misunderstanding Shadow DOM boundaries:** When working with web components and Shadow DOM, developers need to be aware that the internal structure of a component is encapsulated. Incorrect assumptions about node relationships across Shadow DOM boundaries can lead to selection manipulation errors. The `MoveCaretWithShadow` test ensures that the `SelectionModifier` correctly handles these boundaries.

**User Operation Steps Leading to this Code:**

A user's interaction with a web page that involves text selection would eventually utilize the logic tested in this file. Here's a breakdown of how user actions can lead to the execution paths within `SelectionModifier`:

1. **User Interaction:**
   * **Typing:** When a user types in a `contenteditable` area, the browser needs to manage the insertion point (caret), which is a form of selection.
   * **Mouse Selection:** Dragging the mouse across text to select it directly involves the browser's selection mechanism.
   * **Keyboard Navigation:**
     * **Arrow Keys:** Pressing the left/right arrow keys moves the caret by characters.
     * **Ctrl/Cmd + Arrow Keys:** Moving by words.
     * **Up/Down Arrow Keys:** Moving by lines.
     * **Shift + Arrow Keys:** Extending the selection in the corresponding direction and granularity.
   * **Double-Click/Triple-Click:** Selecting words or paragraphs.
   * **Using the context menu:** Options like "Select All" or actions that involve copying selected text.
   * **Programmatic Selection via JavaScript:** JavaScript code can directly set or modify the selection.

2. **Browser Event Handling:** These user actions trigger events within the browser (e.g., `keydown`, `mouseup`, `mousedown`).

3. **Blink Rendering Engine Processing:** The Blink rendering engine, upon receiving these events, needs to update the selection state. This involves:
   * **Identifying the current selection.**
   * **Determining the desired modification (move, extend, etc.) and granularity (character, word, line, etc.).**
   * **Calling the `SelectionModifier` class to perform the actual modification.**

4. **`SelectionModifier` Execution:**  The `SelectionModifier` class, based on the input parameters (alteration, direction, granularity), manipulates the internal representation of the selection, taking into account the DOM structure, CSS layout, and various edge cases.

5. **Updating the UI:**  Finally, the browser updates the visual representation of the selection on the screen.

**As a debugging clue:** If there's a bug related to text selection in a Chromium-based browser, and you suspect the issue lies in how the selection is being moved or extended, you might look at the `SelectionModifier` class and its tests. By examining the tests, you can understand the expected behavior for different scenarios and potentially identify where the actual behavior deviates. You might then use debugging tools to step through the `SelectionModifier::Modify` method and see how it's handling the specific case that's causing the issue.

### 提示词
```
这是目录为blink/renderer/core/editing/selection_modifier_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/selection_modifier.h"

#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"

namespace blink {

class SelectionModifierTest : public EditingTestBase {
 protected:
  std::string MoveBackwardByLine(SelectionModifier& modifier) {
    modifier.Modify(SelectionModifyAlteration::kMove,
                    SelectionModifyDirection::kBackward,
                    TextGranularity::kLine);
    return GetSelectionTextFromBody(modifier.Selection().AsSelection());
  }

  std::string MoveForwardByLine(SelectionModifier& modifier) {
    modifier.Modify(SelectionModifyAlteration::kMove,
                    SelectionModifyDirection::kForward, TextGranularity::kLine);
    return GetSelectionTextFromBody(modifier.Selection().AsSelection());
  }
};

TEST_F(SelectionModifierTest, ExtendForwardByWordNone) {
  SetBodyContent("abc");
  SelectionModifier modifier(GetFrame(), SelectionInDOMTree());
  modifier.Modify(SelectionModifyAlteration::kExtend,
                  SelectionModifyDirection::kForward, TextGranularity::kWord);
  // We should not crash here. See http://crbug.com/832061
  EXPECT_EQ(SelectionInDOMTree(), modifier.Selection().AsSelection());
}

TEST_F(SelectionModifierTest, MoveForwardByWordNone) {
  SetBodyContent("abc");
  SelectionModifier modifier(GetFrame(), SelectionInDOMTree());
  modifier.Modify(SelectionModifyAlteration::kMove,
                  SelectionModifyDirection::kForward, TextGranularity::kWord);
  // We should not crash here. See http://crbug.com/832061
  EXPECT_EQ(SelectionInDOMTree(), modifier.Selection().AsSelection());
}

// http://crbug.com/1300781
TEST_F(SelectionModifierTest, MoveByLineBlockInInline) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "font: 10px/20px Ahem;"
      "padding: 10px;"
      "writing-mode: horizontal-tb;"
      "}"
      "b { background: orange; }");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<div>ab|c<b><p>ABC</p><p>DEF</p>def</b></div>");
  SelectionModifier modifier(GetFrame(), selection);

  EXPECT_EQ("<div>abc<b><p>AB|C</p><p>DEF</p>def</b></div>",
            MoveForwardByLine(modifier));
  EXPECT_EQ("<div>abc<b><p>ABC</p><p>DE|F</p>def</b></div>",
            MoveForwardByLine(modifier));
  EXPECT_EQ("<div>abc<b><p>ABC</p><p>DEF</p>de|f</b></div>",
            MoveForwardByLine(modifier));

  EXPECT_EQ("<div>abc<b><p>ABC</p><p>DE|F</p>def</b></div>",
            MoveBackwardByLine(modifier));
  EXPECT_EQ("<div>abc<b><p>AB|C</p><p>DEF</p>def</b></div>",
            MoveBackwardByLine(modifier));
  EXPECT_EQ("<div>ab|c<b><p>ABC</p><p>DEF</p>def</b></div>",
            MoveBackwardByLine(modifier));
}

TEST_F(SelectionModifierTest, MoveByLineHorizontal) {
  LoadAhem();
  InsertStyleElement(
      "p {"
      "font: 10px/20px Ahem;"
      "padding: 10px;"
      "writing-mode: horizontal-tb;"
      "}");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<p>ab|c<br>d<br><br>ghi</p>");
  SelectionModifier modifier(GetFrame(), selection);

  EXPECT_EQ("<p>abc<br>d|<br><br>ghi</p>", MoveForwardByLine(modifier));
  EXPECT_EQ("<p>abc<br>d<br>|<br>ghi</p>", MoveForwardByLine(modifier));
  EXPECT_EQ("<p>abc<br>d<br><br>gh|i</p>", MoveForwardByLine(modifier));

  EXPECT_EQ("<p>abc<br>d<br>|<br>ghi</p>", MoveBackwardByLine(modifier));
  EXPECT_EQ("<p>abc<br>d|<br><br>ghi</p>", MoveBackwardByLine(modifier));
  EXPECT_EQ("<p>ab|c<br>d<br><br>ghi</p>", MoveBackwardByLine(modifier));
}

TEST_F(SelectionModifierTest, MoveByLineMultiColumnSingleText) {
  LoadAhem();
  InsertStyleElement(
      "div { font: 10px/15px Ahem; column-count: 3; width: 20ch; }");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<div>|abc def ghi jkl mno pqr</div>");
  // This HTML is rendered as:
  //    abc ghi mno
  //    def jkl pqr
  SelectionModifier modifier(GetFrame(), selection);

  EXPECT_EQ("<div>abc |def ghi jkl mno pqr</div>", MoveForwardByLine(modifier));
  EXPECT_EQ("<div>abc def |ghi jkl mno pqr</div>", MoveForwardByLine(modifier));
  EXPECT_EQ("<div>abc def ghi |jkl mno pqr</div>", MoveForwardByLine(modifier));
  EXPECT_EQ("<div>abc def ghi jkl |mno pqr</div>", MoveForwardByLine(modifier));
  EXPECT_EQ("<div>abc def ghi jkl mno |pqr</div>", MoveForwardByLine(modifier));
  EXPECT_EQ("<div>abc def ghi jkl mno pqr|</div>", MoveForwardByLine(modifier));

  EXPECT_EQ("<div>abc def ghi jkl |mno pqr</div>",
            MoveBackwardByLine(modifier));
  EXPECT_EQ("<div>abc def ghi |jkl mno pqr</div>",
            MoveBackwardByLine(modifier));
  EXPECT_EQ("<div>abc def |ghi jkl mno pqr</div>",
            MoveBackwardByLine(modifier));
  EXPECT_EQ("<div>abc |def ghi jkl mno pqr</div>",
            MoveBackwardByLine(modifier));
  EXPECT_EQ("<div>|abc def ghi jkl mno pqr</div>",
            MoveBackwardByLine(modifier));
}

TEST_F(SelectionModifierTest, MoveByLineVertical) {
  LoadAhem();
  InsertStyleElement(
      "p {"
      "font: 10px/20px Ahem;"
      "padding: 10px;"
      "writing-mode: vertical-rl;"
      "}");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<p>ab|c<br>d<br><br>ghi</p>");
  SelectionModifier modifier(GetFrame(), selection);

  EXPECT_EQ("<p>abc<br>d|<br><br>ghi</p>", MoveForwardByLine(modifier));
  EXPECT_EQ("<p>abc<br>d<br>|<br>ghi</p>", MoveForwardByLine(modifier));
  EXPECT_EQ("<p>abc<br>d<br><br>gh|i</p>", MoveForwardByLine(modifier));

  EXPECT_EQ("<p>abc<br>d<br>|<br>ghi</p>", MoveBackwardByLine(modifier));
  EXPECT_EQ("<p>abc<br>d|<br><br>ghi</p>", MoveBackwardByLine(modifier));
  EXPECT_EQ("<p>ab|c<br>d<br><br>ghi</p>", MoveBackwardByLine(modifier));
}

TEST_F(SelectionModifierTest, PreviousLineWithDisplayNone) {
  InsertStyleElement("body{font-family: monospace}");
  const SelectionInDOMTree selection = SetSelectionTextToBody(
      "<div contenteditable>"
      "<div>foo bar</div>"
      "<div>foo <b style=\"display:none\">qux</b> bar baz|</div>"
      "</div>");
  SelectionModifier modifier(GetFrame(), selection);
  modifier.Modify(SelectionModifyAlteration::kMove,
                  SelectionModifyDirection::kBackward, TextGranularity::kLine);
  EXPECT_EQ(
      "<div contenteditable>"
      "<div>foo bar|</div>"
      "<div>foo <b style=\"display:none\">qux</b> bar baz</div>"
      "</div>",
      GetSelectionTextFromBody(modifier.Selection().AsSelection()));
}

// For http://crbug.com/1104582
TEST_F(SelectionModifierTest, PreviousSentenceWithNull) {
  InsertStyleElement("b {display:inline-block}");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<b><b><a>|</a></b></b>");
  SelectionModifier modifier(GetFrame(), selection);
  // We call |PreviousSentence()| with null-position.
  EXPECT_FALSE(modifier.Modify(SelectionModifyAlteration::kMove,
                               SelectionModifyDirection::kBackward,
                               TextGranularity::kSentence));
}

// For http://crbug.com/1100971
TEST_F(SelectionModifierTest, StartOfSentenceWithNull) {
  InsertStyleElement("b {display:inline-block}");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("|<b><b><a></a></b></b>");
  SelectionModifier modifier(GetFrame(), selection);
  // We call |StartOfSentence()| with null-position.
  EXPECT_FALSE(modifier.Modify(SelectionModifyAlteration::kMove,
                               SelectionModifyDirection::kBackward,
                               TextGranularity::kSentenceBoundary));
}

TEST_F(SelectionModifierTest, MoveCaretWithShadow) {
  const char* body_content =
      "a a"
      "<div id='host'>"
      "<span slot='e'>e e</span>"
      "<span slot='c'>c c</span>"
      "</div>"
      "f f";
  const char* shadow_content =
      "b b"
      "<slot name='c'></slot>"
      "d d"
      "<slot name='e'></slot>";
  LoadAhem();
  InsertStyleElement("body {font-family: Ahem}");
  SetBodyContent(body_content);
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(shadow_content);
  UpdateAllLifecyclePhasesForTest();

  Element* body = GetDocument().body();
  Node* a = body->childNodes()->item(0);
  Node* b = shadow_root.childNodes()->item(0);
  Node* c = host->QuerySelector(AtomicString("[slot=c]"))->firstChild();
  Node* d = shadow_root.childNodes()->item(2);
  Node* e = host->QuerySelector(AtomicString("[slot=e]"))->firstChild();
  Node* f = body->childNodes()->item(2);

  auto makeSelection = [&](Position position) {
    return SelectionInDOMTree::Builder().Collapse(position).Build();
  };
  SelectionModifyAlteration move = SelectionModifyAlteration::kMove;
  SelectionModifyDirection direction;
  TextGranularity granularity;

  {
    // Test moving forward, character by character.
    direction = SelectionModifyDirection::kForward;
    granularity = TextGranularity::kCharacter;
    SelectionModifier modifier(GetFrame(), makeSelection(Position(body, 0)));
    EXPECT_EQ(Position(a, 0), modifier.Selection().Anchor());
    for (Node* node : {a, b, c, d, e, f}) {
      if (node == b || node == f) {
        modifier.Modify(move, direction, granularity);
        EXPECT_EQ(node == b ? Position::BeforeNode(*node) : Position(node, 0),
                  modifier.Selection().Anchor());
      }
      modifier.Modify(move, direction, granularity);
      EXPECT_EQ(Position(node, 1), modifier.Selection().Anchor());
      modifier.Modify(move, direction, granularity);
      EXPECT_EQ(Position(node, 2), modifier.Selection().Anchor());
      modifier.Modify(move, direction, granularity);
      EXPECT_EQ(Position(node, 3), modifier.Selection().Anchor());
    }
  }
  {
    // Test moving backward, character by character.
    direction = SelectionModifyDirection::kBackward;
    granularity = TextGranularity::kCharacter;
    SelectionModifier modifier(GetFrame(), makeSelection(Position(body, 3)));
    for (Node* node : {f, e, d, c, b, a}) {
      EXPECT_EQ(Position(node, 3), modifier.Selection().Anchor());
      modifier.Modify(move, direction, granularity);
      EXPECT_EQ(Position(node, 2), modifier.Selection().Anchor());
      modifier.Modify(move, direction, granularity);
      EXPECT_EQ(Position(node, 1), modifier.Selection().Anchor());
      modifier.Modify(move, direction, granularity);
      if (node == f || node == b) {
        EXPECT_EQ(node == b ? Position::BeforeNode(*node) : Position(node, 0),
                  modifier.Selection().Anchor());
        modifier.Modify(move, direction, granularity);
      }
    }
    EXPECT_EQ(Position(a, 0), modifier.Selection().Anchor());
  }
  {
    // Test moving forward, word by word.
    direction = SelectionModifyDirection::kForward;
    granularity = TextGranularity::kWord;
    bool skip_space =
        GetFrame().GetEditor().Behavior().ShouldSkipSpaceWhenMovingRight();
    SelectionModifier modifier(GetFrame(), makeSelection(Position(body, 0)));
    EXPECT_EQ(Position(a, 0), modifier.Selection().Anchor());
    for (Node* node : {a, b, c, d, e, f}) {
      if (node == b || node == f) {
        modifier.Modify(move, direction, granularity);
        EXPECT_EQ(node == b ? Position::BeforeNode(*node) : Position(node, 0),
                  modifier.Selection().Anchor());
      }
      modifier.Modify(move, direction, granularity);
      EXPECT_EQ(Position(node, skip_space ? 2 : 1),
                modifier.Selection().Anchor());
      if (node == a || node == e || node == f) {
        modifier.Modify(move, direction, granularity);
        EXPECT_EQ(Position(node, 3), modifier.Selection().Anchor());
      }
    }
  }
  {
    // Test moving backward, word by word.
    direction = SelectionModifyDirection::kBackward;
    granularity = TextGranularity::kWord;
    SelectionModifier modifier(GetFrame(), makeSelection(Position(body, 3)));
    for (Node* node : {f, e, d, c, b, a}) {
      if (node == f || node == e || node == a) {
        EXPECT_EQ(Position(node, 3), modifier.Selection().Anchor());
        modifier.Modify(move, direction, granularity);
      }
      EXPECT_EQ(Position(node, 2), modifier.Selection().Anchor());
      modifier.Modify(move, direction, granularity);
      if (node == f || node == b) {
        EXPECT_EQ(node == b ? Position::BeforeNode(*node) : Position(node, 0),
                  modifier.Selection().Anchor());
        modifier.Modify(move, direction, granularity);
      }
    }
    EXPECT_EQ(Position(a, 0), modifier.Selection().Anchor());
  }

  // Place the contents into different lines
  InsertStyleElement("span {display: block}");
  UpdateAllLifecyclePhasesForTest();

  {
    // Test moving forward, line by line.
    direction = SelectionModifyDirection::kForward;
    granularity = TextGranularity::kLine;
    for (int i = 0; i <= 3; ++i) {
      SelectionModifier modifier(GetFrame(), makeSelection(Position(a, i)));
      for (Node* node : {a, b, c, d, e, f}) {
        EXPECT_EQ(i == 0 && node == b ? Position::BeforeNode(*node)
                                      : Position(node, i),
                  modifier.Selection().Anchor());
        modifier.Modify(move, direction, granularity);
      }
      EXPECT_EQ(Position(f, 3), modifier.Selection().Anchor());
    }
  }
  {
    // Test moving backward, line by line.
    direction = SelectionModifyDirection::kBackward;
    granularity = TextGranularity::kLine;
    for (int i = 0; i <= 3; ++i) {
      SelectionModifier modifier(GetFrame(), makeSelection(Position(f, i)));
      for (Node* node : {f, e, d, c, b, a}) {
        EXPECT_EQ(i == 0 && node == b ? Position::BeforeNode(*node)
                                      : Position(node, i),
                  modifier.Selection().Anchor());
        modifier.Modify(move, direction, granularity);
      }
      EXPECT_EQ(Position(a, 0), modifier.Selection().Anchor());
    }
  }
}

// For https://crbug.com/1155342 and https://crbug.com/1155309
TEST_F(SelectionModifierTest, PreviousParagraphOfObject) {
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<object>|</object>");
  SelectionModifier modifier(GetFrame(), selection);
  modifier.Modify(SelectionModifyAlteration::kMove,
                  SelectionModifyDirection::kBackward,
                  TextGranularity::kParagraph);
  EXPECT_EQ("|<object></object>",
            GetSelectionTextFromBody(modifier.Selection().AsSelection()));
}

// For https://crbug.com/1177295
TEST_F(SelectionModifierTest, PositionDisconnectedInFlatTree1) {
  const SelectionInDOMTree selection = SetSelectionTextToBody(
      "<div id=a><div id=b><div id=c>^x|</div></div></div>");
  SetShadowContent("", "a");
  SetShadowContent("", "b");
  SetShadowContent("", "c");
  SelectionModifier modifier(GetFrame(), selection);
  modifier.Modify(SelectionModifyAlteration::kMove,
                  SelectionModifyDirection::kBackward,
                  TextGranularity::kParagraph);
  EXPECT_EQ("<div id=\"a\"><div id=\"b\"><div id=\"c\">x</div></div></div>",
            GetSelectionTextFromBody(modifier.Selection().AsSelection()));
}

// For https://crbug.com/1177295
TEST_F(SelectionModifierTest, PositionDisconnectedInFlatTree2) {
  SetBodyContent("<div id=host>x</div>y");
  SetShadowContent("", "host");
  Element* host = GetElementById("host");
  Node* text = host->firstChild();
  Position positions[] = {
      Position::BeforeNode(*host),         Position::FirstPositionInNode(*host),
      Position::LastPositionInNode(*host), Position::AfterNode(*host),
      Position::BeforeNode(*text),         Position::FirstPositionInNode(*text),
      Position::LastPositionInNode(*text), Position::AfterNode(*text)};
  for (const Position& anchor : positions) {
    EXPECT_TRUE(anchor.IsConnected());
    bool flat_anchor_is_connected = ToPositionInFlatTree(anchor).IsConnected();
    EXPECT_EQ(anchor.AnchorNode() == host, flat_anchor_is_connected);
    for (const Position& focus : positions) {
      const SelectionInDOMTree& selection =
          SelectionInDOMTree::Builder().SetBaseAndExtent(anchor, focus).Build();
      Selection().SetSelection(selection, SetSelectionOptions());
      SelectionModifier modifier(GetFrame(), selection);
      modifier.Modify(SelectionModifyAlteration::kExtend,
                      SelectionModifyDirection::kForward,
                      TextGranularity::kParagraph);
      EXPECT_TRUE(focus.IsConnected());
      bool flat_focus_is_connected =
          ToPositionInFlatTree(selection.Focus()).IsConnected();
      EXPECT_EQ(flat_anchor_is_connected || flat_focus_is_connected
                    ? "<div id=\"host\">x</div>^y|"
                    : "<div id=\"host\">x</div>y",
                GetSelectionTextFromBody(modifier.Selection().AsSelection()));
    }
  }
}

// For https://crbug.com/1312704
TEST_F(SelectionModifierTest, OptgroupAndTable) {
  InsertStyleElement(
      "optgroup, table { display: inline-table; }"
      "table { appearance:button; }");
  SelectionModifier modifier(
      GetFrame(), SetSelectionTextToBody(
                      "<optgroup>^</optgroup>|<table><td></td></table>"));
  EXPECT_TRUE(modifier.Modify(SelectionModifyAlteration::kExtend,
                              SelectionModifyDirection::kForward,
                              TextGranularity::kLine));

  const SelectionInDOMTree& selection = modifier.Selection().AsSelection();
  EXPECT_EQ(
      "<optgroup></optgroup><table><tbody><tr><td></td></tr></tbody></table>",
      GetSelectionTextFromBody(selection));

  Element* optgroup = GetDocument().QuerySelector(AtomicString("optgroup"));
  ShadowRoot* shadow_root = optgroup->GetShadowRoot();
  Element* label =
      shadow_root->getElementById(shadow_element_names::kIdOptGroupLabel);
  EXPECT_EQ(Position(label, 0), selection.Anchor());
  EXPECT_EQ(Position(shadow_root, 1), selection.Focus());
}

TEST_F(SelectionModifierTest, EditableVideo) {
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("a^<video contenteditable> </video>|");
  GetFrame().GetSettings()->SetEditingBehaviorType(
      mojom::EditingBehavior::kEditingUnixBehavior);
  for (SelectionModifyDirection direction :
       {SelectionModifyDirection::kBackward, SelectionModifyDirection::kForward,
        SelectionModifyDirection::kLeft, SelectionModifyDirection::kRight}) {
    for (TextGranularity granularity :
         {TextGranularity::kCharacter, TextGranularity::kWord,
          TextGranularity::kSentence, TextGranularity::kLine,
          TextGranularity::kParagraph, TextGranularity::kSentenceBoundary,
          TextGranularity::kLineBoundary, TextGranularity::kParagraphBoundary,
          TextGranularity::kDocumentBoundary}) {
      SelectionModifier modifier(GetFrame(), selection);
      // We should not crash here. See http://crbug.com/1376218
      modifier.Modify(SelectionModifyAlteration::kMove, direction, granularity);
      EXPECT_EQ("a|<video contenteditable> </video>",
                GetSelectionTextFromBody(modifier.Selection().AsSelection()))
          << "Direction " << (int)direction << ", granularity "
          << (int)granularity;
      ;
    }
  }
}

}  // namespace blink
```