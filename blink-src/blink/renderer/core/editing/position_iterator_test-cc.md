Response:
My thought process for analyzing the provided code and generating the response goes like this:

1. **Understand the Core Purpose:** The file name `position_iterator_test.cc` immediately tells me this is a test file for something related to "position iterator". The presence of `#include "third_party/blink/renderer/core/editing/position_iterator.h"` confirms this. The "editing" directory suggests it's related to text editing functionality within the browser.

2. **Identify Key Classes and Concepts:**  I scan the `#include` directives and the code itself to pick out the important classes:
    * `PositionIterator` (from the header, and used in the test class name and logic)
    * `Position` (and its template variants like `PositionInFlatTree`)
    * `Text`, `HTMLInputElement`, `HTMLSelectElement`, `HTMLObjectElement` (DOM elements involved in the tests)
    * `EditingTestBase` (the base class for the tests, providing setup and utility functions)
    * `FlatTreeTraversal` (related to how the DOM tree is traversed)
    * The `ScanBackward` and `ScanForward` methods are clearly central to what's being tested.

3. **Analyze the Test Structure:**  I see a class `PositionIteratorTest` inheriting from `EditingTestBase`. This is the standard structure for Blink unit tests. The `protected` methods `ScanBackward` and `ScanForward` (and their `InFlatTree` variants) are helper functions that drive the iteration and collect the results. The `ToString` helper method formats the output for easy comparison. The `TEST_F` macros indicate individual test cases.

4. **Deconstruct the `ScanBackward`/`ScanForward` Logic:**  These methods create a `PositionIteratorAlgorithm` object and then iterate either backward or forward. Inside the loop, `ToString` is called to capture the state of the iterator at each step. This tells me the tests are about verifying the sequence of positions visited by the iterator.

5. **Examine the `ToString` Function:** This is crucial for understanding the test output. It outputs information about:
    * Whether the iterator is at the start/end of the document or the current node.
    * The current node being visited.
    * The offset within a text node or the before/after state for other nodes.
    * The "canonical" `ComputePosition()` and a "deprecated" `DeprecatedComputePosition()`. This suggests there might be some historical reasons or different ways of calculating positions.

6. **Study the Test Cases:**  Each `TEST_F` function sets up a specific HTML structure using `SetBodyContent` and then calls `ScanBackward` (or `ScanBackwardInFlatTree`) with a particular starting position. The `EXPECT_THAT` macro compares the output of the scan with an expected sequence of strings. This is where I see the specific scenarios being tested, like iterating through input elements, object elements, select elements, and various DOM structures with text, comments, and different element types.

7. **Infer Functionality (High-Level):** Based on the above, I can conclude that `position_iterator_test.cc` tests the correctness of the `PositionIterator` class. This class is responsible for traversing the DOM tree in a specific order, both forwards and backwards, starting from a given position. It needs to handle different types of DOM nodes and edge cases correctly.

8. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The tests heavily use HTML elements. The `PositionIterator` is crucial for implementing editing features that manipulate the HTML structure.
    * **JavaScript:** JavaScript code running in a browser often interacts with the DOM. Features like `document.getSelection()` and manual DOM manipulation rely on accurate position information, which the `PositionIterator` helps provide.
    * **CSS:** While not directly manipulated by the `PositionIterator`, CSS styling influences the layout and rendering of the DOM, which can indirectly affect how users perceive and interact with the text, thus making the accurate positioning important for user experience. For instance, line breaks and whitespace handling (like in the "DecrementWithCollapsedSpace" test) can be affected by CSS and need to be handled correctly by the iterator.

9. **Deduce Logic and Examples:** The tests themselves provide concrete examples of input and expected output. I can use these to illustrate the behavior of the iterator in different scenarios. For example, the tests with `<input>` and `<select>` elements show how the iterator steps into and out of these special elements.

10. **Identify Potential Errors:** By looking at the different test cases, I can infer potential errors developers might make when using or implementing similar logic:
    * Incorrectly handling boundaries of nodes (start/end).
    * Failing to account for different node types (text, elements, comments, etc.).
    * Issues with flat tree traversal versus the regular DOM tree.
    * Incorrectly calculating offsets within text nodes.

11. **Trace User Actions:** I consider how a user might trigger the code being tested. Any text editing action (typing, deleting, selecting) ultimately relies on the browser's ability to understand and manipulate positions within the DOM. Therefore, the `PositionIterator` is a foundational component for these user interactions.

12. **Synthesize the Summary:** Finally, I combine all the information gathered into a concise summary of the file's functionality. I highlight the key aspects: testing the `PositionIterator`, its role in text editing, and the types of scenarios covered by the tests.

By following these steps, I can systematically analyze the code and generate a comprehensive and informative response that addresses all aspects of the prompt.
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/position_iterator.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"

namespace blink {

using ::testing::ElementsAre;

class PositionIteratorTest : public EditingTestBase {
 protected:
  std::vector<std::string> ScanBackward(const char* selection_text) {
    return ScanBackward(SetCaretTextToBody(selection_text));
  }

  std::vector<std::string> ScanBackwardInFlatTree(const char* selection_text) {
    return ScanBackward(
        ToPositionInFlatTree(SetCaretTextToBody(selection_text)));
  }

  std::vector<std::string> ScanForward(const char* selection_text) {
    return ScanForward(SetCaretTextToBody(selection_text));
  }

  std::vector<std::string> ScanForwardInFlatTree(const char* selection_text) {
    return ScanForward(
        ToPositionInFlatTree(SetCaretTextToBody(selection_text)));
  }

  template <typename Strategy>
  std::vector<std::string> ScanBackward(
      const PositionTemplate<Strategy>& start) {
    std::vector<std::string> positions;
    for (PositionIteratorAlgorithm<Strategy> it(start); !it.AtStart();
         it.Decrement()) {
      positions.push_back(ToString(it));
    }
    return positions;
  }

  template <typename Strategy>
  std::vector<std::string> ScanForward(
      const PositionTemplate<Strategy>& start) {
    std::vector<std::string> positions;
    for (PositionIteratorAlgorithm<Strategy> it(start); !it.AtEnd();
         it.Increment()) {
      positions.push_back(ToString(it));
    }
    return positions;
  }

 private:
  template <typename Strategy>
  static std::string ToString(const PositionIteratorAlgorithm<Strategy>& it) {
    const PositionTemplate<Strategy> position1 = it.ComputePosition();
    const PositionTemplate<Strategy> position2 = it.DeprecatedComputePosition();
    std::ostringstream os;
    os << (it.AtStart() ? "S" : "-") << (it.AtStartOfNode() ? "S" : "-")
       << (it.AtEnd() ? "E" : "-") << (it.AtEndOfNode() ? "E" : "-") << " "
       << it.GetNode();
    if (IsA<Text>(it.GetNode())) {
      os << "@" << it.OffsetInTextNode();
    } else if (EditingIgnoresContent(*it.GetNode())) {
      os << "@" << (it.AtStartOfNode() ? "0" : "1");
    }
    os << " " << position1;
    if (position1 != position2)
      os << " " << position2;
    return os.str();
  }
};

TEST_F(PositionIteratorTest, DecrementFromInputElementAfterChildren) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::LastPositionInNode(input_element)),
      ElementsAre("---E INPUT@1 INPUT@afterAnchor",
                  // Note: `DeprecatedComputePosition()` should return
                  // `INPUT@beforeAnchor`.
                  "-S-E INPUT@0 INPUT@beforeAnchor INPUT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementAfterNode) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::AfterNode(input_element)),
      ElementsAre("---E INPUT@1 INPUT@afterAnchor",
                  // Note: `DeprecatedComputePosition()` should return
                  // `INPUT@beforeAnchor`.
                  "-S-E INPUT@0 INPUT@beforeAnchor INPUT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementBeforeNode) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::BeforeNode(input_element)),
      ElementsAre("-S-- INPUT@0 INPUT@offsetInAnchor[0] INPUT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementInnerEditorAfterNode) {
  // FlatTree is "ABC" <input><div>"123"</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  // `PositionIterator` stops at `<input>`.
  EXPECT_THAT(
      ScanBackward(
          PositionInFlatTree::AfterNode(*input_element.InnerEditorElement())),
      ElementsAre("---E DIV (editable) DIV (editable)@afterChildren",
                  "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
                  "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
                  "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
                  "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
                  "-S-- DIV (editable) DIV (editable)@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementOffset0) {
  // FlatTree is "ABC" <input><div>"123"</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(input_element, 0)),
      ElementsAre("-S-- INPUT@0 INPUT@offsetInAnchor[0] INPUT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementOffset1) {
  // FlatTree is "ABC" <input><div>"123"</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(input_element, 1)),
      ElementsAre("---E INPUT@1 INPUT@afterAnchor",
                  // Note: `DeprecatedComputePosition()` should return
                  // `INPUT@beforeAnchor`.
                  "-S-E INPUT@0 INPUT@beforeAnchor INPUT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementAfterChildren) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::LastPositionInNode(object_element)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementAfterNode) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::AfterNode(object_element)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementBeforeNode) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::BeforeNode(object_element)),
      ElementsAre("-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementOffset0) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(object_element, 0)),
      ElementsAre("-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementOffset1) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(object_element, 1)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementAfterChildren) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  for (const Node* node = &select_element; node;
       node = FlatTreeTraversal::Next(*node))
    DVLOG(0) << node << " " << FlatTreeTraversal::Parent(*node);
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::LastPositionInNode(select_element)),
      ElementsAre("---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "-S-E SELECT@0 SELECT@beforeAnchor SELECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementAfterNode) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::AfterNode(select_element)),
      ElementsAre("---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "-S-E SELECT@0 SELECT@beforeAnchor SELECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementBeforeNode) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::BeforeNode(select_element)),
      ElementsAre("-S-- SELECT@0 SELECT@offsetInAnchor[0] SELECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementOffset0) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(select_element, 0)),
      ElementsAre("-S-- SELECT@0 SELECT@offsetInAnchor[0] SELECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementOffset1) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(select_element, 1)),
      ElementsAre("---- SELECT@1 SELECT@offsetInAnchor[1] SELECT@beforeAnchor",
                  "---E DIV DIV@afterChildren",
                  "-S-E #text \"\"@0 #text \"\"@offsetInAnchor[0]",
                  "-S-- DIV DIV@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithBrInOption) {
  const char* selection_text = "<option><br></option>|";

  // `<br>` is not associated to `LayoutObject`.
  EXPECT_THAT(ScanBackward(selection_text),
              ElementsAre("---E BODY BODY@afterChildren",
                          "---E OPTION OPTION@afterChildren",
                          "---E BR@1 BR@afterAnchor",
                          "-S-- OPTION OPTION@offsetInAnchor[0]",
                          "-S-- BODY BODY@offsetInAnchor[0]",
                          "---- HTML HTML@offsetInAnchor[1]",
                          "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                          "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithCollapsedSpace) {
  const char* selection_text = "<p> abc </p>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre("---E BODY BODY@afterChildren", "---E P P@afterChildren",
                  "---E #text \" abc \"@5 #text \" abc \"@offsetInAnchor[5]",
                  "---- #text \" abc \"@4 #text \" abc \"@offsetInAnchor[4]",
                  "---- #text \" abc \"@3 #text \" abc \"@offsetInAnchor[3]",
                  "---- #text \" abc \"@2 #text \" abc \"@offsetInAnchor[2]",
                  "---- #text \" abc \"@1 #text \" abc \"@offsetInAnchor[1]",
                  "-S-- #text \" abc \"@0 #text \" abc \"@offsetInAnchor[0]",
                  "-S-- P P@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithCommentEmpty) {
  const char* selection_text = "<p>a<br>b<br><!----><br>c</p>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre("---E BODY BODY@afterChildren", "---E P P@afterChildren",
                  "---E #text \"c\"@1 #text \"c\"@offsetInAnchor[1]",
                  "-S-- #text \"c\"@0 #text \"c\"@offsetInAnchor[0]",
                  "---- P P@offsetInAnchor[6]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[5]",
                  // Empty comment returns true for `AtStartNode()` and
                  // `AtEndOfNode()`.
                  "-S-E #comment@0 #comment@beforeAnchor",
                  "---- P P@offsetInAnchor[4]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[3]",
                  "---E #text \"b\"@1 #text \"b\"@offsetInAnchor[1]",
                  "-S-- #text \"b\"@0 #text \"b\"@offsetInAnchor[0]",
                  "---- P P@offsetInAnchor[2]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[1]",
                  "---E #text \"a\"@1 #text \"a\"@offsetInAnchor[1]",
                  "-S-- #text \"a\"@0 #text \"a\"@offsetInAnchor[0]",
                  "-S-- P P@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-
Prompt: 
```
这是目录为blink/renderer/core/editing/position_iterator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/position_iterator.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"

namespace blink {

using ::testing::ElementsAre;

class PositionIteratorTest : public EditingTestBase {
 protected:
  std::vector<std::string> ScanBackward(const char* selection_text) {
    return ScanBackward(SetCaretTextToBody(selection_text));
  }

  std::vector<std::string> ScanBackwardInFlatTree(const char* selection_text) {
    return ScanBackward(
        ToPositionInFlatTree(SetCaretTextToBody(selection_text)));
  }

  std::vector<std::string> ScanForward(const char* selection_text) {
    return ScanForward(SetCaretTextToBody(selection_text));
  }

  std::vector<std::string> ScanForwardInFlatTree(const char* selection_text) {
    return ScanForward(
        ToPositionInFlatTree(SetCaretTextToBody(selection_text)));
  }

  template <typename Strategy>
  std::vector<std::string> ScanBackward(
      const PositionTemplate<Strategy>& start) {
    std::vector<std::string> positions;
    for (PositionIteratorAlgorithm<Strategy> it(start); !it.AtStart();
         it.Decrement()) {
      positions.push_back(ToString(it));
    }
    return positions;
  }

  template <typename Strategy>
  std::vector<std::string> ScanForward(
      const PositionTemplate<Strategy>& start) {
    std::vector<std::string> positions;
    for (PositionIteratorAlgorithm<Strategy> it(start); !it.AtEnd();
         it.Increment()) {
      positions.push_back(ToString(it));
    }
    return positions;
  }

 private:
  template <typename Strategy>
  static std::string ToString(const PositionIteratorAlgorithm<Strategy>& it) {
    const PositionTemplate<Strategy> position1 = it.ComputePosition();
    const PositionTemplate<Strategy> position2 = it.DeprecatedComputePosition();
    std::ostringstream os;
    os << (it.AtStart() ? "S" : "-") << (it.AtStartOfNode() ? "S" : "-")
       << (it.AtEnd() ? "E" : "-") << (it.AtEndOfNode() ? "E" : "-") << " "
       << it.GetNode();
    if (IsA<Text>(it.GetNode())) {
      os << "@" << it.OffsetInTextNode();
    } else if (EditingIgnoresContent(*it.GetNode())) {
      os << "@" << (it.AtStartOfNode() ? "0" : "1");
    }
    os << " " << position1;
    if (position1 != position2)
      os << " " << position2;
    return os.str();
  }
};

TEST_F(PositionIteratorTest, DecrementFromInputElementAfterChildren) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::LastPositionInNode(input_element)),
      ElementsAre("---E INPUT@1 INPUT@afterAnchor",
                  // Note: `DeprecatedComputePosition()` should return
                  // `INPUT@beforeAnchor`.
                  "-S-E INPUT@0 INPUT@beforeAnchor INPUT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementAfterNode) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::AfterNode(input_element)),
      ElementsAre("---E INPUT@1 INPUT@afterAnchor",
                  // Note: `DeprecatedComputePosition()` should return
                  // `INPUT@beforeAnchor`.
                  "-S-E INPUT@0 INPUT@beforeAnchor INPUT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementBeforeNode) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::BeforeNode(input_element)),
      ElementsAre("-S-- INPUT@0 INPUT@offsetInAnchor[0] INPUT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementInnerEditorAfterNode) {
  // FlatTree is "ABC" <input><div>"123"</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  // `PositionIterator` stops at `<input>`.
  EXPECT_THAT(
      ScanBackward(
          PositionInFlatTree::AfterNode(*input_element.InnerEditorElement())),
      ElementsAre("---E DIV (editable) DIV (editable)@afterChildren",
                  "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
                  "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
                  "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
                  "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
                  "-S-- DIV (editable) DIV (editable)@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementOffset0) {
  // FlatTree is "ABC" <input><div>"123"</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(input_element, 0)),
      ElementsAre("-S-- INPUT@0 INPUT@offsetInAnchor[0] INPUT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromInInputElementOffset1) {
  // FlatTree is "ABC" <input><div>"123"</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(input_element, 1)),
      ElementsAre("---E INPUT@1 INPUT@afterAnchor",
                  // Note: `DeprecatedComputePosition()` should return
                  // `INPUT@beforeAnchor`.
                  "-S-E INPUT@0 INPUT@beforeAnchor INPUT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementAfterChildren) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::LastPositionInNode(object_element)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementAfterNode) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::AfterNode(object_element)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementBeforeNode) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::BeforeNode(object_element)),
      ElementsAre("-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementOffset0) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(object_element, 0)),
      ElementsAre("-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromObjectElementOffset1) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(object_element, 1)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementAfterChildren) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  for (const Node* node = &select_element; node;
       node = FlatTreeTraversal::Next(*node))
    DVLOG(0) << node << " " << FlatTreeTraversal::Parent(*node);
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::LastPositionInNode(select_element)),
      ElementsAre("---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "-S-E SELECT@0 SELECT@beforeAnchor SELECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementAfterNode) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::AfterNode(select_element)),
      ElementsAre("---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "---E SELECT@1 SELECT@afterAnchor",
                  "-S-E SELECT@0 SELECT@beforeAnchor SELECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementBeforeNode) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree::BeforeNode(select_element)),
      ElementsAre("-S-- SELECT@0 SELECT@offsetInAnchor[0] SELECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementOffset0) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(select_element, 0)),
      ElementsAre("-S-- SELECT@0 SELECT@offsetInAnchor[0] SELECT@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementFromSelectElementOffset1) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanBackward(PositionInFlatTree(select_element, 1)),
      ElementsAre("---- SELECT@1 SELECT@offsetInAnchor[1] SELECT@beforeAnchor",
                  "---E DIV DIV@afterChildren",
                  "-S-E #text \"\"@0 #text \"\"@offsetInAnchor[0]",
                  "-S-- DIV DIV@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithBrInOption) {
  const char* selection_text = "<option><br></option>|";

  // `<br>` is not associated to `LayoutObject`.
  EXPECT_THAT(ScanBackward(selection_text),
              ElementsAre("---E BODY BODY@afterChildren",
                          "---E OPTION OPTION@afterChildren",
                          "---E BR@1 BR@afterAnchor",
                          "-S-- OPTION OPTION@offsetInAnchor[0]",
                          "-S-- BODY BODY@offsetInAnchor[0]",
                          "---- HTML HTML@offsetInAnchor[1]",
                          "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                          "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithCollapsedSpace) {
  const char* selection_text = "<p> abc </p>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre("---E BODY BODY@afterChildren", "---E P P@afterChildren",
                  "---E #text \" abc \"@5 #text \" abc \"@offsetInAnchor[5]",
                  "---- #text \" abc \"@4 #text \" abc \"@offsetInAnchor[4]",
                  "---- #text \" abc \"@3 #text \" abc \"@offsetInAnchor[3]",
                  "---- #text \" abc \"@2 #text \" abc \"@offsetInAnchor[2]",
                  "---- #text \" abc \"@1 #text \" abc \"@offsetInAnchor[1]",
                  "-S-- #text \" abc \"@0 #text \" abc \"@offsetInAnchor[0]",
                  "-S-- P P@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithCommentEmpty) {
  const char* selection_text = "<p>a<br>b<br><!----><br>c</p>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre("---E BODY BODY@afterChildren", "---E P P@afterChildren",
                  "---E #text \"c\"@1 #text \"c\"@offsetInAnchor[1]",
                  "-S-- #text \"c\"@0 #text \"c\"@offsetInAnchor[0]",
                  "---- P P@offsetInAnchor[6]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[5]",
                  // Empty comment returns true for `AtStartNode()` and
                  // `AtEndOfNode()`.
                  "-S-E #comment@0 #comment@beforeAnchor",
                  "---- P P@offsetInAnchor[4]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[3]",
                  "---E #text \"b\"@1 #text \"b\"@offsetInAnchor[1]",
                  "-S-- #text \"b\"@0 #text \"b\"@offsetInAnchor[0]",
                  "---- P P@offsetInAnchor[2]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[1]",
                  "---E #text \"a\"@1 #text \"a\"@offsetInAnchor[1]",
                  "-S-- #text \"a\"@0 #text \"a\"@offsetInAnchor[0]",
                  "-S-- P P@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithCommentNotEmpty) {
  const char* selection_text = "<p>a<br>b<br><!--XYZ--><br>c</p>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre("---E BODY BODY@afterChildren", "---E P P@afterChildren",
                  "---E #text \"c\"@1 #text \"c\"@offsetInAnchor[1]",
                  "-S-- #text \"c\"@0 #text \"c\"@offsetInAnchor[0]",
                  "---- P P@offsetInAnchor[6]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[5]",
                  // Not-empty comment returns true for `AtEndOfNode()`.
                  "---E #comment@1 #comment@afterAnchor",
                  "---- P P@offsetInAnchor[4]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[3]",
                  "---E #text \"b\"@1 #text \"b\"@offsetInAnchor[1]",
                  "-S-- #text \"b\"@0 #text \"b\"@offsetInAnchor[0]",
                  "---- P P@offsetInAnchor[2]", "---E BR@1 BR@afterAnchor",
                  "-S-- BR@0 BR@beforeAnchor", "---- P P@offsetInAnchor[1]",
                  "---E #text \"a\"@1 #text \"a\"@offsetInAnchor[1]",
                  "-S-- #text \"a\"@0 #text \"a\"@offsetInAnchor[0]",
                  "-S-- P P@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithInlineElemnt) {
  const char* selection_text = "<p><a><b>ABC</b></a><i><s>DEF</s></i></p>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre("---E BODY BODY@afterChildren", "---E P P@afterChildren",
                  "---E I I@afterChildren", "---E S S@afterChildren",
                  "---E #text \"DEF\"@3 #text \"DEF\"@offsetInAnchor[3]",
                  "---- #text \"DEF\"@2 #text \"DEF\"@offsetInAnchor[2]",
                  "---- #text \"DEF\"@1 #text \"DEF\"@offsetInAnchor[1]",
                  "-S-- #text \"DEF\"@0 #text \"DEF\"@offsetInAnchor[0]",
                  "-S-- S S@offsetInAnchor[0]", "-S-- I I@offsetInAnchor[0]",
                  "---- P P@offsetInAnchor[1]", "---E A A@afterChildren",
                  "---E B B@afterChildren",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "-S-- B B@offsetInAnchor[0]", "-S-- A A@offsetInAnchor[0]",
                  "-S-- P P@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));
}

// For http://crbug.com/695317
TEST_F(PositionIteratorTest, decrementWithInputElement) {
  const char* const selection_text = "123<input id=target value='abc'>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre("---E BODY BODY@afterChildren",
                  "---E INPUT id=\"target\"@1 INPUT id=\"target\"@afterAnchor",
                  "-S-- INPUT id=\"target\"@0 INPUT id=\"target\"@beforeAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
                  "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
                  "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
                  "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
                  "-S-- BODY BODY@offsetInAnchor[0]",
                  "---- HTML HTML@offsetInAnchor[1]",
                  "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
                  "-S-- HTML HTML@offsetInAnchor[0]"));

  EXPECT_THAT(
      ScanBackwardInFlatTree(selection_text),
      ElementsAre(
          "---E BODY BODY@afterChildren",
          "---E INPUT id=\"target\"@1 INPUT id=\"target\"@afterAnchor",
          "-S-E INPUT id=\"target\"@0 INPUT id=\"target\"@beforeAnchor INPUT "
          "id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
          "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
          "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
          "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
          "-S-- BODY BODY@offsetInAnchor[0]",
          "---- HTML HTML@offsetInAnchor[1]",
          "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
          "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, DecrementWithNoChildren) {
  const char* const selection_text = "abc<br>def<img><br>|";
  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre(
          "---E BODY BODY@afterChildren", "---E BR@1 BR@afterAnchor",
          "-S-- BR@0 BR@beforeAnchor", "---- BODY BODY@offsetInAnchor[4]",
          "---E IMG@1 IMG@afterAnchor", "-S-- IMG@0 IMG@beforeAnchor",
          "---- BODY BODY@offsetInAnchor[3]",
          "---E #text \"def\"@3 #text \"def\"@offsetInAnchor[3]",
          "---- #text \"def\"@2 #text \"def\"@offsetInAnchor[2]",
          "---- #text \"def\"@1 #text \"def\"@offsetInAnchor[1]",
          "-S-- #text \"def\"@0 #text \"def\"@offsetInAnchor[0]",
          "---- BODY BODY@offsetInAnchor[2]", "---E BR@1 BR@afterAnchor",
          "-S-- BR@0 BR@beforeAnchor", "---- BODY BODY@offsetInAnchor[1]",
          "---E #text \"abc\"@3 #text \"abc\"@offsetInAnchor[3]",
          "---- #text \"abc\"@2 #text \"abc\"@offsetInAnchor[2]",
          "---- #text \"abc\"@1 #text \"abc\"@offsetInAnchor[1]",
          "-S-- #text \"abc\"@0 #text \"abc\"@offsetInAnchor[0]",
          "-S-- BODY BODY@offsetInAnchor[0]",
          "---- HTML HTML@offsetInAnchor[1]",
          "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
          "-S-- HTML HTML@offsetInAnchor[0]"));
}

TEST_F(PositionIteratorTest, decrementWithSelectElement) {
  const char* const selection_text =
      "123<select id=target><option>1</option><option>2</option></select>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre(
          "---E BODY BODY@afterChildren",
          "---E SELECT id=\"target\"@1 SELECT id=\"target\"@afterAnchor",
          "-S-E SELECT id=\"target\"@0 SELECT id=\"target\"@beforeAnchor "
          "SELECT id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
          "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
          "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
          "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
          "-S-- BODY BODY@offsetInAnchor[0]",
          "---- HTML HTML@offsetInAnchor[1]",
          "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
          "-S-- HTML HTML@offsetInAnchor[0]"));

  EXPECT_THAT(
      ScanBackwardInFlatTree(selection_text),
      ElementsAre(
          "---E BODY BODY@afterChildren",
          "---E SELECT id=\"target\"@1 SELECT id=\"target\"@afterAnchor",
          // Note: `DeprecatedComputePosition()` should return
          // `SELECT@beforeAnchor`.
          "-S-E SELECT id=\"target\"@0 SELECT id=\"target\"@beforeAnchor "
          "SELECT id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
          "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
          "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
          "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
          "-S-- BODY BODY@offsetInAnchor[0]",
          "---- HTML HTML@offsetInAnchor[1]",
          "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
          "-S-- HTML HTML@offsetInAnchor[0]"));
}

// For http://crbug.com/695317
TEST_F(PositionIteratorTest, decrementWithTextAreaElement) {
  const char* const selection_text = "123<textarea id=target>456</textarea>|";

  EXPECT_THAT(
      ScanBackward(selection_text),
      ElementsAre(
          "---E BODY BODY@afterChildren",
          "---E TEXTAREA id=\"target\"@1 TEXTAREA id=\"target\"@afterAnchor",
          // Note: `DeprecatedComputePosition()` shoul
"""


```