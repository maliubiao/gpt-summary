Response:
The user wants a summary of the provided C++ code file, `ax_position_test.cc`. Specifically, they want to understand:

1. **Functionality:** What does this code do?
2. **Relation to web technologies:** How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logical reasoning:** If there's any conditional logic, show example inputs and outputs.
4. **Common user errors:** Are there common mistakes users or developers might make when interacting with this functionality?
5. **User journey:** How might a user's actions lead to this code being executed? This helps with debugging.
6. **Concise summary:**  A brief overall summary of the file's purpose.

Let's break down the code:

- **Includes:** The file includes headers related to accessibility (`ax_position.h`, `ax_object.h`, etc.), DOM manipulation (`element.h`, `node.h`), editing (`position.h`), and testing (`gtest/gtest.h`, `accessibility_test.h`). This strongly suggests the file is for testing the accessibility features, specifically the `AXPosition` class.

- **`kCSSBeforeAndAfter`, `kHTMLTable`, `kMap`:** These are raw string literals containing HTML and CSS code. These are likely used as test cases to set up different DOM structures for testing `AXPosition` functionality in various scenarios.

- **`TEST_F(AccessibilityTest, ...)`:**  These are Google Test test cases. Each test focuses on a specific aspect of `AXPosition`.

- **Individual Tests:** The names of the tests provide hints about their function:
    - `PositionInText`: Testing positions within a text node.
    - `PositionBeforeText`: Testing positions before a text node.
    - `PositionAfterText`: Testing positions after a text node.
    - `PositionBeforeLineBreak`: Testing positions before a `<br>` element.
    - `PositionAfterLineBreak`: Testing positions after a `<br>` element.
    - `FirstPositionInDivContainer`: Testing the first position within a `<div>`.
    - `LastPositionInDivContainer`: Testing the last position within a `<div>`.
    - `FirstPositionInTextContainer`: Testing the first position within an AX representation of text.
    - `LastPositionInTextContainer`: Testing the last position within an AX representation of text.
    - `AXPositionComparisonOperators`: Testing how `AXPosition` objects are compared.
    - `AXPositionOperatorBool`: Testing the boolean conversion of `AXPosition` objects.
    - Tests with "WhiteSpace": Testing how `AXPosition` handles whitespace.
    - Tests with "PreservedLeadingWhitespace": Testing how `AXPosition` handles `white-space: pre-wrap;`.
    - Tests with "SVGTextWithXCoordinates": Testing how `AXPosition` handles SVG text with explicit coordinates.

**Plan:**

1. **Summarize the core functionality:**  The file tests the `AXPosition` class, which represents a position within the accessibility tree.
2. **Relate to web technologies:**
    - **HTML:**  The test cases use HTML structures to create different scenarios. `AXPosition` maps to conceptual positions within rendered HTML content.
    - **CSS:** The `kCSSBeforeAndAfter` test shows how CSS content (like `::before` and `::after`) affects accessibility positions.
    - **JavaScript:**  While this file doesn't directly involve JavaScript, the `AXPosition` class is part of the accessibility API, which JavaScript can use to interact with assistive technologies. Example: A screen reader using the accessibility tree to navigate content.
3. **Logical reasoning:** The tests involve creating `AXPosition` objects in various ways and then asserting their properties (e.g., `AnchorNode`, `OffsetInContainerNode`, `TextOffset`). I can create a simplified input/output example based on one of the tests.
4. **Common user errors:**  Misunderstanding how whitespace is handled in the accessibility tree compared to the DOM tree is a potential source of confusion.
5. **User journey:**  A user interacting with a webpage, especially using assistive technologies like screen readers or keyboard navigation, relies on the accessibility tree, and thus indirectly on the logic being tested here.
6. **Concise summary:**  A testing file for the `AXPosition` class in the Chromium accessibility module.
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/ax_position.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/testing/accessibility_test.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {
namespace test {

namespace {

constexpr char kCSSBeforeAndAfter[] = R"HTML(
    <style>
      q::before {
        content: "«";
        color: blue;
      }
      q::after {
        content: "»";
        color: red;
      }
    </style>
    <q id="quote">Hello there,</q> she said.
    )HTML";

constexpr char kHTMLTable[] = R"HTML(
    <p id="before">Before table.</p>
    <table id="table" border="1">
      <thead id="thead">
        <tr id="headerRow">
          <th id="firstHeaderCell">Number</th>
          <th>Month</th>
          <th id="lastHeaderCell">Expenses</th>
        </tr>
      </thead>
      <tbody id="tbody">
        <tr id="firstRow">
          <th id="firstCell">1</th>
          <td>Jan</td>
          <td>100</td>
        </tr>
        <tr>
          <th>2</th>
          <td>Feb</td>
          <td>150</td>
        </tr>
        <tr id="lastRow">
          <th>3</th>
          <td>Mar</td>
          <td id="lastCell">200</td>
        </tr>
      </tbody>
    </table>
    <p id="after">After table.</p>
    )HTML";

constexpr char kMap[] = R"HTML(
    <br id="br">
    <map id="map">
      <area shape="rect" coords="0,0,10,10" href="about:blank">
    </map>
    )HTML";
}  // namespace

//
// Basic tests.
//

TEST_F(AccessibilityTest, PositionInText) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionInTextObject(*ax_static_text, 3);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(3, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

// To prevent surprises when comparing equality of two |AXPosition|s, position
// before text object should be the same as position in text object at offset 0.
TEST_F(AccessibilityTest, PositionBeforeText) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionBeforeObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionBeforeTextWithFirstLetterCSSRule) {
  SetBodyInnerHTML(
      R"HTML(<style>p ::first-letter { color: red; font-size: 200%; }</style>
      <p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionBeforeObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

// To prevent surprises when comparing equality of two |AXPosition|s, position
// after text object should be the same as position in text object at offset
// text length.
TEST_F(AccessibilityTest, PositionAfterText) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionAfterObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionBeforeLineBreak) {
  SetBodyInnerHTML(R"HTML(Hello<br id="br">there)HTML");
  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_div = ax_br->ParentObjectUnignored();
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());

  const auto ax_position = AXPosition::CreatePositionBeforeObject(*ax_br);
  EXPECT_FALSE(ax_position.IsTextPosition());
  EXPECT_EQ(ax_div, ax_position.ContainerObject());
  EXPECT_EQ(1, ax_position.ChildIndex());
  EXPECT_EQ(ax_br, ax_position.ChildAfterTreePosition());

  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(GetDocument().body(), position.AnchorNode());
  EXPECT_EQ(1, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
}

TEST_F(AccessibilityTest, PositionAfterLineBreak) {
  SetBodyInnerHTML(R"HTML(Hello<br id="br">there)HTML");
  GetAXRootObject()->LoadInlineTextBoxes();
  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_static_text =
      GetAXRootObject()->DeepestLastChildIncludingIgnored()->ParentObject();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position = AXPosition::CreatePositionAfterObject(*ax_br);
  EXPECT_EQ(ax_static_text, ax_position.ContainerObject());
  EXPECT_TRUE(ax_position.IsTextPosition());
  EXPECT_EQ(0, ax_position.TextOffset());

  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(ax_static_text->GetNode(), position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
}

TEST_F(AccessibilityTest, FirstPositionInDivContainer) {
  SetBodyInnerHTML(R"HTML(<div id="div">Hello<br>there</div>)HTML");
  const Element* div = GetElementById("div");
  ASSERT_NE(nullptr, div);
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());
  const AXObject* ax_static_text = ax_div->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  // "Before object" positions that are anchored to before a text object are
  // always converted to a "text position" before the object's first unignored
  // character.
  const auto ax_position = AXPosition::CreateFirstPositionInObject(*ax_div);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(div->firstChild(), position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_TRUE(ax_position_from_dom.IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_position_from_dom.ContainerObject());
  EXPECT_EQ(0, ax_position_from_dom.TextOffset());
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, LastPositionInDivContainer) {
  SetBodyInnerHTML(R"HTML(<div id="div">Hello<br>there</div>
                   <div>Next div</div>)HTML");
  const Element* div = GetElementById("div");
  ASSERT_NE(nullptr, div);
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());

  const auto ax_position = AXPosition::CreateLastPositionInObject(*ax_div);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(div, position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsAfterChildren());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, FirstPositionInTextContainer) {
  SetBodyInnerHTML(R"HTML(<div id="div">Hello</div>)HTML");
  const Node* text = GetElementById("div")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreateFirstPositionInObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, LastPositionInTextContainer) {
  SetBodyInnerHTML(R"HTML(<div id="div">Hello</div>)HTML");
  const Node* text = GetElementById("div")->lastChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreateLastPositionInObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

//
// Test comparing two AXPosition objects based on their position in the
// accessibility tree.
//

TEST_F(AccessibilityTest, AXPositionComparisonOperators) {
  SetBodyInnerHTML(R"HTML(<input id="input" type="text" value="value">
                   <p id="paragraph">hello<br>there</p>)HTML");

  const AXObject* body = GetAXBodyObject();
  ASSERT_NE(nullptr, body);
  const auto root_first = AXPosition::CreateFirstPositionInObject(*body);
  const auto root_last = AXPosition::CreateLastPositionInObject(*body);

  const AXObject* input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, input);
  const auto input_before = AXPosition::CreatePositionBeforeObject(*input);
  const auto input_after = AXPosition::CreatePositionAfterObject(*input);

  const AXObject* paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, paragraph);
  ASSERT_NE(nullptr, paragraph->FirstChildIncludingIgnored());
  ASSERT_NE(nullptr, paragraph->LastChildIncludingIgnored());
  const auto paragraph_before = AXPosition::CreatePositionBeforeObject(
      *paragraph->FirstChildIncludingIgnored());
  const auto paragraph_after = AXPosition::CreatePositionAfterObject(
      *paragraph->LastChildIncludingIgnored());
  const auto paragraph_start = AXPosition::CreatePositionInTextObject(
      *paragraph->FirstChildIncludingIgnored(), 0);
  const auto paragraph_end = AXPosition::CreatePositionInTextObject(
      *paragraph->LastChildIncludingIgnored(), 5);

  EXPECT_TRUE(root_first == root_first);
  EXPECT_TRUE(root_last == root_last);
  EXPECT_FALSE(root_first != root_first);
  EXPECT_TRUE(root_first != root_last);

  EXPECT_TRUE(root_first < root_last);
  EXPECT_TRUE(root_first <= root_first);
  EXPECT_TRUE(root_last > root_first);
  EXPECT_TRUE(root_last >= root_last);

  EXPECT_TRUE(input_before == root_first);
  EXPECT_TRUE(input_after > root_first);
  EXPECT_TRUE(input_after >= root_first);
  EXPECT_FALSE(input_before < root_first);
  EXPECT_TRUE(input_before <= root_first);

  //
  // Text positions.
  //

  EXPECT_TRUE(paragraph_before == paragraph_start);
  EXPECT_TRUE(paragraph_after == paragraph_end);
  EXPECT_TRUE(paragraph_start < paragraph_end);
}

TEST_F(AccessibilityTest, AXPositionOperatorBool) {
  SetBodyInnerHTML(R"HTML(Hello)HTML");
  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const auto root_first = AXPosition::CreateFirstPositionInObject(*root);
  EXPECT_TRUE(static_cast<bool>(root_first));
  // The following should create an after children position on the root so it
  // should be valid.
  EXPECT_TRUE(static_cast<bool>(root_first.CreateNextPosition()));
  EXPECT_FALSE(static_cast<bool>(root_first.CreatePreviousPosition()));
}

//
// Test converting to and from visible text with white space.
// The accessibility tree is based on visible text with white space compressed,
// vs. the DOM tree where white space is preserved.
//

TEST_F(AccessibilityTest, PositionInTextWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">     Hello     </p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionInTextObject(*ax_static_text, 3);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(8, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionBeforeTextWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">     Hello     </p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionBeforeObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionAfterTextWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">     Hello     </p>)HTML");
  const Node* text = GetElementById("paragraph")->lastChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionAfterObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(10, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionBeforeLineBreakWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(Hello     <br id="br">     there)HTML");
  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_div = ax_br->ParentObjectUnignored();
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());

  const auto ax_position = AXPosition::CreatePositionBeforeObject(*ax_br);
  EXPECT_FALSE(ax_position.IsTextPosition());
  EXPECT_EQ(ax_div, ax_position.ContainerObject());
  EXPECT_EQ(1, ax_position.ChildIndex());
  EXPECT_EQ(ax_br, ax_position.ChildAfterTreePosition());

  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(GetDocument().body(), position.AnchorNode());
  EXPECT_EQ(1, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
}

TEST_F(AccessibilityTest, PositionAfterLineBreakWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(Hello     <br id="br">     there)HTML");
  GetAXRootObject()->LoadInlineTextBoxes();
  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_static_text =
      GetAXRootObject()->DeepestLastChildIncludingIgnored()->ParentObject();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position = AXPosition::CreatePositionAfterObject(*ax_br);
  EXPECT_EQ(ax_static_text, ax_position.ContainerObject());
  EXPECT_TRUE(ax_position.IsTextPosition());
  EXPECT_EQ(0, ax_position.TextOffset());

  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(ax_static_text->GetNode(), position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  // Any white space in the DOM should have been skipped.
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
}

TEST_F(AccessibilityTest, FirstPositionInDivContainerWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello<br>there     </div>)HTML");
  const Element* div = GetElementById("div");
  ASSERT_NE(nullptr, div);
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());
  const AXObject* ax_static_text = ax_div->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  // "Before object" positions that are anchored to before a text object are
  // always converted to a "text position" before the object's first unignored
  // character.
  const auto ax_position = AXPosition::CreateFirstPositionInObject(*ax_div);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(div->firstChild(), position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  // Any white space in the DOM should have been skipped.
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_TRUE(ax_position_from_dom.IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_position_from_dom.ContainerObject());
  EXPECT_EQ(0, ax_position_from_dom.TextOffset());
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, LastPositionInDivContainerWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello<br>there     </div>
                   <div>Next div</div>)HTML");
  const Element* div = GetElementById("div");
  ASSERT_NE(nullptr, div);
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());

  const auto ax_position = AXPosition::CreateLastPositionInObject(*ax_div);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(div, position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsAfterChildren());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, FirstPositionInTextContainerWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello     </div>)HTML");
  const Node* text = GetElementById("div")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreateFirstPositionInObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  // Any white space in the DOM should have been skipped.
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, LastPositionInTextContainerWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello     </div>)HTML");
  const Node* text = GetElementById("div")->lastChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::
Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_position_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/ax_position.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/testing/accessibility_test.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {
namespace test {

namespace {

constexpr char kCSSBeforeAndAfter[] = R"HTML(
    <style>
      q::before {
        content: "«";
        color: blue;
      }
      q::after {
        content: "»";
        color: red;
      }
    </style>
    <q id="quote">Hello there,</q> she said.
    )HTML";

constexpr char kHTMLTable[] = R"HTML(
    <p id="before">Before table.</p>
    <table id="table" border="1">
      <thead id="thead">
        <tr id="headerRow">
          <th id="firstHeaderCell">Number</th>
          <th>Month</th>
          <th id="lastHeaderCell">Expenses</th>
        </tr>
      </thead>
      <tbody id="tbody">
        <tr id="firstRow">
          <th id="firstCell">1</th>
          <td>Jan</td>
          <td>100</td>
        </tr>
        <tr>
          <th>2</th>
          <td>Feb</td>
          <td>150</td>
        </tr>
        <tr id="lastRow">
          <th>3</th>
          <td>Mar</td>
          <td id="lastCell">200</td>
        </tr>
      </tbody>
    </table>
    <p id="after">After table.</p>
    )HTML";

constexpr char kMap[] = R"HTML(
    <br id="br">
    <map id="map">
      <area shape="rect" coords="0,0,10,10" href="about:blank">
    </map>
    )HTML";
}  // namespace

//
// Basic tests.
//

TEST_F(AccessibilityTest, PositionInText) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionInTextObject(*ax_static_text, 3);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(3, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

// To prevent surprises when comparing equality of two |AXPosition|s, position
// before text object should be the same as position in text object at offset 0.
TEST_F(AccessibilityTest, PositionBeforeText) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionBeforeObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionBeforeTextWithFirstLetterCSSRule) {
  SetBodyInnerHTML(
      R"HTML(<style>p ::first-letter { color: red; font-size: 200%; }</style>
      <p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionBeforeObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

// To prevent surprises when comparing equality of two |AXPosition|s, position
// after text object should be the same as position in text object at offset
// text length.
TEST_F(AccessibilityTest, PositionAfterText) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionAfterObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionBeforeLineBreak) {
  SetBodyInnerHTML(R"HTML(Hello<br id="br">there)HTML");
  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_div = ax_br->ParentObjectUnignored();
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());

  const auto ax_position = AXPosition::CreatePositionBeforeObject(*ax_br);
  EXPECT_FALSE(ax_position.IsTextPosition());
  EXPECT_EQ(ax_div, ax_position.ContainerObject());
  EXPECT_EQ(1, ax_position.ChildIndex());
  EXPECT_EQ(ax_br, ax_position.ChildAfterTreePosition());

  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(GetDocument().body(), position.AnchorNode());
  EXPECT_EQ(1, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
}

TEST_F(AccessibilityTest, PositionAfterLineBreak) {
  SetBodyInnerHTML(R"HTML(Hello<br id="br">there)HTML");
  GetAXRootObject()->LoadInlineTextBoxes();
  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_static_text =
      GetAXRootObject()->DeepestLastChildIncludingIgnored()->ParentObject();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position = AXPosition::CreatePositionAfterObject(*ax_br);
  EXPECT_EQ(ax_static_text, ax_position.ContainerObject());
  EXPECT_TRUE(ax_position.IsTextPosition());
  EXPECT_EQ(0, ax_position.TextOffset());

  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(ax_static_text->GetNode(), position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
}

TEST_F(AccessibilityTest, FirstPositionInDivContainer) {
  SetBodyInnerHTML(R"HTML(<div id="div">Hello<br>there</div>)HTML");
  const Element* div = GetElementById("div");
  ASSERT_NE(nullptr, div);
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());
  const AXObject* ax_static_text = ax_div->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  // "Before object" positions that are anchored to before a text object are
  // always converted to a "text position" before the object's first unignored
  // character.
  const auto ax_position = AXPosition::CreateFirstPositionInObject(*ax_div);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(div->firstChild(), position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_TRUE(ax_position_from_dom.IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_position_from_dom.ContainerObject());
  EXPECT_EQ(0, ax_position_from_dom.TextOffset());
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, LastPositionInDivContainer) {
  SetBodyInnerHTML(R"HTML(<div id="div">Hello<br>there</div>
                   <div>Next div</div>)HTML");
  const Element* div = GetElementById("div");
  ASSERT_NE(nullptr, div);
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());

  const auto ax_position = AXPosition::CreateLastPositionInObject(*ax_div);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(div, position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsAfterChildren());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, FirstPositionInTextContainer) {
  SetBodyInnerHTML(R"HTML(<div id="div">Hello</div>)HTML");
  const Node* text = GetElementById("div")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreateFirstPositionInObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, LastPositionInTextContainer) {
  SetBodyInnerHTML(R"HTML(<div id="div">Hello</div>)HTML");
  const Node* text = GetElementById("div")->lastChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreateLastPositionInObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

//
// Test comparing two AXPosition objects based on their position in the
// accessibility tree.
//

TEST_F(AccessibilityTest, AXPositionComparisonOperators) {
  SetBodyInnerHTML(R"HTML(<input id="input" type="text" value="value">
                   <p id="paragraph">hello<br>there</p>)HTML");

  const AXObject* body = GetAXBodyObject();
  ASSERT_NE(nullptr, body);
  const auto root_first = AXPosition::CreateFirstPositionInObject(*body);
  const auto root_last = AXPosition::CreateLastPositionInObject(*body);

  const AXObject* input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, input);
  const auto input_before = AXPosition::CreatePositionBeforeObject(*input);
  const auto input_after = AXPosition::CreatePositionAfterObject(*input);

  const AXObject* paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, paragraph);
  ASSERT_NE(nullptr, paragraph->FirstChildIncludingIgnored());
  ASSERT_NE(nullptr, paragraph->LastChildIncludingIgnored());
  const auto paragraph_before = AXPosition::CreatePositionBeforeObject(
      *paragraph->FirstChildIncludingIgnored());
  const auto paragraph_after = AXPosition::CreatePositionAfterObject(
      *paragraph->LastChildIncludingIgnored());
  const auto paragraph_start = AXPosition::CreatePositionInTextObject(
      *paragraph->FirstChildIncludingIgnored(), 0);
  const auto paragraph_end = AXPosition::CreatePositionInTextObject(
      *paragraph->LastChildIncludingIgnored(), 5);

  EXPECT_TRUE(root_first == root_first);
  EXPECT_TRUE(root_last == root_last);
  EXPECT_FALSE(root_first != root_first);
  EXPECT_TRUE(root_first != root_last);

  EXPECT_TRUE(root_first < root_last);
  EXPECT_TRUE(root_first <= root_first);
  EXPECT_TRUE(root_last > root_first);
  EXPECT_TRUE(root_last >= root_last);

  EXPECT_TRUE(input_before == root_first);
  EXPECT_TRUE(input_after > root_first);
  EXPECT_TRUE(input_after >= root_first);
  EXPECT_FALSE(input_before < root_first);
  EXPECT_TRUE(input_before <= root_first);

  //
  // Text positions.
  //

  EXPECT_TRUE(paragraph_before == paragraph_start);
  EXPECT_TRUE(paragraph_after == paragraph_end);
  EXPECT_TRUE(paragraph_start < paragraph_end);
}

TEST_F(AccessibilityTest, AXPositionOperatorBool) {
  SetBodyInnerHTML(R"HTML(Hello)HTML");
  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const auto root_first = AXPosition::CreateFirstPositionInObject(*root);
  EXPECT_TRUE(static_cast<bool>(root_first));
  // The following should create an after children position on the root so it
  // should be valid.
  EXPECT_TRUE(static_cast<bool>(root_first.CreateNextPosition()));
  EXPECT_FALSE(static_cast<bool>(root_first.CreatePreviousPosition()));
}

//
// Test converting to and from visible text with white space.
// The accessibility tree is based on visible text with white space compressed,
// vs. the DOM tree where white space is preserved.
//

TEST_F(AccessibilityTest, PositionInTextWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">     Hello     </p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionInTextObject(*ax_static_text, 3);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(8, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionBeforeTextWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">     Hello     </p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionBeforeObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionAfterTextWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">     Hello     </p>)HTML");
  const Node* text = GetElementById("paragraph")->lastChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreatePositionAfterObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(10, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionBeforeLineBreakWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(Hello     <br id="br">     there)HTML");
  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_div = ax_br->ParentObjectUnignored();
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());

  const auto ax_position = AXPosition::CreatePositionBeforeObject(*ax_br);
  EXPECT_FALSE(ax_position.IsTextPosition());
  EXPECT_EQ(ax_div, ax_position.ContainerObject());
  EXPECT_EQ(1, ax_position.ChildIndex());
  EXPECT_EQ(ax_br, ax_position.ChildAfterTreePosition());

  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(GetDocument().body(), position.AnchorNode());
  EXPECT_EQ(1, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
}

TEST_F(AccessibilityTest, PositionAfterLineBreakWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(Hello     <br id="br">     there)HTML");
  GetAXRootObject()->LoadInlineTextBoxes();
  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_static_text =
      GetAXRootObject()->DeepestLastChildIncludingIgnored()->ParentObject();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position = AXPosition::CreatePositionAfterObject(*ax_br);
  EXPECT_EQ(ax_static_text, ax_position.ContainerObject());
  EXPECT_TRUE(ax_position.IsTextPosition());
  EXPECT_EQ(0, ax_position.TextOffset());

  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(ax_static_text->GetNode(), position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  // Any white space in the DOM should have been skipped.
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
}

TEST_F(AccessibilityTest, FirstPositionInDivContainerWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello<br>there     </div>)HTML");
  const Element* div = GetElementById("div");
  ASSERT_NE(nullptr, div);
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());
  const AXObject* ax_static_text = ax_div->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  // "Before object" positions that are anchored to before a text object are
  // always converted to a "text position" before the object's first unignored
  // character.
  const auto ax_position = AXPosition::CreateFirstPositionInObject(*ax_div);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(div->firstChild(), position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  // Any white space in the DOM should have been skipped.
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_TRUE(ax_position_from_dom.IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_position_from_dom.ContainerObject());
  EXPECT_EQ(0, ax_position_from_dom.TextOffset());
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, LastPositionInDivContainerWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello<br>there     </div>
                   <div>Next div</div>)HTML");
  const Element* div = GetElementById("div");
  ASSERT_NE(nullptr, div);
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_div->RoleValue());

  const auto ax_position = AXPosition::CreateLastPositionInObject(*ax_div);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(div, position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsAfterChildren());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, FirstPositionInTextContainerWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello     </div>)HTML");
  const Node* text = GetElementById("div")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreateFirstPositionInObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  // Any white space in the DOM should have been skipped.
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, LastPositionInTextContainerWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello     </div>)HTML");
  const Node* text = GetElementById("div")->lastChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_position =
      AXPosition::CreateLastPositionInObject(*ax_static_text);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_EQ(10, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(nullptr, ax_position_from_dom.ChildAfterTreePosition());
}

// Test that DOM positions in white space will be collapsed to the first or last
// valid offset in an |AXPosition|.
TEST_F(AccessibilityTest, AXPositionFromDOMPositionWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<div id="div">     Hello     </div>)HTML");
  const Node* text = GetElementById("div")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  ASSERT_EQ(15U, text->textContent().length());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("div")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const Position position_at_start(*text, 0);
  const auto ax_position_at_start = AXPosition::FromPosition(position_at_start);
  EXPECT_TRUE(ax_position_at_start.IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_position_at_start.ContainerObject());
  EXPECT_EQ(0, ax_position_at_start.TextOffset());
  EXPECT_EQ(nullptr, ax_position_at_start.ChildAfterTreePosition());

  const Position position_after_white_space(*text, 5);
  const auto ax_position_after_white_space =
      AXPosition::FromPosition(position_after_white_space);
  EXPECT_TRUE(ax_position_after_white_space.IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_position_after_white_space.ContainerObject());
  EXPECT_EQ(0, ax_position_after_white_space.TextOffset());
  EXPECT_EQ(nullptr, ax_position_after_white_space.ChildAfterTreePosition());

  const Position position_at_end(*text, 15);
  const auto ax_position_at_end = AXPosition::FromPosition(position_at_end);
  EXPECT_TRUE(ax_position_at_end.IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_position_at_end.ContainerObject());
  EXPECT_EQ(5, ax_position_at_end.TextOffset());
  EXPECT_EQ(nullptr, ax_position_at_end.ChildAfterTreePosition());

  const Position position_before_white_space(*text, 10);
  const auto ax_position_before_white_space =
      AXPosition::FromPosition(position_before_white_space);
  EXPECT_TRUE(ax_position_before_white_space.IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_position_before_white_space.ContainerObject());
  EXPECT_EQ(5, ax_position_before_white_space.TextOffset());
  EXPECT_EQ(nullptr, ax_position_before_white_space.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, AXPositionsWithPreservedLeadingWhitespace) {
  SetBodyInnerHTML(R"HTML(
    <div id="div" style="white-space: pre-wrap;">   Bar</div>
    )HTML");

  const Node* text = GetElementById("div")->firstChild();
  ASSERT_NE(nullptr, text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_EQ(6U, text->textContent().length());

  const Position position_at_start(*text, 0);
  const auto ax_position_at_start = AXPosition::FromPosition(position_at_start);
  EXPECT_TRUE(ax_position_at_start.IsTextPosition());
  EXPECT_EQ(0, ax_position_at_start.TextOffset());

  // If we didn't adjust for the break opportunity, the accessible text offset
  // would be 4 instead of 3.
  const Position position_after_white_space(*text, 3);
  const auto ax_position_after_white_space =
      AXPosition::FromPosition(position_after_white_space);
  EXPECT_TRUE(ax_position_after_white_space.IsTextPosition());
  EXPECT_EQ(3, ax_position_after_white_space.TextOffset());

  // If we didn't adjust for the break opportunity, the accessible text offset
  // would be 7 instead of 6.
  const Position position_at_end(*text, 6);
  const auto ax_position_at_end = AXPosition::FromPosition(position_at_end);
  EXPECT_TRUE(ax_position_at_end.IsTextPosition());
  EXPECT_EQ(6, ax_position_at_end.TextOffset());
}

TEST_F(AccessibilityTest, AXPositionsWithPreservedLeadingWhitespaceAndBreak) {
  SetBodyInnerHTML(R"HTML(
    <div><span id="foo" style="white-space:pre-wrap;"> Foo</span>
    <br>
    <span id="bar" style="white-space:pre-wrap;">   Bar</span></div>
    )HTML");

  const Node* span = GetElementById("foo");
  ASSERT_NE(nullptr, span);
  EXPECT_EQ(4U, span->textContent().length());

  const Node* text = span->firstChild();
  ASSERT_NE(nullptr, text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_EQ(4U, text->textContent().length());

  const Position position_at_start_1(*text, 0);
  const auto ax_position_at_start_1 =
      AXPosition::FromPosition(position_at_start_1);
  EXPECT_TRUE(ax_position_at_start_1.IsTextPosition());
  EXPECT_EQ(0, ax_position_at_start_1.TextOffset());

  // If we didn't adjust for the break opportunity, the accessible text offset
  // would be 2 instead of 1.
  const Position position_after_white_space_1(*text, 1);
  const auto ax_position_after_white_space_1 =
      AXPosition::FromPosition(position_after_white_space_1);
  EXPECT_TRUE(ax_position_after_white_space_1.IsTextPosition());
  EXPECT_EQ(1, ax_position_after_white_space_1.TextOffset());

  // If we didn't adjust for the break opportunity, the accessible text offset
  // would be 5 instead of 4.
  const Position position_at_end_1(*text, 4);
  const auto ax_position_at_end_1 = AXPosition::FromPosition(position_at_end_1);
  EXPECT_TRUE(ax_position_at_end_1.IsTextPosition());
  EXPECT_EQ(4, ax_position_at_end_1.TextOffset());

  span = GetElementById("bar");
  ASSERT_NE(nullptr, span);
  EXPECT_EQ(6U, span->textContent().length());

  text = span->firstChild();
  ASSERT_NE(nullptr, text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_EQ(6U, text->textContent().length());

  const Position position_at_start_2(*text, 0);
  const auto ax_position_at_start_2 =
      AXPosition::FromPosition(position_at_start_2);
  EXPECT_TRUE(ax_position_at_start_2.IsTextPosition());
  EXPECT_EQ(0, ax_position_at_start_2.TextOffset());

  // If we didn't adjust for the break opportunity, the accessible text offset
  // would be 4 instead of 3.
  const Position position_after_white_space_2(*text, 3);
  const auto ax_position_after_white_space_2 =
      AXPosition::FromPosition(position_after_white_space_2);
  EXPECT_TRUE(ax_position_after_white_space_2.IsTextPosition());
  EXPECT_EQ(3, ax_position_after_white_space_2.TextOffset());

  // If we didn't adjust for the break opportunity, the accessible text offset
  // would be 7 instead of 6.
  const Position position_at_end_2(*text, 6);
  const auto ax_position_at_end_2 = AXPosition::FromPosition(position_at_end_2);
  EXPECT_TRUE(ax_position_at_end_2.IsTextPosition());
  EXPECT_EQ(6, ax_position_at_end_2.TextOffset());
}

TEST_F(AccessibilityTest, AXPositionsInSVGTextWithXCoordinates) {
  SetBodyInnerHTML(R"HTML(
    <div>
    <svg version="1.1" baseProfile="basic" xmlns="http://www.w3.org/2000/svg"
         xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 160 120">
    <text id="text" x="0 10 20 30 40 50 60 70 80 90 100 110">Hel<tspan>lo </tspan>
      <tspan id="tspan">world</tspan>!</text>
    </svg>
    </div>
    )HTML");

  // Check the text node containing "Hel"
  const Node* text = GetElementById("text")->firstChild();
  ASSERT_NE(nullptr, text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_EQ(3U, text->textContent().length());
  EXPECT_EQ("Hel", text->textContent().Utf8());

  const Position position_at_h(*text, 0);
  const auto ax_position_at_h = AXPosition::FromPosition(position_at_h);
  EXPECT_TRUE(ax_position_at_h.IsTextPosition());
  EXPECT_EQ(0, ax_position_at_h.TextOffset());

  // If we didn't adjust for isolate characters, the accessible text offset
  // would be 7 instead of 3.
  const Position position_after_l(*text, 3);
  const auto ax_position_after_l = AXPosition::FromPosition(position_after_l);
  EXPECT_TRUE(ax_position_after_l.IsTextPosition());
  EXPECT_EQ(3, ax_position_after_l.TextOffset());

  // Check the text node child of the first tspan containing "lo "
  text = text->nextSibling()->firstChild();
  ASSERT_NE(nullptr, text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_EQ(3U, text->textContent().length());
  EXPECT_EQ("lo ", text->textContent().Utf8());

  // If we didn't adjust for isolate characters, the accessible text offset
  // would be 3 instead of 1.
  const Position position_at_o(*text, 1);
  const auto ax_position_at_o = AXPosition::FromPosition(position_at_o);
  EXPECT_TRUE(ax_position_at_o.IsTextPosition());
  EXPECT_EQ(1, ax_position_at_o.TextOffset());

  // Check the text
"""


```