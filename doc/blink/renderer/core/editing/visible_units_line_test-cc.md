Response:
The user wants a summary of the C++ code file `visible_units_line_test.cc`. I need to identify the purpose of the code, how it interacts with web technologies, and any potential issues or debugging information it provides.

**Plan:**

1. **Identify the core functionality:** Based on the file name and included headers, the file likely contains unit tests for functions related to the concept of "lines" in web page rendering and editing.
2. **Analyze the tests:**  Examine the `TEST_F` macros to understand what specific functionalities are being tested. The tests use functions like `EndOfLine`, `StartOfLine`, `IsEndOfLine`, `IsStartOfLine`, `LogicalEndOfLine`, `LogicalStartOfLine`, and `InSameLine`.
3. **Relate to web technologies:** Consider how these line-related functions might be used in the context of HTML, CSS, and JavaScript. Think about text selection, cursor movement, and how line breaks are handled.
4. **Identify assumptions and potential issues:** Look for patterns in the test cases, especially those involving different DOM structures (including shadow DOM) and text directions (Bidi). This might reveal assumptions about how lines are defined and potential edge cases.
5. **Infer user actions:**  Based on the functionality being tested, think about what user interactions would trigger these functions in a browser.
6. **Synthesize the summary:**  Combine the findings into a concise description of the file's purpose and its relevance to web development.
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"

namespace blink {

static VisiblePosition EndOfLine(const VisiblePosition& position) {
  return CreateVisiblePosition(EndOfLine(position.ToPositionWithAffinity()));
}

static VisiblePositionInFlatTree EndOfLine(
    const VisiblePositionInFlatTree& position) {
  return CreateVisiblePosition(EndOfLine(position.ToPositionWithAffinity()));
}

class VisibleUnitsLineTest : public EditingTestBase {
 protected:
  static PositionWithAffinity PositionWithAffinityInDOMTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return PositionWithAffinity(CanonicalPositionOf(Position(&anchor, offset)),
                                affinity);
  }

  static VisiblePosition CreateVisiblePositionInDOMTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(Position(&anchor, offset), affinity);
  }

  static PositionInFlatTreeWithAffinity PositionWithAffinityInFlatTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return PositionInFlatTreeWithAffinity(
        CanonicalPositionOf(PositionInFlatTree(&anchor, offset)), affinity);
  }

  static VisiblePositionInFlatTree CreateVisiblePositionInFlatTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(PositionInFlatTree(&anchor, offset), affinity);
  }

  std::string TestEndOfLine(const std::string& input) {
    const Position& caret = SetCaretTextToBody(input);
    const Position& result =
        EndOfLine(CreateVisiblePosition(caret)).DeepEquivalent();
    return GetCaretTextFromBody(result);
  }

  std::string TestLogicalEndOfLine(const std::string& input) {
    const Position& caret = SetCaretTextToBody(input);
    const Position& result =
        LogicalEndOfLine(CreateVisiblePosition(caret)).DeepEquivalent();
    return GetCaretTextFromBody(result);
  }

  std::string TestStartOfLine(const std::string& input) {
    const Position& caret = SetCaretTextToBody(input);
    const Position& result =
        StartOfLine(CreateVisiblePosition(caret)).DeepEquivalent();
    return GetCaretTextFromBody(result);
  }
};

TEST_F(VisibleUnitsLineTest, endOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_EQ(
      Position(seven, 7),
      EndOfLine(CreateVisiblePositionInDOMTree(*one, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(seven, 7),
      EndOfLine(CreateVisiblePositionInFlatTree(*one, 0)).DeepEquivalent());

  EXPECT_EQ(
      Position(seven, 7),
      EndOfLine(CreateVisiblePositionInDOMTree(*one, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(seven, 7),
      EndOfLine(CreateVisiblePositionInFlatTree(*one, 1)).DeepEquivalent());

  EXPECT_EQ(Position(two, 2), EndOfLine(CreateVisiblePositionInDOMTree(
                                            *two, 0, TextAffinity::kUpstream))
                                  .DeepEquivalent());
  EXPECT_EQ(
      Position(two, 2),
      EndOfLine(CreateVisiblePositionInDOMTree(*two, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two, 2),
      EndOfLine(CreateVisiblePositionInFlatTree(*two, 0)).DeepEquivalent());

  EXPECT_EQ(
      Position(two, 2),
      EndOfLine(CreateVisiblePositionInDOMTree(*two, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two, 2),
      EndOfLine(CreateVisiblePositionInFlatTree(*two, 1)).DeepEquivalent());

  EXPECT_EQ(Position(four, 4),
            EndOfLine(CreateVisiblePositionInDOMTree(*three, 0,
                                                     TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(
      Position(four, 4),
      EndOfLine(CreateVisiblePositionInDOMTree(*three, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(four, 4),
      EndOfLine(CreateVisiblePositionInFlatTree(*three, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(four, 4),
      EndOfLine(CreateVisiblePositionInDOMTree(*four, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(four, 4),
      EndOfLine(CreateVisiblePositionInFlatTree(*four, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(two, 2),
      EndOfLine(CreateVisiblePositionInDOMTree(*five, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two, 2),
      EndOfLine(CreateVisiblePositionInFlatTree(*five, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(six, 6),
      EndOfLine(CreateVisiblePositionInDOMTree(*six, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(six, 6),
      EndOfLine(CreateVisiblePositionInFlatTree(*six, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(seven, 7),
      EndOfLine(CreateVisiblePositionInDOMTree(*seven, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(seven, 7),
      EndOfLine(CreateVisiblePositionInFlatTree(*seven, 1)).DeepEquivalent());
}

TEST_F(VisibleUnitsLineTest, isEndOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_TRUE(IsEndOfLine(
      CreateVisiblePositionInFlatTree(*two, 2, TextAffinity::kUpstream)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*two, 2)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*two, 2)));

  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInDOMTree(*three, 3)));
  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*three, 3)));

  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInDOMTree(*four, 4)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*four, 4)));

  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*five, 5)));
  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*five, 5)));

  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInDOMTree(*six, 6)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*six, 6)));

  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInDOMTree(*seven, 7)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*seven, 7)));
}

TEST_F(VisibleUnitsLineTest, isLogicalEndOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_TRUE(IsLogicalEndOfLine(
      CreateVisiblePositionInDOMTree(*two, 2, TextAffinity::kUpstream)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*two, 2)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*two, 2)));

  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*three, 3)));
  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*three, 3)));

  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*four, 4)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*four, 4)));

  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*five, 5)));
  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*five, 5)));

  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*six, 6)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*six, 6)));

  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*seven, 7)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*seven, 7)));
}

TEST_F(VisibleUnitsLineTest, inSameLine) {
  const char* body_content =
      "<p id='host'>00<b slot='#one' id='one'>11</b><b slot='#two' "
      "id='two'>22</b>33</p>";
  const char* shadow_content =
      "<div><span id='s4'>44</span><slot name='#two'></slot><br><span "
      "id='s5'>55</span><br><slot name='#one'></slot><span "
      "id='s6'>66</span></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Element* body = GetDocument().body();
  Element* one = body->QuerySelector(AtomicString("#one"));
  Element* two = body->QuerySelector(AtomicString("#two"));
  Element* four = shadow_root->QuerySelector(AtomicString("#s4"));
  Element* five = shadow_root->QuerySelector(AtomicString("#s5"));

  EXPECT_FALSE(InSameLine(PositionWithAffinityInDOMTree(*one, 0),
                          PositionWithAffinityInDOMTree(*two, 0)));
  EXPECT_FALSE(
      InSameLine(PositionWithAffinityInDOMTree(*one->firstChild(), 0),
                 PositionWithAffinityInDOMTree(*two->firstChild(), 0)));
  EXPECT_FALSE(
      InSameLine(PositionWithAffinityInDOMTree(*one->firstChild(), 0),
                 PositionWithAffinityInDOMTree(*five->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(PositionWithAffinityInDOMTree(*two->firstChild(), 0),
                 PositionWithAffinityInDOMTree(*four->firstChild(), 0)));

  EXPECT_FALSE(InSameLine(
      CreateVisiblePositionInDOMTree(*one, 0),
      CreateVisiblePositionInDOMTree(*two, 0, TextAffinity::kUpstream)));
  EXPECT_FALSE(InSameLine(CreateVisiblePositionInDOMTree(*one, 0),
                          CreateVisiblePositionInDOMTree(*two, 0)));
  EXPECT_FALSE(InSameLine(CreateVisiblePositionInDOMTree(*one->firstChild(), 0),
                          CreateVisiblePositionInDOMTree(
                              *two->firstChild(), 0, TextAffinity::kUpstream)));
  EXPECT_FALSE(
      InSameLine(CreateVisiblePositionInDOMTree(*one->firstChild(), 0),
                 CreateVisiblePositionInDOMTree(*two->firstChild(), 0)));
  EXPECT_FALSE(
      InSameLine(CreateVisiblePositionInDOMTree(*one->firstChild(), 0),
                 CreateVisiblePositionInDOMTree(*five->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(CreateVisiblePositionInDOMTree(*two->firstChild(), 0,
                                                TextAffinity::kUpstream),
                 CreateVisiblePositionInDOMTree(*four->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(CreateVisiblePositionInDOMTree(*two->firstChild(), 0),
                 CreateVisiblePositionInDOMTree(*four->firstChild(), 0)));

  EXPECT_FALSE(InSameLine(PositionWithAffinityInFlatTree(*one, 0),
                          PositionWithAffinityInFlatTree(*two, 0)));
  EXPECT_FALSE(
      InSameLine(PositionWithAffinityInFlatTree(*one->firstChild(), 0),
                 PositionWithAffinityInFlatTree(*two->firstChild(), 0)));
  EXPECT_FALSE(
      InSameLine(PositionWithAffinityInFlatTree(*one->firstChild(), 0),
                 PositionWithAffinityInFlatTree(*five->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(PositionWithAffinityInFlatTree(*two->firstChild(), 0),
                 PositionWithAffinityInFlatTree(*four->firstChild(), 0)));

  EXPECT_FALSE(InSameLine(CreateVisiblePositionInFlatTree(*one, 0),
                          CreateVisiblePositionInFlatTree(*two, 0)));
  EXPECT_FALSE(
      InSameLine(CreateVisiblePositionInFlatTree(*one->firstChild(), 0),
                 CreateVisiblePositionInFlatTree(*two->firstChild(), 0)));
  EXPECT_FALSE(
      InSameLine(CreateVisiblePositionInFlatTree(*one->firstChild(), 0),
                 CreateVisiblePositionInFlatTree(*five->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(CreateVisiblePositionInFlatTree(*two->firstChild(), 0),
                 CreateVisiblePositionInFlatTree(*four->firstChild(), 0)));
}

TEST_F(VisibleUnitsLineTest, isStartOfLine) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInDOMTree(*two, 0)));
  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInFlatTree(*two, 0)));

  EXPECT_TRUE(IsStartOfLine(
      CreateVisiblePositionInDOMTree(*three, 0, TextAffinity::kUpstream)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInDOMTree(*three, 0)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInFlatTree(*three, 0)));

  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInDOMTree(*four, 0)));
  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInFlatTree(*four, 0)));

  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInDOMTree(*five, 0)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInFlatTree(*five, 0)));

  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInDOMTree(*six, 0)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInFlatTree(*six, 0)));

  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInDOMTree(*seven, 0)));
  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInFlatTree(*seven, 0)));
}

TEST_F(VisibleUnitsLineTest, logicalEndOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_EQ(Position(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*one, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*one, 0))
                .DeepEquivalent());

  EXPECT_EQ(Position(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*one, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*one, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(
                                 *two, 0, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*two, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*two, 0))
                .DeepEquivalent());

  EXPECT_EQ(Position(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*two, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*two, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(
                                 *three, 0, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*three, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*three, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*four, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*four, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*five, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*five, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(six, 6),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*six, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(six, 6),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*six, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*seven, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*seven, 1))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsLineTest, logicalStartOfLine) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_EQ(Position(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*one, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*one, 0))
                .DeepEquivalent());

  EXPECT_EQ(Position(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*one, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*one, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(
                                   *two, 0, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*two, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*two, 0))
                .DeepEquivalent());

  EXPECT_EQ(Position(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*two, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*two, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(
                                   *three, 0, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*three, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*three, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(
                                   *four, 1, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*four, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*four, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*five, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*five, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(six, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*six, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(six, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*six, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*seven, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*seven, 1))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsLineTest, startOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><
### 提示词
```
这是目录为blink/renderer/core/editing/visible_units_line_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"

namespace blink {

static VisiblePosition EndOfLine(const VisiblePosition& position) {
  return CreateVisiblePosition(EndOfLine(position.ToPositionWithAffinity()));
}

static VisiblePositionInFlatTree EndOfLine(
    const VisiblePositionInFlatTree& position) {
  return CreateVisiblePosition(EndOfLine(position.ToPositionWithAffinity()));
}

class VisibleUnitsLineTest : public EditingTestBase {
 protected:
  static PositionWithAffinity PositionWithAffinityInDOMTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return PositionWithAffinity(CanonicalPositionOf(Position(&anchor, offset)),
                                affinity);
  }

  static VisiblePosition CreateVisiblePositionInDOMTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(Position(&anchor, offset), affinity);
  }

  static PositionInFlatTreeWithAffinity PositionWithAffinityInFlatTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return PositionInFlatTreeWithAffinity(
        CanonicalPositionOf(PositionInFlatTree(&anchor, offset)), affinity);
  }

  static VisiblePositionInFlatTree CreateVisiblePositionInFlatTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(PositionInFlatTree(&anchor, offset), affinity);
  }

  std::string TestEndOfLine(const std::string& input) {
    const Position& caret = SetCaretTextToBody(input);
    const Position& result =
        EndOfLine(CreateVisiblePosition(caret)).DeepEquivalent();
    return GetCaretTextFromBody(result);
  }

  std::string TestLogicalEndOfLine(const std::string& input) {
    const Position& caret = SetCaretTextToBody(input);
    const Position& result =
        LogicalEndOfLine(CreateVisiblePosition(caret)).DeepEquivalent();
    return GetCaretTextFromBody(result);
  }

  std::string TestStartOfLine(const std::string& input) {
    const Position& caret = SetCaretTextToBody(input);
    const Position& result =
        StartOfLine(CreateVisiblePosition(caret)).DeepEquivalent();
    return GetCaretTextFromBody(result);
  }
};

TEST_F(VisibleUnitsLineTest, endOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_EQ(
      Position(seven, 7),
      EndOfLine(CreateVisiblePositionInDOMTree(*one, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(seven, 7),
      EndOfLine(CreateVisiblePositionInFlatTree(*one, 0)).DeepEquivalent());

  EXPECT_EQ(
      Position(seven, 7),
      EndOfLine(CreateVisiblePositionInDOMTree(*one, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(seven, 7),
      EndOfLine(CreateVisiblePositionInFlatTree(*one, 1)).DeepEquivalent());

  EXPECT_EQ(Position(two, 2), EndOfLine(CreateVisiblePositionInDOMTree(
                                            *two, 0, TextAffinity::kUpstream))
                                  .DeepEquivalent());
  EXPECT_EQ(
      Position(two, 2),
      EndOfLine(CreateVisiblePositionInDOMTree(*two, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two, 2),
      EndOfLine(CreateVisiblePositionInFlatTree(*two, 0)).DeepEquivalent());

  EXPECT_EQ(
      Position(two, 2),
      EndOfLine(CreateVisiblePositionInDOMTree(*two, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two, 2),
      EndOfLine(CreateVisiblePositionInFlatTree(*two, 1)).DeepEquivalent());

  EXPECT_EQ(Position(four, 4),
            EndOfLine(CreateVisiblePositionInDOMTree(*three, 0,
                                                     TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(
      Position(four, 4),
      EndOfLine(CreateVisiblePositionInDOMTree(*three, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(four, 4),
      EndOfLine(CreateVisiblePositionInFlatTree(*three, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(four, 4),
      EndOfLine(CreateVisiblePositionInDOMTree(*four, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(four, 4),
      EndOfLine(CreateVisiblePositionInFlatTree(*four, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(two, 2),
      EndOfLine(CreateVisiblePositionInDOMTree(*five, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two, 2),
      EndOfLine(CreateVisiblePositionInFlatTree(*five, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(six, 6),
      EndOfLine(CreateVisiblePositionInDOMTree(*six, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(six, 6),
      EndOfLine(CreateVisiblePositionInFlatTree(*six, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(seven, 7),
      EndOfLine(CreateVisiblePositionInDOMTree(*seven, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(seven, 7),
      EndOfLine(CreateVisiblePositionInFlatTree(*seven, 1)).DeepEquivalent());
}

TEST_F(VisibleUnitsLineTest, isEndOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_TRUE(IsEndOfLine(
      CreateVisiblePositionInFlatTree(*two, 2, TextAffinity::kUpstream)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*two, 2)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*two, 2)));

  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInDOMTree(*three, 3)));
  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*three, 3)));

  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInDOMTree(*four, 4)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*four, 4)));

  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*five, 5)));
  EXPECT_FALSE(IsEndOfLine(CreateVisiblePositionInFlatTree(*five, 5)));

  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInDOMTree(*six, 6)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*six, 6)));

  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInDOMTree(*seven, 7)));
  EXPECT_TRUE(IsEndOfLine(CreateVisiblePositionInFlatTree(*seven, 7)));
}

TEST_F(VisibleUnitsLineTest, isLogicalEndOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_TRUE(IsLogicalEndOfLine(
      CreateVisiblePositionInDOMTree(*two, 2, TextAffinity::kUpstream)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*two, 2)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*two, 2)));

  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*three, 3)));
  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*three, 3)));

  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*four, 4)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*four, 4)));

  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*five, 5)));
  EXPECT_FALSE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*five, 5)));

  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*six, 6)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*six, 6)));

  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInDOMTree(*seven, 7)));
  EXPECT_TRUE(IsLogicalEndOfLine(CreateVisiblePositionInFlatTree(*seven, 7)));
}

TEST_F(VisibleUnitsLineTest, inSameLine) {
  const char* body_content =
      "<p id='host'>00<b slot='#one' id='one'>11</b><b slot='#two' "
      "id='two'>22</b>33</p>";
  const char* shadow_content =
      "<div><span id='s4'>44</span><slot name='#two'></slot><br><span "
      "id='s5'>55</span><br><slot name='#one'></slot><span "
      "id='s6'>66</span></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Element* body = GetDocument().body();
  Element* one = body->QuerySelector(AtomicString("#one"));
  Element* two = body->QuerySelector(AtomicString("#two"));
  Element* four = shadow_root->QuerySelector(AtomicString("#s4"));
  Element* five = shadow_root->QuerySelector(AtomicString("#s5"));

  EXPECT_FALSE(InSameLine(PositionWithAffinityInDOMTree(*one, 0),
                          PositionWithAffinityInDOMTree(*two, 0)));
  EXPECT_FALSE(
      InSameLine(PositionWithAffinityInDOMTree(*one->firstChild(), 0),
                 PositionWithAffinityInDOMTree(*two->firstChild(), 0)));
  EXPECT_FALSE(
      InSameLine(PositionWithAffinityInDOMTree(*one->firstChild(), 0),
                 PositionWithAffinityInDOMTree(*five->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(PositionWithAffinityInDOMTree(*two->firstChild(), 0),
                 PositionWithAffinityInDOMTree(*four->firstChild(), 0)));

  EXPECT_FALSE(InSameLine(
      CreateVisiblePositionInDOMTree(*one, 0),
      CreateVisiblePositionInDOMTree(*two, 0, TextAffinity::kUpstream)));
  EXPECT_FALSE(InSameLine(CreateVisiblePositionInDOMTree(*one, 0),
                          CreateVisiblePositionInDOMTree(*two, 0)));
  EXPECT_FALSE(InSameLine(CreateVisiblePositionInDOMTree(*one->firstChild(), 0),
                          CreateVisiblePositionInDOMTree(
                              *two->firstChild(), 0, TextAffinity::kUpstream)));
  EXPECT_FALSE(
      InSameLine(CreateVisiblePositionInDOMTree(*one->firstChild(), 0),
                 CreateVisiblePositionInDOMTree(*two->firstChild(), 0)));
  EXPECT_FALSE(
      InSameLine(CreateVisiblePositionInDOMTree(*one->firstChild(), 0),
                 CreateVisiblePositionInDOMTree(*five->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(CreateVisiblePositionInDOMTree(*two->firstChild(), 0,
                                                TextAffinity::kUpstream),
                 CreateVisiblePositionInDOMTree(*four->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(CreateVisiblePositionInDOMTree(*two->firstChild(), 0),
                 CreateVisiblePositionInDOMTree(*four->firstChild(), 0)));

  EXPECT_FALSE(InSameLine(PositionWithAffinityInFlatTree(*one, 0),
                          PositionWithAffinityInFlatTree(*two, 0)));
  EXPECT_FALSE(
      InSameLine(PositionWithAffinityInFlatTree(*one->firstChild(), 0),
                 PositionWithAffinityInFlatTree(*two->firstChild(), 0)));
  EXPECT_FALSE(
      InSameLine(PositionWithAffinityInFlatTree(*one->firstChild(), 0),
                 PositionWithAffinityInFlatTree(*five->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(PositionWithAffinityInFlatTree(*two->firstChild(), 0),
                 PositionWithAffinityInFlatTree(*four->firstChild(), 0)));

  EXPECT_FALSE(InSameLine(CreateVisiblePositionInFlatTree(*one, 0),
                          CreateVisiblePositionInFlatTree(*two, 0)));
  EXPECT_FALSE(
      InSameLine(CreateVisiblePositionInFlatTree(*one->firstChild(), 0),
                 CreateVisiblePositionInFlatTree(*two->firstChild(), 0)));
  EXPECT_FALSE(
      InSameLine(CreateVisiblePositionInFlatTree(*one->firstChild(), 0),
                 CreateVisiblePositionInFlatTree(*five->firstChild(), 0)));
  EXPECT_TRUE(
      InSameLine(CreateVisiblePositionInFlatTree(*two->firstChild(), 0),
                 CreateVisiblePositionInFlatTree(*four->firstChild(), 0)));
}

TEST_F(VisibleUnitsLineTest, isStartOfLine) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInDOMTree(*two, 0)));
  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInFlatTree(*two, 0)));

  EXPECT_TRUE(IsStartOfLine(
      CreateVisiblePositionInDOMTree(*three, 0, TextAffinity::kUpstream)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInDOMTree(*three, 0)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInFlatTree(*three, 0)));

  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInDOMTree(*four, 0)));
  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInFlatTree(*four, 0)));

  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInDOMTree(*five, 0)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInFlatTree(*five, 0)));

  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInDOMTree(*six, 0)));
  EXPECT_TRUE(IsStartOfLine(CreateVisiblePositionInFlatTree(*six, 0)));

  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInDOMTree(*seven, 0)));
  EXPECT_FALSE(IsStartOfLine(CreateVisiblePositionInFlatTree(*seven, 0)));
}

TEST_F(VisibleUnitsLineTest, logicalEndOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_EQ(Position(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*one, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*one, 0))
                .DeepEquivalent());

  EXPECT_EQ(Position(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*one, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*one, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(
                                 *two, 0, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*two, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*two, 0))
                .DeepEquivalent());

  EXPECT_EQ(Position(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*two, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*two, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(
                                 *three, 0, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*three, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*three, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*four, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 4),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*four, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*five, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(two, 2),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*five, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(six, 6),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*six, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(six, 6),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*six, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInDOMTree(*seven, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(seven, 7),
            LogicalEndOfLine(CreateVisiblePositionInFlatTree(*seven, 1))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsLineTest, logicalStartOfLine) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_EQ(Position(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*one, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*one, 0))
                .DeepEquivalent());

  EXPECT_EQ(Position(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*one, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*one, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(
                                   *two, 0, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*two, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*two, 0))
                .DeepEquivalent());

  EXPECT_EQ(Position(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*two, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*two, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(
                                   *three, 0, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*three, 0))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*three, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(
                                   *four, 1, TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(Position(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*four, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(three, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*four, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*five, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(five, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*five, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(six, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*six, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(six, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*six, 1))
                .DeepEquivalent());

  EXPECT_EQ(Position(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInDOMTree(*seven, 1))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(one, 0),
            LogicalStartOfLine(CreateVisiblePositionInFlatTree(*seven, 1))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsLineTest, startOfLine) {
  // Test case:
  // 5555522
  // 666666
  // 117777777
  // 3334444
  const char* body_content =
      "<span id=host><b slot='#one' id=one>11</b><b slot='#two' "
      "id=two>22</b></span><i id=three>333</i><i "
      "id=four>4444</i><br>";
  const char* shadow_content =
      "<div><u id=five>55555</u><slot name='#two'></slot><br><u "
      "id=six>666666</u><br><slot name='#one'></slot><u "
      "id=seven>7777777</u></div>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = GetDocument().getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* six = shadow_root->getElementById(AtomicString("six"))->firstChild();
  Node* seven =
      shadow_root->getElementById(AtomicString("seven"))->firstChild();

  EXPECT_EQ(
      Position(one, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*one, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(one, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*one, 0)).DeepEquivalent());

  EXPECT_EQ(
      Position(one, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*one, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(one, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*one, 1)).DeepEquivalent());

  EXPECT_EQ(Position(five, 0),
            StartOfLine(CreateVisiblePositionInDOMTree(*two, 0,
                                                       TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(
      Position(five, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*two, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(five, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*two, 0)).DeepEquivalent());

  EXPECT_EQ(
      Position(five, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*two, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(five, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*two, 1)).DeepEquivalent());

  EXPECT_EQ(Position(three, 0),
            StartOfLine(CreateVisiblePositionInDOMTree(*three, 0,
                                                       TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(
      Position(three, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*three, 0)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(three, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*three, 1)).DeepEquivalent());

  EXPECT_EQ(Position(three, 0),
            StartOfLine(CreateVisiblePositionInDOMTree(*four, 1,
                                                       TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(
      Position(three, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*four, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(three, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*four, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(five, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*five, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(five, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*five, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(six, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*six, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(six, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*six, 1)).DeepEquivalent());

  EXPECT_EQ(
      Position(one, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*seven, 1)).DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(one, 0),
      StartOfLine(CreateVisiblePositionInFlatTree(*seven, 1)).DeepEquivalent());
}

TEST_F(VisibleUnitsLineTest, EndOfLineWithBidi) {
  LoadAhem();
  InsertStyleElement("p { font: 30px/3 Ahem; }");

  EXPECT_EQ(
      "<p dir=\"ltr\"><bdo dir=\"ltr\">ab cd ef|</bdo></p>",
      TestEndOfLine("<p dir=\"ltr\"><bdo dir=\"ltr\">a|b cd ef</bdo></p>"))
      << "LTR LTR";
  EXPECT_EQ(
      "<p dir=\"ltr\"><bdo dir=\"rtl\">ab cd ef|</bdo></p>",
      TestEndOfLine("<p dir=\"ltr\"><bdo dir=\"rtl\">a|b cd ef</bdo></p>"))
      << "LTR RTL";
  EXPECT_EQ(
      "<p dir=\"rtl\"><bdo dir=\"ltr\">ab cd ef|</bdo></p>",
      TestEndOfLine("<p dir=\"rtl\"><bdo dir=\"ltr\">a|b cd ef</bdo></p>"))
      << "RTL LTR";
  EXPECT_EQ(
      "<p dir=\"rtl\"><bdo dir=\"rtl\">ab cd ef|</bdo></p>",
      TestEndOfLine("<p dir=\"rtl\"><bdo dir=\"rtl\">a|b cd ef</bdo></p>"))
      << "RTL RTL";
}

// http://crbug.com/1136740
TEST_F(VisibleUnitsLineTest, EndOfLineWithHangingSpace) {
  LoadAhem();
  InsertStyleElement(
      "p {"
      "font: 30px/3 Ahem;"
      "overflow-wrap: break-word;"
      "white-space: pre-wrap;"
      "width: 4ch;"
      "}");

  // _____ _=Space
  // abcd
  // efgh
  EXPECT_EQ("<p>     |abcdefgh</p>", TestEndOfLine("<p>|     abcdefgh</p>"));
  EXPECT_EQ("<p>     |abcdefgh</p>", TestEndOfLine("<p> |    abcdefgh</p>"));
  EXPECT_EQ("<p>     |abcdefgh</p>", TestEndOfLine("<p>  |   abcdefgh</p>"));
  EXPECT_EQ("<p>     |abcdefgh</p>", TestEndOfLine("<p>   |  abcdefgh</p>"));
  EXPECT_EQ("<p>     |abcdefgh</p>", TestEndOfLine("<p>    | abcdefgh</p>"));
  EXPECT_EQ("<p>     abcd|efgh</p>", TestEndOfLine("<p>     |abcdefgh</p>"));
  EXPECT_EQ("<p>     abcd|efgh</p>", TestEndOfLine("<p>     a|bcdefgh</p>"));

  // __x__ _=Space
  // abcd
  // efgh
  EXPECT_EQ("<p>  x |abcdefgh</p>", TestEndOfLine("<p>|  x abcdefgh</p>"));
  EXPECT_EQ("<p>  x |abcdefgh</p>", TestEndOfLine("<p> | x abcdefgh</p>"));
  EXPECT_EQ("<p>  x |abcdefgh</p>", TestEndOfLine("<p>  x| abcdefgh</p>"));
  EXPECT_EQ("<p>  x |abcdefgh</p>", TestEndOfLine("<p>  x| abcdefgh</p>"));
  EXPECT_EQ("<p>  x abcd|efgh</p>", TestEndOfLine("<p>  x |abcdefgh</p>"));
  EXPECT_EQ("<p>  x abcd|efgh</p>", TestEndOfLine("<p>  x a|bcdefgh</p>"));
}

TEST_F(VisibleUnitsLineTest, EndOfLineWithPositionRelative) {
  LoadAhem();
  InsertStyleElement(
      "b { position:relative; left: 30px; }"
      "p { font: 30px/3 Ahem; }");

  EXPECT_EQ("<p>ab <b>cd</b
```