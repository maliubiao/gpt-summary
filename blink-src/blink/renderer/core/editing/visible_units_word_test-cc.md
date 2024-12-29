Response:
My thought process for analyzing the provided C++ code and fulfilling the request goes like this:

1. **Understand the Goal:** The core request is to analyze a C++ test file for Chromium's Blink rendering engine. Specifically, the file `visible_units_word_test.cc` is about testing word-related navigation functionalities. The request asks for the file's purpose, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning (input/output), common user errors, debugging clues, and a summary of its functions.

2. **High-Level Overview:** I first scan the file to get a general idea of its contents. I see `#include` directives for core Blink editing functionalities (`visible_units.h`, `selection_template.h`, `editing_test_base.h`, `visible_position.h`). This immediately tells me the file is about testing how the engine handles word boundaries and movement within editable content. The `VisibleUnitsWordTest` class inheriting from `EditingTestBase` confirms it's a unit test.

3. **Analyze the Helper Functions:** I then look at the protected member functions: `DoStartOfWord`, `DoEndOfWord`, `DoNextWord`, `DoNextWordSkippingSpaces`, `DoPreviousWord`, and `DoMiddleOfWord`. These functions are crucial. I observe they all take a `selection_text` string as input, set the caret or selection based on this string, and then call the corresponding `VisibleUnits` functions (`StartOfWordPosition`, `EndOfWordPosition`, `NextWordPosition`, `PreviousWordPosition`, `MiddleOfWordPosition`). The return value is the text around the new caret position. This pattern signifies that the tests are designed to check the correctness of these word-navigation functions.

4. **Examine the Test Cases:** The `TEST_F` macros define the individual test cases. I start reading through them, noticing the naming convention (`VisibleUnitsWordTest`, followed by a descriptive name like `StartOfWordBasic`). The `EXPECT_EQ` macro is used to compare the expected output with the actual output of the helper functions. The input strings to the helper functions contain a `|` to indicate the caret position, and the expected output strings also use `|` to show where the caret should be after the operation.

5. **Identify Core Functionality:** Based on the helper functions and test cases, I can determine the main functions being tested:
    * Moving the caret to the beginning of a word.
    * Moving the caret to the end of a word.
    * Moving the caret to the next word (with and without skipping spaces).
    * Moving the caret to the previous word.
    * Moving the caret to the middle of a word (based on a selection).

6. **Relate to Web Technologies:**  I consider how these functionalities are relevant to web development:
    * **JavaScript:**  JavaScript APIs like `Selection` and `Range` allow developers to programmatically manipulate the selection and caret position. The underlying logic tested here directly impacts the behavior of those APIs when moving by words.
    * **HTML:** The test cases use HTML tags (`<p>`, `<b>`, `<i>`, `input`, etc.) to simulate different document structures. The word navigation needs to work correctly across these elements.
    * **CSS:**  Some test cases involve CSS properties like `first-letter` and `white-space: pre`, and `-webkit-text-security`. This shows that the word navigation logic needs to consider CSS styling that affects text layout and rendering.

7. **Infer Logical Reasoning and Input/Output:** The `EXPECT_EQ` calls within the test cases directly demonstrate logical reasoning. The *input* is the `selection_text` string with the initial caret position. The *output* is the expected `selection_text` string with the final caret position after applying the word-navigation function. I can pick specific test cases and explain the logic: "If the caret is at the beginning of a word, `StartOfWordPosition` should keep it there."

8. **Consider User Errors:** I think about common user interactions and how they might relate to these functionalities. Selecting or placing the caret in unexpected locations could be a user error. The test cases with `WordSide::kPreviousWordIfOnBoundary` address edge cases where the user's caret is right on a word boundary.

9. **Trace User Operations for Debugging:** I imagine a user interacting with a web page: clicking to set the caret, using keyboard shortcuts (Ctrl+Left/Right Arrow) to move by words, or selecting text. If word navigation isn't working correctly, this test file provides a way for developers to isolate and debug the underlying C++ logic.

10. **Summarize Functionality:** Finally, I synthesize all the information to provide a concise summary of the file's purpose and the functionalities it tests.

By following these steps, I can systematically analyze the code and address all aspects of the request, providing a comprehensive explanation of the `visible_units_word_test.cc` file.
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"

namespace blink {

class VisibleUnitsWordTest : public EditingTestBase {
 protected:
  std::string DoStartOfWord(
      const std::string& selection_text,
      WordSide word_side = WordSide::kNextWordIfOnBoundary) {
    const Position position = SetCaretTextToBody(selection_text);
    return GetCaretTextFromBody(StartOfWordPosition(position, word_side));
  }

  std::string DoEndOfWord(
      const std::string& selection_text,
      WordSide word_side = WordSide::kNextWordIfOnBoundary) {
    const Position position = SetCaretTextToBody(selection_text);
    return GetCaretTextFromBody(EndOfWordPosition(position, word_side));
  }

  std::string DoNextWord(const std::string& selection_text) {
    const Position position = SetCaretTextToBody(selection_text);
    const PlatformWordBehavior platform_word_behavior =
        PlatformWordBehavior::kWordDontSkipSpaces;
    return GetCaretTextFromBody(
        CreateVisiblePosition(
            NextWordPosition(position, platform_word_behavior))
            .DeepEquivalent());
  }

  std::string DoNextWordSkippingSpaces(const std::string& selection_text) {
    const Position position = SetCaretTextToBody(selection_text);
    const PlatformWordBehavior platform_word_behavior =
        PlatformWordBehavior::kWordSkipSpaces;
    return GetCaretTextFromBody(
        CreateVisiblePosition(
            NextWordPosition(position, platform_word_behavior))
            .DeepEquivalent());
  }

  std::string DoPreviousWord(const std::string& selection_text) {
    const Position position = SetCaretTextToBody(selection_text);
    const Position result =
        CreateVisiblePosition(PreviousWordPosition(position)).DeepEquivalent();
    if (result.IsNull())
      return GetSelectionTextFromBody(SelectionInDOMTree());
    return GetCaretTextFromBody(result);
  }

  std::string DoMiddleOfWord(const std::string& selection_text) {
    SelectionInDOMTree selection = SetSelectionTextToBody(selection_text);
    return GetCaretTextFromBody(
        MiddleOfWordPosition(selection.Anchor(), selection.Focus()));
  }

  // To avoid name conflict in jumbo build, following functions should be here.
  static VisiblePosition CreateVisiblePositionInDOMTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(Position(&anchor, offset), affinity);
  }

  static VisiblePositionInFlatTree CreateVisiblePositionInFlatTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(PositionInFlatTree(&anchor, offset), affinity);
  }
};

TEST_F(VisibleUnitsWordTest, StartOfWordBasic) {
  EXPECT_EQ("<p> |(1) abc def</p>", DoStartOfWord("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> |(1) abc def</p>", DoStartOfWord("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>", DoStartOfWord("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoStartOfWord("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1)| abc def</p>", DoStartOfWord("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoStartOfWord("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoStartOfWord("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoStartOfWord("<p> (1) abc def</p>|"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordPreviousWordIfOnBoundaryBasic) {
  EXPECT_EQ("<p> |(1) abc def</p>",
            DoStartOfWord("<p>| (1) abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> |(1) abc def</p>",
            DoStartOfWord("<p> |(1) abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> |(1) abc def</p>",
            DoStartOfWord("<p> (|1) abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (|1) abc def</p>",
            DoStartOfWord("<p> (1|) abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1|) abc def</p>",
            DoStartOfWord("<p> (1)| abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1)| abc def</p>",
            DoStartOfWord("<p> (1) |abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) |abc def</p>",
            DoStartOfWord("<p> (1) a|bc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) |abc def</p>",
            DoStartOfWord("<p> (1) ab|c def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) |abc def</p>",
            DoStartOfWord("<p> (1) abc| def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc| def</p>",
            DoStartOfWord("<p> (1) abc |def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoStartOfWord("<p> (1) abc d|ef</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoStartOfWord("<p> (1) abc de|f</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoStartOfWord("<p> (1) abc def|</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoStartOfWord("<p> (1) abc def</p>|",
                          WordSide::kPreviousWordIfOnBoundary));
}

TEST_F(VisibleUnitsWordTest, StartOfWordCrossing) {
  EXPECT_EQ("<b>|abc</b><i>def</i>", DoStartOfWord("<b>abc</b><i>|def</i>"));
  EXPECT_EQ("<b>abc</b><i>def|</i>", DoStartOfWord("<b>abc</b><i>def</i>|"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordFirstLetter) {
  InsertStyleElement("p::first-letter {font-size:200%;}");
  // Note: Expectations should match with |StartOfWordBasic|.
  EXPECT_EQ("<p> |(1) abc def</p>", DoStartOfWord("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> |(1) abc def</p>", DoStartOfWord("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>", DoStartOfWord("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoStartOfWord("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1)| abc def</p>", DoStartOfWord("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoStartOfWord("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoStartOfWord("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoStartOfWord("<p> (1) abc def</p>|"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordShadowDOM) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>1</b> <b slot='#two' "
      "id=two>22</b></span><i id=three>333</i>";
  const char* shadow_content =
      "<p><u id=four>44444</u><slot name=#two></slot><span id=space> "
      "</span><slot name=#one></slot><u id=five>55555</u></p>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = shadow_root->getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* space =
      shadow_root->getElementById(AtomicString("space"))->firstChild();

  EXPECT_EQ(Position(one, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*one, 0).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(space, 1),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*one, 0).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(one, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*one, 1).DeepEquivalent()))
                .DeepEquivalent());

  EXPECT_EQ(PositionInFlatTree(space, 1),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*one, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*two, 0).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*two, 0).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*two, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*two, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(three, 0),
            CreateVisiblePosition(
                StartOfWordPosition(CreateVisiblePositionInDOMTree(
                                        *three, 1, TextAffinity::kUpstream)
                                        .DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(three, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*three, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(three, 0),
      CreateVisiblePosition(
          StartOfWordPosition(
              CreateVisiblePositionInFlatTree(*three, 1).DeepEquivalent()))
          .DeepEquivalent());
  EXPECT_EQ(Position(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*four, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*four, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(one, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*five, 1).DeepEquivalent()))
                .DeepEquivalent());
  // Flat tree canonicalization moves result to downstream position
  EXPECT_EQ(PositionInFlatTree(space, 1),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*five, 1).DeepEquivalent()))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsWordTest, StartOfWordTextSecurity) {
  // Note: |StartOfWordPosition()| considers security characters
  // as a sequence "x".
  InsertStyleElement("s {-webkit-text-security:disc;}");
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("|abc<s>foo bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc|<s>foo bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>|foo bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>f|oo bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo| bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo |bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo bar|</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo bar</s>|baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo bar</s>b|az"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordTextControl) {
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("|foo<input value=\"bla\">bar"));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("f|oo<input value=\"bla\">bar"));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("fo|o<input value=\"bla\">bar"));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoStartOfWord("foo|<input value=\"bla\">bar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">|bar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">b|ar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">ba|r"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoStartOfWord("foo<input value=\"bla\">bar|"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordPreviousWordIfOnBoundaryTextControl) {
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("|foo<input value=\"bla\">bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("f|oo<input value=\"bla\">bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("fo|o<input value=\"bla\">bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("foo|<input value=\"bla\">bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoStartOfWord("foo<input value=\"bla\">|bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">b|ar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">ba|r",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">bar|",
                          WordSide::kPreviousWordIfOnBoundary));
}

TEST_F(VisibleUnitsWordTest, EndOfWordBasic) {
  EXPECT_EQ("<p> (|1) abc def</p>", DoEndOfWord("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>", DoEndOfWord("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoEndOfWord("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (1)| abc def</p>", DoEndOfWord("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoEndOfWord("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoEndOfWord("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoEndOfWord("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoEndOfWord("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoEndOfWord("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoEndOfWord("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoEndOfWord("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoEndOfWord("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoEndOfWord("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc def</p>|", DoEndOfWord("<p> (1) abc def</p>|"));
}

TEST_F(VisibleUnitsWordTest, EndOfWordPreviousWordIfOnBoundaryBasic) {
  EXPECT_EQ(
      "<p> |(1) abc def</p>",
      DoEndOfWord("<p>| (1) abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> |(1) abc def</p>",
      DoEndOfWord("<p> |(1) abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (|1) abc def</p>",
      DoEndOfWord("<p> (|1) abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1|) abc def</p>",
      DoEndOfWord("<p> (1|) abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1)| abc def</p>",
      DoEndOfWord("<p> (1)| abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) |abc def</p>",
      DoEndOfWord("<p> (1) |abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc| def</p>",
      DoEndOfWord("<p> (1) a|bc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc| def</p>",
      DoEndOfWord("<p> (1) ab|c def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc| def</p>",
      DoEndOfWord("<p> (1) abc| def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc |def</p>",
      DoEndOfWord("<p> (1) abc |def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc def|</p>",
      DoEndOfWord("<p> (1) abc d|ef</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc def|</p>",
      DoEndOfWord("<p> (1) abc de|f</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc def|</p>",
      DoEndOfWord("<p> (1) abc def|</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc def</p>|",
      DoEndOfWord("<p> (1) abc def</p>|", WordSide::kPreviousWordIfOnBoundary));
}

TEST_F(VisibleUnitsWordTest, EndOfWordShadowDOM) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>1</b> <b slot='#two' "
      "id=two>22</b></span><i id=three>333</i>";
  const char* shadow_content =
      "<p><u id=four>44444</u><slot name=#two></slot><span id=space> "
      "</span><slot name=#one></slot><u id=five>55555</u></p>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = shadow_root->getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();

  EXPECT_EQ(Position(five, 5), EndOfWordPosition(Position(*one, 0)));
  EXPECT_EQ(PositionInFlatTree(five, 5),
            EndOfWordPosition(PositionInFlatTree(*one, 0)));

  EXPECT_EQ(Position(five, 5), EndOfWordPosition(Position(*one, 1)));
  EXPECT_EQ(PositionInFlatTree(five, 5),
            EndOfWordPosition(PositionInFlatTree(*one, 1)));

  EXPECT_EQ(Position(two, 2), EndOfWordPosition(Position(*two, 0)));
  EXPECT_EQ(PositionInFlatTree(two, 2),
            EndOfWordPosition(PositionInFlatTree(*two, 0)));

  EXPECT_EQ(Position(two, 2), EndOfWordPosition(Position(*two, 1)));
  EXPECT_EQ(PositionInFlatTree(two, 2),
            EndOfWordPosition(PositionInFlatTree(*two, 1)));

  EXPECT_EQ(Position(three, 3), EndOfWordPosition(Position(*three, 1)));
  EXPECT_EQ(PositionInFlatTree(three, 3),
            EndOfWordPosition(PositionInFlatTree(*three, 1)));

  EXPECT_EQ(Position(two, 2), EndOfWordPosition(Position(*four, 1)));
  EXPECT_EQ(PositionInFlatTree(two, 2),
            EndOfWordPosition(PositionInFlatTree(*four, 1)));

  EXPECT_EQ(Position(five, 5), EndOfWordPosition(Position(*five, 1)));
  EXPECT_EQ(PositionInFlatTree(five, 5),
            EndOfWordPosition(PositionInFlatTree(*five, 1)));
}

TEST_F(VisibleUnitsWordTest, EndOfWordTextSecurity) {
  // Note: |EndOfWord()| considers security characters as a sequence "x".
  InsertStyleElement("s {-webkit-text-security:disc;}");
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("|abc<s>foo bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc|<s>foo bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>|foo bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>f|oo bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo| bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo |bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo bar|</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo bar</s>|baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo bar</s>b|az"));
}

TEST_F(VisibleUnitsWordTest, EndOfWordTextControl) {
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("|foo<input value=\"bla\">bar"));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("f|oo<input value=\"bla\">bar"));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("fo|o<input value=\"bla\">bar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoEndOfWord("foo|<input value=\"bla\">bar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">|bar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">b|ar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">ba|r"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">bar|"));
}

TEST_F(VisibleUnitsWordTest, EndOfWordPreviousWordIfOnBoundaryTextControl) {
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoEndOfWord("|foo<input value=\"bla\">bar",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("f|oo<input value=\"bla\">bar",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo|<input value=\"bla\">
Prompt: 
```
这是目录为blink/renderer/core/editing/visible_units_word_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"

namespace blink {

class VisibleUnitsWordTest : public EditingTestBase {
 protected:
  std::string DoStartOfWord(
      const std::string& selection_text,
      WordSide word_side = WordSide::kNextWordIfOnBoundary) {
    const Position position = SetCaretTextToBody(selection_text);
    return GetCaretTextFromBody(StartOfWordPosition(position, word_side));
  }

  std::string DoEndOfWord(
      const std::string& selection_text,
      WordSide word_side = WordSide::kNextWordIfOnBoundary) {
    const Position position = SetCaretTextToBody(selection_text);
    return GetCaretTextFromBody(EndOfWordPosition(position, word_side));
  }

  std::string DoNextWord(const std::string& selection_text) {
    const Position position = SetCaretTextToBody(selection_text);
    const PlatformWordBehavior platform_word_behavior =
        PlatformWordBehavior::kWordDontSkipSpaces;
    return GetCaretTextFromBody(
        CreateVisiblePosition(
            NextWordPosition(position, platform_word_behavior))
            .DeepEquivalent());
  }

  std::string DoNextWordSkippingSpaces(const std::string& selection_text) {
    const Position position = SetCaretTextToBody(selection_text);
    const PlatformWordBehavior platform_word_behavior =
        PlatformWordBehavior::kWordSkipSpaces;
    return GetCaretTextFromBody(
        CreateVisiblePosition(
            NextWordPosition(position, platform_word_behavior))
            .DeepEquivalent());
  }

  std::string DoPreviousWord(const std::string& selection_text) {
    const Position position = SetCaretTextToBody(selection_text);
    const Position result =
        CreateVisiblePosition(PreviousWordPosition(position)).DeepEquivalent();
    if (result.IsNull())
      return GetSelectionTextFromBody(SelectionInDOMTree());
    return GetCaretTextFromBody(result);
  }

  std::string DoMiddleOfWord(const std::string& selection_text) {
    SelectionInDOMTree selection = SetSelectionTextToBody(selection_text);
    return GetCaretTextFromBody(
        MiddleOfWordPosition(selection.Anchor(), selection.Focus()));
  }

  // To avoid name conflict in jumbo build, following functions should be here.
  static VisiblePosition CreateVisiblePositionInDOMTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(Position(&anchor, offset), affinity);
  }

  static VisiblePositionInFlatTree CreateVisiblePositionInFlatTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(PositionInFlatTree(&anchor, offset), affinity);
  }
};

TEST_F(VisibleUnitsWordTest, StartOfWordBasic) {
  EXPECT_EQ("<p> |(1) abc def</p>", DoStartOfWord("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> |(1) abc def</p>", DoStartOfWord("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>", DoStartOfWord("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoStartOfWord("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1)| abc def</p>", DoStartOfWord("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoStartOfWord("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoStartOfWord("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoStartOfWord("<p> (1) abc def</p>|"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordPreviousWordIfOnBoundaryBasic) {
  EXPECT_EQ("<p> |(1) abc def</p>",
            DoStartOfWord("<p>| (1) abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> |(1) abc def</p>",
            DoStartOfWord("<p> |(1) abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> |(1) abc def</p>",
            DoStartOfWord("<p> (|1) abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (|1) abc def</p>",
            DoStartOfWord("<p> (1|) abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1|) abc def</p>",
            DoStartOfWord("<p> (1)| abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1)| abc def</p>",
            DoStartOfWord("<p> (1) |abc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) |abc def</p>",
            DoStartOfWord("<p> (1) a|bc def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) |abc def</p>",
            DoStartOfWord("<p> (1) ab|c def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) |abc def</p>",
            DoStartOfWord("<p> (1) abc| def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc| def</p>",
            DoStartOfWord("<p> (1) abc |def</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoStartOfWord("<p> (1) abc d|ef</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoStartOfWord("<p> (1) abc de|f</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoStartOfWord("<p> (1) abc def|</p>",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoStartOfWord("<p> (1) abc def</p>|",
                          WordSide::kPreviousWordIfOnBoundary));
}

TEST_F(VisibleUnitsWordTest, StartOfWordCrossing) {
  EXPECT_EQ("<b>|abc</b><i>def</i>", DoStartOfWord("<b>abc</b><i>|def</i>"));
  EXPECT_EQ("<b>abc</b><i>def|</i>", DoStartOfWord("<b>abc</b><i>def</i>|"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordFirstLetter) {
  InsertStyleElement("p::first-letter {font-size:200%;}");
  // Note: Expectations should match with |StartOfWordBasic|.
  EXPECT_EQ("<p> |(1) abc def</p>", DoStartOfWord("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> |(1) abc def</p>", DoStartOfWord("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>", DoStartOfWord("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoStartOfWord("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1)| abc def</p>", DoStartOfWord("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoStartOfWord("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoStartOfWord("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoStartOfWord("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoStartOfWord("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoStartOfWord("<p> (1) abc def</p>|"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordShadowDOM) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>1</b> <b slot='#two' "
      "id=two>22</b></span><i id=three>333</i>";
  const char* shadow_content =
      "<p><u id=four>44444</u><slot name=#two></slot><span id=space> "
      "</span><slot name=#one></slot><u id=five>55555</u></p>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = shadow_root->getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();
  Node* space =
      shadow_root->getElementById(AtomicString("space"))->firstChild();

  EXPECT_EQ(Position(one, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*one, 0).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(space, 1),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*one, 0).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(one, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*one, 1).DeepEquivalent()))
                .DeepEquivalent());

  EXPECT_EQ(PositionInFlatTree(space, 1),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*one, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*two, 0).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*two, 0).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*two, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*two, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(three, 0),
            CreateVisiblePosition(
                StartOfWordPosition(CreateVisiblePositionInDOMTree(
                                        *three, 1, TextAffinity::kUpstream)
                                        .DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(three, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*three, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(three, 0),
      CreateVisiblePosition(
          StartOfWordPosition(
              CreateVisiblePositionInFlatTree(*three, 1).DeepEquivalent()))
          .DeepEquivalent());
  EXPECT_EQ(Position(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*four, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*four, 1).DeepEquivalent()))
                .DeepEquivalent());
  EXPECT_EQ(Position(one, 0),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInDOMTree(*five, 1).DeepEquivalent()))
                .DeepEquivalent());
  // Flat tree canonicalization moves result to downstream position
  EXPECT_EQ(PositionInFlatTree(space, 1),
            CreateVisiblePosition(
                StartOfWordPosition(
                    CreateVisiblePositionInFlatTree(*five, 1).DeepEquivalent()))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsWordTest, StartOfWordTextSecurity) {
  // Note: |StartOfWordPosition()| considers security characters
  // as a sequence "x".
  InsertStyleElement("s {-webkit-text-security:disc;}");
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("|abc<s>foo bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc|<s>foo bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>|foo bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>f|oo bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo| bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo |bar</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo bar|</s>baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo bar</s>|baz"));
  EXPECT_EQ("|abc<s>foo bar</s>baz", DoStartOfWord("abc<s>foo bar</s>b|az"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordTextControl) {
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("|foo<input value=\"bla\">bar"));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("f|oo<input value=\"bla\">bar"));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("fo|o<input value=\"bla\">bar"));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoStartOfWord("foo|<input value=\"bla\">bar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">|bar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">b|ar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">ba|r"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoStartOfWord("foo<input value=\"bla\">bar|"));
}

TEST_F(VisibleUnitsWordTest, StartOfWordPreviousWordIfOnBoundaryTextControl) {
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("|foo<input value=\"bla\">bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("f|oo<input value=\"bla\">bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("fo|o<input value=\"bla\">bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoStartOfWord("foo|<input value=\"bla\">bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoStartOfWord("foo<input value=\"bla\">|bar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">b|ar",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">ba|r",
                          WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoStartOfWord("foo<input value=\"bla\">bar|",
                          WordSide::kPreviousWordIfOnBoundary));
}

TEST_F(VisibleUnitsWordTest, EndOfWordBasic) {
  EXPECT_EQ("<p> (|1) abc def</p>", DoEndOfWord("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>", DoEndOfWord("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoEndOfWord("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (1)| abc def</p>", DoEndOfWord("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoEndOfWord("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoEndOfWord("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoEndOfWord("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoEndOfWord("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoEndOfWord("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoEndOfWord("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoEndOfWord("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoEndOfWord("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoEndOfWord("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc def</p>|", DoEndOfWord("<p> (1) abc def</p>|"));
}

TEST_F(VisibleUnitsWordTest, EndOfWordPreviousWordIfOnBoundaryBasic) {
  EXPECT_EQ(
      "<p> |(1) abc def</p>",
      DoEndOfWord("<p>| (1) abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> |(1) abc def</p>",
      DoEndOfWord("<p> |(1) abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (|1) abc def</p>",
      DoEndOfWord("<p> (|1) abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1|) abc def</p>",
      DoEndOfWord("<p> (1|) abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1)| abc def</p>",
      DoEndOfWord("<p> (1)| abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) |abc def</p>",
      DoEndOfWord("<p> (1) |abc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc| def</p>",
      DoEndOfWord("<p> (1) a|bc def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc| def</p>",
      DoEndOfWord("<p> (1) ab|c def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc| def</p>",
      DoEndOfWord("<p> (1) abc| def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc |def</p>",
      DoEndOfWord("<p> (1) abc |def</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc def|</p>",
      DoEndOfWord("<p> (1) abc d|ef</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc def|</p>",
      DoEndOfWord("<p> (1) abc de|f</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc def|</p>",
      DoEndOfWord("<p> (1) abc def|</p>", WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ(
      "<p> (1) abc def</p>|",
      DoEndOfWord("<p> (1) abc def</p>|", WordSide::kPreviousWordIfOnBoundary));
}

TEST_F(VisibleUnitsWordTest, EndOfWordShadowDOM) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>1</b> <b slot='#two' "
      "id=two>22</b></span><i id=three>333</i>";
  const char* shadow_content =
      "<p><u id=four>44444</u><slot name=#two></slot><span id=space> "
      "</span><slot name=#one></slot><u id=five>55555</u></p>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = shadow_root->getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();

  EXPECT_EQ(Position(five, 5), EndOfWordPosition(Position(*one, 0)));
  EXPECT_EQ(PositionInFlatTree(five, 5),
            EndOfWordPosition(PositionInFlatTree(*one, 0)));

  EXPECT_EQ(Position(five, 5), EndOfWordPosition(Position(*one, 1)));
  EXPECT_EQ(PositionInFlatTree(five, 5),
            EndOfWordPosition(PositionInFlatTree(*one, 1)));

  EXPECT_EQ(Position(two, 2), EndOfWordPosition(Position(*two, 0)));
  EXPECT_EQ(PositionInFlatTree(two, 2),
            EndOfWordPosition(PositionInFlatTree(*two, 0)));

  EXPECT_EQ(Position(two, 2), EndOfWordPosition(Position(*two, 1)));
  EXPECT_EQ(PositionInFlatTree(two, 2),
            EndOfWordPosition(PositionInFlatTree(*two, 1)));

  EXPECT_EQ(Position(three, 3), EndOfWordPosition(Position(*three, 1)));
  EXPECT_EQ(PositionInFlatTree(three, 3),
            EndOfWordPosition(PositionInFlatTree(*three, 1)));

  EXPECT_EQ(Position(two, 2), EndOfWordPosition(Position(*four, 1)));
  EXPECT_EQ(PositionInFlatTree(two, 2),
            EndOfWordPosition(PositionInFlatTree(*four, 1)));

  EXPECT_EQ(Position(five, 5), EndOfWordPosition(Position(*five, 1)));
  EXPECT_EQ(PositionInFlatTree(five, 5),
            EndOfWordPosition(PositionInFlatTree(*five, 1)));
}

TEST_F(VisibleUnitsWordTest, EndOfWordTextSecurity) {
  // Note: |EndOfWord()| considers security characters as a sequence "x".
  InsertStyleElement("s {-webkit-text-security:disc;}");
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("|abc<s>foo bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc|<s>foo bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>|foo bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>f|oo bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo| bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo |bar</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo bar|</s>baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo bar</s>|baz"));
  EXPECT_EQ("abc<s>foo bar</s>baz|", DoEndOfWord("abc<s>foo bar</s>b|az"));
}

TEST_F(VisibleUnitsWordTest, EndOfWordTextControl) {
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("|foo<input value=\"bla\">bar"));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("f|oo<input value=\"bla\">bar"));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("fo|o<input value=\"bla\">bar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoEndOfWord("foo|<input value=\"bla\">bar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">|bar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">b|ar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">ba|r"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">bar|"));
}

TEST_F(VisibleUnitsWordTest, EndOfWordPreviousWordIfOnBoundaryTextControl) {
  EXPECT_EQ("|foo<input value=\"bla\">bar",
            DoEndOfWord("|foo<input value=\"bla\">bar",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("f|oo<input value=\"bla\">bar",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("fo|o<input value=\"bla\">bar",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoEndOfWord("foo|<input value=\"bla\">bar",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoEndOfWord("foo<input value=\"bla\">|bar",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">b|ar",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">ba|r",
                        WordSide::kPreviousWordIfOnBoundary));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoEndOfWord("foo<input value=\"bla\">bar|",
                        WordSide::kPreviousWordIfOnBoundary));
}

TEST_F(VisibleUnitsWordTest, NextWordSkipSpacesBasic) {
  EXPECT_EQ("<p> (|1) abc def</p>",
            DoNextWordSkippingSpaces("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>",
            DoNextWordSkippingSpaces("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>",
            DoNextWordSkippingSpaces("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>",
            DoNextWordSkippingSpaces("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>",
            DoNextWordSkippingSpaces("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoNextWordSkippingSpaces("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoNextWordSkippingSpaces("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoNextWordSkippingSpaces("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>",
            DoNextWordSkippingSpaces("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>",
            DoNextWordSkippingSpaces("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>",
            DoNextWordSkippingSpaces("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>",
            DoNextWordSkippingSpaces("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>",
            DoNextWordSkippingSpaces("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>",
            DoNextWordSkippingSpaces("<p> (1) abc def</p>|"));
}

TEST_F(VisibleUnitsWordTest, NextWordBasic) {
  EXPECT_EQ("<p> (|1) abc def</p>", DoNextWord("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>", DoNextWord("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoNextWord("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (1)| abc def</p>", DoNextWord("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoNextWord("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoNextWord("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoNextWord("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) abc| def</p>", DoNextWord("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoNextWord("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoNextWord("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoNextWord("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoNextWord("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoNextWord("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc def|</p>", DoNextWord("<p> (1) abc def</p>|"));
}

TEST_F(VisibleUnitsWordTest, NextWordCrossingBlock) {
  EXPECT_EQ("<p>abc|</p><p>def</p>", DoNextWord("<p>|abc</p><p>def</p>"));
  EXPECT_EQ("<p>abc</p><p>|def</p>", DoNextWord("<p>abc|</p><p>def</p>"));
}

TEST_F(VisibleUnitsWordTest, NextWordCrossingPlaceholderBR) {
  EXPECT_EQ("<p><br></p><p>|abc</p>", DoNextWord("<p>|<br></p><p>abc</p>"));
}

TEST_F(VisibleUnitsWordTest, NextWordMixedEditability) {
  EXPECT_EQ(
      "<p contenteditable>"
      "abc<b contenteditable=\"false\">def ghi</b>|jkl mno</p>",
      DoNextWord("<p contenteditable>"
                 "|abc<b contenteditable=false>def ghi</b>jkl mno</p>"));
  EXPECT_EQ(
      "<p contenteditable>"
      "abc<b contenteditable=\"false\">def| ghi</b>jkl mno</p>",
      DoNextWord("<p contenteditable>"
                 "abc<b contenteditable=false>|def ghi</b>jkl mno</p>"));
  EXPECT_EQ(
      "<p contenteditable>"
      "abc<b contenteditable=\"false\">def ghi|</b>jkl mno</p>",
      DoNextWord("<p contenteditable>"
                 "abc<b contenteditable=false>def |ghi</b>jkl mno</p>"));
  EXPECT_EQ(
      "<p contenteditable>"
      "abc<b contenteditable=\"false\">def ghi|</b>jkl mno</p>",
      DoNextWord("<p contenteditable>"
                 "abc<b contenteditable=false>def ghi|</b>jkl mno</p>"));
}

TEST_F(VisibleUnitsWordTest, NextWordPunctuation) {
  EXPECT_EQ("abc|.def", DoNextWord("|abc.def"));
  EXPECT_EQ("abc|.def", DoNextWord("a|bc.def"));
  EXPECT_EQ("abc|.def", DoNextWord("ab|c.def"));
  EXPECT_EQ("abc.|def", DoNextWord("abc|.def"));
  EXPECT_EQ("abc.def|", DoNextWord("abc.|def"));

  EXPECT_EQ("abc|...def", DoNextWord("|abc...def"));
  EXPECT_EQ("abc|...def", DoNextWord("a|bc...def"));
  EXPECT_EQ("abc|...def", DoNextWord("ab|c...def"));
  EXPECT_EQ("abc...|def", DoNextWord("abc|...def"));
  EXPECT_EQ("abc...|def", DoNextWord("abc.|..def"));
  EXPECT_EQ("abc...|def", DoNextWord("abc..|.def"));
  EXPECT_EQ("abc...def|", DoNextWord("abc...|def"));

  EXPECT_EQ("abc| ((())) def", DoNextWord("|abc ((())) def"));
  EXPECT_EQ("abc ((()))| def", DoNextWord("abc |((())) def"));
  EXPECT_EQ("abc| 32.3 def", DoNextWord("|abc 32.3 def"));
  EXPECT_EQ("abc 32.3| def", DoNextWord("abc |32.3 def"));
}

TEST_F(VisibleUnitsWordTest, NextWordSkipTab) {
  InsertStyleElement("s { white-space: pre }");
  EXPECT_EQ("<p><s>\t</s>foo|</p>", DoNextWord("<p><s>\t|</s>foo</p>"));
}

TEST_F(VisibleUnitsWordTest, NextWordSkipTextControl) {
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoNextWord("|foo<input value=\"bla\">bar"));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoNextWord("f|oo<input value=\"bla\">bar"));
  EXPECT_EQ("foo|<input value=\"bla\">bar",
            DoNextWord("fo|o<input value=\"bla\">bar"));
  EXPECT_EQ("foo<input value=\"bla\">|bar",
            DoNextWord("foo|<input value=\"bla\">bar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoNextWord("foo<input value=\"bla\">|bar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoNextWord("foo<input value=\"bla\">b|ar"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoNextWord("foo<input value=\"bla\">ba|r"));
  EXPECT_EQ("foo<input value=\"bla\">bar|",
            DoNextWord("foo<input value=\"bla\">bar|"));
}

TEST_F(VisibleUnitsWordTest, NextWordSkipSpacesEmoji) {
  EXPECT_EQ("<p> abc |😂 def</p>",
            DoNextWordSkippingSpaces("<p> |abc &#x1F602; def</p>"));
  EXPECT_EQ("<p> abc 😂 |def</p>",
            DoNextWordSkippingSpaces("<p> abc |&#x1F602; def</p>"));
  EXPECT_EQ("<p> abc 😂 def|</p>",
            DoNextWordSkippingSpaces("<p> abc &#x1F602; |def</p>"));
}

TEST_F(VisibleUnitsWordTest, NextWordEmoji) {
  EXPECT_EQ("<p> abc| 😂 def</p>", DoNextWord("<p> |abc &#x1F602; def</p>"));
  EXPECT_EQ("<p> abc 😂| def</p>", DoNextWord("<p> abc |&#x1F602; def</p>"));
  EXPECT_EQ("<p> abc 😂 def|</p>", DoNextWord("<p> abc &#x1F602; |def</p>"));
}

TEST_F(VisibleUnitsWordTest, NextWordEmojiSequence) {
  EXPECT_EQ("<p> abc| 😂😂 def</p>",
            DoNextWord("<p> |abc &#x1F602;&#x1F602; def</p>"));
  EXPECT_EQ("<p> abc 😂😂| def</p>",
            DoNextWord("<p> abc |&#x1F602;&#x1F602; def</p>"));
  EXPECT_EQ("<p> abc 😂😂 def|</p>",
            DoNextWord("<p> abc &#x1F602;&#x1F602; |def</p>"));
}

//----

TEST_F(VisibleUnitsWordTest, PreviousWordBasic) {
  EXPECT_EQ("<p> |(1) abc def</p>", DoPreviousWord("<p>| (1) abc def</p>"));
  EXPECT_EQ("<p> |(1) abc def</p>", DoPreviousWord("<p> |(1) abc def</p>"));
  EXPECT_EQ("<p> |(1) abc def</p>", DoPreviousWord("<p> (|1) abc def</p>"));
  EXPECT_EQ("<p> (|1) abc def</p>", DoPreviousWord("<p> (1|) abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoPreviousWord("<p> (1)| abc def</p>"));
  EXPECT_EQ("<p> (1|) abc def</p>", DoPreviousWord("<p> (1) |abc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoPreviousWord("<p> (1) a|bc def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoPreviousWord("<p> (1) ab|c def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoPreviousWord("<p> (1) abc| def</p>"));
  EXPECT_EQ("<p> (1) |abc def</p>", DoPreviousWord("<p> (1) abc |def</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoPreviousWord("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoPreviousWord("<p> (1) abc de|f</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoPreviousWord("<p> (1) abc def|</p>"));
  EXPECT_EQ("<p> (1) abc |def</p>", DoPreviousWord("<p> (1) abc def</p>|"));
  EXPECT_EQ("<p> |abc ((())) def</p>",
            DoPreviousWord("<p> abc |((())) def</p>"));
  EXPECT_EQ("<p> abc |((())) def</p>",
            DoPreviousWord("<p> abc ((())) |def</p>"));
  EXPECT_EQ("<p> |abc 32.3 def</p>", DoPreviousWord("<p> abc |32.3 def</p>"));
  EXPECT_EQ("<p> abc |32.3 def</p>", DoPreviousWord("<p> abc 32.3 |def</p>"));
}

TEST_F(VisibleUnitsWordTest, PreviousWordCrossingBlock) {
  EXPECT_EQ("<p>abc|</p><p>def</p>", DoPreviousWord("<p>abc</p><p>|def</p>"));
}

TEST_F(VisibleUnitsWordTest, PreviousWordCrossingPlaceholderBR) {
  EXPECT_EQ("<p>|<br></p><p>abc</p>", DoPreviousWord("<p><br></p><p>|abc</p>"));
}

TEST_F(VisibleUnitsWordTest, PreviousWordInFloat) {
  InsertStyleElement(
      "c { display: block; float: right; }"
      "e { display: block; }");

  // To "|abc"
  EXPECT_EQ("<c><e>|abc def ghi</e></c>",
            DoPreviousWord("<c><e>|abc def ghi</e></c>"));
  EXPECT_EQ("<c><e>|abc def ghi</e></c>",
            DoPreviousWord("<c><e>a|bc def ghi</e></c>"));
  EXPECT_EQ("<c><e>|abc def ghi</e></c>",
            DoPreviousWord("<c><e>ab|c def ghi</e></c>"));
  EXPECT_EQ("<c><e>|abc def ghi</e></c>",
            DoPreviousWord("<c><e>abc| def ghi</e></c>"));
  EXPECT_EQ("<c><e>|abc def ghi</e></c>",
   
"""


```