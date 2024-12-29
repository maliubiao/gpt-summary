Response:
The user wants to understand the functionality of the provided C++ source code file. The file seems to be testing the calculation of the caret (text cursor) position in scenarios involving bidirectional text.

Here's a breakdown of how to address the user's request:

1. **Identify the Core Functionality:** The file's name and content strongly suggest it tests the `LocalCaretRectOfPosition` function, specifically focusing on how it handles bidirectional text (`Bidi`).

2. **Explain the Test Structure:** The code uses the `TEST_F` macro, indicating it's a Google Test framework file. Each test case sets up a specific HTML structure with bidirectional text and verifies the calculated caret position.

3. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    - **HTML:** The tests directly manipulate HTML structure using `<div dir>`, `<bdo dir>`, and text content. These HTML elements are fundamental to controlling text direction.
    - **CSS:** The `InsertStyleElement` function injects CSS to control font and width, affecting the visual layout and therefore the caret position.
    - **JavaScript:** While this specific file doesn't directly use JavaScript, it's crucial to understand that JavaScript can dynamically modify the DOM, including text direction, which could lead to the execution paths tested here.

4. **Explain the Logic and Provide Examples:**
    - **Bidirectional Text:** Define what bidirectional text is and the challenges it presents for caret positioning.
    - **`dir` Attribute:** Explain how the `dir` attribute (ltr/rtl) works on HTML elements.
    - **`<bdo>` Element:** Explain the purpose of the `<bdo>` element in overriding the default bidirectional algorithm.
    - **Test Case Structure:** Illustrate how each test case sets up an HTML snippet, places the caret (`|`), and asserts the expected caret rectangle (`PhysicalRect`).
    - **Visual Order vs. Logical Order:** Emphasize the difference between how the text is stored (logical order) and how it's displayed (visual order) in bidirectional text.

5. **Address Potential User Errors:** Focus on common mistakes users might make when working with bidirectional text in HTML, such as incorrect or missing `dir` attributes.

6. **Explain How a User Might Reach This Code (Debugging Scenario):** Describe the steps a developer might take that would involve the caret positioning logic being tested. This helps the user understand the context of the code.

7. **Summarize the Functionality for Part 1:** Provide a concise summary of the file's purpose based on the analysis.

**Constraint Checklist & Confidence Score:**

* Provide the functionality: Yes
* Relationship with JavaScript, HTML, CSS: Yes
* Examples for web technologies: Yes
* Logical reasoning: Yes
* Assumptions with input and output: Yes (inferred from test cases)
* Common user/programming errors: Yes
* User operation steps: Yes
* Summarize functionality (Part 1): Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I mentally walked through a few of the test cases, visualizing how the bidirectional algorithm would reorder the text and how the caret position would be calculated. I considered scenarios where the `dir` attribute is used on different elements and how nesting affects the final visual order. I also imagined a developer trying to debug an issue where the caret appears in the wrong place in bidirectional text and how these tests could help pinpoint the problem.
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/local_caret_rect.h"

#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class LocalCaretRectBidiTest : public EditingTestBase {};

// This file contains script-generated tests for LocalCaretRectOfPosition()
// that are related to Bidirectional text. The test cases are only for
// behavior recording purposes, and do not necessarily reflect the
// correct/desired behavior.

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterRtlRunTouchingLineBoundary) {
  // Sample: A B C|d e f
  // Bidi:   1 1 1 0 0 0
  // Visual: C B A|d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>ABC</bdo>|def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterRtlRun) {
  // Sample: g h i A B C|d e f
  // Bidi:   0 0 0 1 1 1 0 0 0
  // Visual: g h i C B A|d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi<bdo dir=rtl>ABC</bdo>|def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterRtlRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: A B C|d e f
  // Bidi:   1 1 1 0 0 0
  // Visual: C B A|d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>ABC|</bdo>def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterRtlRunAtDeepPosition) {
  // Sample: g h i A B C|d e f
  // Bidi:   0 0 0 1 1 1 0 0 0
  // Visual: g h i C B A|d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi<bdo dir=rtl>ABC|</bdo>def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterTwoNestedRuns) {
  // Sample: D E F a b c|g h i
  // Bidi:   1 1 1 2 2 2 0 0 0
  // Visual: a b c F E D|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>|ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterTwoNestedRunsAtDeepPosition) {
  // Sample: D E F a b c|g h i
  // Bidi:   1 1 1 2 2 2 0 0 0
  // Visual: a b c F E D|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc|</bdo></bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterThreeNestedRuns) {
  // Sample: G H I d e f A B C|j k l
  // Bidi:   1 1 1 2 2 2 3 3 3 0 0 0
  // Visual: d e f C B A I H G|j k l
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo>|jkl</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterThreeNestedRunsAtDeepPosition) {
  // Sample: G H I d e f A B C|j k l
  // Bidi:   1 1 1 2 2 2 3 3 3 0 0 0
  // Visual: d e f C B A I H G|j k l
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC|</bdo></bdo></bdo>jkl</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterFourNestedRuns) {
  // Sample: J K L g h i D E F a b c|m n o
  // Bidi:   1 1 1 2 2 2 3 3 3 4 4 4 0 0 0
  // Visual: g h i a b c F E D L K J|m n o
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo "
      "dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></bdo></bdo>|mno</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(120, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterFourNestedRunsAtDeepPosition) {
  // Sample: J K L g h i D E F a b c|m n o
  // Bidi:   1 1 1 2 2 2 3 3 3 4 4 4 0 0 0
  // Visual: g h i a b c F E D L K J|m n o
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo "
      "dir=rtl>DEF<bdo dir=ltr>abc|</bdo></bdo></bdo></bdo>mno</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeRtlRunTouchingLineBoundary) {
  // Sample: d e f|A B C
  // Bidi:   0 0 0 1 1 1
  // Visual: d e f|C B A
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def|<bdo dir=rtl>ABC</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeRtlRun) {
  // Sample: d e f|A B C g h i
  // Bidi:   0 0 0 1 1 1 0 0 0
  // Visual: d e f|C B A g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def|<bdo dir=rtl>ABC</bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeRtlRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: d e f|A B C
  // Bidi:   0 0 0 1 1 1
  // Visual: d e f|C B A
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def<bdo dir=rtl>|ABC</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeRtlRunAtDeepPosition) {
  // Sample: d e f|A B C g h i
  // Bidi:   0 0 0 1 1 1 0 0 0
  // Visual: d e f|C B A g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def<bdo dir=rtl>|ABC</bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeTwoNestedRuns) {
  // Sample: g h i|a b c D E F
  // Bidi:   0 0 0 2 2 2 1 1 1
  // Visual: g h i|F E D a b c
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi|<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeTwoNestedRunsAtDeepPosition) {
  // Sample: g h i|a b c D E F
  // Bidi:   0 0 0 2 2 2 1 1 1
  // Visual: g h i|F E D a b c
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>|abc</bdo>DEF</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeThreeNestedRuns) {
  // Sample: j k l|A B C d e f G H I
  // Bidi:   0 0 0 3 3 3 2 2 2 1 1 1
  // Visual: j k l I H G|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>jkl|<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeThreeNestedRunsAtDeepPosition) {
  // Sample: j k l|A B C d e f G H I
  // Bidi:   0 0 0 3 3 3 2 2 2 1 1 1
  // Visual: j k l I H G|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>jkl<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>|ABC</bdo>def</bdo>GHI</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeFourNestedRuns) {
  // Sample: m n o|a b c D E F g h i J K L
  // Bidi:   0 0 0 4 4 4 3 3 3 2 2 2 1 1 1
  // Visual: m n o L K J|F E D a b c g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>mno|<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo>ghi</bdo>JKL</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeFourNestedRunsAtDeepPosition) {
  // Sample: m n o|a b c D E F g h i J K L
  // Bidi:   0 0 0 4 4 4 3 3 3 2 2 2 1 1 1
  // Visual: m n o L K J|F E D a b c g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>mno<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl><bdo dir=ltr>|abc</bdo>DEF</bdo>ghi</bdo>JKL</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterLtrRunTouchingLineBoundary) {
  // Sample: a b c|D E F
  // Bidi:   2 2 2 1 1 1
  // Visual: F E D a b c|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc</bdo>|DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterLtrRun) {
  // Sample: G H I a b c|D E F
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: F E D a b c|I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>|DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterLtrRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: a b c|D E F
  // Bidi:   2 2 2 1 1 1
  // Visual: F E D a b c|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc|</bdo>DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterLtrRunAtDeepPosition) {
  // Sample: G H I a b c|D E F
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: F E D a b c|I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>abc|</bdo>DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterTwoNestedRuns) {
  // Sample: d e f A B C|G H I
  // Bidi:   2 2 2 3 3 3 1 1 1
  // Visual: I H G d e f C B A|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>|GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterTwoNestedRunsAtDeepPosition) {
  // Sample: d e f A B C|G H I
  // Bidi:   2 2 2 3 3 3 1 1 1
  // Visual: I H G d e f C B A|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC|</bdo></bdo>GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterThreeNestedRuns) {
  // Sample: g h i D E F a b c|J K L
  // Bidi:   2 2 2 3 3 3 4 4 4 1 1 1
  // Visual: L K J g h i a b c F E D|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo></bdo>|JKL</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(120, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterThreeNestedRunsAtDeepPosition) {
  // Sample: g h i D E F a b c|J K L
  // Bidi:   2 2 2 3 3 3 4 4 4 1 1 1
  // Visual: L K J g h i a b c F E D|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc|</bdo></bdo></bdo>JKL</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(120, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterFourNestedRuns) {
  // Sample: j k l G H I d e f A B C|M N O
  // Bidi:   2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  // Visual: O N M j k l d e f C B A I H G|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo></bdo></bdo>|MNO</b
Prompt: 
```
这是目录为blink/renderer/core/editing/local_caret_rect_bidi_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/local_caret_rect.h"

#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class LocalCaretRectBidiTest : public EditingTestBase {};

// This file contains script-generated tests for LocalCaretRectOfPosition()
// that are related to Bidirectional text. The test cases are only for
// behavior recording purposes, and do not necessarily reflect the
// correct/desired behavior.

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterRtlRunTouchingLineBoundary) {
  // Sample: A B C|d e f
  // Bidi:   1 1 1 0 0 0
  // Visual: C B A|d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>ABC</bdo>|def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterRtlRun) {
  // Sample: g h i A B C|d e f
  // Bidi:   0 0 0 1 1 1 0 0 0
  // Visual: g h i C B A|d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi<bdo dir=rtl>ABC</bdo>|def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterRtlRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: A B C|d e f
  // Bidi:   1 1 1 0 0 0
  // Visual: C B A|d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>ABC|</bdo>def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterRtlRunAtDeepPosition) {
  // Sample: g h i A B C|d e f
  // Bidi:   0 0 0 1 1 1 0 0 0
  // Visual: g h i C B A|d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi<bdo dir=rtl>ABC|</bdo>def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterTwoNestedRuns) {
  // Sample: D E F a b c|g h i
  // Bidi:   1 1 1 2 2 2 0 0 0
  // Visual: a b c F E D|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>|ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterTwoNestedRunsAtDeepPosition) {
  // Sample: D E F a b c|g h i
  // Bidi:   1 1 1 2 2 2 0 0 0
  // Visual: a b c F E D|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc|</bdo></bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterThreeNestedRuns) {
  // Sample: G H I d e f A B C|j k l
  // Bidi:   1 1 1 2 2 2 3 3 3 0 0 0
  // Visual: d e f C B A I H G|j k l
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo>|jkl</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterThreeNestedRunsAtDeepPosition) {
  // Sample: G H I d e f A B C|j k l
  // Bidi:   1 1 1 2 2 2 3 3 3 0 0 0
  // Visual: d e f C B A I H G|j k l
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC|</bdo></bdo></bdo>jkl</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunAfterFourNestedRuns) {
  // Sample: J K L g h i D E F a b c|m n o
  // Bidi:   1 1 1 2 2 2 3 3 3 4 4 4 0 0 0
  // Visual: g h i a b c F E D L K J|m n o
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo "
      "dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></bdo></bdo>|mno</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(120, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunAfterFourNestedRunsAtDeepPosition) {
  // Sample: J K L g h i D E F a b c|m n o
  // Bidi:   1 1 1 2 2 2 3 3 3 4 4 4 0 0 0
  // Visual: g h i a b c F E D L K J|m n o
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo "
      "dir=rtl>DEF<bdo dir=ltr>abc|</bdo></bdo></bdo></bdo>mno</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeRtlRunTouchingLineBoundary) {
  // Sample: d e f|A B C
  // Bidi:   0 0 0 1 1 1
  // Visual: d e f|C B A
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def|<bdo dir=rtl>ABC</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeRtlRun) {
  // Sample: d e f|A B C g h i
  // Bidi:   0 0 0 1 1 1 0 0 0
  // Visual: d e f|C B A g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def|<bdo dir=rtl>ABC</bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeRtlRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: d e f|A B C
  // Bidi:   0 0 0 1 1 1
  // Visual: d e f|C B A
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def<bdo dir=rtl>|ABC</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeRtlRunAtDeepPosition) {
  // Sample: d e f|A B C g h i
  // Bidi:   0 0 0 1 1 1 0 0 0
  // Visual: d e f|C B A g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def<bdo dir=rtl>|ABC</bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeTwoNestedRuns) {
  // Sample: g h i|a b c D E F
  // Bidi:   0 0 0 2 2 2 1 1 1
  // Visual: g h i|F E D a b c
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi|<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeTwoNestedRunsAtDeepPosition) {
  // Sample: g h i|a b c D E F
  // Bidi:   0 0 0 2 2 2 1 1 1
  // Visual: g h i|F E D a b c
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>|abc</bdo>DEF</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeThreeNestedRuns) {
  // Sample: j k l|A B C d e f G H I
  // Bidi:   0 0 0 3 3 3 2 2 2 1 1 1
  // Visual: j k l I H G|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>jkl|<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeThreeNestedRunsAtDeepPosition) {
  // Sample: j k l|A B C d e f G H I
  // Bidi:   0 0 0 3 3 3 2 2 2 1 1 1
  // Visual: j k l I H G|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>jkl<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>|ABC</bdo>def</bdo>GHI</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLtrBaseRunBeforeFourNestedRuns) {
  // Sample: m n o|a b c D E F g h i J K L
  // Bidi:   0 0 0 4 4 4 3 3 3 2 2 2 1 1 1
  // Visual: m n o L K J|F E D a b c g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>mno|<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo>ghi</bdo>JKL</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLtrBaseRunBeforeFourNestedRunsAtDeepPosition) {
  // Sample: m n o|a b c D E F g h i J K L
  // Bidi:   0 0 0 4 4 4 3 3 3 2 2 2 1 1 1
  // Visual: m n o L K J|F E D a b c g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>mno<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl><bdo dir=ltr>|abc</bdo>DEF</bdo>ghi</bdo>JKL</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterLtrRunTouchingLineBoundary) {
  // Sample: a b c|D E F
  // Bidi:   2 2 2 1 1 1
  // Visual: F E D a b c|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc</bdo>|DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterLtrRun) {
  // Sample: G H I a b c|D E F
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: F E D a b c|I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>|DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterLtrRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: a b c|D E F
  // Bidi:   2 2 2 1 1 1
  // Visual: F E D a b c|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc|</bdo>DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterLtrRunAtDeepPosition) {
  // Sample: G H I a b c|D E F
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: F E D a b c|I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>abc|</bdo>DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterTwoNestedRuns) {
  // Sample: d e f A B C|G H I
  // Bidi:   2 2 2 3 3 3 1 1 1
  // Visual: I H G d e f C B A|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>|GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterTwoNestedRunsAtDeepPosition) {
  // Sample: d e f A B C|G H I
  // Bidi:   2 2 2 3 3 3 1 1 1
  // Visual: I H G d e f C B A|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC|</bdo></bdo>GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterThreeNestedRuns) {
  // Sample: g h i D E F a b c|J K L
  // Bidi:   2 2 2 3 3 3 4 4 4 1 1 1
  // Visual: L K J g h i a b c F E D|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo></bdo>|JKL</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(120, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterThreeNestedRunsAtDeepPosition) {
  // Sample: g h i D E F a b c|J K L
  // Bidi:   2 2 2 3 3 3 4 4 4 1 1 1
  // Visual: L K J g h i a b c F E D|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc|</bdo></bdo></bdo>JKL</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(120, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunAfterFourNestedRuns) {
  // Sample: j k l G H I d e f A B C|M N O
  // Bidi:   2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  // Visual: O N M j k l d e f C B A I H G|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo></bdo></bdo>|MNO</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(150, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunAfterFourNestedRunsAtDeepPosition) {
  // Sample: j k l G H I d e f A B C|M N O
  // Bidi:   2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  // Visual: O N M j k l d e f C B A I H G|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr>def<bdo dir=rtl>ABC|</bdo></bdo></bdo></bdo>MNO</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(120, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunBeforeLtrRunTouchingLineBoundary) {
  // Sample: D E F|a b c
  // Bidi:   1 1 1 2 2 2
  // Visual:|a b c F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>DEF|<bdo dir=ltr>abc</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunBeforeLtrRun) {
  // Sample: D E F|a b c G H I
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: I H G|a b c F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>DEF|<bdo dir=ltr>abc</bdo>GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunBeforeLtrRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: D E F|a b c
  // Bidi:   1 1 1 2 2 2
  // Visual:|a b c F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>|abc</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunBeforeLtrRunAtDeepPosition) {
  // Sample: D E F|a b c G H I
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: I H G|a b c F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>|abc</bdo>GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunBeforeTwoNestedRuns) {
  // Sample: G H I|A B C d e f
  // Bidi:   1 1 1 3 3 3 2 2 2
  // Visual:|C B A d e f I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>GHI|<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunBeforeTwoNestedRunsAtDeepPosition) {
  // Sample: G H I|A B C d e f
  // Bidi:   1 1 1 3 3 3 2 2 2
  // Visual:|C B A d e f I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>|ABC</bdo>def</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunBeforeThreeNestedRuns) {
  // Sample: J K L|a b c D E F g h i
  // Bidi:   1 1 1 4 4 4 3 3 3 2 2 2
  // Visual:|F E D a b c g h i L K J
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>JKL|<bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo>ghi</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunBeforeThreeNestedRunsAtDeepPosition) {
  // Sample: J K L|a b c D E F g h i
  // Bidi:   1 1 1 4 4 4 3 3 3 2 2 2
  // Visual:|F E D a b c g h i L K J
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>|abc</bdo>DEF</bdo>ghi</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockRtlBaseRunBeforeFourNestedRuns) {
  // Sample: M N O|A B C d e f G H I j k l
  // Bidi:   1 1 1 5 5 5 4 4 4 3 3 3 2 2 2
  // Visual: I H G|C B A d e f j k l O N M
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>MNO|<bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo>GHI</bdo>jkl</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockRtlBaseRunBeforeFourNestedRunsAtDeepPosition) {
  // Sample: M N O|A B C d e f G H I j k l
  // Bidi:   1 1 1 5 5 5 4 4 4 3 3 3 2 2 2
  // Visual: I H G|C B A d e f j k l O N M
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>MNO<bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr><bdo dir=rtl>|ABC</bdo>def</bdo>GHI</bdo>jkl</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunAfterRtlRunTouchingLineBoundary) {
  // Sample: A B C|d e f
  // Bidi:   3 3 3 2 2 2
  // Visual:|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>ABC</bdo>|def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunAfterRtlRun) {
  // Sample: g h i A B C|d e f
  // Bidi:   2 2 2 3 3 3 2 2 2
  // Visual: g h i|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>ABC</bdo>|def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunAfterRtlRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: A B C|d e f
  // Bidi:   3 3 3 2 2 2
  // Visual:|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>ABC|</bdo>def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunAfterRtlRunAtDeepPosition) {
  // Sample: g h i A B C|d e f
  // Bidi:   2 2 2 3 3 3 2 2 2
  // Visual: g h i|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>ABC|</bdo>def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunAfterTwoNestedRuns) {
  // Sample: D E F a b c|g h i
  // Bidi:   3 3 3 4 4 4 2 2 2
  // Visual:|a b c F E D g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>|ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(210, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunAfterTwoNestedRunsAtDeepPosition) {
  // Sample: D E F a b c|g h i
  // Bidi:   3 3 3 4 4 4 2 2 2
  // Visual:|a b c F E D g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc|</bdo></bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(210, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunAfterThreeNestedRuns) {
  // Sample: G H I d e f A B C|j k l
  // Bidi:   3 3 3 4 4 4 5 5 5 2 2 2
  // Visual:|d e f C B A I H G j k l
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo>|jkl</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(180, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunAfterThreeNestedRunsAtDeepPosition) {
  // Sample: G H I d e f A B C|j k l
  // Bidi:   3 3 3 4 4 4 5 5 5 2 2 2
  // Visual:|d e f C B A I H G j k l
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
   
"""


```