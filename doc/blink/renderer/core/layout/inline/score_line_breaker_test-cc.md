Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Functionality:** The file name itself is a big clue: `score_line_breaker_test.cc`. This immediately tells us it's testing the `ScoreLineBreaker` class. The "breaker" part suggests it's about breaking lines of text. The "score" part hints that the breaking process isn't just about fitting within a width, but involves some kind of evaluation or scoring of different break points.

2. **Examine Includes:** The `#include` directives tell us what other parts of the Blink rendering engine this code interacts with:
    * `score_line_breaker.h`:  Confirms we're testing this specific class.
    * `constraint_space_builder.h`:  Likely involved in determining available space for layout.
    * `inline_cursor.h`, `inline_node.h`: Suggests it's dealing with inline layout, where text flows.
    * `leading_floats.h`: Hints at how floating elements affect line breaking.
    * `line_break_point.h`, `line_info_list.h`, `line_widths.h`: These are key data structures for the line breaking process, storing information about potential break points, lines formed, and their widths.
    * `physical_box_fragment.h`:  Represents a contiguous piece of rendered content, including text.
    * `core_unit_test_helper.h`:  Provides the base class `RenderingTest` for writing unit tests.

3. **Analyze the Test Class (`ScoreLineBreakerTest`):**
    * **`RunUntilSuspended`:** This function looks interesting. It seems to drive the `ScoreLineBreaker` in steps, processing lines until some condition is met (not active, no break token, empty line list). This suggests the `ScoreLineBreaker` might operate in a stateful or iterative manner.
    * **`ComputeScores`:** This method explicitly calculates "scores" for line breaks. It creates a `ScoreLineBreaker` object and then calls `OptimalBreakPoints`. The name "OptimalBreakPoints" reinforces the idea that the `ScoreLineBreaker` tries to find the *best* places to break lines. The `SetScoresOutForTesting` method is a clear indicator of exposing internal workings for testing purposes.

4. **Examine Individual Test Cases:** This is where we see concrete examples of how the `ScoreLineBreaker` is used and tested:
    * **`LastLines`:** Tests the scenario where the breaker processes lines sequentially, likely related to caching or handling the end of the content.
    * **`BalanceMaxLinesExceeded`:** Focuses on the `text-wrap: balance` CSS property and how the line breaker behaves when the content exceeds a certain number of lines. This links directly to CSS.
    * **`BlockInInlineTest`:**  Deals with the complexity of block-level elements embedded within inline content (`<div>` inside `<span>`). This tests how the line breaker handles these "atomic" inline elements.
    * **`ForcedBreak`:**  Tests the behavior of `<br>` tags, ensuring the line breaker respects explicit line breaks.
    * **`DisabledByLineBreakerTest`:** Checks conditions where the "scoring" or optimization aspect of the line breaker is disabled (e.g., due to overflows, specific CSS properties). This shows how different factors can influence the line breaking algorithm.
    * **`FloatRetry`:** A simple test that mainly checks for crashes when the line breaker is called multiple times for the same line due to floating elements. This highlights the interaction between line breaking and float placement.
    * **`Zoom`:** Verifies that the scoring mechanism is consistent even when the page zoom level changes. It checks if scores scale appropriately.
    * **`UseCountNotCountedForWrap`/`UseCountNotCountedForBalance`:** These tests verify that the correct usage counters are incremented for the `text-wrap` CSS property. This is related to tracking feature usage in the browser.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  As we analyze the test cases, connections to web technologies become apparent:
    * **HTML:** The test cases use HTML snippets to set up the content being laid out. Examples: `SetBodyInnerHTML(...)`.
    * **CSS:** Several test cases directly involve CSS properties like `width`, `font-family`, `font-size`, `text-wrap`, `overflow-wrap`, `white-space`, and `-webkit-box-decoration-break`. The tests verify how the line breaker responds to these styles.
    * **JavaScript:** While this specific test file doesn't *directly* involve JavaScript, the functionality being tested is crucial for how web pages render, which is indirectly affected by JavaScript that might manipulate the DOM or styles.

6. **Identify Logical Reasoning and Assumptions:**  In cases like `LastLines`, there's an assumption about the `ScoreLineBreaker` caching a certain number of lines. The test verifies this assumption. The `BlockInInlineTest` reasons that a block element inside inline content should be treated as an atomic unit for line breaking.

7. **Spot Potential User/Programming Errors:**  The `DisabledByLineBreakerTest` indirectly points to potential issues. If a user sets `overflow-wrap: anywhere` but also has very long, unbreakable strings, they might expect "pretty" or "balance" text wrapping to still work perfectly, but this test shows that the scoring mechanism might be disabled in such cases. A programming error within the `ScoreLineBreaker` could lead to incorrect line breaks, crashes (as tested in `FloatRetry`), or inconsistent behavior across zoom levels.

8. **Structure the Explanation:** Finally, organize the findings into logical sections like "Functionality," "Relationship to Web Technologies," "Logic and Assumptions," and "Potential Errors," providing specific examples and code snippets where relevant. Use clear and concise language.

By following these steps, we can systematically dissect the provided C++ test file and understand its purpose, its connections to web technologies, and the underlying assumptions and potential pitfalls related to the `ScoreLineBreaker`.这个文件 `score_line_breaker_test.cc` 是 Chromium Blink 引擎中用于测试 `ScoreLineBreaker` 类的单元测试。`ScoreLineBreaker` 的主要功能是**在给定约束条件下，为内联布局（inline layout）中的文本找到最优的换行点**，它会根据一些评分机制来决定哪些换行点更合适，以达到更好的排版效果，例如避免出现孤立的单词或者尽可能平衡各行的长度。

下面详细列举其功能以及与 JavaScript, HTML, CSS 的关系：

**主要功能:**

1. **测试 `ScoreLineBreaker::OptimalBreakPoints` 方法:**  这是 `ScoreLineBreaker` 的核心方法，用于计算最优的换行点。测试用例会模拟不同的文本内容和布局约束，然后调用这个方法，并验证返回的换行点是否符合预期。
2. **验证换行点的连贯性:** `TestLinesAreContiguous` 函数用于检查生成的行信息列表中的换行点是否是连续的，即当前行的起始位置是否与前一行的换行点一致。
3. **测试在不同场景下的换行行为:**  测试用例涵盖了各种场景，例如：
    * 处理多行文本 (`LastLines`)
    * 当 `text-wrap: balance` 生效但行数过多时的情况 (`BalanceMaxLinesExceeded`)
    * 处理内联块元素 (`BlockInInlineTest`)
    * 处理强制换行符 `<br>` (`ForcedBreak`)
    * 在特定 CSS 属性影响下，`ScoreLineBreaker` 是否会被禁用 (`DisabledByLineBreakerTest`)，例如 `overflow-wrap: anywhere` 或 `break-word` 以及不支持的 `white-space: break-spaces` 和 `box-decoration-break: clone`。
    * 当由于浮动元素导致需要重试换行的情况 (`FloatRetry`)
    * 在页面缩放 (zoom) 情况下，评分机制是否保持一致 (`Zoom`)
4. **测试 UseCounter 功能:** 验证 `text-wrap: balance` 和 `text-wrap: pretty` 这两个 CSS 属性是否正确触发了 Blink 的 UseCounter 机制，用于统计 Web 功能的使用情况 (`UseCountNotCountedForWrap`, `UseCountNotCountedForBalance`)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ScoreLineBreaker` 的功能直接影响着网页的文本排版，而文本排版是由 HTML 结构和 CSS 样式共同决定的。JavaScript 可以动态修改 HTML 结构和 CSS 样式，从而间接地影响 `ScoreLineBreaker` 的行为。

* **HTML:**  测试用例通过 `SetBodyInnerHTML` 设置 HTML 内容，模拟需要进行换行处理的文本结构。
    * **举例:** 在 `LastLines` 测试中，HTML 代码定义了一个包含多行文本的 `div` 元素：
      ```html
      <div id="target">
        1234 67 90
        234 67 901
        ...
      </div>
      ```
      `ScoreLineBreaker` 的作用就是决定如何将这些文本分成多行进行显示。

* **CSS:**  CSS 样式定义了文本容器的宽度、字体大小等属性，这些属性会影响 `ScoreLineBreaker` 的换行决策。特定的 CSS 属性，如 `text-wrap: balance` 和 `text-wrap: pretty`，会触发 `ScoreLineBreaker` 的优化算法。
    * **举例:** 在 `BalanceMaxLinesExceeded` 测试中，CSS 设置了 `text-wrap: balance`：
      ```css
      #target {
        text-wrap: balance;
      }
      ```
      测试目的是验证当文本行数超过一定限制时，`balance` 效果是否仍然生效。
    * **举例:** 在 `DisabledByLineBreakerTest` 中，测试了 `overflow-wrap: anywhere` 和 `break-word` 等属性对 `ScoreLineBreaker` 的影响。如果设置了这些属性，并且出现了可能导致单词溢出的情况，`ScoreLineBreaker` 的某些优化可能会被禁用。

* **JavaScript:** JavaScript 可以动态地改变 HTML 内容或 CSS 样式，这会导致浏览器重新进行布局，并重新调用 `ScoreLineBreaker` 来计算新的换行点。
    * **假设输入:** 一个包含长文本的 `div` 元素，初始宽度较小。
    * **JavaScript 操作:**  使用 JavaScript 修改该 `div` 元素的 `style.width` 属性，使其变宽。
    * **输出:**  `ScoreLineBreaker` 会根据新的宽度约束重新计算换行点，使得文本在更宽的容器中以更优的方式排列。

**逻辑推理与假设输入/输出:**

* **假设输入 (ForcedBreak 测试):**
    ```html
    <div id="target">
      1234 6789 12<br>
      1234 6789
      1234 6789
      12
    </div>
    ```
    `ScoreLineBreaker` 从头开始处理这段文本。
* **逻辑推理:**  `ScoreLineBreaker` 遇到 `<br>` 标签时，会认为这是一个强制换行点，应该在此处断开。  由于 `<br>` 前面的文本只有少量单词，无法形成多个有效的换行候选项，因此在处理第一个段落时，优化器可能不会进行复杂的评分，而是直接根据可用的换行点生成 `LineInfo`。
* **输出:**  在遇到 `<br>` 之前，`line_info_list` 中会包含对应于第一行文本的 `LineInfo` 对象。当继续处理后续文本时，`ScoreLineBreaker` 会为剩余的段落计算最优的换行点，`break_points` 中会包含这些计算出的断点。

**用户或编程常见的使用错误:**

* **错误地假设 `text-wrap: balance` 或 `pretty` 在所有情况下都生效:**  开发者可能会期望 `text-wrap: balance` 或 `pretty` 总是能产生最佳的排版效果，但正如 `BalanceMaxLinesExceeded` 和 `DisabledByLineBreakerTest` 所展示的，这些属性在某些特定情况下可能不会生效，或者效果会受到限制。例如，当文本行数过多时，`balance` 可能会被禁用以避免性能问题。
* **忽略了特定 CSS 属性对换行行为的影响:**  开发者可能没有意识到像 `overflow-wrap` 或 `white-space` 这样的属性会影响 `ScoreLineBreaker` 的行为。例如，如果设置了 `overflow-wrap: anywhere`，即使某个单词很长，也可能被强制断开，而不会像 `text-wrap: pretty` 那样尽量避免单词断开。
* **在动态修改内容后，没有考虑到布局的重新计算:** 当使用 JavaScript 动态添加或删除文本内容时，开发者需要意识到浏览器的布局会重新计算，`ScoreLineBreaker` 会被再次调用。如果动态修改导致频繁的布局变化，可能会影响性能。

总而言之，`score_line_breaker_test.cc` 这个文件通过各种测试用例，细致地验证了 `ScoreLineBreaker` 类在不同场景下的换行逻辑，确保了 Blink 引擎能够正确且高效地处理文本换行，从而为用户提供良好的网页浏览体验。它与 HTML 结构、CSS 样式以及 JavaScript 的动态操作都有着密切的关系。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/score_line_breaker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/score_line_breaker.h"

#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/leading_floats.h"
#include "third_party/blink/renderer/core/layout/inline/line_break_point.h"
#include "third_party/blink/renderer/core/layout/inline/line_info_list.h"
#include "third_party/blink/renderer/core/layout/inline/line_widths.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

namespace {

LayoutUnit FragmentWidth(const InlineNode& node) {
  const PhysicalBoxFragment* fragment =
      node.GetLayoutBox()->GetPhysicalFragment(0);
  return fragment->Size().width;
}

void TestLinesAreContiguous(const LineInfoList& line_info_list) {
  for (wtf_size_t i = 1; i < line_info_list.Size(); ++i) {
    EXPECT_EQ(line_info_list[i].Start(),
              line_info_list[i - 1].GetBreakToken()->Start());
  }
}

}  // namespace

class ScoreLineBreakerTest : public RenderingTest {
 public:
  void RunUntilSuspended(ScoreLineBreaker& breaker,
                         ScoreLineBreakContext& context) {
    LineInfoList& line_info_list = context.GetLineInfoList();
    line_info_list.Clear();
    LineBreakPoints& break_points = context.GetLineBreakPoints();
    break_points.clear();
    context.DidCreateLine(/*is_end_paragraph*/ true);
    LeadingFloats empty_leading_floats;
    for (;;) {
      breaker.OptimalBreakPoints(empty_leading_floats, context);
      if (!context.IsActive() || !breaker.BreakToken() ||
          line_info_list.IsEmpty()) {
        break;
      }

      // Consume the first line in `line_info_list`.
      const LineInfo& line_info = line_info_list.Front();
      const bool is_end_paragraph = line_info.IsEndParagraph();
      line_info_list.RemoveFront();
      context.DidCreateLine(is_end_paragraph);
    }
  }

  Vector<float> ComputeScores(const InlineNode& node) {
    const LayoutUnit width = FragmentWidth(node);
    ConstraintSpace space = ConstraintSpaceForAvailableSize(width);
    LineWidths line_widths(width);
    const InlineBreakToken* break_token = nullptr;
    ExclusionSpace exclusion_space;
    ScoreLineBreaker optimizer(node, space, line_widths, break_token,
                               &exclusion_space);
    Vector<float> scores;
    optimizer.SetScoresOutForTesting(&scores);
    LeadingFloats empty_leading_floats;
    ScoreLineBreakContextOf<kMaxLinesForOptimal> context;
    optimizer.OptimalBreakPoints(empty_leading_floats, context);
    return scores;
  }
};

TEST_F(ScoreLineBreakerTest, LastLines) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    #target {
      font-family: Ahem;
      font-size: 10px;
      width: 10ch;
    }
    </style>
    <div id="target">
      1234 67 90
      234 67 901
      34 678 012
      456 89 123
      567 901 34
      678 012 45
    </div>
  )HTML");
  const InlineNode node = GetInlineNodeByElementId("target");
  const LayoutUnit width = FragmentWidth(node);
  ConstraintSpace space = ConstraintSpaceForAvailableSize(width);
  LineWidths line_widths(width);
  ScoreLineBreakContextOf<kMaxLinesForOptimal> context;
  LineInfoList& line_info_list = context.GetLineInfoList();
  const InlineBreakToken* break_token = nullptr;
  ExclusionSpace exclusion_space;
  ScoreLineBreaker optimizer(node, space, line_widths, break_token,
                             &exclusion_space);

  // Run the optimizer from the beginning of the `target`. This should cache
  // `optimizer.MaxLines()` lines.
  LeadingFloats empty_leading_floats;
  optimizer.OptimalBreakPoints(empty_leading_floats, context);
  EXPECT_EQ(line_info_list.Size(), optimizer.MaxLines());
  TestLinesAreContiguous(line_info_list);

  // Then continue until `ScoreLineBreaker` consumes all lines in the block.
  wtf_size_t count = 0;
  for (; context.IsActive(); ++count) {
    // Consume the first line in `line_info_list`.
    bool is_cached = false;
    const LineInfo& line_info0 = line_info_list.Get(break_token, is_cached);
    EXPECT_TRUE(is_cached);
    EXPECT_EQ(line_info_list.Size(), optimizer.MaxLines() - 1);
    break_token = line_info0.GetBreakToken();
    // Running again should cache one more line.
    optimizer.OptimalBreakPoints(empty_leading_floats, context);
    EXPECT_EQ(line_info_list.Size(), optimizer.MaxLines());
    TestLinesAreContiguous(line_info_list);
  }
  // All is done. The `BreakToken` should be null, and there should be 6 lines.
  EXPECT_FALSE(line_info_list.Back().GetBreakToken());
  constexpr wtf_size_t target_num_lines = 6;
  EXPECT_EQ(count, target_num_lines - optimizer.MaxLines());
}

TEST_F(ScoreLineBreakerTest, BalanceMaxLinesExceeded) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    #target {
      font-family: Ahem;
      font-size: 10px;
      width: 10ch;
      text-wrap: balance;
    }
    </style>
    <div id="target">
      123 56 89 123 56 89
      123 56 89 123 56 89
      123 56 89 123 56 89
      123 56 89 123 56 89
      123 56 89 123 56 89
      X
    </div>
  )HTML");
  const LayoutBlockFlow* target = GetLayoutBlockFlowByElementId("target");
  InlineCursor cursor(*target);
  cursor.MoveToLastLine();
  cursor.MoveToNext();
  // Neitehr `balance` nor `pretty` should be applied.
  EXPECT_EQ(cursor.Current()->Type(), FragmentItem::kText);
  EXPECT_EQ(cursor.Current()->TextLength(), 1u);
}

class BlockInInlineTest : public ScoreLineBreakerTest,
                          public testing::WithParamInterface<int> {};
INSTANTIATE_TEST_SUITE_P(ScoreLineBreakerTest,
                         BlockInInlineTest,
                         testing::Range(0, 4));

TEST_P(BlockInInlineTest, BeforeAfter) {
  LoadAhem();
  const int test_index = GetParam();
  const bool has_before = test_index & 1;
  const bool has_after = test_index & 2;
  SetBodyInnerHTML(String::Format(
      R"HTML(
    <!DOCTYPE html>
    <style>
    #target {
      font-family: Ahem;
      font-size: 10px;
      width: 10ch;
    }
    </style>
    <div id="target">
      <span>%s<div>
        Inside 89 1234 6789 1234 6789 1234 6789 12
      </div>%s</span>
    </div>
  )HTML",
      has_before ? "Before 89 1234 6789 1234 6789 1234 6789 12" : "",
      has_after ? "After 789 1234 6789 1234 6789 1234 6789 12" : ""));
  const InlineNode node = GetInlineNodeByElementId("target");
  const LayoutUnit width = FragmentWidth(node);
  ConstraintSpace space = ConstraintSpaceForAvailableSize(width);
  LineWidths line_widths(width);
  ScoreLineBreakContextOf<kMaxLinesForOptimal> context;
  LineInfoList& line_info_list = context.GetLineInfoList();
  LineBreakPoints& break_points = context.GetLineBreakPoints();
  ExclusionSpace exclusion_space;
  ScoreLineBreaker optimizer(node, space, line_widths,
                             /*break_token*/ nullptr, &exclusion_space);
  // The `ScoreLineBreaker` should suspend at before the block-in-inline.
  RunUntilSuspended(optimizer, context);
  if (has_before) {
    // The content before the block-in-inline should be optimized.
    EXPECT_NE(break_points.size(), 0u);
  } else {
    // The content before the block-in-inline is just a `<span>`.
    EXPECT_EQ(break_points.size(), 0u);
    EXPECT_EQ(line_info_list.Size(), 1u);
    EXPECT_TRUE(line_info_list[0].HasForcedBreak());
  }

  // Then the block-in-inline comes. Since it's like an atomic inline, it's not
  // optimized.
  RunUntilSuspended(optimizer, context);
  EXPECT_EQ(break_points.size(), 0u);
  EXPECT_EQ(line_info_list.Size(), 1u);
  EXPECT_TRUE(line_info_list[0].IsBlockInInline());
  EXPECT_TRUE(line_info_list[0].HasForcedBreak());

  // Then the content after the block-in-inline.
  RunUntilSuspended(optimizer, context);
  if (has_after) {
    EXPECT_NE(break_points.size(), 0u);
  } else {
    EXPECT_EQ(break_points.size(), 0u);
    EXPECT_EQ(line_info_list.Size(), 1u);
  }
}

TEST_F(ScoreLineBreakerTest, ForcedBreak) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    #target {
      font-family: Ahem;
      font-size: 10px;
      width: 10em;
    }
    </style>
    <div id="target">
      1234 6789 12<br>
      1234 6789
      1234 6789
      12
    </div>
  )HTML");
  const InlineNode node = GetInlineNodeByElementId("target");
  const LayoutUnit width = FragmentWidth(node);
  ConstraintSpace space = ConstraintSpaceForAvailableSize(width);
  LineWidths line_widths(width);
  ScoreLineBreakContextOf<kMaxLinesForOptimal> context;
  LineInfoList& line_info_list = context.GetLineInfoList();
  LineBreakPoints& break_points = context.GetLineBreakPoints();
  const InlineBreakToken* break_token = nullptr;
  ExclusionSpace exclusion_space;
  ScoreLineBreaker optimizer(node, space, line_widths, break_token,
                             &exclusion_space);

  // Run the optimizer from the beginning of the `target`. This should stop at
  // `<br>` so that paragraphs separated by forced breaks are optimized
  // separately.
  //
  // Since the paragraphs has only 2 break candidates, it should return two
  // `LineInfo` without the optimization.
  LeadingFloats empty_leading_floats;
  optimizer.OptimalBreakPoints(empty_leading_floats, context);
  EXPECT_EQ(break_points.size(), 0u);
  EXPECT_EQ(line_info_list.Size(), 2u);

  // Pretend all the lines are consumed.
  EXPECT_TRUE(optimizer.BreakToken());
  line_info_list.Clear();
  context.DidCreateLine(/*is_end_paragraph*/ true);

  // Run the optimizer again to continue. This should run up to the end of
  // `target`. It has 4 break candidates so the optimization should apply.
  optimizer.OptimalBreakPoints(empty_leading_floats, context);
  EXPECT_EQ(break_points.size(), 3u);
  // `line_info_list` should be partially cleared, only after break points were
  // different.
  EXPECT_NE(line_info_list.Size(), 3u);
}

struct DisabledByLineBreakerData {
  bool disabled;
  const char* html;
} disabled_by_line_breaker_data[] = {
    // Normal, should not be disabled.
    {false, R"HTML(
      <div id="target">
        0123 5678
        1234 6789
        234 67890
        45
      </div>
    )HTML"},
    // Overflowing lines should disable.
    {true, R"HTML(
      <div id="target">
        0123 5678
        123456789012
        23 567 90
        45
      </div>
    )HTML"},
    // `overflow-wrap` should be ok, except...
    {false, R"HTML(
      <div id="target" style="overflow-wrap: anywhere">
        0123 5678
        1234 6789
        23 567 90
        45
      </div>
    )HTML"},
    {false, R"HTML(
      <div id="target" style="overflow-wrap: break-word">
        0123 5678
        1234 6789
        23 567 90
        45
      </div>
    )HTML"},
    // ...when there're overflows.
    {true, R"HTML(
      <div id="target" style="overflow-wrap: anywhere">
        0123 5678
        123456789012
        23 567 90
        45
      </div>
    )HTML"},
    {true, R"HTML(
      <div id="target" style="overflow-wrap: break-word">
        0123 5678
        123456789012
        23 567 90
        45
      </div>
    )HTML"},
    // `break-sapces` is not supported.
    {true, R"HTML(
      <div id="target" style="white-space: break-spaces; text-wrap: pretty">0123 5678 1234 6789 23 567 90 45</div>
    )HTML"},
    // `box-decoration-break: clone` is not supported.
    {true, R"HTML(
      <div id="target">
        0123 5678
        1234 6789
        23 <span style="-webkit-box-decoration-break: clone">567</span> 90
        45
      </div>
    )HTML"}};

class DisabledByLineBreakerTest
    : public ScoreLineBreakerTest,
      public testing::WithParamInterface<DisabledByLineBreakerData> {};

INSTANTIATE_TEST_SUITE_P(ScoreLineBreakerTest,
                         DisabledByLineBreakerTest,
                         testing::ValuesIn(disabled_by_line_breaker_data));

TEST_P(DisabledByLineBreakerTest, Data) {
  const auto& data = GetParam();
  LoadAhem();
  SetBodyInnerHTML(String(R"HTML(
    <!DOCTYPE html>
    <style>
    #target {
      font-family: Ahem;
      font-size: 10px;
      width: 10ch;
      text-wrap: pretty;
    }
    </style>
  )HTML") + data.html);
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kTextWrapBalance));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kTextWrapPretty));

  const InlineNode node = GetInlineNodeByElementId("target");
  const LayoutUnit width = FragmentWidth(node);
  ConstraintSpace space = ConstraintSpaceForAvailableSize(width);
  LineWidths line_widths(width);
  ScoreLineBreakContextOf<kMaxLinesForOptimal> context;
  const InlineBreakToken* break_token = nullptr;
  ExclusionSpace exclusion_space;
  ScoreLineBreaker optimizer(node, space, line_widths, break_token,
                             &exclusion_space);
  LeadingFloats empty_leading_floats;
  optimizer.OptimalBreakPoints(empty_leading_floats, context);
  EXPECT_FALSE(context.IsActive());
  if (data.disabled) {
    EXPECT_EQ(context.GetLineBreakPoints().size(), 0u);
  } else {
    EXPECT_NE(context.GetLineBreakPoints().size(), 0u);
  }
}

// Test when `InlineLayoutAlgorithm::Layout` runs `LineBreaker` twice for
// the same line, to retry line breaking due to float placements.
TEST_F(ScoreLineBreakerTest, FloatRetry) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    .container {
      font-size: 16px;
      text-wrap: pretty;
      width: 110px;
    }
    .float {
      float: right;
      width: 50px;
      height: 50px;
    }
    </style>
    <div class="container">
      <div class="float"></div>
      Blah.
      <div class="float"></div>
      Blah blah blah.
    </div>
  )HTML");
  // Test pass if it doesn't crash.
}

TEST_F(ScoreLineBreakerTest, Zoom) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    #target {
      font-family: Ahem;
      font-size: 10px;
      width: 10ch;
    }
    </style>
    <div id="target">
      012 45 789
      012 45 789
      012 45 789
      012
    </div>
  )HTML");
  const InlineNode target = GetInlineNodeByElementId("target");
  Vector<float> scores = ComputeScores(target);

  constexpr float zoom = 2;
  GetFrame().SetLayoutZoomFactor(zoom);
  UpdateAllLifecyclePhasesForTest();
  const Vector<float> scores2 = ComputeScores(target);

  // The scores should be the same even when `EffectiveZoom()` are different.
  EXPECT_EQ(scores.size(), scores2.size());
  for (wtf_size_t i = 0; i < scores.size(); ++i) {
    const float zoomed_score = scores[i] * zoom;
    if (fabs(zoomed_score - scores2[i]) < 3) {
      continue;  // Ignore floating point errors.
    }
    EXPECT_EQ(zoomed_score, scores2[i]) << i;
  }
}

TEST_F(ScoreLineBreakerTest, UseCountNotCountedForWrap) {
  SetBodyInnerHTML(R"HTML(
    <div>012</div>
  )HTML");
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kTextWrapBalance));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kTextWrapPretty));
}

TEST_F(ScoreLineBreakerTest, UseCountNotCountedForBalance) {
  SetBodyInnerHTML(R"HTML(
    <div style="text-wrap: balance">012</div>
  )HTML");
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kTextWrapBalance));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kTextWrapPretty));
}

}  // namespace blink

"""

```