Response:
The user wants a summary of the functionality of the `line_breaker_test.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet to understand its purpose and how it relates to HTML, CSS, and JavaScript.

**Plan:**

1. Identify the main class under test: `LineBreaker`.
2. Analyze the test fixtures and helper functions within `LineBreakerTest`.
3. Examine the individual test cases to understand the specific functionalities being tested.
4. Determine the relationship of these tests to HTML, CSS, and JavaScript concepts.
5. If possible, infer logical reasoning in the tests through input and expected output examples.
6. Identify potential user or programming errors that the tests might be preventing.
7. Finally, summarize the overall functionality of the test file.
这是 blink 渲染引擎中 `blink/renderer/core/layout/inline/line_breaker_test.cc` 文件的前半部分，主要功能是 **测试 `LineBreaker` 类的各种功能**。`LineBreaker` 类的核心职责是将内联内容（例如文本）分割成多行，以适应给定的可用宽度。

以下是根据代码片段归纳出的 `line_breaker_test.cc` 的功能点：

**1. 测试 `LineBreaker` 的基本分行功能:**

*   `BreakLines` 函数是核心的测试辅助函数，它模拟了 `LineBreaker` 的使用，将内联节点的内容根据给定的宽度分割成多行。
*   多个测试用例 (例如 `SingleNode`, `OverflowWord`, `OverflowTab`, `OverflowAtomicInline` 等) 验证了在不同场景下，`LineBreaker` 是否能正确地将文本内容分割成多行。

**与 HTML, CSS 的关系举例:**

*   **HTML 结构:** `CreateInlineNode` 函数通过解析 HTML 字符串创建用于测试的内联节点。例如，`CreateInlineNode("<div id=container>123 456 789</div>")` 创建了一个包含文本内容的 `div` 元素。
*   **CSS 样式:** 测试用例中经常使用 CSS 样式来影响分行的行为。例如，`font`, `width`, `white-space`, `text-overflow`, `word-wrap`, `letter-spacing`, `tab-size` 等 CSS 属性都会影响 `LineBreaker` 的分行逻辑。  例如，在 `FitWithEpsilon` 测试中，`width: 49.99px` 和 `text-overflow: ellipsis` 的 CSS 设置会被用于测试边缘情况下的分行和省略号处理。
*   **内联元素和块级元素:** `LineBreaker` 专注于处理内联内容，虽然测试中创建的容器通常是块级元素 (`div`)，但测试的核心在于如何将容器内的内联内容进行分行。

**2. 测试 `LineBreaker` 处理不同类型内容的能力:**

*   **文本内容:** 大部分测试用例都是关于纯文本的分行。
*   **空格和空白符:** 测试了不同 `white-space` 属性下空格的处理 (例如 `WhitespaceStateTest`, `TrailingSpaceWidthTest`)。
*   **制表符:**  `OverflowTab` 和 `OverflowTabBreakWord` 测试了制表符 (`\t`) 在分行中的处理。
*   **内联块级元素 (Atomic Inline):** `OverflowAtomicInline` 测试了 `display: inline-block` 的元素在分行时的行为，它会被视为一个不可分割的单元。
*   **HTML 标签:**  `TextCombineCloseTag`, `TextCombineBreak`, `TextCombineNoBreak` 等测试用例涉及到带有特殊样式的 HTML 标签 (`<tcy>`)，考察 `LineBreaker` 如何处理这些标签边界。
*   **CSS 盒模型属性:** `OverflowMargin` 测试了元素的 `margin-right` 属性如何影响分行，即使前面的内容可以容纳，但由于 margin 的存在，可能需要换行。

**3. 测试 `LineBreaker` 的边界情况和特殊场景:**

*   **精度问题:** `FitWithEpsilon` 测试了在接近临界宽度时，`LineBreaker` 的处理是否符合预期。
*   **溢出 (Overflow):** 多个测试用例 (如 `OverflowWord`, `OverflowAtomicInline`) 专门测试了内容超出可用宽度时的分行行为。
*   **`text-combine-upright` 属性:** `TextCombineCloseTag`, `TextCombineBreak`, `TextCombineNoBreak` 等测试用例涉及到垂直排版和文字组合的特殊情况。
*   **`letter-spacing` 属性:** `WrapLetterSpacing` 测试了字母间距对分行的影响。
*   **元素边界:** `BoundaryInWord` 和 `BoundaryInFirstWord` 测试了在元素边界处的分行行为。
*   **尾随空格:** `IdeographicTrailingSpaces`, `WhitespaceStateTest`, `TrailingSpaceWidthTest` 等测试用例考察了不同类型的尾随空格在不同 `white-space` 属性下的处理方式。

**4. 测试 `LineBreaker` 与其他布局模块的交互 (间接体现):**

*   `PrepareLayoutIfNeeded()` 表明 `LineBreaker` 依赖于布局信息的预计算。
*   `ConstraintSpaceForAvailableSize()` 和 `LineLayoutOpportunity` 等类的使用暗示了 `LineBreaker` 与约束求解和可用空间管理等布局机制的关联。

**假设输入与输出 (逻辑推理):**

*   **假设输入 (SingleNode):**  HTML: `<div id=container>123 456 789</div>`, CSS: `width: 80px` (假设每个数字宽度为 10px，空格也占空间)
*   **预期输出 (SingleNode):** 两行，第一行 "123 456"，第二行 "789"。
*   **假设输入 (OverflowWord):** HTML: `<div id=container>12345 678</div>`, CSS: `width: 40px`
*   **预期输出 (OverflowWord):** 两行，第一行 "12345"，第二行 "678"。  "12345" 超过了 40px 的宽度，但由于是一个单词，会被强制放在一行。

**用户或编程常见的使用错误 (可能涉及，但代码中未直接体现):**

*   **误解 `white-space` 属性:**  用户可能不清楚 `white-space: normal`, `pre`, `pre-wrap` 等属性对空格和换行的影响，导致分行结果与预期不符。这些测试用例 (如 `WhitespaceStateTest`) 可以帮助开发者理解这些属性的行为。
*   **忽略内联元素的盒模型:**  用户可能只关注文本内容的宽度，而忽略了内联元素的 padding, margin 等属性也会占用空间，导致分行错误。 `OverflowMargin` 测试用例就涵盖了这种情况。
*   **对特殊字符或标签的分行行为不了解:**  例如，不清楚像 `<br>` 标签或 `text-combine-upright` 这样的 CSS 属性如何影响分行。相关的测试用例 (如 `ForcedBreakFollowedByCloseTag`, `TextCombine...`) 帮助确保这些情况被正确处理。

**总结 `line_breaker_test.cc` (前半部分) 的功能:**

这个文件的主要功能是 **全面测试 Blink 渲染引擎中 `LineBreaker` 类的各种分行逻辑**。它通过创建不同 HTML 结构和 CSS 样式的内联内容，并调用 `LineBreaker` 的方法进行分行，然后断言分行结果是否符合预期。测试覆盖了基本的文本分行、各种空白符的处理、内联元素的处理、特殊 CSS 属性的影响以及一些边界情况。 这些测试用例确保了 `LineBreaker` 能够在各种复杂的场景下正确地将内联内容分割成多行，从而保证网页的正确渲染。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/line_breaker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/line_breaker.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result_ruby_column.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/line_info.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/positioned_float.h"
#include "third_party/blink/renderer/core/layout/unpositioned_float.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

String ToString(InlineItemResults line, InlineNode node) {
  StringBuilder builder;
  const String& text = node.ItemsData(false).text_content;
  for (const auto& item_result : line) {
    builder.Append(
        StringView(text, item_result.StartOffset(), item_result.Length()));
  }
  return builder.ToString();
}

class LineBreakerTest : public RenderingTest {
 protected:
  InlineNode CreateInlineNode(const String& html_content) {
    SetBodyInnerHTML(html_content);

    LayoutBlockFlow* block_flow =
        To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
    return InlineNode(block_flow);
  }

  // Break lines using the specified available width.
  Vector<std::pair<String, unsigned>> BreakLines(
      InlineNode node,
      LayoutUnit available_width,
      void (*callback)(const LineBreaker&, const LineInfo&) = nullptr,
      bool fill_first_space_ = false) {
    DCHECK(node);
    node.PrepareLayoutIfNeeded();
    ConstraintSpace space = ConstraintSpaceForAvailableSize(available_width);
    const InlineBreakToken* break_token = nullptr;
    Vector<std::pair<String, unsigned>> lines;
    trailing_whitespaces_.resize(0);
    ExclusionSpace exclusion_space;
    LeadingFloats leading_floats;
    LineLayoutOpportunity line_opportunity(available_width);
    LineInfo line_info;
    do {
      LineBreaker line_breaker(node, LineBreakerMode::kContent, space,
                               line_opportunity, leading_floats, break_token,
                               /* column_spanner_path */ nullptr,
                               &exclusion_space);
      line_breaker.NextLine(&line_info);
      if (callback)
        callback(line_breaker, line_info);
      trailing_whitespaces_.push_back(
          line_breaker.TrailingWhitespaceForTesting());

      if (line_info.Results().empty())
        break;

      break_token = line_info.GetBreakToken();
      if (fill_first_space_ && lines.empty()) {
        first_hang_width_ = line_info.HangWidth();
      }
      lines.push_back(std::make_pair(ToString(line_info.Results(), node),
                                     line_info.Results().back().item_index));
    } while (break_token);

    return lines;
  }

  wtf_size_t BreakLinesAt(InlineNode node,
                          LayoutUnit available_width,
                          base::span<LineBreakPoint> break_points,
                          base::span<LineInfo> line_info_list) {
    DCHECK(node);
    node.PrepareLayoutIfNeeded();
    ConstraintSpace space = ConstraintSpaceForAvailableSize(available_width);
    const InlineBreakToken* break_token = nullptr;
    ExclusionSpace exclusion_space;
    LeadingFloats leading_floats;
    LineLayoutOpportunity line_opportunity(available_width);
    wtf_size_t line_index = 0;
    do {
      LineBreaker line_breaker(node, LineBreakerMode::kContent, space,
                               line_opportunity, leading_floats, break_token,
                               /* column_spanner_path */ nullptr,
                               &exclusion_space);
      if (line_index < break_points.size()) {
        line_breaker.SetBreakAt(break_points[line_index]);
      }
      CHECK_LT(line_index, line_info_list.size());
      LineInfo& line_info = line_info_list[line_index];
      line_breaker.NextLine(&line_info);
      break_token = line_info.GetBreakToken();
      ++line_index;
    } while (break_token);
    return line_index;
  }

  wtf_size_t BreakLines(InlineNode node,
                        LayoutUnit available_width,
                        base::span<LineInfo> line_info_list) {
    Vector<LineBreakPoint> break_points;
    return BreakLinesAt(node, available_width, break_points, line_info_list);
  }

  MinMaxSizes ComputeMinMaxSizes(InlineNode node) {
    const auto space =
        ConstraintSpaceBuilder(node.Style().GetWritingMode(),
                               node.Style().GetWritingDirection(),
                               /* is_new_fc */ false)
            .ToConstraintSpace();

    return node
        .ComputeMinMaxSizes(node.Style().GetWritingMode(), space,
                            MinMaxSizesFloatInput())
        .sizes;
  }

  Vector<LineBreaker::WhitespaceState> trailing_whitespaces_;
  LayoutUnit first_hang_width_;
};

namespace {

TEST_F(LineBreakerTest, FitWithEpsilon) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
      width: 49.99px;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    </style>
    <div id=container>00000</div>
  )HTML");
  auto lines = BreakLines(
      node, LayoutUnit::FromFloatRound(50 - LayoutUnit::Epsilon()),
      [](const LineBreaker& line_breaker, const LineInfo& line_info) {
        EXPECT_FALSE(line_info.HasOverflow());
      });
  EXPECT_EQ(1u, lines.size());

  // Make sure ellipsizing code use the same |HasOverflow|.
  InlineCursor cursor(*node.GetLayoutBlockFlow());
  for (; cursor; cursor.MoveToNext())
    EXPECT_FALSE(cursor.Current().IsEllipsis());
}

TEST_F(LineBreakerTest, SingleNode) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
    }
    </style>
    <div id=container>123 456 789</div>
  )HTML");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(80));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("123 456", lines[0].first);
  EXPECT_EQ("789", lines[1].first);

  lines = BreakLines(node, LayoutUnit(60));
  EXPECT_EQ(3u, lines.size());
  EXPECT_EQ("123", lines[0].first);
  EXPECT_EQ("456", lines[1].first);
  EXPECT_EQ("789", lines[2].first);
}

// For "text-combine-upright-break-inside-001a.html"
TEST_F(LineBreakerTest, TextCombineCloseTag) {
  LoadAhem();
  InsertStyleElement(
      "#container {"
      "  font: 10px/2 Ahem;"
      "  writing-mode: vertical-lr;"
      "}"
      "tcy { text-combine-upright: all }");
  InlineNode node = CreateInlineNode(
      "<div id=container>"
      "abc<tcy style='white-space:pre'>XYZ</tcy>def");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(30));
  EXPECT_EQ(1u, lines.size());
  // |LineBreaker::auto_wrap_| doesn't care about CSS "white-space" property
  // in the element with "text-combine-upright:all".
  //  InlineItemResult
  //    [0] kText 0-3 can_break_after_=false
  //    [1] kOpenTag 3-3 can_break_after_=false
  //    [2] kStartTag 3-3 can_break_after _= fasle
  //    [3] kAtomicInline 3-4 can_break_after _= false
  //    [4] kCloseTag 4-4 can_break_after _= false
  EXPECT_EQ(String(u"abc\uFFFCdef"), lines[0].first);
}

TEST_F(LineBreakerTest, TextCombineBreak) {
  LoadAhem();
  InsertStyleElement(
      "#container {"
      "  font: 10px/2 Ahem;"
      "  writing-mode: vertical-lr;"
      "}"
      "tcy { text-combine-upright: all }");
  InlineNode node = CreateInlineNode("<div id=container>abc<tcy>-</tcy>def");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(30));
  EXPECT_EQ(2u, lines.size());
  // LineBreaker attempts to break line for "abc-def".
  EXPECT_EQ(String(u"abc\uFFFC"), lines[0].first);
  EXPECT_EQ(String(u"def"), lines[1].first);
}

TEST_F(LineBreakerTest, TextCombineNoBreak) {
  LoadAhem();
  InsertStyleElement(
      "#container {"
      "  font: 10px/2 Ahem;"
      "  writing-mode: vertical-lr;"
      "}"
      "tcy { text-combine-upright: all }");
  InlineNode node = CreateInlineNode("<div id=container>abc<tcy>XYZ</tcy>def");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(30));
  EXPECT_EQ(1u, lines.size());
  // LineBreaker attempts to break line for "abcXYZdef".
  EXPECT_EQ(String(u"abc\uFFFCdef"), lines[0].first);
}

TEST_F(LineBreakerTest, TextCombineNoBreakWithSpace) {
  LoadAhem();
  InsertStyleElement(
      "#container {"
      "  font: 10px/2 Ahem;"
      "  writing-mode: vertical-lr;"
      "}"
      "tcy { text-combine-upright: all }");
  InlineNode node = CreateInlineNode("<div id=container>abc<tcy>X Z</tcy>def");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(30));
  EXPECT_EQ(1u, lines.size());
  // LineBreaker checks whether can break after "Z" in "abcX Zdef".
  EXPECT_EQ(String(u"abc\uFFFCdef"), lines[0].first);
}

TEST_F(LineBreakerTest, OverflowWord) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
    }
    </style>
    <div id=container>12345 678</div>
  )HTML");

  // The first line overflows, but the last line does not.
  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(40));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("12345", lines[0].first);
  EXPECT_EQ("678", lines[1].first);

  // Both lines overflow.
  lines = BreakLines(node, LayoutUnit(20));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("12345", lines[0].first);
  EXPECT_EQ("678", lines[1].first);
}

TEST_F(LineBreakerTest, OverflowTab) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
      tab-size: 8;
      white-space: pre-wrap;
      width: 10ch;
    }
    </style>
    <div id=container>12345&#9;&#9;678</div>
  )HTML");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(100));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("12345\t\t", lines[0].first);
  EXPECT_EQ("678", lines[1].first);
}

TEST_F(LineBreakerTest, OverflowTabBreakWord) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
      tab-size: 8;
      white-space: pre-wrap;
      width: 10ch;
      word-wrap: break-word;
    }
    </style>
    <div id=container>12345&#9;&#9;678</div>
  )HTML");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(100));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("12345\t\t", lines[0].first);
  EXPECT_EQ("678", lines[1].first);
}

TEST_F(LineBreakerTest, OverflowAtomicInline) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
    }
    span {
      display: inline-block;
      width: 30px;
      height: 10px;
    }
    </style>
    <div id=container>12345<span></span>678</div>
  )HTML");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(80));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ(String(u"12345\uFFFC"), lines[0].first);
  EXPECT_EQ("678", lines[1].first);

  lines = BreakLines(node, LayoutUnit(70));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("12345", lines[0].first);
  EXPECT_EQ(String(u"\uFFFC678"), lines[1].first);

  lines = BreakLines(node, LayoutUnit(40));
  EXPECT_EQ(3u, lines.size());
  EXPECT_EQ("12345", lines[0].first);
  EXPECT_EQ(String(u"\uFFFC"), lines[1].first);
  EXPECT_EQ("678", lines[2].first);

  lines = BreakLines(node, LayoutUnit(20));
  EXPECT_EQ(3u, lines.size());
  EXPECT_EQ("12345", lines[0].first);
  EXPECT_EQ(String(u"\uFFFC"), lines[1].first);
  EXPECT_EQ("678", lines[2].first);
}

TEST_F(LineBreakerTest, OverflowMargin) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
    }
    span {
      margin-right: 4em;
    }
    </style>
    <div id=container><span>123 456</span> 789</div>
  )HTML");
  const HeapVector<InlineItem>& items = node.ItemsData(false).items;

  // While "123 456" can fit in a line, "456" has a right margin that cannot
  // fit. Since "456" and its right margin is not breakable, "456" should be on
  // the next line.
  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(80));
  EXPECT_EQ(3u, lines.size());
  EXPECT_EQ("123", lines[0].first);
  EXPECT_EQ("456", lines[1].first);
  DCHECK_EQ(InlineItem::kCloseTag, items[lines[1].second - 1].Type());
  EXPECT_EQ("789", lines[2].first);

  // Same as above, but this time "456" overflows the line because it is 70px.
  lines = BreakLines(node, LayoutUnit(60));
  EXPECT_EQ(3u, lines.size());
  EXPECT_EQ("123", lines[0].first);
  EXPECT_EQ("456", lines[1].first);
  DCHECK_EQ(InlineItem::kCloseTag, items[lines[1].second].Type());
  EXPECT_EQ("789", lines[2].first);
}

TEST_F(LineBreakerTest, OverflowAfterSpacesAcrossElements) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    div {
      font: 10px/1 Ahem;
      white-space: pre-wrap;
      width: 10ch;
      word-wrap: break-word;
    }
    </style>
    <div id=container><span>12345 </span> 1234567890123</div>
  )HTML");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(100));
  EXPECT_EQ(3u, lines.size());
  EXPECT_EQ("12345  ", lines[0].first);
  EXPECT_EQ("1234567890", lines[1].first);
  EXPECT_EQ("123", lines[2].first);
}

// Tests when the last word in a node wraps, and another node continues.
TEST_F(LineBreakerTest, WrapLastWord) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
    }
    </style>
    <div id=container>AAA AAA AAA <span>BB</span> CC</div>
  )HTML");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(100));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("AAA AAA", lines[0].first);
  EXPECT_EQ("AAA BB CC", lines[1].first);
}

TEST_F(LineBreakerTest, WrapLetterSpacing) {
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Times;
      letter-spacing: 10px;
      width: 0px;
    }
    </style>
    <div id=container>Star Wars</div>
  )HTML");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(100));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("Star", lines[0].first);
  EXPECT_EQ("Wars", lines[1].first);
}

TEST_F(LineBreakerTest, BoundaryInWord) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
    }
    </style>
    <div id=container><span>123 456</span>789 abc</div>
  )HTML");

  // The element boundary within "456789" should not cause a break.
  // Since "789" does not fit, it should go to the next line along with "456".
  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(80));
  EXPECT_EQ(3u, lines.size());
  EXPECT_EQ("123", lines[0].first);
  EXPECT_EQ("456789", lines[1].first);
  EXPECT_EQ("abc", lines[2].first);

  // Same as above, but this time "456789" overflows the line because it is
  // 60px.
  lines = BreakLines(node, LayoutUnit(50));
  EXPECT_EQ(3u, lines.size());
  EXPECT_EQ("123", lines[0].first);
  EXPECT_EQ("456789", lines[1].first);
  EXPECT_EQ("abc", lines[2].first);
}

TEST_F(LineBreakerTest, BoundaryInFirstWord) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
    }
    </style>
    <div id=container><span>123</span>456 789</div>
  )HTML");

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(80));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("123456", lines[0].first);
  EXPECT_EQ("789", lines[1].first);

  lines = BreakLines(node, LayoutUnit(50));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("123456", lines[0].first);
  EXPECT_EQ("789", lines[1].first);

  lines = BreakLines(node, LayoutUnit(20));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("123456", lines[0].first);
  EXPECT_EQ("789", lines[1].first);
}

// Test for https://crbug.com/1505393, where ideographic trailing spaces counted
// as kPreserved, except when they are in the last line of the paragraph and
// overflow the line, in which case they counted as kNone.
TEST_F(LineBreakerTest, IdeographicTrailingSpaces) {
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        font: 10px/1 Ahem;
      }
    </style>
    <div id="container">xxx&#x3000;&#x3000;&#x3000;&#x3000;xxx&#x3000;&#x3000;&#x3000;&#x3000;</div>
  )HTML");

  String expectedLine = String::FromUTF8("xxx\u3000\u3000\u3000\u3000");

  // The ideographic spaces overflows the line at 60px but fully fits at 90px.
  for (LayoutUnit width : {LayoutUnit(60), LayoutUnit(90)}) {
    Vector<std::pair<String, unsigned>> lines = BreakLines(node, width);
    EXPECT_EQ(2u, lines.size());
    EXPECT_EQ(expectedLine, lines[0].first);
    EXPECT_EQ(expectedLine, lines[1].first);
    EXPECT_EQ(LineBreaker::WhitespaceState::kPreserved,
              trailing_whitespaces_[0]);
    EXPECT_EQ(LineBreaker::WhitespaceState::kPreserved,
              trailing_whitespaces_[1]);
  }
}

struct WhitespaceStateTestData {
  const char* html;
  const char* white_space;
  LineBreaker::WhitespaceState expected;
} whitespace_state_test_data[] = {
    // The most common cases.
    {"12", "normal", LineBreaker::WhitespaceState::kNone},
    {"1234 5678", "normal", LineBreaker::WhitespaceState::kCollapsed},
    // |InlineItemsBuilder| collapses trailing spaces of a block, so
    // |LineBreaker| computes to `none`.
    {"12 ", "normal", LineBreaker::WhitespaceState::kNone},
    // pre/pre-wrap should preserve trailing spaces if exists.
    {"1234 5678", "pre-wrap", LineBreaker::WhitespaceState::kPreserved},
    {"12 ", "pre", LineBreaker::WhitespaceState::kPreserved},
    {"12 ", "pre-wrap", LineBreaker::WhitespaceState::kPreserved},
    {"12", "pre", LineBreaker::WhitespaceState::kNone},
    {"12", "pre-wrap", LineBreaker::WhitespaceState::kNone},
    // Empty/space-only cases.
    {"", "normal", LineBreaker::WhitespaceState::kLeading},
    {" ", "pre", LineBreaker::WhitespaceState::kPreserved},
    {" ", "pre-wrap", LineBreaker::WhitespaceState::kPreserved},
    // Cases needing to rewind.
    {"12 34<span>56</span>", "normal",
     LineBreaker::WhitespaceState::kCollapsed},
    {"12 34<span>56</span>", "pre-wrap",
     LineBreaker::WhitespaceState::kPreserved},
    // Atomic inlines.
    {"12 <span style='display: inline-block'></span>", "normal",
     LineBreaker::WhitespaceState::kNone},
    // fast/text/whitespace/inline-whitespace-wrapping-4.html
    {"<span style='white-space: nowrap'>1234  </span>"
     "<span style='white-space: normal'>  5678</span>",
     "pre", LineBreaker::WhitespaceState::kCollapsed},
};

std::ostream& operator<<(std::ostream& os,
                         const WhitespaceStateTestData& data) {
  return os << static_cast<int>(data.expected) << " for '" << data.html
            << "' with 'white-space: " << data.white_space << "'";
}

class WhitespaceStateTest
    : public LineBreakerTest,
      public testing::WithParamInterface<WhitespaceStateTestData> {};

INSTANTIATE_TEST_SUITE_P(LineBreakerTest,
                         WhitespaceStateTest,
                         testing::ValuesIn(whitespace_state_test_data));

TEST_P(WhitespaceStateTest, WhitespaceState) {
  const auto& data = GetParam();
  LoadAhem();
  InlineNode node = CreateInlineNode(String(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
      width: 50px;
      white-space: )HTML") + data.white_space +
                                     R"HTML(
    }
    </style>
    <div id=container>)HTML" + data.html +
                                     R"HTML(</div>
  )HTML");

  BreakLines(node, LayoutUnit(50));
  EXPECT_EQ(trailing_whitespaces_[0], data.expected);
}

struct TrailingSpaceWidthTestData {
  const char* html;
  const char* white_space;
  unsigned hanging_space_width;
} trailing_space_width_test_data[] = {{" ", "pre", 0},
                                      {"   ", "pre", 0},
                                      {"1 ", "pre", 0},
                                      {"1  ", "pre", 0},
                                      {"1<span> </span>", "pre", 0},
                                      {"<span>1 </span> ", "pre", 0},
                                      {"1<span> </span> ", "pre", 0},
                                      {"1 <span> </span> ", "pre", 0},
                                      {"1 \t", "pre", 0},
                                      {"1  \n", "pre", 0},
                                      {"1  <br>", "pre", 0},

                                      {" ", "pre-wrap", 0},
                                      {"   ", "pre-wrap", 0},
                                      {"1 ", "pre-wrap", 0},
                                      {"1  ", "pre-wrap", 0},
                                      {"1<span> </span>", "pre-wrap", 0},
                                      {"<span>1 </span> ", "pre-wrap", 0},
                                      {"1<span> </span> ", "pre-wrap", 0},
                                      {"1 <span> </span> ", "pre-wrap", 0},
                                      {"1 \t", "pre-wrap", 0},
                                      {"1  <br>", "pre-wrap", 0},
                                      {"12 1234", "pre-wrap", 1},
                                      {"12  1234", "pre-wrap", 2},
                                      {"12  <br>1234", "pre-wrap", 0},
                                      {"12    ", "pre-wrap", 1}};

class TrailingSpaceWidthTest
    : public LineBreakerTest,
      public testing::WithParamInterface<TrailingSpaceWidthTestData> {};

INSTANTIATE_TEST_SUITE_P(LineBreakerTest,
                         TrailingSpaceWidthTest,
                         testing::ValuesIn(trailing_space_width_test_data));

TEST_P(TrailingSpaceWidthTest, TrailingSpaceWidth) {
  const auto& data = GetParam();
  LoadAhem();
  InlineNode node = CreateInlineNode(String(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
      width: 50px;
      tab-size: 2;
      white-space: )HTML") + data.white_space +
                                     R"HTML(;
    }
    </style>
    <div id=container>)HTML" + data.html +
                                     R"HTML(</div>
  )HTML");

  BreakLines(node, LayoutUnit(50), nullptr, true);
  EXPECT_EQ(first_hang_width_, LayoutUnit(10) * data.hanging_space_width);
}

TEST_F(LineBreakerTest, FullyCollapsedSpaces) {
  // The space in `span` will be collapsed in `CollectInlines`, but it may have
  // set `NeedsLayout`. It should be cleared when a layout lifecycle is done,
  // but not by the line breaker.
  InlineNode node = CreateInlineNode(R"HTML(
    <style>
    #container {
      font-size: 10px;
    }
    </style>
    <div id=container>0 <span id=span> </span>2</div>
  )HTML");

  auto* span = To<LayoutInline>(GetLayoutObjectByElementId("span"));
  LayoutObject* space_text = span->FirstChild();
  space_text->SetNeedsLayout("test");

  // `LineBreaker` should not `ClearNeedsLayout`.
  BreakLines(node, LayoutUnit(800));
  EXPECT_TRUE(space_text->NeedsLayout());

  // But a layout pass should.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(space_text->NeedsLayout());
}

TEST_F(LineBreakerTest, TrailingCollapsedSpaces) {
  // The space in `span` is not collapsed but the line breaker removes it as a
  // trailing space. Similar to `FullyCollapsedSpaces` above, its `NeedsLayout`
  // should be cleared in a layout lifecycle, but not by the line breaker.
  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <style>
    #container {
      font-size: 10px;
      font-family: Ahem;
      width: 2em;
    }
    </style>
    <div id=container>0<span id=span> </span>2</div>
  )HTML");

  auto* span = To<LayoutInline>(GetLayoutObjectByElementId("span"));
  LayoutObject* space_text = span->FirstChild();
  space_text->SetNeedsLayout("test");

  // `LineBreaker` should not `ClearNeedsLayout`.
  BreakLines(node, LayoutUnit(800));
  EXPECT_TRUE(space_text->NeedsLayout());

  // But a layout pass should.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(space_text->NeedsLayout());
}

// For http://crbug.com/1104534
TEST_F(LineBreakerTest, SplitTextZero) {
  // Note: |V8TestingScope| is needed for |Text::splitText()|.
  V8TestingScope scope;

  LoadAhem();
  InlineNode node = CreateInlineNode(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      font: 10px/1 Ahem;
      overflow-wrap: break-word;
    }
    </style>
    <div id=container>0123456789<b id=target> </b>ab</i></div>
  )HTML");

  To<Text>(GetElementById("target")->firstChild())
      ->splitText(0, ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  Vector<std::pair<String, unsigned>> lines;
  lines = BreakLines(node, LayoutUnit(100));
  EXPECT_EQ(2u, lines.size());
  EXPECT_EQ("0123456789", lines[0].first);
  EXPECT_EQ("ab", lines[1].first);
}

TEST_F(LineBreakerTest, ForcedBreakFollowedByCloseTag) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id="container">
      <div><span>line<br></span></div>
      <div>
        <span>line<br></span>
      </div>
      <div>
        <span>
          line<br>
        </span>
      </div>
      <div>
        <span>line<br>  </span>
      </div>
      <div>
        <span>line<br>  </span>&#32;&#32;
      </div>
    </div>
  )HTML");
  const LayoutObject* container = GetLayoutObjectByElementId("container");
  for (const LayoutObject* child = container->SlowFirstChild(); child;
       child = child->NextSibling()) {
    InlineCursor cursor(*To<LayoutBlockFlow>(child));
    wtf_size_t line_count = 0;
    for (cursor.MoveToFirstLine(); cursor; cursor.MoveToNextLine())
      ++line_count;
    EXPECT_EQ(line_count, 1u);
  }
}

TEST_F(LineBreakerTest, TableCellWidthCalculationQuirkOutOfFlow) {
  InlineNode node = CreateInlineNode(R"HTML(
    <style>
    table {
      font-size: 10px;
      width: 5ch;
    }
    </style>
    <table><tr><td id=container>
      1234567
      <img style="position: absolute">
    </td></tr></table>
  )HTML");
  // |SetBodyInnerHTML| doesn't set compatibility mode.
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  EXPECT_TRUE(node.GetDocument().InQuirksMode());

  ComputeMinMaxSizes(node);
  // Pass if |ComputeMinMaxSizes| doesn't hit DCHECK failures.
}

TEST_F(LineBreakerTest, BoxDecorationBreakCloneWithoutBoxDecorations) {
  SetBodyInnerHTML(R"HTML(
    <span style="-webkit-box-decoration-break: clone"></span>
  )HTML");
  // Pass if it does not hit DCHECK.
}

TEST_F(LineBreakerTest, RewindPositionedFloat) {
  SetBodyInnerHTML(R"HTML(
<div style="float: left">
  &#xe49d;oB&#xfb45;|&#xf237;&#xfefc;
  )&#xe2c9;&#xea7a;0{r
  6
  <span style="float: left">
    <span style="border-right: solid green 2.166621530302065e+19in"></span>
  </span>
</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
}

// crbug.com/1091359
TEST_F(LineBreakerTest, RewindRubyColumn) {
  InlineNode node = CreateInlineNode(R"HTML(
<div id="container">
<style>
* {
  -webkit-text-security:square;
  font-size:16px;
}
</style>
<big style="word-wrap: break-word">a
<ruby dir="rtl">
<rt>
B AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<svg></svg>
<b>
</rt>
</ruby>
  )HTML");

  ComputeMinMaxSizes(node);
  // This test passes if no CHECK failures.
}

TEST_F(LineBreakerTest, SplitTextIntoSegements) {
  InlineNode node = CreateInlineNode(
      uR"HTML(
      <!DOCTYPE html>
      <svg viewBox="0 0 800 600">
      <text id="container" rotate="1" style="font-family:Times">AV)HTML"
      u"\U0001F197\u05E2\u05B4\u05D1\u05E8\u05B4\u05D9\u05EA</text></svg>)");
  BreakLines(node, LayoutUnit::Max(),
             [](const LineBreaker& line_breaker, const LineInfo& line_info) {
               EXPECT_EQ(8u, line_info.Results().size());
               // "A" and "V" with Times font are typically overlapped. They
               // should be split.
               EXPECT_EQ(1u, line_info.Results()[0].Length());  // A
               EXPECT_EQ(1u, line_info.Results()[1].Length());  // V
               // Non-BMP characters should not be split.
               EXPECT_EQ(2u, line_info.Results()[2].Length());  // U+1F197
               // Connected characters should not be split.
               EXPECT_EQ(2u, line_info.Results()[3].Length());  // U+05E2 U+05B4
               EXPECT_EQ(1u, line_info.Results()[4].Length());  // U+05D1
               EXPECT_EQ(2u, line_info.Results()[5].Length());  // U+05E8 U+05B4
               EXPECT_EQ(1u, line_info.Results()[6].Length());  // U+05D9
               EXPECT_EQ(1u, line_info.Results()[7].Length());  // U+05EA
             });
}

// crbug.com/1251960
TEST_F(LineBreakerTest, SplitTextIntoSegementsCrash) {
  InlineNode node = CreateInlineNode(R"HTML(<!DOCTYPE html>
      <svg viewBox="0 0 800 600">
      <text id="container" x="50 100 150">&#x0343;&#x2585;&#x0343;&#x2585;<!--
      -->&#x0343;&#x2585;</text>
      </svg>)HTML");
  BreakLines(node, LayoutUnit::Max(),
             [](const LineBreaker& line_breaker, const LineInfo& line_info) {
               Vector<const InlineItemResult*> text_results;
               for (const auto& result : line_info.Results()) {
                 if (result.item->Type() == InlineItem::kText) {
                   text_results.push_back(&result);
                 }
               }
               EXPECT_EQ(4u, text_results.size());
               EXPECT_EQ(1u, text_results[0]->Length());  // U+0343
               EXPECT_EQ(1u, text_results[1]->Length());  // U+2585
               EXPECT_EQ(2u, text_results[2]->Length());  // U+0343 U+2585
               EXPECT_EQ(2u, text_results[3]->Length());  // U+0343 U+2585
             });
}

// crbug.com/1214232
TEST_F(LineBreakerTest, GetOverhangCrash) {
  InlineNode node = CreateInlineNode(
      R"HTML(
<!DOCTYPE html>
<style>
* { margin-inline-end: -7%; }
rb { float: right; }
rt { margin: 17179869191em; }
</style>
<div id="container">
<ruby>
<rb>
C c
<rt>
)HTML");
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kStyleClean);
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInPerformLayout);
  // The test passes if we have no DCHECK failures in BreakLines().
  BreakLines(node, LayoutUnit::Max());
}

// https://crbug.com/1292848
// Test that, if it's not possible to break after an ideographic space (as
// happens before an end bracket), previous break opportunities are considered.
TEST_F(LineBreakerTest, IdeographicSpaceBeforeEndBracket) {
  LoadAhem();
  // Atomic inline, and ideographic space before the ideographic full stop.
  InlineNode node1 = CreateInlineNode(
      uR"HTML(
<!DOCTYPE html>
<style>
body { margin: 0; padding: 0; font: 10px/10px Ahem; }
</style>
<div id="container">
全角空白の前では、変な行末があります。　]
</div>
)HTML");
  auto lines1 = BreakLines(node1, LayoutUnit(190));

  // Test that it doesn't overflow.
  EXPECT_EQ(lines1.size(), 2u);

  // No ideographic space.
  InlineNode node2 = CreateInlineNode(
      uR"HTML(
<!DOCTYPE html>
<style>
body { margin: 0; padding: 0; font: 10px/10px Ahem; }
</style>
<div id="container">
全角空白の前では、変な行末があります。]
</div>
)HTML");
  auto lines2 = BreakLines(node2, LayoutUnit(190));

  // node1 and node2 should break at the same point because there aren't break
  // opportunities after the ideographic period, and any opportunities before it
  // should be the same.
  EXPECT_EQ(lines1[0].first, lines2[0].first);
}

TEST_F(LineBreakerTest, BreakAt) {
  LoadAhem();
  SetBodyInnerHTML(R"HT
"""


```