Response:
Let's break down the thought process for analyzing the `score_line_breaker.cc` file.

1. **Understand the Goal:** The core task is to analyze a C++ file from the Chromium Blink engine and explain its functionality, relationships to web technologies (HTML, CSS, JavaScript), and potential usage scenarios and errors.

2. **Identify the File's Purpose:** The filename `score_line_breaker.cc` and the surrounding directory `blink/renderer/core/layout/inline/` strongly suggest this file is responsible for making decisions about where to break lines of text within inline content. The "score" part hints at an optimization or cost-based approach.

3. **High-Level Overview:** Read the initial comments and includes to get a general idea. The copyright notice and BSD license are standard. The includes reveal dependencies on other Blink layout components like `InlineBreakToken`, `InlineNode`, `LineBreaker`, `LineInfoList`, and font shaping. This confirms the file's role in text layout.

4. **Analyze Key Functions and Classes:**  Focus on the public interface and major functions.

    * **`ScoreLineBreaker` Class:** This is the central class. Note its member variables like `is_balanced_`, `break_token_`, `node_`, `line_widths_`, and `scores_out_for_testing_`. These provide clues about its state and interactions.

    * **`OptimalBreakPoints`:** This looks like the main entry point for determining optimal breakpoints. The comments mention caching and using `LineBreaker`. The `ShouldOptimize` function suggests a conditional application of the scoring mechanism.

    * **`BalanceBreakPoints`:**  This seems related to `OptimalBreakPoints` but specifically for balanced text.

    * **`Optimize`:** This is where the "scoring" likely happens. It calls `ComputeCandidates`, `ComputeLineWidths`, `ComputeScores`, and `ComputeBreakPoints`.

    * **`ComputeCandidates`:** This likely identifies potential break points within the text.

    * **`ComputeLineWidths`:**  This calculates the available width for each line, taking into account indents.

    * **`SetupParameters`:** This initializes parameters used in the scoring process, potentially based on CSS styles.

    * **`ComputeScores`:** This is the core of the scoring logic, assigning scores to break opportunities.

    * **`ComputeBreakPoints`:** This uses the calculated scores to determine the final set of breakpoints.

5. **Infer Functionality:** Based on the function names and their interactions, infer the overall workflow:

    * Start with a greedy line-breaking approach using `LineBreaker`.
    * Optionally, apply the scoring mechanism (`ScoreLineBreaker`) if `ShouldOptimize` returns true. This is likely done to improve the visual appearance of the text.
    * Identify candidate break points.
    * Calculate the cost or penalty of breaking at each candidate point, considering factors like line length, hyphenation, and orphans.
    * Use a dynamic programming-like approach (suggested by the `ComputeScores` logic with `best` and `best_prev_index`) to find the combination of breakpoints with the lowest overall score.
    * Output the optimized breakpoints.

6. **Connect to Web Technologies:**

    * **CSS:** The code directly interacts with `ComputedStyle` to get font size, text alignment (`text-align: justify`), and zoom level. This is the primary connection to CSS.
    * **HTML:** The code operates on the layout of inline content, which is defined by HTML structure. It breaks lines within HTML elements.
    * **JavaScript:** While this specific C++ file doesn't *directly* interact with JavaScript, the layout engine as a whole is triggered by changes in the DOM (manipulated by JavaScript) and CSS styles (also potentially manipulated by JavaScript). JavaScript actions can lead to relayout, which involves this code.

7. **Illustrate with Examples:** Create concrete examples to demonstrate the interactions with HTML and CSS.

    * **CSS `text-align: justify;`:** Show how the `is_justified_` flag affects hyphenation and line penalties.
    * **Short Last Line:**  Explain how the `ShouldOptimize` function targets this scenario.
    * **Consecutive Hyphenated Lines:** Explain how the `ShouldOptimize` function targets this scenario.

8. **Consider Edge Cases and Errors:** Think about what could go wrong or common mistakes a developer might make.

    * **Incorrect CSS:** Applying conflicting styles could lead to unexpected behavior in line breaking.
    * **Performance:**  The comments mention the "expensive" nature of the scoring algorithm. This implies that excessively long or complex text layouts could have performance implications.

9. **Hypothesize Input and Output:**  Create simple scenarios with hypothetical inputs and the expected output based on the inferred logic. Focus on how different CSS styles would influence the breakpoints.

10. **Review and Refine:** Read through the explanation to ensure clarity, accuracy, and completeness. Correct any misunderstandings or missing information. For instance, initially, I might have missed the significance of the "balanced" text concept, but further reading of the `BalanceBreakPoints` function and related comments clarifies this.

By following these steps, systematically examining the code, and connecting it to the broader context of web technologies, you can arrive at a comprehensive and accurate explanation of the `score_line_breaker.cc` file's functionality.
这个文件是 Chromium Blink 渲染引擎中负责**对内联文本进行高级换行优化的组件**。它尝试在保证文本可读性的前提下，找到更美观的换行位置，尤其是在处理多行文本时。

**功能总结:**

1. **优化换行位置:**  `ScoreLineBreaker` 的主要目标是通过计算不同换行方案的 "得分" 来找到最佳的换行位置。这个评分机制会考虑多种因素，例如避免过短的最后一行（orphans）、避免连续的连字符行等。
2. **有条件的应用:** 由于其计算成本较高，`ScoreLineBreaker` 并不会总是被调用。它会先通过 `ShouldOptimize` 函数判断是否有优化的必要。只有当贪婪换行算法的结果不够理想时，才会启用 `ScoreLineBreaker` 进行更精细的计算。
3. **支持平衡换行:**  `BalanceBreakPoints` 方法表明它可以用于实现更均衡的换行，这在一些排版场景下（例如，标题或强调文本）会更美观。
4. **考虑 CSS 样式:**  它会获取元素的 `ComputedStyle`，特别是 `text-align` 属性（用于判断是否需要进行两端对齐）和字体大小等信息，来调整其换行策略和计算参数。
5. **处理连字符:**  它会考虑连字符带来的影响，并试图避免不必要的连字符。
6. **与 `LineBreaker` 协同工作:**  `ScoreLineBreaker` 并不是从头开始进行换行，而是建立在 `LineBreaker` 的基础上。`LineBreaker` 实现了基本的贪婪换行算法，而 `ScoreLineBreaker` 则对其结果进行优化。
7. **支持行限制:**  它会考虑 `MaxLines()` 限制，避免生成超过最大行数的换行方案。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**
    * **`text-align: justify;` (两端对齐):**  如果 CSS 样式中设置了 `text-align: justify;`，`ScoreLineBreaker` 会调整其评分策略，使连字符更积极，并可能取消行尾惩罚。这是因为两端对齐通常会产生较大的单词间距，而连字符可以改善这种情况。
        * **假设输入:** 一个 `<p style="text-align: justify;">` 元素包含一段长文本。
        * **逻辑推理:** `SetupParameters` 中会检测到 `text-align: justify`，并将 `hyphen_penalty_` 设置得较低， `line_penalty_` 设置为 0。在 `ComputeScores` 中，即使某行的长度略微不足，也不会受到过高的惩罚，从而更倾向于通过连字符来填充该行。
        * **输出:** 最终的换行结果可能会包含更多的连字符，但每行的宽度会更接近可用宽度，实现两端对齐的效果。
    * **字体大小 (`font-size`):**  字体大小会影响 `ScoreLineBreaker` 的内部参数计算。较大的字体可能意味着更宽松的换行限制。
        * **假设输入:** 两个 `<p>` 元素，内容相同，但一个设置了较大的 `font-size`。
        * **逻辑推理:** `SetupParameters` 中会根据 `font-size` 计算 `width_times_font_size`，进而影响 `hyphen_penalty_` 和 `line_penalty_`。对于较大字体的段落，这些惩罚值可能会更高。
        * **输出:** 较大字体段落的换行可能更少，每行的单词数可能更少，因为其对“不够满”的行容忍度更高。

* **HTML:**
    * `ScoreLineBreaker` 负责处理 HTML 元素内部的文本内容，决定如何在这些内容中换行。不同的 HTML 结构会导致不同的布局上下文，从而影响 `ScoreLineBreaker` 的行为。
    * **假设输入:** 一个包含多个 `<span>` 标签的长文本段落。
    * **逻辑推理:**  `ScoreLineBreaker` 会遍历这些内联节点，考虑每个节点的大小和属性，以及它们之间的断点机会。
    * **输出:** 最终的换行位置会考虑这些 `<span>` 标签的边界，例如，避免在 `<span>` 内部进行不必要的断行。

* **JavaScript:**
    * JavaScript 可以动态修改 HTML 结构和 CSS 样式。当 JavaScript 导致文本内容或样式发生变化时，渲染引擎会重新进行布局，这可能会触发 `ScoreLineBreaker` 重新计算换行位置。
    * **假设输入:** 一个包含长文本的 `<div>` 元素，初始时 `text-align` 为 `left`。JavaScript 代码动态地将其 `text-align` 修改为 `justify`。
    * **逻辑推理:**  当 `text-align` 属性发生变化时，渲染引擎会标记需要重新布局。在布局过程中，`ScoreLineBreaker` 会读取新的 `text-align` 值，并在后续的换行计算中使用新的参数。
    * **输出:**  在 JavaScript 修改样式后，该 `<div>` 元素的文本换行方式会发生改变，可能会出现更多的连字符，以实现两端对齐的效果。

**逻辑推理的假设输入与输出:**

**场景 1: 短的最后一行优化**

* **假设输入:** 一段文本，使用贪婪算法换行后，最后一行非常短，只有一个词。
* **逻辑推理:** `ShouldOptimize` 函数会检测到 `last_line.Width() < last_line.AvailableWidth() / kShortLineDenominator` 并且 `!line_breaker.CanBreakInside(last_line)`，从而返回 `true`，触发 `ScoreLineBreaker` 的优化。`ComputeScores` 中会给予较短的行较高的惩罚。
* **输出:** `ScoreLineBreaker` 可能会将最后一行的一个或多个单词移动到倒数第二行，以避免过短的最后一行。

**场景 2: 避免连续的连字符行**

* **假设输入:** 一段文本，使用贪婪算法换行后，倒数第二行和倒数第三行都以连字符结尾。
* **逻辑推理:** `ShouldOptimize` 函数会检测到 `line_info_list[num_lines - 2].IsHyphenated()` 和 `line_info_list[num_lines - 3].IsHyphenated()`，从而返回 `true`，触发 `ScoreLineBreaker` 的优化。`ComputeScores` 中会给予连续连字符的换行较高的惩罚。
* **输出:** `ScoreLineBreaker` 可能会调整倒数第二行或倒数第三行的换行位置，以避免连续出现连字符。

**用户或编程常见的使用错误:**

1. **过度依赖 `ScoreLineBreaker` 的优化效果:**  开发者可能会期望 `ScoreLineBreaker` 能解决所有换行问题。但 `ScoreLineBreaker` 只是一个优化步骤，其效果受限于文本内容、可用空间和 CSS 样式。对于某些极端情况，即使经过优化，换行结果可能仍然不尽如人意。
    * **示例:**  在非常狭窄的容器中显示包含很长单词的文本，即使 `ScoreLineBreaker` 尽力优化，也可能无法避免单词溢出或难看的断行。
2. **错误地理解 `ShouldOptimize` 的触发条件:** 开发者可能认为只要启用了 `ScoreLineBreaker`，就能获得最佳的换行效果。但实际上，只有当 `ShouldOptimize` 判断有优化的必要时，`ScoreLineBreaker` 才会运行。
    * **示例:**  对于单行文本或换行机会较少的短文本，`ShouldOptimize` 通常会返回 `false`，这意味着 `ScoreLineBreaker` 不会参与计算，最终的换行结果可能与贪婪算法相同。
3. **忽略 CSS 样式对换行的影响:** 开发者可能只关注 `ScoreLineBreaker` 的代码，而忽略了 CSS 样式对换行的决定性作用。例如，设置了 `white-space: nowrap` 将阻止任何自动换行，即使 `ScoreLineBreaker` 参与了计算也不会生效。
    * **示例:**  一个元素设置了 `white-space: nowrap;`，开发者可能会疑惑为什么文本没有按照预期的方式换行。这是因为 CSS 的优先级高于浏览器的默认换行行为和 `ScoreLineBreaker` 的优化。

总而言之，`blink/renderer/core/layout/inline/score_line_breaker.cc` 是 Blink 引擎中一个重要的排版优化组件，它通过评分机制来改善内联文本的换行效果，尤其关注提高多行文本的可读性和美观性。它与 CSS 样式紧密相关，并作为布局过程的一部分，间接地受到 HTML 结构和 JavaScript 操作的影响。理解其功能和触发条件有助于开发者更好地理解和控制网页的文本排版。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/score_line_breaker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/score_line_breaker.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/line_breaker.h"
#include "third_party/blink/renderer/core/layout/inline/line_info_list.h"
#include "third_party/blink/renderer/core/layout/inline/line_widths.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"

namespace blink {

namespace {

// Determines whether `ScoreLineBreaker` should be applied or not from the
// greedy line break results. Because the `ScoreLineBreaker` is expensive,
// and it often produces the similar results to the greedy algorithm, apply
// it only when its benefit is obvious.
ALWAYS_INLINE bool ShouldOptimize(const LineInfoList& line_info_list,
                                  LineBreaker& line_breaker) {
  // The optimization benefit is most visible when the last line is short.
  // Otherwise, the improvement is not worth the performance impact.
  const LineInfo& last_line = line_info_list.Back();
  constexpr int kShortLineDenominator = 3;
  if (last_line.Width() < last_line.AvailableWidth() / kShortLineDenominator &&
      // Similarly, optimize only when the last line has a single word; i.e.,
      // has no break opportunities. This takes some cost, but the performance
      // improvement by reducing the applicability wins over the cost.
      !line_breaker.CanBreakInside(last_line)) {
    return true;
  }

  // Hyphenating the second to last line is not desirable, and consecutive
  // hyphenated lines are not desirable either. For now, apply only if both
  // occur, to minimize the performance impact.
  constexpr wtf_size_t kNumLastHyphenatedLines = 2;
  const wtf_size_t num_lines = line_info_list.Size();
  if (num_lines >= kNumLastHyphenatedLines + 1 &&
      line_info_list[num_lines - 2].IsHyphenated() &&
      line_info_list[num_lines - 3].IsHyphenated()) {
    return true;
  }

  return false;
}

}  // namespace

void ScoreLineBreaker::SetScoresOutForTesting(Vector<float>* scores_out) {
  scores_out_for_testing_ = scores_out;
}

void ScoreLineBreaker::OptimalBreakPoints(const LeadingFloats& leading_floats,
                                          ScoreLineBreakContext& context) {
  DCHECK(!is_balanced_ || !break_token_);
  DCHECK(context.GetLineBreakPoints().empty());
  DCHECK(!node_.IsScoreLineBreakDisabled());
  DCHECK(context.IsActive());
  LineInfoList& line_info_list = context.GetLineInfoList();
  const wtf_size_t max_lines = MaxLines();
  DCHECK_GE(line_info_list.MaxLines(), max_lines);
  DCHECK_LT(line_info_list.Size(), max_lines);
  wtf_size_t line_index = 0;
  if (!line_info_list.IsEmpty()) {
    line_index = line_info_list.Size();
    // To compute the next line after the last cached line, update
    // `break_token_` to the last cached break token.
    const LineInfo& last_line = line_info_list.Back();
    break_token_ = last_line.GetBreakToken();
    // The last line should not be the end of paragraph.
    // `SuspendUntilConsumed()` should have prevented this from happening.
    DCHECK(break_token_ && !last_line.HasForcedBreak());
  }

  // Compute line breaks and cache the results (`LineInfo`) up to
  // `LineInfoList::kCapacity` lines.
  LayoutUnit line_width = line_widths_[line_index];
  LineBreaker line_breaker(
      node_, LineBreakerMode::kContent, GetConstraintSpace(),
      LineLayoutOpportunity(line_width), leading_floats, break_token_,
      /* column_spanner_path */ nullptr, exclusion_space_);
  const int lines_until_clamp =
      space_.GetLineClampData().LinesUntilClamp().value_or(0);
  for (;;) {
    LineInfo& line_info = line_info_list.Append();
    line_breaker.NextLine(&line_info);
    break_token_ = line_info.GetBreakToken();
    if (line_breaker.ShouldDisableScoreLineBreak()) [[unlikely]] {
      context.SuspendUntilEndParagraph();
      return;
    }
    if (line_info.IsEndParagraph() || [&] {
          if (lines_until_clamp > 0 &&
              line_info_list.Size() ==
                  static_cast<wtf_size_t>(lines_until_clamp)) [[unlikely]] {
            return true;
          }
          return false;
        }()) {
      context.SuspendUntilEndParagraph();
      break;
    }
    DCHECK(!line_info.Results().empty());
    DCHECK(!line_breaker.IsFinished());
    if (line_info_list.Size() >= max_lines) {
      return;
    }

    const LayoutUnit next_line_width = line_widths_[++line_index];
    if (next_line_width != line_width) {
      line_width = next_line_width;
      line_breaker.SetLineOpportunity(LineLayoutOpportunity(line_width));
    }
  }
  DCHECK(!line_info_list.IsEmpty());

  // Now we have a "paragraph" in `line_info_list`; i.e., a block, or a part
  // of a block segmented by forced line breaks.
  if (line_info_list.Size() <= 1) {
    return;  // Optimization not needed for single line paragraphs.
  }
  if (!is_balanced_) {
    if (!ShouldOptimize(line_info_list, line_breaker)) {
      return;
    }
  }

  LineBreakPoints& break_points = context.GetLineBreakPoints();
  if (!Optimize(line_info_list, line_breaker, break_points)) {
    DCHECK(break_points.empty());
    return;
  }
  DCHECK(!break_points.empty());

  // If succeeded, clear the previously computed `line_info_list` if optimized
  // break points are different.
  DCHECK_EQ(line_info_list.Size(), break_points.size());
  for (wtf_size_t i = 0; i < line_info_list.Size(); ++i) {
    const LineInfo& line_info = line_info_list[i];
    if (line_info.End() != break_points[i].offset) {
      line_info_list.Shrink(i);
      break;
    }
  }
}

void ScoreLineBreaker::BalanceBreakPoints(const LeadingFloats& leading_floats,
                                          ScoreLineBreakContext& context) {
  is_balanced_ = true;
  OptimalBreakPoints(leading_floats, context);
}

bool ScoreLineBreaker::Optimize(const LineInfoList& line_info_list,
                                LineBreaker& line_breaker,
                                LineBreakPoints& break_points) {
  DCHECK(break_points.empty());

  SetupParameters();

  // Compute all break opportunities and their penalties.
  LineBreakCandidates candidates;
  if (!ComputeCandidates(line_info_list, line_breaker, candidates)) {
    DCHECK(break_points.empty());
    return false;
  }

  // Optimization not needed if one or no break opportunities in the paragraph.
  // The `candidates` has sentinels, one at the front and one at the back, so
  // `2` means no break opportunities, `3` means one.
  DCHECK_GE(candidates.size(), 2u);
  constexpr wtf_size_t kMinCandidates = 3;
  if (candidates.size() < kMinCandidates + 2) {
    DCHECK(break_points.empty());
    return false;
  }

  if (candidates.size() >= 4) {
    // Increase penalties to minimize typographic orphans.
    constexpr float kOrphansPenalty = 10000;
    const float orphans_penalty = kOrphansPenalty * zoom_;
    const auto candidates_span =
        base::span(candidates).first(candidates.size() - 1);
    for (LineBreakCandidate& candidate : base::Reversed(candidates_span)) {
      candidate.penalty += orphans_penalty;
      if (!candidate.is_hyphenated) {
        break;
      }
    }
  }

  ComputeLineWidths(line_info_list);

  // Compute score for each break opportunity.
  LineBreakScores scores;
  scores.ReserveInitialCapacity(candidates.size());
  ComputeScores(candidates, scores);
  DCHECK_EQ(candidates.size(), scores.size());

  // Determine final break points.
  ComputeBreakPoints(candidates, scores, break_points);

  // Copy data for testing.
  if (scores_out_for_testing_) [[unlikely]] {
    for (const LineBreakScore& score : scores) {
      scores_out_for_testing_->push_back(score.score);
    }
  }

  return true;
}

bool ScoreLineBreaker::ComputeCandidates(const LineInfoList& line_info_list,
                                         LineBreaker& line_breaker,
                                         LineBreakCandidates& candidates) {
  // The first entry is a sentinel at the start of the line.
  DCHECK(candidates.empty());
  LineBreakCandidateContext context(candidates);
  context.SetHyphenPenalty(hyphen_penalty_);
  context.EnsureFirstSentinel(line_info_list.Front());

  for (wtf_size_t i = 0; i < line_info_list.Size(); ++i) {
    const LineInfo& line_info = line_info_list[i];
    if (!context.AppendLine(line_info, line_breaker)) {
      candidates.clear();
      return false;
    }
  }

  // The last entry is a sentinel at the end of the line.
  context.EnsureLastSentinel(line_info_list.Back());
  return true;
}

LayoutUnit ScoreLineBreaker::AvailableWidth(wtf_size_t line_index) const {
  LayoutUnit available_width = line_widths_[line_index];
  if (line_index == 0) {
    available_width -= first_line_indent_;
  }
  return available_width.ClampNegativeToZero();
}

void ScoreLineBreaker::ComputeLineWidths(const LineInfoList& line_info_list) {
  first_line_indent_ = line_info_list.Front().TextIndent();
#if EXPENSIVE_DCHECKS_ARE_ON()
  // Only the first line may have an indent.
  for (wtf_size_t i = 1; i < line_info_list.Size(); ++i) {
    DCHECK_EQ(line_info_list[i].TextIndent(), LayoutUnit());
  }
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
}

void ScoreLineBreaker::SetupParameters() {
  // Use the same heuristic parameters as Minikin's `computePenalties()`.
  // https://cs.android.com/android/platform/superproject/+/master:frameworks/minikin/libs/minikin/OptimalLineBreaker.cpp
  const LayoutUnit available_width =
      line_widths_.Default().ClampNegativeToZero();
  const ComputedStyle& block_style = node_.Style();
  const float font_size = block_style.GetFontDescription().ComputedSize();
  zoom_ = block_style.EffectiveZoom();
  DCHECK_GT(zoom_, .0f);
  // Penalties/scores should be a zoomed value. Because both `font_size` and
  // `available_width` are zoomed, unzoom once.
  const float width_times_font_size =
      available_width.ToFloat() * font_size / zoom_;
  is_justified_ = block_style.GetTextAlign() == ETextAlign::kJustify;
  if (is_justified_) {
    // For justified text, make hyphenation more aggressive and no line penalty.
    hyphen_penalty_ = width_times_font_size / 2;
    line_penalty_ = .0f;
  } else {
    hyphen_penalty_ = width_times_font_size * 2;
    line_penalty_ = hyphen_penalty_ * 2;
  }
}

void ScoreLineBreaker::ComputeScores(const LineBreakCandidates& candidates,
                                     LineBreakScores& scores) {
  DCHECK_GE(candidates.size(), 2u);
  DCHECK(scores.empty());
  scores.push_back(LineBreakScore{0, 0, 0});
  wtf_size_t active = 0;

  // `end` iterates through candidates for the end of the line.
  for (wtf_size_t end = 1; end < candidates.size(); ++end) {
    const LineBreakCandidate& end_candidate = candidates[end];
    const bool is_end_last_candidate = end == candidates.size() - 1;
    float best = kScoreInfinity;
    wtf_size_t best_prev_index = 0;

    wtf_size_t last_line_index = scores[active].line_index;
    LayoutUnit available_width = AvailableWidthToFit(last_line_index);
    float start_edge = end_candidate.pos_if_break - available_width;
    float best_hope = 0;

    // `start` iterates through candidates for the beginning of the line, to
    // determine the best score for the `end`.
    for (wtf_size_t start = active; start < end; ++start) {
      const LineBreakScore& start_score = scores[start];
      const wtf_size_t line_index = start_score.line_index;
      if (line_index != last_line_index) {
        last_line_index = line_index;
        const LayoutUnit new_available_width = AvailableWidthToFit(line_index);
        if (new_available_width != available_width) {
          available_width = new_available_width;
          start_edge = end_candidate.pos_if_break - available_width;
          best_hope = 0;
        }
      }
      const float start_score_value = start_score.score;
      if (start_score_value + best_hope >= best) {
        continue;
      }
      const LineBreakCandidate& start_candidate = candidates[start];
      const float delta = start_candidate.pos_no_break - start_edge;

      // Compute width score for line.

      // Note: the "best_hope" optimization makes the assumption that, when
      // delta is non-negative, width_score will increase monotonically as
      // successive candidate breaks are considered.
      float width_score = 0;
      float additional_penalty = 0;
      if ((is_end_last_candidate || !is_justified_) && delta < 0) {
        width_score = kScoreOverfull;
      } else if (is_end_last_candidate && !is_balanced_) {
        // Increase penalty for hyphen on last line.
        // TODO(kojii): Review the penalty value.
        additional_penalty =
            kLastLinePenaltyMultiplier * start_candidate.penalty;
      } else if (delta < 0) {
        width_score = kScoreOverfull;
      } else {
        // Penalties/scores should be a zoomed value. Because `delta` is zoomed,
        // unzoom once.
        width_score = delta * delta / zoom_;
      }
      if (delta < 0) {
        active = start + 1;
      } else {
        best_hope = width_score;
      }
      const float score = start_score_value + width_score + additional_penalty;
      if (score <= best) {
        best = score;
        best_prev_index = start;
      }
    }

    scores.push_back(LineBreakScore{
        best + end_candidate.penalty + line_penalty_, best_prev_index,
        scores[best_prev_index].line_index + 1});
  }
}

void ScoreLineBreaker::ComputeBreakPoints(const LineBreakCandidates& candidates,
                                          const LineBreakScores& scores,
                                          LineBreakPoints& break_points) {
  DCHECK_GE(candidates.size(), 3u);
  DCHECK_EQ(candidates.size(), scores.size());
  DCHECK(break_points.empty());
  DCHECK_LE(scores.back().line_index, MaxLines());

  for (wtf_size_t i = scores.size() - 1, prev_index; i > 0; i = prev_index) {
    prev_index = scores[i].prev_index;
    const LineBreakCandidate& candidate = candidates[i];
    break_points.push_back(candidate);
#if EXPENSIVE_DCHECKS_ARE_ON()
    const LineBreakCandidate& prev_candidate = candidates[prev_index];
    const LayoutUnit line_width = LayoutUnit::FromFloatCeil(
        candidate.pos_if_break - prev_candidate.pos_no_break);
    DCHECK_GE(line_width, 0);
    break_points.back().line_width = line_width;
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
  }
  DCHECK_EQ(break_points.size(), scores.back().line_index);

  // `break_points` is in the descending order. Reverse it.
  break_points.Reverse();

#if EXPENSIVE_DCHECKS_ARE_ON()
  DCHECK_EQ(break_points.size(), scores.back().line_index);
  for (wtf_size_t i = 1; i < break_points.size(); ++i) {
    DCHECK_GT(break_points[i].offset, break_points[i - 1].offset);
  }
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
}

}  // namespace blink
```