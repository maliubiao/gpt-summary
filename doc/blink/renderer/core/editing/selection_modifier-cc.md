Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the summary.

**1. Initial Understanding & Goal:**

The request asks for a functional breakdown of the `selection_modifier.cc` file within the Chromium Blink engine. It specifically requests information about its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning with input/output examples, common usage errors, debugging clues, and finally, a concise functional summary of this first part.

**2. High-Level Overview of the File:**

The file name itself, `selection_modifier.cc`, strongly suggests its primary function: modifying text selections within a web page. The copyright header and included files provide initial clues about the scope and dependencies. The includes like `editing/`, `frame/`, `layout/`, and `page/` point towards core functionalities related to text editing, document structure, and page rendering.

**3. Deeper Dive into Key Functionality (Iterative Process):**

I started by scanning the code for significant function names, keywords, and data structures.

* **`SelectionModifier` class:** This is clearly the central class. Its constructor takes a `LocalFrame` and `SelectionInDOMTree`, indicating it operates within the context of a web page and manipulates the selection.
* **`Modify...` methods:** Functions like `ModifyExtendingRight`, `ModifyMovingForward`, `ModifyExtendingLeft`, `ModifyMovingBackward` immediately stand out. The names suggest different ways the selection can be changed (extending or moving) in different directions (right, forward, left, backward). The `TextGranularity` enum suggests the level of modification (character, word, line, paragraph, etc.).
* **`VisiblePositionInFlatTree`:** This data type appears frequently. The name implies a position within the rendered page, likely accounting for layout and potentially non-linear text flow.
* **`VisibleSelectionInFlatTree` and `SelectionInDOMTree`:** These represent the selection itself at different levels of abstraction (flat tree vs. DOM tree). The code includes conversions between them.
* **Helper functions:**  Functions like `PreviousParagraphPosition`, `NextParagraphPosition`, `LeftBoundaryOfLine`, `RightBoundaryOfLine`, `NextWordPositionForPlatform`, etc., suggest fine-grained manipulation of positions and boundaries within the text.
* **Directionality:**  The frequent use of `TextDirection` and functions like `DirectionOfEnclosingBlock`, `DirectionOfSelection`, `LineDirectionOfFocus` indicates a concern for handling bidirectional text.
* **Platform-specific behavior:**  The `...ForPlatform` suffixes on some function names (e.g., `NextWordPositionForPlatform`) suggest handling differences in selection behavior across operating systems.
* **User Select All:** The `AdjustForwardPositionForUserSelectAll` and `AdjustBackwardPositionForUserSelectAll` functions point to specific logic for handling "select all" scenarios.

**4. Connecting to Web Technologies:**

Based on the identified functionalities, I started thinking about how these relate to JavaScript, HTML, and CSS.

* **JavaScript:**  JavaScript can trigger selection changes through user interactions (like mouse dragging) or programmatically using the Selection API. This API's actions would eventually call into the native code like `selection_modifier.cc`.
* **HTML:** The structure of the HTML document (elements, text nodes, etc.) directly influences how selections are made and modified. The boundaries of elements, paragraphs, and lines defined in HTML are what the `selection_modifier.cc` code operates on.
* **CSS:**  CSS properties like `direction` (for RTL text) and `user-select` can influence the behavior of the selection and are likely considered by the code.

**5. Constructing Examples and Scenarios:**

To illustrate the functionality, I imagined common user actions and their corresponding inputs and outputs within the context of selection modification.

* **Extending selection by word:**  Start with a cursor position, extend the selection by one word to the right. Consider LTR and RTL scenarios.
* **Moving the cursor by paragraph:**  Start at one point, move the cursor to the next paragraph.
* **Double-clicking to select a word:**  This implicitly triggers a selection modification at the word granularity.

**6. Identifying Potential Errors and Debugging Clues:**

Thinking about how things could go wrong led to identifying potential user errors and debugging strategies.

* **Incorrect cursor placement:**  The user might place the cursor in an unexpected location, leading to unexpected selection behavior.
* **Bidirectional text issues:**  Mixing LTR and RTL text can create complex scenarios.
* **Editing boundaries:**  Selections might be constrained by non-editable content.

The debugging clues focus on how to trace the user's actions and the code execution to pinpoint the source of an issue.

**7. Structuring the Output:**

I organized the information into the requested categories: functionality, relation to web technologies, logical reasoning, user errors, debugging, and summary. This provides a clear and structured overview of the file's purpose.

**8. Drafting and Refining:**

The initial draft was likely more scattered. I refined the language, ensuring clarity and conciseness. I made sure to provide concrete examples and explanations rather than just listing features. The iterative process of understanding the code and then explaining it helped to solidify the understanding. For example, the initial understanding of the `PrepareToModifySelection` might have been vague, but by looking at its logic regarding anchor and focus, the explanation became more precise.

**Self-Correction/Refinement during the process:**

* **Initially, I might have focused too much on specific function implementations.**  The prompt asked for *functionality*, so I shifted towards a higher-level description of what the code *does* rather than how it does it (for most parts).
* **I ensured the examples were realistic and relatable to web development scenarios.**  Abstract examples are less helpful.
* **I double-checked the relationship to JavaScript, HTML, and CSS.**  It's important to connect the native code to the higher-level web technologies.

By following this iterative process of exploring the code, connecting it to web concepts, generating examples, and refining the explanation, I was able to create the comprehensive summary provided in the initial example.好的，让我们一起来分析 `blink/renderer/core/editing/selection_modifier.cc` 这个文件的功能。

**功能列举:**

这个文件的核心功能是**修改文本的选择范围 (Selection)**。它提供了一系列方法来移动和扩展当前的选择，支持不同的粒度（字符、单词、行、段落等）和方向（向前、向后、向左、向右）。

更具体地说，它实现了以下功能：

1. **基于不同粒度的选择移动和扩展:**
   - 以字符为单位向前、向后移动或扩展选择。
   - 以单词为单位向前、向后移动或扩展选择。
   - 以行为单位向上、向下移动或扩展选择。
   - 以段落为单位向上、向下移动或扩展选择。
   - 以句子为单位向前、向后移动或扩展选择。
   - 移动到行首、行尾、段落首、段落尾、文档首、文档尾。

2. **处理文本方向 (LTR/RTL):**
   - 考虑文本的阅读方向，例如在 RTL (从右到左) 文本中，“向右”移动实际上是逻辑上的向后移动。
   - 提供方法判断当前光标所在块级元素的文本方向。

3. **处理编辑边界:**
   - 可以配置是否允许跨越不可编辑内容边界进行选择移动和扩展。

4. **处理平台差异:**
   - 某些选择行为在不同的操作系统上可能存在差异，例如单词选择的定义。该文件会考虑这些平台特定的行为。

5. **处理 `user-select: all` 属性:**
   -  当遇到设置了 `user-select: all` 的元素时，能正确地将选择范围调整到整个元素。

6. **辅助功能:**
   -  例如，对于垂直方向的移动，它需要知道当前光标的水平位置，以便在换行时保持相对的水平位置。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件是 Blink 渲染引擎的一部分，它处理的是浏览器内核层面的选择修改逻辑。JavaScript 可以通过浏览器的 Selection API 来触发这些修改。HTML 结构和 CSS 样式会影响选择的行为。

* **JavaScript:**
    - **举例:** 当用户在网页上拖动鼠标进行选择时，或者使用键盘快捷键 (如 Shift + 箭头键) 来扩展选择时，JavaScript 的事件监听器会捕获这些操作，并调用 Selection API 的相应方法（例如 `Selection.extend()`, `Selection.collapse()` 等）。这些 API 调用最终会触发 `selection_modifier.cc` 中的 C++ 代码执行。

        ```javascript
        // 获取当前的选择对象
        const selection = window.getSelection();

        // 扩展选择到下一个单词
        selection.modify('extend', 'forward', 'word');

        // 将选择折叠到焦点位置
        selection.collapseToEnd();
        ```

* **HTML:**
    - **举例:** HTML 文档的结构定义了文本的段落、行和单词的边界。`selection_modifier.cc` 中的代码会根据 HTML 的 DOM 树结构来确定这些边界，例如，`<p>` 标签定义了段落的边界，换行符或 `<br>` 标签会影响行的边界。

        ```html
        <p>This is the first paragraph.</p>
        <p>This is the second paragraph with <b>bold</b> text.</p>
        ```
        在这个例子中，当使用段落粒度移动选择时，代码会识别 `<p>` 标签作为段落的起始和结束。

* **CSS:**
    - **举例:** CSS 的 `direction` 属性会影响文本的阅读方向，从而影响选择的移动方向。例如，对于包含 `direction: rtl;` 样式的元素，`selection_modifier.cc` 中的代码会将“向右”的移动解释为逻辑上的向后移动。
    - **举例:** CSS 的 `user-select` 属性可以控制元素是否可选，以及如何选择。例如，`user-select: none;` 会阻止用户选择元素内的文本。`user-select: all;` 会使得点击元素时选中所有内容。`selection_modifier.cc` 需要处理这些 CSS 属性带来的影响。

        ```css
        .rtl-text {
            direction: rtl;
        }

        .unselectable {
            user-select: none;
        }

        .select-all {
            user-select: all;
        }
        ```

**逻辑推理的假设输入与输出:**

假设输入：

1. **当前选择:**  光标位于字符串 "Hello World!" 中 "W" 的前面。
2. **操作:**  调用 `ModifyMovingForward(TextGranularity::kWord)`。
3. **文本方向:**  LTR。

输出：

1. **新的选择:** 光标将移动到 "orld!" 之后，即移动到了下一个单词的末尾。

假设输入：

1. **当前选择:**  选中了字符串 "你好世界" 中的 "好" 字。
2. **操作:**  调用 `ModifyExtendingBackward(TextGranularity::kCharacter)`。
3. **文本方向:**  LTR (尽管文本内容是中文，但假设 surrounding block 的方向是 LTR，这会影响某些扩展行为的逻辑)。

输出：

1. **新的选择:**  将选中 "你好" 两个字 (因为是 backward extending，所以会包含前一个字符)。

**用户或编程常见的使用错误举例说明:**

1. **用户错误:** 用户可能无意中按下了错误的快捷键，导致选择范围意外地发生了改变。例如，在文本框中输入时，误触了 Shift + Ctrl + 箭头键，导致选择了多个单词或整个段落。

2. **编程错误 (JavaScript):**  开发者可能错误地使用 Selection API，例如，传递了错误的参数给 `selection.modify()` 方法，或者在不恰当的时机修改了选择，导致用户界面出现非预期的行为。

   ```javascript
   // 错误地尝试向后移动选择的锚点，而不是焦点
   // (Selection API 通常是操作焦点)
   // window.getSelection().anchorNode.textContent.modify('move', 'backward', 'word'); // 这不是正确的 API 用法
   ```

**用户操作是如何一步步到达这里 (调试线索):**

1. **用户交互:** 用户进行了与选择相关的操作，例如：
   - **鼠标操作:** 点击并拖动鼠标来选择文本。
   - **键盘操作:** 使用方向键移动光标，或者结合 Shift 键来扩展选择。
   - **双击/三击:** 双击选择单词，三击选择段落。
   - **上下文菜单:** 使用上下文菜单中的“全选”或其他选择相关操作。

2. **浏览器事件:** 用户的操作会被浏览器捕获为相应的事件，例如 `mousedown`, `mouseup`, `mousemove`, `keydown`, `keyup` 等。

3. **事件处理:** 浏览器的事件处理机制会处理这些事件。对于与选择相关的事件，浏览器会调用相应的内部逻辑。

4. **Blink 渲染引擎:** 这些内部逻辑会涉及到 Blink 渲染引擎的组件。对于选择的修改，会调用 `core/editing/` 目录下的相关代码。

5. **`selection_modifier.cc`:**  最终，根据用户的操作类型和当前的上下文，可能会调用 `SelectionModifier` 类中的相应方法，例如 `ModifyMovingForward`, `ModifyExtendingRight` 等。

**作为调试线索，可以关注以下几点:**

* **断点:** 在 `selection_modifier.cc` 中设置断点，特别是 `Modify...` 开头的方法，可以观察代码的执行流程和变量的值。
* **输入参数:** 检查传递给 `SelectionModifier` 方法的参数，例如当前的 `SelectionInDOMTree` 和 `TextGranularity`，是否符合预期。
* **调用堆栈:** 查看函数调用堆栈，可以追踪用户操作是如何一步步触发到 `selection_modifier.cc` 的代码的。
* **日志输出:** 在关键位置添加日志输出，记录选择范围的变化和相关的状态信息。

**功能归纳 (第 1 部分):**

这个 `selection_modifier.cc` 文件的第一部分主要定义了 `SelectionModifier` 类及其核心的修改选择范围的功能。它提供了基于不同文本粒度和方向移动及扩展选择的方法，并初步考虑了文本方向性。  核心目标是根据用户的输入或程序的要求，精确地调整当前文档中的文本选择范围。这部分代码是浏览器处理文本选择操作的核心逻辑之一。

### 提示词
```
这是目录为blink/renderer/core/editing/selection_modifier.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010 Apple Inc. All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/selection_modifier.h"

#include "third_party/blink/renderer/core/editing/bidi_adjustment.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/inline_box_position.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/ng_flat_tree_shorthands.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/layout/inline/inline_caret_position.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/physical_fragment.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

// There are some cases where |SelectionModifier::ModifyWithPageGranularity()|
// enters an infinite loop. Work around it by hard-limiting the iteration.
const unsigned kMaxIterationForPageGranularityMovement = 1024;

VisiblePositionInFlatTree LeftBoundaryOfLine(const VisiblePositionInFlatTree& c,
                                             TextDirection direction) {
  DCHECK(c.IsValid()) << c;
  return direction == TextDirection::kLtr ? LogicalStartOfLine(c)
                                          : LogicalEndOfLine(c);
}

VisiblePositionInFlatTree RightBoundaryOfLine(
    const VisiblePositionInFlatTree& c,
    TextDirection direction) {
  DCHECK(c.IsValid()) << c;
  return direction == TextDirection::kLtr ? LogicalEndOfLine(c)
                                          : LogicalStartOfLine(c);
}

}  // namespace

static bool InSameParagraph(const VisiblePositionInFlatTree& a,
                            const VisiblePositionInFlatTree& b,
                            EditingBoundaryCrossingRule boundary_crossing_rule =
                                kCannotCrossEditingBoundary) {
  DCHECK(a.IsValid()) << a;
  DCHECK(b.IsValid()) << b;
  return a.IsNotNull() &&
         StartOfParagraph(a, boundary_crossing_rule).DeepEquivalent() ==
             StartOfParagraph(b, boundary_crossing_rule).DeepEquivalent();
}

// static
VisiblePositionInFlatTree SelectionModifier::PreviousParagraphPosition(
    const VisiblePositionInFlatTree& passed_position,
    LayoutUnit x_point) {
  VisiblePositionInFlatTree position = passed_position;
  do {
    DCHECK(position.IsValid()) << position;
    const VisiblePositionInFlatTree& new_position = CreateVisiblePosition(
        PreviousLinePosition(position.ToPositionWithAffinity(), x_point));
    if (new_position.IsNull() ||
        new_position.DeepEquivalent() == position.DeepEquivalent())
      break;
    position = new_position;
  } while (InSameParagraph(
      passed_position, position,
      RuntimeEnabledFeatures::ModifyParagraphCrossEditingoundaryEnabled()
          ? kCanCrossEditingBoundary
          : kCannotCrossEditingBoundary));
  return position;
}

// static
VisiblePositionInFlatTree SelectionModifier::NextParagraphPosition(
    const VisiblePositionInFlatTree& passed_position,
    LayoutUnit x_point) {
  VisiblePositionInFlatTree position = passed_position;
  do {
    DCHECK(position.IsValid()) << position;
    const VisiblePositionInFlatTree& new_position = CreateVisiblePosition(
        NextLinePosition(position.ToPositionWithAffinity(), x_point));
    if (new_position.IsNull() ||
        new_position.DeepEquivalent() == position.DeepEquivalent())
      break;
    position = new_position;
  } while (InSameParagraph(
      passed_position, position,
      RuntimeEnabledFeatures::ModifyParagraphCrossEditingoundaryEnabled()
          ? kCanCrossEditingBoundary
          : kCannotCrossEditingBoundary));
  return position;
}

LayoutUnit NoXPosForVerticalArrowNavigation() {
  return LayoutUnit::Min();
}

bool SelectionModifier::ShouldAlwaysUseDirectionalSelection(
    const LocalFrame& frame) {
  return frame.GetEditor().Behavior().ShouldConsiderSelectionAsDirectional();
}

SelectionModifier::SelectionModifier(
    const LocalFrame& frame,
    const SelectionInDOMTree& selection,
    LayoutUnit x_pos_for_vertical_arrow_navigation)
    : frame_(&frame),
      current_selection_(ConvertToSelectionInFlatTree(selection)),
      x_pos_for_vertical_arrow_navigation_(
          x_pos_for_vertical_arrow_navigation) {}

SelectionModifier::SelectionModifier(const LocalFrame& frame,
                                     const SelectionInDOMTree& selection)
    : SelectionModifier(frame, selection, NoXPosForVerticalArrowNavigation()) {}

VisibleSelection SelectionModifier::Selection() const {
  return CreateVisibleSelection(
      ConvertToSelectionInDOMTree(current_selection_));
}

static VisiblePositionInFlatTree ComputeVisibleFocus(
    const VisibleSelectionInFlatTree& visible_selection) {
  return CreateVisiblePosition(visible_selection.Focus(),
                               visible_selection.Affinity());
}

TextDirection SelectionModifier::DirectionOfEnclosingBlock() const {
  const PositionInFlatTree& selection_focus = selection_.Focus();

  // TODO(editing-dev): Check for PositionInFlatTree::IsNotNull is an easy fix
  // for few editing/ web tests, that didn't expect that (e.g.
  // editing/selection/extend-byline-withfloat.html).
  // That should be fixed in a more appropriate manner.
  // We should either have SelectionModifier aborted earlier for null selection,
  // or do not allow null selection in SelectionModifier at all.
  return selection_focus.IsNotNull()
             ? DirectionOfEnclosingBlockOf(selection_focus)
             : TextDirection::kLtr;
}

namespace {

std::optional<TextDirection> DirectionAt(
    const PositionInFlatTreeWithAffinity& position) {
  if (position.IsNull())
    return std::nullopt;
  const PositionInFlatTreeWithAffinity adjusted =
      ComputeInlineAdjustedPosition(position);
  if (adjusted.IsNull())
    return std::nullopt;

  if (NGInlineFormattingContextOf(adjusted.GetPosition())) {
    const InlineCursor& cursor = ComputeInlineCaretPosition(adjusted).cursor;
    if (cursor)
      return cursor.Current().ResolvedDirection();
    return std::nullopt;
  }

  return std::nullopt;
}

// TODO(xiaochengh): Deduplicate code with |DirectionAt()|.
std::optional<TextDirection> LineDirectionAt(
    const PositionInFlatTreeWithAffinity& position) {
  if (position.IsNull())
    return std::nullopt;
  const PositionInFlatTreeWithAffinity adjusted =
      ComputeInlineAdjustedPosition(position);
  if (adjusted.IsNull())
    return std::nullopt;

  if (NGInlineFormattingContextOf(adjusted.GetPosition())) {
    InlineCursor line = ComputeInlineCaretPosition(adjusted).cursor;
    if (!line)
      return std::nullopt;
    line.MoveToContainingLine();
    return line.Current().BaseDirection();
  }

  return std::nullopt;
}

TextDirection DirectionOf(const VisibleSelectionInFlatTree& visible_selection) {
  std::optional<TextDirection> maybe_start_direction =
      DirectionAt(visible_selection.VisibleStart().ToPositionWithAffinity());
  std::optional<TextDirection> maybe_end_direction =
      DirectionAt(visible_selection.VisibleEnd().ToPositionWithAffinity());
  if (maybe_start_direction.has_value() && maybe_end_direction.has_value() &&
      maybe_start_direction.value() == maybe_end_direction.value())
    return maybe_start_direction.value();

  return DirectionOfEnclosingBlockOf(visible_selection.Focus());
}

}  // namespace

TextDirection SelectionModifier::DirectionOfSelection() const {
  return DirectionOf(selection_);
}

TextDirection SelectionModifier::LineDirectionOfFocus() const {
  return LineDirectionAt(selection_.VisibleFocus().ToPositionWithAffinity())
      .value_or(DirectionOfEnclosingBlockOf(selection_.Focus()));
}

static bool IsAnchorStart(const VisibleSelectionInFlatTree& visible_selection,
                          SelectionModifyDirection direction) {
  switch (direction) {
    case SelectionModifyDirection::kRight:
      return DirectionOf(visible_selection) == TextDirection::kLtr;
    case SelectionModifyDirection::kForward:
      return true;
    case SelectionModifyDirection::kLeft:
      return DirectionOf(visible_selection) != TextDirection::kLtr;
    case SelectionModifyDirection::kBackward:
      return false;
  }
  NOTREACHED() << "We should handle " << static_cast<int>(direction);
}

// This function returns |VisibleSelectionInFlatTree| from start and end
// position of current_selection_'s |VisibleSelectionInFlatTree| with
// |direction| and ordering of anchor and focus to handle anchor/focus don't
// match to start/end, e.g. granularity
// != character, and start/end adjustment in
// |VisibleSelectionInFlatTree::validate()| for range selection.
VisibleSelectionInFlatTree SelectionModifier::PrepareToModifySelection(
    SelectionModifyAlteration alter,
    SelectionModifyDirection direction) const {
  const VisibleSelectionInFlatTree& visible_selection =
      CreateVisibleSelection(current_selection_);
  if (alter != SelectionModifyAlteration::kExtend)
    return visible_selection;
  if (visible_selection.IsNone())
    return visible_selection;

  const EphemeralRangeInFlatTree& range =
      visible_selection.AsSelection().ComputeRange();
  if (range.IsCollapsed())
    return visible_selection;
  SelectionInFlatTree::Builder builder;
  // Make anchor and focus match start and end so we extend the user-visible
  // selection. This only matters for cases where anchor and focus point to
  // different positions than start and end (e.g. after a double-click to
  // select a word).
  const bool anchor_is_start =
      selection_is_directional_ ? visible_selection.IsAnchorFirst()
                                : IsAnchorStart(visible_selection, direction);
  if (anchor_is_start) {
    builder.SetAsForwardSelection(range);
  } else {
    builder.SetAsBackwardSelection(range);
  }
  return CreateVisibleSelection(builder.Build());
}

VisiblePositionInFlatTree SelectionModifier::PositionForPlatform(
    bool is_get_start) const {
  Settings* settings = GetFrame().GetSettings();
  if (settings && settings->GetEditingBehaviorType() ==
                      mojom::blink::EditingBehavior::kEditingMacBehavior)
    return is_get_start ? selection_.VisibleStart() : selection_.VisibleEnd();
  // Linux and Windows always extend selections from the focus endpoint.
  // FIXME: VisibleSelectionInFlatTree should be fixed to ensure as an invariant
  // that anchor/focus always point to the same nodes as start/end, but which
  // points to which depends on the value of IsAnchorFirst. Then this can be
  // changed to just return selection_.Focus().
  return selection_.IsAnchorFirst() ? selection_.VisibleEnd()
                                    : selection_.VisibleStart();
}

VisiblePositionInFlatTree SelectionModifier::StartForPlatform() const {
  return PositionForPlatform(true);
}

VisiblePositionInFlatTree SelectionModifier::EndForPlatform() const {
  return PositionForPlatform(false);
}

PositionInFlatTree SelectionModifier::NextWordPositionForPlatform(
    const PositionInFlatTree& original_position) {
  const PlatformWordBehavior platform_word_behavior =
      GetFrame().GetEditor().Behavior().ShouldSkipSpaceWhenMovingRight()
          ? PlatformWordBehavior::kWordSkipSpaces
          : PlatformWordBehavior::kWordDontSkipSpaces;
  // Next word position can't be upstream.
  const PositionInFlatTree position_after_current_word =
      NextWordPosition(original_position, platform_word_behavior).GetPosition();

  return position_after_current_word;
}

static VisiblePositionInFlatTree AdjustForwardPositionForUserSelectAll(
    const VisiblePositionInFlatTree& position) {
  Node* const root_user_select_all = EditingStrategy::RootUserSelectAllForNode(
      position.DeepEquivalent().AnchorNode());
  if (!root_user_select_all)
    return position;
  return CreateVisiblePosition(MostForwardCaretPosition(
      PositionInFlatTree::AfterNode(*root_user_select_all),
      kCanCrossEditingBoundary));
}

static VisiblePositionInFlatTree AdjustBackwardPositionForUserSelectAll(
    const VisiblePositionInFlatTree& position) {
  Node* const root_user_select_all = EditingStrategy::RootUserSelectAllForNode(
      position.DeepEquivalent().AnchorNode());
  if (!root_user_select_all)
    return position;
  return CreateVisiblePosition(MostBackwardCaretPosition(
      PositionInFlatTree::BeforeNode(*root_user_select_all),
      kCanCrossEditingBoundary));
}

VisiblePositionInFlatTree SelectionModifier::ModifyExtendingRightInternal(
    TextGranularity granularity) {
  // The difference between modifyExtendingRight and modifyExtendingForward is:
  // modifyExtendingForward always extends forward logically.
  // modifyExtendingRight behaves the same as modifyExtendingForward except for
  // extending character or word, it extends forward logically if the enclosing
  // block is LTR direction, but it extends backward logically if the enclosing
  // block is RTL direction.
  switch (granularity) {
    case TextGranularity::kCharacter:
      if (DirectionOfEnclosingBlock() == TextDirection::kLtr) {
        return NextPositionOf(ComputeVisibleFocus(selection_),
                              kCanSkipOverEditingBoundary);
      }
      return PreviousPositionOf(ComputeVisibleFocus(selection_),
                                kCanSkipOverEditingBoundary);
    case TextGranularity::kWord:
      if (DirectionOfEnclosingBlock() == TextDirection::kLtr) {
        return CreateVisiblePosition(NextWordPositionForPlatform(
            ComputeVisibleFocus(selection_).DeepEquivalent()));
      }
      return CreateVisiblePosition(PreviousWordPosition(
          ComputeVisibleFocus(selection_).DeepEquivalent()));
    case TextGranularity::kLineBoundary:
      if (DirectionOfEnclosingBlock() == TextDirection::kLtr)
        return ModifyExtendingForwardInternal(granularity);
      return ModifyExtendingBackwardInternal(granularity);
    case TextGranularity::kSentence:
    case TextGranularity::kLine:
    case TextGranularity::kParagraph:
    case TextGranularity::kSentenceBoundary:
    case TextGranularity::kParagraphBoundary:
    case TextGranularity::kDocumentBoundary:
      // TODO(editing-dev): implement all of the above?
      return ModifyExtendingForwardInternal(granularity);
  }
  NOTREACHED() << static_cast<int>(granularity);
}

VisiblePositionInFlatTree SelectionModifier::ModifyExtendingRight(
    TextGranularity granularity) {
  const VisiblePositionInFlatTree& pos =
      ModifyExtendingRightInternal(granularity);
  if (DirectionOfEnclosingBlock() == TextDirection::kLtr)
    return AdjustForwardPositionForUserSelectAll(pos);
  return AdjustBackwardPositionForUserSelectAll(pos);
}

VisiblePositionInFlatTree SelectionModifier::ModifyExtendingForwardInternal(
    TextGranularity granularity) {
  switch (granularity) {
    case TextGranularity::kCharacter:
      return NextPositionOf(ComputeVisibleFocus(selection_),
                            kCanSkipOverEditingBoundary);
    case TextGranularity::kWord:
      return CreateVisiblePosition(NextWordPositionForPlatform(
          ComputeVisibleFocus(selection_).DeepEquivalent()));
    case TextGranularity::kSentence:
      return CreateVisiblePosition(
          NextSentencePosition(
              ComputeVisibleFocus(selection_).DeepEquivalent()),
          TextAffinity::kUpstreamIfPossible);
    case TextGranularity::kLine: {
      const VisiblePositionInFlatTree& pos = ComputeVisibleFocus(selection_);
      DCHECK(pos.IsValid()) << pos;
      return CreateVisiblePosition(NextLinePosition(
          pos.ToPositionWithAffinity(),
          LineDirectionPointForBlockDirectionNavigation(selection_.Focus())));
    }
    case TextGranularity::kParagraph:
      return NextParagraphPosition(
          ComputeVisibleFocus(selection_),
          LineDirectionPointForBlockDirectionNavigation(selection_.Focus()));
    case TextGranularity::kSentenceBoundary:
      return EndOfSentence(EndForPlatform());
    case TextGranularity::kLineBoundary:
      return LogicalEndOfLine(EndForPlatform());
    case TextGranularity::kParagraphBoundary:
      return EndOfParagraph(EndForPlatform());
    case TextGranularity::kDocumentBoundary: {
      const VisiblePositionInFlatTree& pos = EndForPlatform();
      if (IsEditablePosition(pos.DeepEquivalent())) {
        DCHECK(pos.IsValid()) << pos;
        return CreateVisiblePosition(
            EndOfEditableContent(pos.DeepEquivalent()));
      }
      return EndOfDocument(pos);
    }
  }
  NOTREACHED() << static_cast<int>(granularity);
}

VisiblePositionInFlatTree SelectionModifier::ModifyExtendingForward(
    TextGranularity granularity) {
  const VisiblePositionInFlatTree pos =
      ModifyExtendingForwardInternal(granularity);
  if (DirectionOfEnclosingBlock() == TextDirection::kLtr)
    return AdjustForwardPositionForUserSelectAll(pos);
  return AdjustBackwardPositionForUserSelectAll(pos);
}

VisiblePositionInFlatTree SelectionModifier::ModifyMovingRight(
    TextGranularity granularity) {
  switch (granularity) {
    case TextGranularity::kCharacter:
      if (!selection_.IsRange()) {
        if (LineDirectionOfFocus() == TextDirection::kLtr) {
          return ModifyMovingForward(granularity);
        }
        return ModifyMovingBackward(granularity);
      }
      if (DirectionOfSelection() == TextDirection::kLtr)
        return CreateVisiblePosition(selection_.End(), selection_.Affinity());
      return CreateVisiblePosition(selection_.Start(), selection_.Affinity());
    case TextGranularity::kWord:
      if (LineDirectionOfFocus() == TextDirection::kLtr) {
        return ModifyMovingForward(granularity);
      }
      return ModifyMovingBackward(granularity);
    case TextGranularity::kSentence:
    case TextGranularity::kLine:
    case TextGranularity::kParagraph:
    case TextGranularity::kSentenceBoundary:
    case TextGranularity::kParagraphBoundary:
    case TextGranularity::kDocumentBoundary:
      // TODO(editing-dev): Implement all of the above.
      return ModifyMovingForward(granularity);
    case TextGranularity::kLineBoundary:
      return RightBoundaryOfLine(StartForPlatform(),
                                 DirectionOfEnclosingBlock());
  }
  NOTREACHED() << static_cast<int>(granularity);
}

VisiblePositionInFlatTree SelectionModifier::ModifyMovingForward(
    TextGranularity granularity) {
  // TODO(editing-dev): Stay in editable content for the less common
  // granularities.
  switch (granularity) {
    case TextGranularity::kCharacter:
      if (selection_.IsRange())
        return CreateVisiblePosition(selection_.End(), selection_.Affinity());
      return NextPositionOf(ComputeVisibleFocus(selection_),
                            kCanSkipOverEditingBoundary);
    case TextGranularity::kWord:
      return CreateVisiblePosition(NextWordPositionForPlatform(
          ComputeVisibleFocus(selection_).DeepEquivalent()));
    case TextGranularity::kSentence:
      return CreateVisiblePosition(
          NextSentencePosition(
              ComputeVisibleFocus(selection_).DeepEquivalent()),
          TextAffinity::kUpstreamIfPossible);
    case TextGranularity::kLine: {
      const VisiblePositionInFlatTree& pos = EndForPlatform();
      DCHECK(pos.IsValid()) << pos;
      if (RuntimeEnabledFeatures::
              UseSelectionFocusNodeForCaretNavigationEnabled()) {
        return CreateVisiblePosition(NextLinePosition(
            pos.ToPositionWithAffinity(),
            LineDirectionPointForBlockDirectionNavigation(selection_.Focus())));
      }
      return CreateVisiblePosition(NextLinePosition(
          pos.ToPositionWithAffinity(),
          LineDirectionPointForBlockDirectionNavigation(selection_.Start())));
    }
    case TextGranularity::kParagraph:
      if (RuntimeEnabledFeatures::
              UseSelectionFocusNodeForCaretNavigationEnabled()) {
        return NextParagraphPosition(
            EndForPlatform(),
            LineDirectionPointForBlockDirectionNavigation(selection_.Focus()));
      }
      return NextParagraphPosition(
          EndForPlatform(),
          LineDirectionPointForBlockDirectionNavigation(selection_.Start()));
    case TextGranularity::kSentenceBoundary:
      return EndOfSentence(EndForPlatform());
    case TextGranularity::kLineBoundary:
      return LogicalEndOfLine(EndForPlatform());
    case TextGranularity::kParagraphBoundary:
      return EndOfParagraph(
          EndForPlatform(),
          RuntimeEnabledFeatures::
                      MoveToParagraphStartOrEndSkipsNonEditableEnabled() &&
                  IsEditablePosition(EndForPlatform().DeepEquivalent())
              ? EditingBoundaryCrossingRule::kCanSkipOverEditingBoundary
              : EditingBoundaryCrossingRule::kCannotCrossEditingBoundary);
    case TextGranularity::kDocumentBoundary: {
      const VisiblePositionInFlatTree& pos = EndForPlatform();
      if (IsEditablePosition(pos.DeepEquivalent())) {
        DCHECK(pos.IsValid()) << pos;
        return CreateVisiblePosition(
            EndOfEditableContent(pos.DeepEquivalent()));
      }
      return EndOfDocument(pos);
    }
  }
  NOTREACHED() << static_cast<int>(granularity);
}

VisiblePositionInFlatTree SelectionModifier::ModifyExtendingLeftInternal(
    TextGranularity granularity) {
  // The difference between modifyExtendingLeft and modifyExtendingBackward is:
  // modifyExtendingBackward always extends backward logically.
  // modifyExtendingLeft behaves the same as modifyExtendingBackward except for
  // extending character or word, it extends backward logically if the enclosing
  // block is LTR direction, but it extends forward logically if the enclosing
  // block is RTL direction.
  switch (granularity) {
    case TextGranularity::kCharacter:
      if (DirectionOfEnclosingBlock() == TextDirection::kLtr) {
        return PreviousPositionOf(ComputeVisibleFocus(selection_),
                                  kCanSkipOverEditingBoundary);
      }
      return NextPositionOf(ComputeVisibleFocus(selection_),
                            kCanSkipOverEditingBoundary);
    case TextGranularity::kWord:
      if (DirectionOfEnclosingBlock() == TextDirection::kLtr) {
        return CreateVisiblePosition(PreviousWordPosition(
            ComputeVisibleFocus(selection_).DeepEquivalent()));
      }
      return CreateVisiblePosition(NextWordPositionForPlatform(
          ComputeVisibleFocus(selection_).DeepEquivalent()));
    case TextGranularity::kLineBoundary:
      if (DirectionOfEnclosingBlock() == TextDirection::kLtr)
        return ModifyExtendingBackwardInternal(granularity);
      return ModifyExtendingForwardInternal(granularity);
    case TextGranularity::kSentence:
    case TextGranularity::kLine:
    case TextGranularity::kParagraph:
    case TextGranularity::kSentenceBoundary:
    case TextGranularity::kParagraphBoundary:
    case TextGranularity::kDocumentBoundary:
      return ModifyExtendingBackwardInternal(granularity);
  }
  NOTREACHED() << static_cast<int>(granularity);
}

VisiblePositionInFlatTree SelectionModifier::ModifyExtendingLeft(
    TextGranularity granularity) {
  const VisiblePositionInFlatTree& pos =
      ModifyExtendingLeftInternal(granularity);
  if (DirectionOfEnclosingBlock() == TextDirection::kLtr)
    return AdjustBackwardPositionForUserSelectAll(pos);
  return AdjustForwardPositionForUserSelectAll(pos);
}

VisiblePositionInFlatTree SelectionModifier::ModifyExtendingBackwardInternal(
    TextGranularity granularity) {
  // Extending a selection backward by word or character from just after a table
  // selects the table.  This "makes sense" from the user perspective, esp. when
  // deleting. It was done here instead of in VisiblePositionInFlatTree because
  // we want VPs to iterate over everything.
  switch (granularity) {
    case TextGranularity::kCharacter:
      return PreviousPositionOf(ComputeVisibleFocus(selection_),
                                kCanSkipOverEditingBoundary);
    case TextGranularity::kWord:
      return CreateVisiblePosition(PreviousWordPosition(
          ComputeVisibleFocus(selection_).DeepEquivalent()));
    case TextGranularity::kSentence:
      return CreateVisiblePosition(PreviousSentencePosition(
          ComputeVisibleFocus(selection_).DeepEquivalent()));
    case TextGranularity::kLine: {
      const VisiblePositionInFlatTree& pos = ComputeVisibleFocus(selection_);
      DCHECK(pos.IsValid()) << pos;
      return CreateVisiblePosition(PreviousLinePosition(
          pos.ToPositionWithAffinity(),
          LineDirectionPointForBlockDirectionNavigation(selection_.Focus())));
    }
    case TextGranularity::kParagraph:
      return PreviousParagraphPosition(
          ComputeVisibleFocus(selection_),
          LineDirectionPointForBlockDirectionNavigation(selection_.Focus()));
    case TextGranularity::kSentenceBoundary:
      return CreateVisiblePosition(
          StartOfSentencePosition(StartForPlatform().DeepEquivalent()));
    case TextGranularity::kLineBoundary:
      return LogicalStartOfLine(StartForPlatform());
    case TextGranularity::kParagraphBoundary:
      return StartOfParagraph(StartForPlatform());
    case TextGranularity::kDocumentBoundary: {
      const VisiblePositionInFlatTree pos = StartForPlatform();
      if (IsEditablePosition(pos.DeepEquivalent())) {
        DCHECK(pos.IsValid()) << pos;
        return CreateVisiblePosition(
            StartOfEditableContent(pos.DeepEquivalent()));
      }
      return CreateVisiblePosition(StartOfDocument(pos.DeepEquivalent()));
    }
  }
  NOTREACHED() << static_cast<int>(granularity);
}

VisiblePositionInFlatTree SelectionModifier::ModifyExtendingBackward(
    TextGranularity granularity) {
  const VisiblePositionInFlatTree pos =
      ModifyExtendingBackwardInternal(granularity);
  if (DirectionOfEnclosingBlock() == TextDirection::kLtr)
    return AdjustBackwardPositionForUserSelectAll(pos);
  return AdjustForwardPositionForUserSelectAll(pos);
}

VisiblePositionInFlatTree SelectionModifier::ModifyMovingLeft(
    TextGranularity granularity) {
  switch (granularity) {
    case TextGranularity::kCharacter:
      if (!selection_.IsRange()) {
        if (LineDirectionOfFocus() == TextDirection::kLtr) {
          return ModifyMovingBackward(granularity);
        }
        return ModifyMovingForward(granularity);
      }
      if (DirectionOfSelection() == TextDirection::kLtr)
        return CreateVisiblePosition(selection_.Start(), selection_.Affinity());
      return CreateVisiblePosition(selection_.End(), selection_.Affinity());
    case TextGranularity::kWord:
      if (LineDirectionOfFocus() == TextDirection::kLtr) {
        return ModifyMovingBackward(granularity);
      }
      return ModifyMovingForward(granularity);
    case TextGranularity::kSentence:
    case TextGranularity::kLine:
    case TextGranularity::kParagraph:
    case TextGranularity::kSentenceBoundary:
    case TextGranularity::kParagraphBoundary:
    case TextGranularity::kDocumentBoundary:
      // FIXME: Implement all of the above.
      return ModifyMovingBackward(granularity);
    case TextGranularity::kLineBoundary:
      return LeftBoundaryOfLine(StartForPlatform(),
                                DirectionOfEnclosingBlock());
  }
  NOTREACHED() << static_cast<int>(granularity);
}

VisiblePositionInFlatTree SelectionModifier::ModifyMovingBackward(
    TextGranularity granularity) {
  VisiblePositionInFlatTree pos;
  switch (granularity) {
    case TextGranularity::kCharacter:
      if (selection_.IsRange()) {
        pos = CreateVisiblePosition(selection_.Start(), selection_.Affinity());
      } else {
        pos = PreviousPositionOf(ComputeVisibleFocus(selection_),
                                 kCanSkipOverEditingBoundary);
      }
      break;
    case TextGranularity::kWord:
      pos = CreateVisiblePosition(PreviousWordPosition(
          ComputeVisibleFocus(selection_).DeepEquivalent()));
      break;
    case TextGranularity::kSentence:
      pos = CreateVisiblePosition(PreviousSentencePosition(
          ComputeVisibleFocus(selection_).DeepEquivalent()));
      break;
    case TextGranularity::kLine: {
      const VisiblePositionInFlatTree& start = StartForPlatform();
      DCHECK(start.IsValid()) << start;
      if (RuntimeEnabledFeatures::
              UseSelectionFocusNodeForCaretNavigationEnabled()) {
        pos = CreateVisiblePosition(PreviousLinePosition(
            start.ToPositionWithAffinity(),
            LineDirectionPointForBlockDirectionNavigation(selection_.Focus())));
      } else {
        pos = CreateVisiblePosition(PreviousLinePosition(
            start.ToPositionWithAffinity(),
            LineDirectionPointForBlockDirectionNavigation(selection_.Start())));
      }
      break;
    }
    case TextGranularity::kParagraph:
      if (RuntimeEnabledFeatures::
              UseSelectionFocusNodeForCaretNavigationEnabled()) {
        pos = PreviousParagraphPosition(
            StartForPlatform(),
            LineDirectionPointForBlockDirectionNavigation(selection_.Focus()));
      } else {
        pos = PreviousParagraphPosition(
            StartForPlatform(),
            LineDirectionPointForBlockDirectionNavigation(selection_.Start()));
      }
      break;
    case TextGranularity::kSentenceBoundary:
      pos = CreateVisiblePosition(
          StartOfSentencePosition(StartForPlatform().DeepEquivalent()));
      break;
    case TextGranularity::kLineBoundary:
      pos = LogicalStartOfLine(StartForPlatform());
      break;
    case TextGranularity::kParagraphBoundary:
      pos = StartOfParagraph(
          StartForPlatform(),
          RuntimeEnabledFeatures::
                      MoveToParagraphStartOrEndSkipsNonEditableEnabled() &&
                  IsEditablePosition(StartForPlatform().DeepEquivalent())
              ? EditingBoundaryCrossingRule::kCanSkipOverEditingBoundary
              : EditingBoundaryCrossingRule::kCannotCrossEditingBoundary);
      break;
    case TextGranularity::kDocumentBoundary:
      pos = StartForPlatform();
      if (IsEditablePosition(pos.DeepEquivalent())) {
        DCHECK(pos.IsValid()) << pos;
        pos =
            CreateVisiblePosition(StartOfEditableContent(pos.DeepEquivalent()));
      } else {
        pos = CreateVisiblePosition(StartOfDocument(pos.DeepEquivalent()));
      }
      break;
  }
  return pos;
}

static bool IsBoundary(TextGranularity granularity) {
  return granularity == TextGranularity::kLineBoundary ||
         granularity == TextGranularity::kParagraphBoundary ||
         granularity == TextGranularity::kDocumentBoundary;
}

VisiblePositionInFlatTree SelectionModifier::ComputeModifyPosition(
    SelectionModifyAlteration alter,
    SelectionModifyDirecti
```