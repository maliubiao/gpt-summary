Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink rendering engine and resides in `blink/renderer/core/layout/inline/line_breaker.cc`. The summary should also highlight the code's relationship to web technologies like JavaScript, HTML, and CSS, provide examples where applicable, and address potential user or programming errors.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The file name `line_breaker.cc` strongly suggests its primary function is to handle line breaking in text layout. The included headers like `inline_break_token.h`, `line_info.h`, `shaping_line_breaker.h`, and `bidi_paragraph.h` reinforce this idea, pointing to the management of breaking points, line properties, text shaping, and bidirectional text handling.

2. **Analyze Key Data Structures and Classes:**  The code introduces the `LineBreaker` class as the central component. It also mentions `LineInfo`, `InlineItem`, `InlineItemResult`, and related structures. Understanding these is crucial:
    * `LineBreaker`: The main class responsible for determining where to break lines.
    * `LineInfo`:  Stores information about a single line of text.
    * `InlineItem`: Represents a discrete element within the inline flow (text, inline elements, etc.).
    * `InlineItemResult`: Holds the processed results for an `InlineItem` on a specific line, including its size and breakability.

3. **Examine Key Methods and Logic (Based on the Snippet):**
    * **Constructor:**  Initializes the `LineBreaker` with context like the inline node, layout constraints, and any existing break token (for continuation from a previous break). It also handles SVG and text-combine specific logic and disables auto-wrapping in certain cases.
    * **`UpdateAvailableWidth()`:** Calculates the available width for the current line, taking into account overrides and cloned box decorations.
    * **`AddItem()`/`AddEmptyItem()`:** Adds an `InlineItem` or an empty item to the current line's information.
    * **`HandleOverflowIfNeeded()`:** Checks if the current content exceeds the available width and triggers overflow handling.
    * **`ComputeBaseDirection()`:** Determines the base direction for bidirectional text.
    * **`RecalcClonedBoxDecorations()`:**  Handles the special case of `box-decoration-break: clone`.
    * **`AddHyphen()`/`RemoveHyphen()`/`RestoreLastHyphen()`/`FinalizeHyphen()`:** Manages the insertion and removal of hyphens for line breaking.
    * **`PrepareNextLine()`:** Resets the `LineBreaker`'s state for the next line, inheriting or recalculating necessary properties.

4. **Identify Relationships with Web Technologies:**
    * **HTML:** The code deals with the layout of HTML elements (represented by `InlineNode` and `InlineItem`). The presence of open and close tags is handled. The concept of inline flow directly relates to how HTML content is rendered.
    * **CSS:**  The code heavily relies on `ComputedStyle` to make decisions about line breaking. CSS properties like `white-space`, `word-break`, `overflow-wrap`, `text-indent`, `unicode-bidi`, and `box-decoration-break` are directly relevant. The handling of hyphenation is also a CSS feature.
    * **JavaScript:** While this specific file doesn't directly interact with JavaScript, the line breaking logic impacts how text is rendered, which in turn affects how JavaScript interacts with and manipulates the DOM and text content. For instance, the position of the cursor or text selection in JavaScript relies on accurate layout.

5. **Infer Potential Errors:**
    * **User Errors (CSS):** Incorrect or conflicting CSS properties related to line breaking (e.g., `white-space: nowrap` combined with `overflow-wrap: break-word`) can lead to unexpected or suboptimal line breaking behavior.
    * **Programming Errors (Blink Development):** Incorrectly calculating available width, mishandling edge cases in hyphenation, or failing to account for different writing modes could lead to layout bugs. The comments mentioning `TODO(crbug...)` also hint at ongoing development and potential areas for improvement or fixes.

6. **Construct Examples (Hypothetical):**
    * **CSS Relationship:** Demonstrate how different `white-space` values affect line breaking.
    * **Hyphenation:** Show how CSS hyphenation properties influence where words are broken.
    * **User Error:** Illustrate a case where conflicting CSS properties cause unexpected behavior.

7. **Synthesize a Summary:** Combine the above points into a concise overview of the `LineBreaker`'s functionality, its connections to web technologies, and potential pitfalls. Organize the information logically into functional areas.

8. **Review and Refine:** Ensure the summary is accurate, clear, and addresses all aspects of the prompt. Check for any jargon that needs explanation or any logical gaps. Specifically address the "Part 1 of 6" constraint by providing a high-level overview.

This systematic approach helps to dissect the code snippet, understand its purpose within the larger context of the Blink rendering engine, and articulate its functionality and relevance to web developers and users.
好的，根据你提供的代码片段，`blink/renderer/core/layout/inline/line_breaker.cc` 文件的第 1 部分主要负责 **初始化和准备进行行布局所需的各种状态和数据**。它主要做了以下几件事情：

**核心功能归纳：**

1. **`LineBreaker` 类的构造和初始化：**
   - 接收 `InlineNode`（代表要进行行布局的内联节点）、布局模式、约束空间、行布局机会等关键信息。
   - 初始化各种内部状态，例如是否是初始字母盒、是否是 SVG 文本、是否是文本组合等。
   - 处理首行样式的应用（`use_first_line_style_`）。
   - 初始化 `items_data_` 指针，指向与当前节点相关的内联项数据。
   - 初始化文本内容相关的变量，并根据特定 quirk（`sticky_images_quirk_`）进行调整。
   - 初始化约束空间、排除空间、断点标记等。
   - 初始化文本迭代器 (`break_iterator_`)、文本塑形器 (`shaper_`) 和空格处理器 (`spacing_`)。
   - 初始化浮动元素信息 (`leading_floats_`) 和基础方向 (`base_direction_`)。
   - **处理 SVG 特有的初始化逻辑，判断是否需要进行 SVG 分割。**
   - **禁用某些情况下的自动换行，例如 SVG 文本、文本组合和初始字母盒。**
   - **如果存在断点标记 (`break_token_`)，则恢复之前的布局状态，包括当前的位置、Ruby 断点信息、文本迭代器的起始位置和是否是强制断点。**  同时会设置当前行的初始样式。

2. **更新可用宽度 (`UpdateAvailableWidth`)：**
   - 根据行布局机会 (`line_opportunity_`) 或外部覆盖值 (`override_available_width_`) 计算当前行的可用宽度。
   - 确保可用宽度不小于克隆盒装饰的初始大小。
   - 将可用宽度限制在最大值附近。

3. **设置断点位置 (`SetBreakAt`)：**
   - 允许外部指定一个固定的断点，并强制可用宽度为最大值。

4. **添加内联项 (`AddItem`, `AddEmptyItem`)：**
   - 提供将 `InlineItem` 添加到当前行信息 (`LineInfo`) 的方法。
   - 会记录内联项的起始和结束文本偏移量，以及是否应该创建新的行盒和是否存在未定位的浮动元素。
   - 对于文本组合，会标记该行包含文本组合或 Ruby 项。
   - `AddEmptyItem` 特殊处理空内联项的断点属性。

5. **处理溢出 (`HandleOverflowIfNeeded`)：**
   - 如果当前状态允许继续布局 (`kContinue`) 并且内容超出可用宽度，则会调用溢出处理函数。

6. **设置固有尺寸输出 (`SetIntrinsicSizeOutputs`)：**
   - 用于内容尺寸计算模式，允许外部接收最大尺寸缓存和是否依赖于块级约束的信息。

7. **计算基础方向 (`ComputeBaseDirection`)：**
   - 根据 `unicode-bidi` 属性的值，确定当前行的双向文本基础方向。
   - 如果 `unicode-bidi` 是 `plaintext`，则会根据文本内容计算基础方向。

8. **重新计算克隆盒装饰 (`RecalcClonedBoxDecorations`)：**
   - 处理 `box-decoration-break: clone` 属性，计算由于克隆盒装饰带来的额外空间。
   - 查找当前未闭合且设置了 `box-decoration-break: clone` 的标签，并计算其初始和结束的边距、边框和内边距。
   - 更新当前布局位置 (`position_`) 以容纳克隆盒装饰的初始大小。

9. **添加和移除连字符 (`AddHyphen`, `RemoveHyphen`)：**
   - 提供添加连字符到 `InlineItemResult` 的功能，会计算连字符的宽度并更新 `inline_size`。
   - 提供移除连字符的功能，并重置连字符相关的内部状态。

10. **恢复和完成连字符 (`RestoreLastHyphen`, `FinalizeHyphen`)：**
    - `RestoreLastHyphen` 用于在回溯后恢复上一个连字符的状态。
    - `FinalizeHyphen` 标记最终的连字符结果。

11. **准备下一行 (`PrepareNextLine`)：**
    - 重置当前行的信息。
    - 继承或更新上一行的状态，例如是否是强制断点、是否是首行等。
    - 设置新一行的起始位置、是否是首行和行样式。
    - 应用 `text-indent` 属性作为初始位置。
    - 重置克隆盒装饰相关的状态。
    - 如果存在断点标记且包含克隆盒装饰，则恢复其状态。

**与 JavaScript, HTML, CSS 的关系：**

- **HTML:**  `LineBreaker` 处理的是 HTML 结构在屏幕上的最终排布，它接收 `InlineNode` 对象，这些对象代表了 HTML 元素在布局树中的一部分。例如，一个 `<span>` 标签内的文本会被表示为一个或多个 `InlineNode`。
- **CSS:**  `LineBreaker` 的行为很大程度上受到 CSS 属性的影响。
    - `white-space`:  决定如何处理空格和换行符，例如 `white-space: nowrap` 会阻止自动换行。
    - `word-break`, `overflow-wrap`: 控制单词在何处断开。
    - `text-indent`:  影响首行的缩进，`LineBreaker` 会在 `PrepareNextLine` 中处理。
    - `unicode-bidi`:  影响双向文本的布局，`ComputeBaseDirection` 负责计算。
    - `box-decoration-break`:  `RecalcClonedBoxDecorations` 专门处理 `clone` 值，影响行盒的装饰如何跨行绘制。
    - `hyphens`:  控制是否以及如何在单词中插入连字符，`AddHyphen` 等方法实现了这一功能。
- **JavaScript:**  JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改最终会影响 `LineBreaker` 的工作。例如，通过 JavaScript 改变元素的 `textContent` 或修改 CSS 的 `white-space` 属性，都会导致重新进行行布局。

**逻辑推理的假设输入与输出：**

**假设输入：**

- 一个包含文本 "Hello World! This is a long sentence." 的 `InlineNode`。
- 可用宽度为 100px。
- `white-space` CSS 属性为默认值 (`normal`)。

**推断输出：**

`LineBreaker` 会根据空格和标点符号寻找合适的断点，将文本分成多行，例如：

```
Hello
World!
This is a
long
sentence.
```

**假设输入：**

- 相同的 `InlineNode` 和文本。
- 可用宽度为 50px。
- `white-space: nowrap` CSS 属性。

**推断输出：**

`LineBreaker` 不会进行自动换行，文本会超出容器的边界：

```
HelloWorld!Thisisalongsentence.
```

**用户或编程常见的使用错误：**

1. **CSS 属性冲突导致意外的换行行为：**
   - **示例：** 设置了 `white-space: nowrap` 阻止换行，但又设置了 `overflow-wrap: break-word`，后者会强制在单词内断开，可能与用户的预期不符。

2. **错误的断点逻辑导致文本溢出或不必要的断行：**
   - **示例（编程错误）：** 在 `LineBreaker` 的实现中，如果对各种断点条件的判断存在漏洞，可能会导致本不应该断开的地方断开了，或者应该断开的地方没有断开。

3. **未正确处理不同语言和书写方向的断行规则：**
   - `LineBreaker` 需要考虑到不同语言的断词规则以及从右向左的书写方向。如果处理不当，可能会出现布局错误。

4. **`box-decoration-break: clone` 的使用不当：**
   - **示例：**  过度使用 `box-decoration-break: clone` 可能会导致复杂的边框和背景在多行重复绘制，影响性能和视觉效果。

**总结一下它的功能 (第 1 部分)：**

在 `blink/renderer/core/layout/inline/line_breaker.cc` 文件的第 1 部分，主要的功能是 **初始化 `LineBreaker` 对象并为其准备行布局所需的各种初始状态和数据**。这包括接收布局上下文信息，处理特殊情况（如 SVG、文本组合、克隆盒装饰），计算可用宽度，以及提供添加内联项到行信息的方法。 这一部分为后续的行布局和断点查找奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/line_breaker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/line_breaker.h"

#include "base/containers/adapters.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/floats_utils.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result_ruby_column.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_segment.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/line_break_candidate.h"
#include "third_party/blink/renderer/core/layout/inline/line_info.h"
#include "third_party/blink/renderer/core/layout/inline/ruby_utils.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/positioned_float.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/svg/resolved_text_layout_attributes_iterator.h"
#include "third_party/blink/renderer/core/layout/unpositioned_float.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/svg/svg_text_content_element.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shaping_line_breaker.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/bidi_paragraph.h"
#include "third_party/blink/renderer/platform/text/character.h"

namespace blink {

namespace {

inline LineBreakStrictness StrictnessFromLineBreak(LineBreak line_break) {
  switch (line_break) {
    case LineBreak::kAuto:
    case LineBreak::kAfterWhiteSpace:
    case LineBreak::kAnywhere:
      return LineBreakStrictness::kDefault;
    case LineBreak::kNormal:
      return LineBreakStrictness::kNormal;
    case LineBreak::kStrict:
      return LineBreakStrictness::kStrict;
    case LineBreak::kLoose:
      return LineBreakStrictness::kLoose;
  }
  NOTREACHED();
}

// Returns smallest negative left and right bearing in `box_fragment`.
// This function is used for calculating side bearing.
LineBoxStrut ComputeNegativeSideBearings(
    const PhysicalBoxFragment& box_fragment) {
  const auto get_shape_result =
      [](const InlineCursor cursor) -> const ShapeResultView* {
    if (!cursor)
      return nullptr;
    const FragmentItem& item = *cursor.CurrentItem();
    if (item.Type() != FragmentItem::kText &&
        item.Type() != FragmentItem::kGeneratedText) {
      return nullptr;
    }
    if (item.IsFlowControl())
      return nullptr;
    return item.TextShapeResult();
  };

  LineBoxStrut side_bearing;

  for (InlineCursor cursor(box_fragment); cursor; cursor.MoveToNextLine()) {
    // Take left/right bearing from the first/last child in the line if it has
    // `ShapeResult`. The first/last child can be non text item, e.g. image.
    // Note: Items in the line are in visual order. So, first=left, last=right.
    //
    // Example: If we have three text item "[", "T", "]", we should take left
    // baring from "[" and right bearing from "]". The text ink bounds of "T"
    // is not involved with side bearing calculation.
    DCHECK(cursor.Current().IsLineBox());

    // `gfx::RectF` returned from `ShapeResult::ComputeInkBounds()` is in
    // text origin coordinate aka baseline. Y-coordinate of points above
    // baseline are negative.
    //
    //  Text Ink Bounds:
    //   * left bearing = text_ink_bounds.X()
    //   * right bearing = width - text_ink_bounds.InlineEndOffset()
    //
    //          <--> left bearing (positive)
    //          ...+---------+
    //          ...|*********|..<
    //          ...|....*....|..<
    //          ...|....*....|<-> right bearing (positive)
    //          ...|....*....|..<
    //          ...|....*....|..<
    //          >..+----*----+..< baseline
    //          ^text origin
    //          <---------------> width/advance
    //
    //            left bearing (negative)
    //          <-->          <--> right bearing (negative)
    //          +----------------+
    //          |... *****..*****|
    //          |......*.....*<..|
    //          |.....*.....*.<..|
    //          |....*******..<..|
    //          |...*.....*...<..|
    //          |..*.....*....<..|
    //          +****..*****..<..+
    //             ^ text origin
    //             <----------> width/advance
    //
    // When `FragmentItem` has `ShapeTesult`, its `rect` is
    //    * `rect.offset.left = X`
    //    * `rect.size.width  = shape_result.SnappedWidth() // advance
    // where `X` is the original item offset.
    // For the initial letter text, its `rect` is[1]
    //    * `rect.offset.left = X - text_ink_bounds.X()`
    //    * `rect.size.width  = text_ink_bounds.Width()`
    // [1] https://drafts.csswg.org/css-inline/#initial-letter-box-size
    // Sizeing the Initial Letter Box
    InlineCursor child_at_left_edge = cursor;
    child_at_left_edge.MoveToFirstChild();
    if (auto* shape_result = get_shape_result(child_at_left_edge)) {
      const LayoutUnit left_bearing =
          LogicalRect::EnclosingRect(shape_result->ComputeInkBounds())
              .offset.inline_offset;
      side_bearing.inline_start =
          std::min(side_bearing.inline_start, left_bearing);
    }

    InlineCursor child_at_right_edge = cursor;
    child_at_right_edge.MoveToLastChild();
    if (auto* shape_result = get_shape_result(child_at_right_edge)) {
      const LayoutUnit width = shape_result->SnappedWidth();
      const LogicalRect text_ink_bounds =
          LogicalRect::EnclosingRect(shape_result->ComputeInkBounds());
      const LayoutUnit right_bearing =
          width - text_ink_bounds.InlineEndOffset();
      side_bearing.inline_end =
          std::min(side_bearing.inline_end, right_bearing);
    }
  }

  return side_bearing;
}

// This rule comes from the spec[1].
// Note: We don't apply inline kerning for vertical writing mode with text
// orientation other than `sideways` because characters are laid out vertically.
// [1] https://drafts.csswg.org/css-inline/#initial-letter-inline-position
bool ShouldApplyInlineKerning(const PhysicalBoxFragment& box_fragment) {
  if (!box_fragment.Borders().IsZero() || !box_fragment.Padding().IsZero())
    return false;
  const ComputedStyle& style = box_fragment.Style();
  return style.IsHorizontalWritingMode() ||
         style.GetTextOrientation() == ETextOrientation::kSideways;
}

// CSS-defined white space characters, excluding the newline character.
// In most cases, the line breaker consider break opportunities are before
// spaces because it handles trailing spaces differently from other normal
// characters, but breaking before newline characters is not desired.
inline bool IsBreakableSpace(UChar c) {
  return c == kSpaceCharacter || c == kTabulationCharacter;
}

inline bool IsBreakableSpaceOrOtherSeparator(UChar c) {
  return IsBreakableSpace(c) || Character::IsOtherSpaceSeparator(c);
}

inline bool IsAllBreakableSpaces(const String& string,
                                 unsigned start,
                                 unsigned end) {
  DCHECK_GE(end, start);
  return StringView(string, start, end - start)
      .IsAllSpecialCharacters<IsBreakableSpace>();
}

inline bool IsBidiTrailingSpace(UChar c) {
  return u_charDirection(c) == UCharDirection::U_WHITE_SPACE_NEUTRAL;
}

inline LayoutUnit HyphenAdvance(const ComputedStyle& style,
                                bool is_ltr,
                                const HyphenResult& hyphen_result,
                                std::optional<LayoutUnit>& cache) {
  if (cache) {
    return *cache;
  }
  const LayoutUnit size = hyphen_result ? hyphen_result.InlineSize()
                                        : HyphenResult(style).InlineSize();
  const LayoutUnit advance = is_ltr ? size : -size;
  cache = advance;
  return advance;
}

// True if the item is "trailable". Trailable items should be included in the
// line if they are after the soft wrap point.
//
// Note that some items are ambiguous; e.g., text is trailable if it has leading
// spaces, and open tags are trailable if spaces follow. This function returns
// true for such cases.
inline bool IsTrailableItemType(InlineItem::InlineItemType type) {
  return type != InlineItem::kAtomicInline &&
         type != InlineItem::kOutOfFlowPositioned &&
         type != InlineItem::kInitialLetterBox &&
         type != InlineItem::kListMarker && type != InlineItem::kOpenRubyColumn;
}

inline bool CanBreakAfterLast(const InlineItemResults& item_results) {
  return !item_results.empty() && item_results.back().can_break_after;
}

inline bool ShouldCreateLineBox(const InlineItemResults& item_results) {
  return !item_results.empty() && item_results.back().should_create_line_box;
}

inline bool HasUnpositionedFloats(const InlineItemResults& item_results) {
  return !item_results.empty() && item_results.back().has_unpositioned_floats;
}

LayoutUnit ComputeInlineEndSize(const ConstraintSpace& space,
                                const ComputedStyle* style) {
  DCHECK(style);
  BoxStrut margins = ComputeMarginsForSelf(space, *style);
  BoxStrut borders = ComputeBordersForInline(*style);
  BoxStrut paddings = ComputePadding(space, *style);

  return margins.inline_end + borders.inline_end + paddings.inline_end;
}

bool NeedsAccurateEndPosition(const InlineItem& line_end_item) {
  DCHECK(line_end_item.Type() == InlineItem::kText ||
         line_end_item.Type() == InlineItem::kControl);
  DCHECK(line_end_item.Style());
  const ComputedStyle& line_end_style = *line_end_item.Style();
  return line_end_style.HasBoxDecorationBackground() ||
         line_end_style.HasAppliedTextDecorations();
}

inline bool NeedsAccurateEndPosition(const LineInfo& line_info,
                                     const InlineItem& line_end_item) {
  return line_info.NeedsAccurateEndPosition() ||
         NeedsAccurateEndPosition(line_end_item);
}

inline void ComputeCanBreakAfter(InlineItemResult* item_result,
                                 bool auto_wrap,
                                 const LazyLineBreakIterator& break_iterator) {
  item_result->can_break_after =
      auto_wrap && break_iterator.IsBreakable(item_result->EndOffset());
}

inline void RemoveLastItem(LineInfo* line_info) {
  InlineItemResults* item_results = line_info->MutableResults();
  DCHECK_GT(item_results->size(), 0u);
  item_results->Shrink(item_results->size() - 1);
}

// To correctly determine if a float is allowed to be on the same line as its
// content, we need to determine if it has any ancestors with inline-end
// padding, border, or margin.
// The inline-end size from all of these ancestors contribute to the "used
// size" of the float, and may cause the float to be pushed down.
LayoutUnit ComputeFloatAncestorInlineEndSize(
    const ConstraintSpace& space,
    const HeapVector<InlineItem>& items,
    wtf_size_t item_index) {
  LayoutUnit inline_end_size;
  for (const InlineItem *cur = items.data() + item_index,
                        *end = items.data() + items.size();
       cur != end; ++cur) {
    const InlineItem& item = *cur;

    if (item.Type() == InlineItem::kCloseTag) {
      inline_end_size += ComputeInlineEndSize(space, item.Style());
      continue;
    }

    // For this calculation, any open tag (even if its empty) stops this
    // calculation, and allows the float to appear on the same line. E.g.
    // <span style="padding-right: 20px;"><f></f><span></span></span>
    //
    // Any non-empty item also allows the float to be on the same line.
    if (item.Type() == InlineItem::kOpenTag || !item.IsEmptyItem()) {
      break;
    }
  }
  return inline_end_size;
}

// See LineBreaker::SplitTextIntoSegments().
void CollectCharIndex(void* context,
                      unsigned char_index,
                      Glyph,
                      gfx::Vector2dF,
                      float,
                      bool,
                      CanvasRotationInVertical,
                      const SimpleFontData*) {
  auto* index_list = static_cast<Vector<unsigned>*>(context);
  wtf_size_t size = index_list->size();
  if (size > 0 && index_list->at(size - 1) == char_index)
    return;
  index_list->push_back(char_index);
}

inline LayoutTextCombine* MayBeTextCombine(const InlineItem* item) {
  if (!item)
    return nullptr;
  return DynamicTo<LayoutTextCombine>(item->GetLayoutObject());
}

LayoutUnit MaxLineWidth(const LineInfo& base_line,
                        const HeapVector<LineInfo, 1>& annotation_lines) {
  LayoutUnit max = base_line.Width();
  for (const auto& line : annotation_lines) {
    max = std::max(max, line.Width());
  }
  return max;
}

// Represents data associated with an `InlineItemResult`.
class FastMinTextContext {
  STACK_ALLOCATED();

 public:
  LayoutUnit MinInlineSize() const { return min_inline_size_; }

  LayoutUnit HyphenInlineSize(InlineItemResult& item_result) const {
    if (!hyphen_inline_size_) {
      if (!item_result.hyphen) {
        item_result.ShapeHyphen();
      }
      hyphen_inline_size_ = item_result.hyphen.InlineSize();
    }
    return *hyphen_inline_size_;
  }

  void Add(LayoutUnit width) {
    min_inline_size_ = std::max(width, min_inline_size_);
  }

  // Add the width between the `start_offset` and the `end_offset`.
  void Add(const ShapeResult& shape_result,
           unsigned start_offset,
           unsigned end_offset,
           bool has_hyphen,
           InlineItemResult& item_result) {
    LayoutUnit width = shape_result.CachedWidth(start_offset, end_offset);
    if (has_hyphen) [[unlikely]] {
      const LayoutUnit hyphen_inline_size = HyphenInlineSize(item_result);
      width += hyphen_inline_size;
    }
    Add(width);
  }

  // Hyphenate the `word` and add all parts.
  void AddHyphenated(const ShapeResult& shape_result,
                     unsigned start_offset,
                     unsigned end_offset,
                     bool has_hyphen,
                     InlineItemResult& item_result,
                     const Hyphenation& hyphenation,
                     const StringView& word) {
    Vector<wtf_size_t, 8> locations = hyphenation.HyphenLocations(word);
    // |locations| is a list of hyphenation points in the descending order.
#if EXPENSIVE_DCHECKS_ARE_ON()
    DCHECK_EQ(word.length(), end_offset - start_offset);
    DCHECK(std::is_sorted(locations.rbegin(), locations.rend()));
    DCHECK(!locations.Contains(0u));
    DCHECK(!locations.Contains(word.length()));
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
    // Append 0 to process all parts the same way.
    locations.push_back(0);
    const LayoutUnit hyphen_inline_size = HyphenInlineSize(item_result);
    LayoutUnit max_part_width;
    for (const wtf_size_t location : locations) {
      const unsigned part_start_offset = start_offset + location;
      LayoutUnit part_width =
          shape_result.CachedWidth(part_start_offset, end_offset);
      if (has_hyphen) {
        part_width += hyphen_inline_size;
      }
      max_part_width = std::max(part_width, max_part_width);
      end_offset = part_start_offset;
      has_hyphen = true;
    }
    Add(max_part_width);
  }

 private:
  LayoutUnit min_inline_size_;
  mutable std::optional<LayoutUnit> hyphen_inline_size_;
};

}  // namespace

inline bool LineBreaker::ShouldAutoWrap(const ComputedStyle& style) const {
  if (disallow_auto_wrap_) [[unlikely]] {
    return false;
  }
  return style.ShouldWrapLine();
}

void LineBreaker::UpdateAvailableWidth() {
  LayoutUnit available_width;
  if (override_available_width_) [[unlikely]] {
    available_width = override_available_width_;
  } else {
    available_width = line_opportunity_.AvailableInlineSize();
  }
  // Make sure it's at least the initial size, which is usually 0 but not so
  // when `box-decoration-break: clone`.
  available_width =
      std::max(available_width, cloned_box_decorations_initial_size_);
  // Available width must be smaller than |LayoutUnit::Max()| so that the
  // position can be larger.
  available_width = std::min(available_width, LayoutUnit::NearlyMax());
  available_width_ = available_width;
}

LineBreaker::LineBreaker(InlineNode node,
                         LineBreakerMode mode,
                         const ConstraintSpace& space,
                         const LineLayoutOpportunity& line_opportunity,
                         const LeadingFloats& leading_floats,
                         const InlineBreakToken* break_token,
                         const ColumnSpannerPath* column_spanner_path,
                         ExclusionSpace* exclusion_space)
    : line_opportunity_(line_opportunity),
      node_(node),
      mode_(mode),
      is_initial_letter_box_(node.IsInitialLetterBox()),
      is_svg_text_(node.IsSvgText()),
      is_text_combine_(node.IsTextCombine()),
      is_first_formatted_line_(
          (!break_token || !break_token->IsPastFirstFormattedLine()) &&
          node.CanContainFirstFormattedLine()),
      use_first_line_style_(is_first_formatted_line_ &&
                            node.UseFirstLineStyle()),
      sticky_images_quirk_(mode != LineBreakerMode::kContent &&
                           node.IsStickyImagesQuirkForContentSize()),
      items_data_(&node.ItemsData(use_first_line_style_)),
      end_item_index_(items_data_->items.size()),
      text_content_(
          !sticky_images_quirk_
              ? items_data_->text_content
              : InlineNode::TextContentForStickyImagesQuirk(*items_data_)),
      constraint_space_(space),
      exclusion_space_(exclusion_space),
      break_token_(break_token),
      column_spanner_path_(column_spanner_path),
      break_iterator_(text_content_),
      shaper_(text_content_),
      spacing_(text_content_, is_svg_text_),
      leading_floats_(leading_floats),
      base_direction_(node_.BaseDirection()) {
  UpdateAvailableWidth();
  if (is_svg_text_) {
    const auto& char_data_list = node_.SvgCharacterDataList();
    if (node_.SvgTextPathRangeList().empty() &&
        node_.SvgTextLengthRangeList().empty() &&
        (char_data_list.empty() ||
         (char_data_list.size() == 1 && char_data_list[0].first == 0))) {
      needs_svg_segmentation_ = false;
    } else {
      needs_svg_segmentation_ = true;
      svg_resolved_iterator_ =
          std::make_unique<ResolvedTextLayoutAttributesIterator>(
              char_data_list);
    }
  }
  // TODO(crbug.com/40362375): SVG <text> should not be auto_wrap_ for now.
  //
  // Combine text should not cause line break.
  //
  // TODO(crbug.com/40207613): Once we implement multiple line initial letter,
  // we should allow auto wrap. Below example causes multiple lines text in
  // initial letter box.
  //   <style>
  //    p::.first-letter { line-break: anywhere; }
  //    p { width: 0px; }
  //  </style>
  //  <p>(A) punctuation characters can be part of ::first-letter.</p>
  disallow_auto_wrap_ =
      is_svg_text_ || is_text_combine_ || is_initial_letter_box_;

  if (!break_token)
    return;

  const ComputedStyle* line_initial_style = break_token->Style();
  if (!line_initial_style) [[unlikely]] {
    // Usually an inline break token has the line initial style, but class C
    // breaks and last-resort breaks require a break token to start from the
    // beginning of the block. In that case, the line is still the first
    // formatted line, and the line initial style should be computed from the
    // containing block.
    DCHECK_EQ(break_token->StartItemIndex(), 0u);
    DCHECK_EQ(break_token->StartTextOffset(), 0u);
    DCHECK(!break_token->IsForcedBreak());
    DCHECK_EQ(current_, break_token->Start());
    DCHECK_EQ(is_forced_break_, break_token->IsForcedBreak());
    return;
  }

  current_ = break_token->Start();
  ruby_break_token_ = break_token->RubyData();
  break_iterator_.SetStartOffset(current_.text_offset);
  is_forced_break_ = break_token->IsForcedBreak();
  items_data_->AssertOffset(current_);
  SetCurrentStyle(*line_initial_style);
}

LineBreaker::~LineBreaker() = default;

void LineBreaker::SetLineOpportunity(
    const LineLayoutOpportunity& line_opportunity) {
  line_opportunity_ = line_opportunity;
  UpdateAvailableWidth();
}

void LineBreaker::OverrideAvailableWidth(LayoutUnit available_width) {
  DCHECK_GE(available_width, LayoutUnit());
  override_available_width_ = available_width;
  UpdateAvailableWidth();
}

void LineBreaker::SetBreakAt(const LineBreakPoint& offset) {
  break_at_ = offset;
  OverrideAvailableWidth(LayoutUnit::NearlyMax());
}

inline InlineItemResult* LineBreaker::AddItem(const InlineItem& item,
                                              unsigned end_offset,
                                              LineInfo* line_info) {
  if (item.Type() != InlineItem::kOpenRubyColumn) {
    DCHECK_EQ(&item, &items_data_->items[current_.item_index]);
    DCHECK_GE(current_.text_offset, item.StartOffset());
    DCHECK_GE(end_offset, current_.text_offset);
    DCHECK_LE(end_offset, item.EndOffset());
  }
  if (item.IsTextCombine()) [[unlikely]] {
    line_info->SetHaveTextCombineOrRubyItem();
  }
  InlineItemResults* item_results = line_info->MutableResults();
  return &item_results->emplace_back(
      &item, current_.item_index,
      TextOffsetRange(current_.text_offset, end_offset),
      break_anywhere_if_overflow_, ShouldCreateLineBox(*item_results),
      HasUnpositionedFloats(*item_results));
}

inline InlineItemResult* LineBreaker::AddItem(const InlineItem& item,
                                              LineInfo* line_info) {
  return AddItem(item, item.EndOffset(), line_info);
}

InlineItemResult* LineBreaker::AddEmptyItem(const InlineItem& item,
                                            LineInfo* line_info) {
  InlineItemResult* item_result =
      AddItem(item, current_.text_offset, line_info);

  // Prevent breaking before an empty item, but allow to break after if the
  // previous item had `can_break_after`.
  DCHECK(!item_result->can_break_after);
  if (line_info->Results().size() >= 2) {
    InlineItemResult* last_item_result = std::prev(item_result);
    if (last_item_result->can_break_after) {
      last_item_result->can_break_after = false;
      item_result->can_break_after = true;
    }
  }
  return item_result;
}

// Call |HandleOverflow()| if the position is beyond the available space.
inline bool LineBreaker::HandleOverflowIfNeeded(LineInfo* line_info) {
  if (state_ == LineBreakState::kContinue && !CanFitOnLine()) {
    HandleOverflow(line_info);
    return true;
  }
  return false;
}

void LineBreaker::SetIntrinsicSizeOutputs(
    MaxSizeCache* max_size_cache,
    bool* depends_on_block_constraints_out) {
  DCHECK_NE(mode_, LineBreakerMode::kContent);
  DCHECK(max_size_cache);
  max_size_cache_ = max_size_cache;
  depends_on_block_constraints_out_ = depends_on_block_constraints_out;
}

// Compute the base direction for bidi algorithm for this line.
void LineBreaker::ComputeBaseDirection() {
  // If 'unicode-bidi' is not 'plaintext', use the base direction of the block.
  if (node_.Style().GetUnicodeBidi() != UnicodeBidi::kPlaintext)
    return;

  const String& text = Text();
  if (text.Is8Bit())
    return;

  // If 'unicode-bidi: plaintext', compute the base direction for each
  // "paragraph" (separated by forced break.)
  wtf_size_t start_offset;
  if (previous_line_had_forced_break_) {
    start_offset = current_.text_offset;
  } else {
    // If this "paragraph" is at the beginning of the block, use
    // |node_.BaseDirection()|.
    if (!current_.text_offset) {
      return;
    }
    start_offset =
        text.ReverseFind(kNewlineCharacter, current_.text_offset - 1);
    if (start_offset == kNotFound)
      return;
    ++start_offset;
  }

  // LTR when no strong characters because `plaintext` uses P2 and P3 of UAX#9:
  // https://w3c.github.io/csswg-drafts/css-writing-modes-3/#valdef-unicode-bidi-plaintext
  // which sets to LTR if no strong characters.
  // https://unicode.org/reports/tr9/#P3
  base_direction_ = BidiParagraph::BaseDirectionForStringOrLtr(
      StringView(text, start_offset),
      // For CSS processing, line feed (U+000A) is treated as a segment break.
      // https://w3c.github.io/csswg-drafts/css-text-3/#segment-break
      Character::IsLineFeed);
}

void LineBreaker::RecalcClonedBoxDecorations() {
  cloned_box_decorations_count_ = 0u;
  cloned_box_decorations_initial_size_ = LayoutUnit();
  cloned_box_decorations_end_size_ = LayoutUnit();
  has_cloned_box_decorations_ = false;

  // Compute which tags are not closed at |current_.item_index|.
  InlineItemsData::OpenTagItems open_items;
  items_data_->GetOpenTagItems(0u, current_.item_index, &open_items);

  for (const InlineItem* item : open_items) {
    if (item->Style()->BoxDecorationBreak() == EBoxDecorationBreak::kClone) {
      has_cloned_box_decorations_ = true;
      disable_score_line_break_ = true;
      ++cloned_box_decorations_count_;
      InlineItemResult item_result;
      ComputeOpenTagResult(*item, constraint_space_, is_svg_text_,
                           &item_result);
      cloned_box_decorations_initial_size_ += item_result.inline_size;
      cloned_box_decorations_end_size_ += item_result.margins.inline_end +
                                          item_result.borders.inline_end +
                                          item_result.padding.inline_end;
    }
  }
  // Advance |position_| by the initial size so that the tab position can
  // accommodate cloned box decorations.
  position_ += cloned_box_decorations_initial_size_;
  // |cloned_box_decorations_initial_size_| may affect available width.
  UpdateAvailableWidth();
  DCHECK_GE(available_width_, cloned_box_decorations_initial_size_);
}

// Add a hyphen string to the |InlineItemResult|.
//
// This function changes |InlineItemResult::inline_size|, but does not change
// |position_|
LayoutUnit LineBreaker::AddHyphen(InlineItemResults* item_results,
                                  wtf_size_t index,
                                  InlineItemResult* item_result) {
  DCHECK(!HasHyphen());
  DCHECK_EQ(index, static_cast<wtf_size_t>(item_result - item_results->data()));
  DCHECK_LT(index, item_results->size());
  hyphen_index_ = index;

  if (!item_result->hyphen) {
    item_result->ShapeHyphen();
    has_any_hyphens_ = true;
  }
  DCHECK(item_result->hyphen);
  DCHECK(has_any_hyphens_);

  const LayoutUnit hyphen_inline_size = item_result->hyphen.InlineSize();
  item_result->inline_size += hyphen_inline_size;
  return hyphen_inline_size;
}

LayoutUnit LineBreaker::AddHyphen(InlineItemResults* item_results,
                                  wtf_size_t index) {
  InlineItemResult* item_result = &(*item_results)[index];
  DCHECK(item_result->item);
  return AddHyphen(item_results, index, item_result);
}

LayoutUnit LineBreaker::AddHyphen(InlineItemResults* item_results,
                                  InlineItemResult* item_result) {
  return AddHyphen(
      item_results,
      base::checked_cast<wtf_size_t>(item_result - item_results->data()),
      item_result);
}

// Remove the hyphen string from the |InlineItemResult|.
//
// This function changes |InlineItemResult::inline_size|, but does not change
// |position_|
LayoutUnit LineBreaker::RemoveHyphen(InlineItemResults* item_results) {
  DCHECK(HasHyphen());
  InlineItemResult* item_result = &(*item_results)[*hyphen_index_];
  DCHECK(item_result->hyphen);
  const LayoutUnit hyphen_inline_size = item_result->hyphen.InlineSize();
  item_result->inline_size -= hyphen_inline_size;
  // |hyphen_string| and |hyphen_shape_result| may be reused when rewinded.
  hyphen_index_.reset();
  return hyphen_inline_size;
}

// Add a hyphen string to the last inflow item in |item_results| if it is
// hyphenated. This can restore the hyphenation state after rewind.
void LineBreaker::RestoreLastHyphen(InlineItemResults* item_results) {
  DCHECK(!hyphen_index_);
  DCHECK(has_any_hyphens_);
  for (InlineItemResult& item_result : base::Reversed(*item_results)) {
    DCHECK(item_result.item);
    if (item_result.hyphen) {
      AddHyphen(item_results, &item_result);
      return;
    }
    const InlineItem& item = *item_result.item;
    if (item.Type() == InlineItem::kText ||
        item.Type() == InlineItem::kAtomicInline) {
      return;
    }
  }
}

// Set the final hyphenation results to |item_results|.
void LineBreaker::FinalizeHyphen(InlineItemResults* item_results) {
  DCHECK(HasHyphen());
  InlineItemResult* item_result = &(*item_results)[*hyphen_index_];
  DCHECK(item_result->hyphen);
  item_result->is_hyphenated = true;
}

// Initialize internal states for the next line.
void LineBreaker::PrepareNextLine(LineInfo* line_info) {
  line_info->Reset();

  const InlineItemResults& item_results = line_info->Results();
  DCHECK(item_results.empty());

  if (parent_breaker_) {
    previous_line_had_forced_break_ =
        parent_breaker_->previous_line_had_forced_break_;
    is_forced_break_ = parent_breaker_->is_forced_break_;
    is_first_formatted_line_ = parent_breaker_->is_first_formatted_line_;
    use_first_line_style_ = parent_breaker_->use_first_line_style_;
    items_data_ = parent_breaker_->items_data_;
  } else if (!current_.IsZero()) {
    // We're past the first line
    previous_line_had_forced_break_ = is_forced_break_;
    is_forced_break_ = false;
    // If we resumed at a break token, and we're past the resume point stored
    // there, we're also past the first formatted line (otherwise, there may be
    // lines solely consisting of leading floats, and those don't count as
    // "formatted lines", since they aren't actually lines, as far as the spec
    // is concerned).
    if (!RuntimeEnabledFeatures::LineBoxBelowLeadingFloatsEnabled() ||
        !break_token_ || current_ != break_token_->Start()) {
      is_first_formatted_line_ = false;
      use_first_line_style_ = false;
    }
  }

  line_info->SetStart(current_);
  line_info->SetIsFirstFormattedLine(is_first_formatted_line_);
  line_info->SetLineStyle(node_, *items_data_, use_first_line_style_);

  DCHECK(!line_info->TextIndent());
  if (is_first_formatted_line_ && end_item_index_ == Items().size()) {
    const Length& length = line_info->LineStyle().TextIndent();
    LayoutUnit maximum_value;
    // Ignore percentages (resolve to 0) when calculating min/max intrinsic
    // sizes.
    if (length.HasPercent() && mode_ == LineBreakerMode::kContent) {
      maximum_value = constraint_space_.AvailableSize().inline_size;
    }
    line_info->SetTextIndent(MinimumValueForLength(length, maximum_value));
  }

  // Set the initial style of this line from the line style, if the style from
  // the end of previous line is not available. Example:
  //   <p>...<span>....</span></p>
  // When the line wraps in <span>, the 2nd line needs to start with the style
  // of the <span>.
  override_break_anywhere_ = false;
  disable_phrase_ = false;
  disable_score_line_break_ = false;
  disable_bisect_line_break_ = false;
  if (!current_style_)
    SetCurrentStyle(line_info->LineStyle());
  ComputeBaseDirection();
  line_info->SetBaseDirection(base_direction_);
  hyphen_index_.reset();
  has_any_hyphens_ = false;
  resume_block_in_inline_in_same_flow_ = false;

  // Use 'text-indent' as the initial position. This lets tab positions to align
  // regardless of 'text-indent'.
  applied_text_indent_ = line_info->TextIndent();
  position_ = applied_text_indent_;

  has_cloned_box_decorations_ = false;
  if ((break_token_ && break_token_->HasClonedBoxDecorations()) ||
      cloned_box_decorations
"""


```