Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. I need to identify the core purpose of the `column_layout_algorithm.cc` file and explain its role in rendering web pages. Specifically, I should mention its relation to HTML, CSS, and JavaScript, provide examples, describe logical reasoning with input/output scenarios, and highlight common usage errors.

**Plan:**

1. **Identify the core functionality:** The file name suggests it's responsible for laying out content in columns, likely related to the CSS `column-*` properties.
2. **Explain the relation to HTML, CSS, and JavaScript:**
    *   **HTML:**  This algorithm determines how HTML elements are positioned within columns.
    *   **CSS:** It directly implements the CSS multi-column layout properties.
    *   **JavaScript:** While not directly interacting, JavaScript can dynamically modify styles that trigger this algorithm.
3. **Provide examples:**  Show how CSS properties like `column-count`, `column-width`, and `column-span` influence the algorithm's behavior.
4. **Describe logical reasoning with input/output scenarios:**
    *   **Input:**  HTML structure, CSS `column-*` properties, available space.
    *   **Output:** Positions and dimensions of elements within columns.
5. **Highlight common usage errors:** Mention potential pitfalls like content overflow or unexpected layout behavior with complex configurations.
6. **Summarize the functionality:** Briefly reiterate the main purpose of the code.
这是 `blink/renderer/core/layout/column_layout_algorithm.cc` 文件的第一部分，其主要功能是**实现 CSS 多列布局**。它负责计算并将 HTML 元素放置在多列容器中，处理诸如列数、列宽、列间距以及跨列元素等情况。

**功能归纳:**

1. **多列布局核心算法:** 该代码定义了 `ColumnLayoutAlgorithm` 类，该类是 Blink 渲染引擎中用于处理 CSS 多列布局的核心算法实现。
2. **处理多列容器的子元素:** 它负责遍历多列容器（例如设置了 `column-count` 或 `column-width` 的元素）的子元素，并决定它们在各个列中的位置和大小。
3. **处理跨列元素 (Spanners):** 代码中包含对跨越多个列的元素（使用 `column-span: all`）的处理逻辑，确保这些元素占据正确的宽度并放置在所有列的上方或下方。
4. **处理列之间的分割 (Gaps):**  算法考虑了 `column-gap` 属性，并在列之间添加正确的间距。
5. **处理分页/分段 (Fragmentation):** 该算法与 Blink 的分段机制集成，能够处理多列容器在分页或分栏时的布局，例如在打印或多窗口显示时。
6. **计算多列容器的最小/最大尺寸:**  `ComputeMinMaxSizes` 函数用于计算多列容器在不同约束下的最小和最大尺寸，这对于布局引擎确定容器的最佳大小至关重要。
7. **创建空列:** `CreateEmptyColumn` 函数用于在需要时创建空的列容器。
8. **处理列表标记:** 考虑了列表项在使用多列布局时的列表标记的定位。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **CSS:**  此代码直接响应和实现了 CSS 的多列布局属性。
    *   **示例:**  当 HTML 元素的 CSS 样式中设置了 `column-count: 3;` 或 `column-width: 200px;` 时，`ColumnLayoutAlgorithm` 就会被调用来计算元素的布局，将其内容分配到 3 列或宽度为 200px 的多列中。
    *   **示例:**  CSS 属性 `column-gap: 10px;`  会直接影响到 `ResolveUsedColumnGap` 函数的返回值，从而在列之间创建 10 像素的间距。
    *   **示例:**  `column-span: all;`  会触发代码中处理 "spanner" 元素的逻辑，确保该元素横跨所有列。

*   **HTML:**  该算法接收 HTML 元素作为输入，并根据 CSS 样式决定这些元素在多列布局中的最终呈现位置。
    *   **假设输入:**  一段包含多个 `<p>` 标签的 `<div>` 元素，该 `<div>` 元素的 CSS 设置了 `column-count: 2;`.
    *   **预期输出:**  `ColumnLayoutAlgorithm` 会将这些 `<p>` 标签的内容尽可能均匀地分配到两列中。

*   **JavaScript:** 虽然 JavaScript 不直接操作此 C++ 代码，但 JavaScript 可以动态修改元素的 CSS 样式，从而间接地触发 `ColumnLayoutAlgorithm` 的执行。
    *   **示例:**  JavaScript 代码使用 `element.style.columnCount = '4';`  来动态改变元素的列数，这将导致浏览器重新调用 `ColumnLayoutAlgorithm` 来更新布局。

**逻辑推理的假设输入与输出:**

*   **假设输入:**
    *   一个 `<div>` 元素，其 CSS 为 `{ column-width: 150px; column-gap: 20px; }`
    *   `ChildAvailableSize().inline_size` (可用内联尺寸) 为 500px。
*   **逻辑推理:**
    *   `ResolveUsedColumnInlineSize` 会计算出每列的宽度为 150px。
    *   `ResolveUsedColumnGap` 会计算出列间距为 20px。
    *   `ResolveUsedColumnCount` 会尝试在 500px 的可用宽度内放置尽可能多的 150px 列，并考虑 20px 的间距。  计算方式大致为 `floor((500 + 20) / (150 + 20)) = floor(520 / 170) = 3` 列。
*   **预期输出:** `used_column_count_` 的值为 3。

**涉及用户或编程常见的使用错误:**

*   **内容溢出:** 用户可能会提供过多的内容，导致在固定的列数和列宽下出现内容溢出，超出容器边界。
    *   **示例:**  设置了 `column-count: 2;` 和固定高度的容器，但内容过多无法完全显示在两列中。
*   **未考虑容器宽度:** 开发者可能会忘记考虑多列容器的可用宽度，导致列的布局不如预期。
    *   **示例:**  设置了 `column-width: 300px;` 但父容器宽度只有 400px，预期会出现两列，但实际可能只会显示一列。
*   **与 `column-width` 和 `column-count` 的冲突:** 同时设置 `column-width` 和 `column-count` 时，浏览器的行为可能会让用户感到困惑，因为只有一个属性会真正生效（通常是 `column-width` 优先）。
*   **跨列元素超出边界:**  如果跨列元素的宽度大于多列容器的宽度，可能会导致布局问题。

总而言之，这段代码是 Chromium 渲染引擎中负责将 CSS 多列布局规范转化为实际像素绘制的关键部分，它处理了各种与多列布局相关的复杂逻辑和边缘情况。

### 提示词
```
这是目录为blink/renderer/core/layout/column_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/column_layout_algorithm.h"

#include <algorithm>

#include "base/not_fatal_until.h"
#include "third_party/blink/renderer/core/dom/column_pseudo_element.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm_utils.h"
#include "third_party/blink/renderer/core/layout/column_spanner_path.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/fragment_geometry.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/geometry/margin_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/list/unpositioned_list_marker.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/out_of_flow_layout_part.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/simplified_oof_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/table/table_layout_utils.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {

namespace {

// An itinerary of multicol container parts to walk separately for layout. A
// part is either a chunk of regular column content, or a column spanner.
class MulticolPartWalker {
  STACK_ALLOCATED();

 public:
  // What to lay out or process next.
  struct Entry {
    STACK_ALLOCATED();

   public:
    Entry() = default;
    Entry(const BlockBreakToken* token, BlockNode spanner)
        : break_token(token), spanner(spanner) {}

    // The incoming break token for the content to process, or null if we're at
    // the start.
    const BlockBreakToken* break_token = nullptr;

    // The column spanner node to process, or null if we're dealing with regular
    // column content.
    BlockNode spanner = nullptr;
  };

  MulticolPartWalker(BlockNode multicol_container,
                     const BlockBreakToken* break_token)
      : multicol_container_(multicol_container),
        parent_break_token_(break_token),
        child_token_idx_(0) {
    UpdateCurrent();
    // The first entry in the first multicol fragment may be empty (that just
    // means that we haven't started yet), but if this happens anywhere else, it
    // means that we're finished. Nothing inside this multicol container left to
    // process.
    if (IsBreakInside(parent_break_token_) && !current_.break_token &&
        parent_break_token_->HasSeenAllChildren())
      is_finished_ = true;
  }

  Entry Current() const {
    DCHECK(!is_finished_);
    return current_;
  }

  bool IsFinished() const { return is_finished_; }

  // Move to the next part.
  void Next();

  // Move over to the specified spanner, and take it from there.
  void MoveToSpanner(BlockNode spanner,
                     const BlockBreakToken* next_column_token);

  // Push a break token for the column content to resume at.
  void AddNextColumnBreakToken(const BlockBreakToken& next_column_token);

  // If a column was added for an OOF before a spanner, we need to update the
  // column break token so that the content is resumed at the correct spot.
  void UpdateNextColumnBreakToken(
      const FragmentBuilder::ChildrenVector& children);

 private:
  void MoveToNext();
  void UpdateCurrent();

  Entry current_;
  BlockNode spanner_ = nullptr;
  BlockNode multicol_container_;
  const BlockBreakToken* parent_break_token_;
  const BlockBreakToken* next_column_token_ = nullptr;

  // An index into parent_break_token_'s ChildBreakTokens() vector. Used for
  // keeping track of the next child break token to inspect.
  wtf_size_t child_token_idx_;

  bool is_finished_ = false;
};

void MulticolPartWalker::Next() {
  if (is_finished_)
    return;
  MoveToNext();
  if (!is_finished_)
    UpdateCurrent();
}

void MulticolPartWalker::MoveToSpanner(
    BlockNode spanner,
    const BlockBreakToken* next_column_token) {
  *this = MulticolPartWalker(multicol_container_, nullptr);
  DCHECK(spanner.IsColumnSpanAll());
  spanner_ = spanner;
  next_column_token_ = next_column_token;
  UpdateCurrent();
}

void MulticolPartWalker::AddNextColumnBreakToken(
    const BlockBreakToken& next_column_token) {
  *this = MulticolPartWalker(multicol_container_, nullptr);
  next_column_token_ = &next_column_token;
  UpdateCurrent();
}

void MulticolPartWalker::UpdateNextColumnBreakToken(
    const FragmentBuilder::ChildrenVector& children) {
  if (children.empty())
    return;
  const blink::PhysicalFragment* last_child =
      children[children.size() - 1].fragment;
  if (!last_child->IsColumnBox())
    return;
  const auto* child_break_token =
      To<BlockBreakToken>(last_child->GetBreakToken());
  if (child_break_token && child_break_token != next_column_token_)
    next_column_token_ = child_break_token;
}

void MulticolPartWalker::UpdateCurrent() {
  DCHECK(!is_finished_);
  if (parent_break_token_) {
    const auto& child_break_tokens = parent_break_token_->ChildBreakTokens();
    if (child_token_idx_ < child_break_tokens.size()) {
      const auto* child_break_token =
          To<BlockBreakToken>(child_break_tokens[child_token_idx_].Get());
      if (child_break_token->InputNode() == multicol_container_) {
        current_.spanner = nullptr;
      } else {
        current_.spanner = To<BlockNode>(child_break_token->InputNode());
        DCHECK(current_.spanner.IsColumnSpanAll());
      }
      current_.break_token = child_break_token;
      return;
    }
  }

  if (spanner_) {
    current_ = Entry(/* break_token */ nullptr, spanner_);
    return;
  }

  if (next_column_token_) {
    current_ = Entry(next_column_token_, /* spanner */ nullptr);
    return;
  }

  // The current entry is empty. That's only the case when we're at the very
  // start of the multicol container, or if we're past all children.
  DCHECK(!is_finished_);
  DCHECK(!current_.spanner);
  DCHECK(!current_.break_token);
}

void MulticolPartWalker::MoveToNext() {
  if (parent_break_token_) {
    const auto& child_break_tokens = parent_break_token_->ChildBreakTokens();
    if (child_token_idx_ < child_break_tokens.size()) {
      child_token_idx_++;
      // If we have more incoming break tokens, we'll use that.
      if (child_token_idx_ < child_break_tokens.size())
        return;
      // We just ran out of break tokens. Fall through.
    }
  }

  if (spanner_) {
    LayoutInputNode next = spanner_.NextSibling();
    // Otherwise, if there's a next spanner, we'll use that.
    if (next && next.IsColumnSpanAll()) {
      spanner_ = To<BlockNode>(next);
      return;
    }
    spanner_ = nullptr;

    // Otherwise, if we have column content to resume at, use that.
    if (next_column_token_)
      return;
  }

  // Otherwise, we're done.
  is_finished_ = true;
}

BlockNode GetSpannerFromPath(const ColumnSpannerPath* path) {
  while (path->Child())
    path = path->Child();
  DCHECK(path->GetBlockNode().IsColumnSpanAll());
  return path->GetBlockNode();
}

}  // namespace

ColumnLayoutAlgorithm::ColumnLayoutAlgorithm(
    const LayoutAlgorithmParams& params)
    : LayoutAlgorithm(params) {
  // When a list item has multicol, |ColumnLayoutAlgorithm| needs to keep
  // track of the list marker instead of the child layout algorithm. See
  // |BlockLayoutAlgorithm|.
  if (const BlockNode marker_node = Node().ListMarkerBlockNodeIfListItem()) {
    if (!marker_node.ListMarkerOccupiesWholeLine() &&
        (!GetBreakToken() || GetBreakToken()->HasUnpositionedListMarker())) {
      container_builder_.SetUnpositionedListMarker(
          UnpositionedListMarker(marker_node));
    }
  }
}

const LayoutResult* ColumnLayoutAlgorithm::Layout() {
  const LogicalSize border_box_size = container_builder_.InitialBorderBoxSize();
  // TODO(mstensho): This isn't the content-box size, as
  // |BorderScrollbarPadding()| has been adjusted for fragmentation. Verify
  // that this is the correct size.
  column_block_size_ =
      ShrinkLogicalSize(border_box_size, BorderScrollbarPadding()).block_size;

  DCHECK_GE(ChildAvailableSize().inline_size, LayoutUnit());
  column_inline_size_ =
      ResolveUsedColumnInlineSize(ChildAvailableSize().inline_size, Style());

  column_inline_progression_ =
      column_inline_size_ +
      ResolveUsedColumnGap(ChildAvailableSize().inline_size, Style());
  used_column_count_ =
      ResolveUsedColumnCount(ChildAvailableSize().inline_size, Style());

  // Write the column inline-size and count back to the legacy flow thread if
  // we're at the first fragment. TextAutosizer needs the inline-size, and the
  // legacy fragmentainer group machinery needs the count.
  if (!IsBreakInside(GetBreakToken())) {
    node_.StoreColumnSizeAndCount(column_inline_size_, used_column_count_);

    StyleEngine& style_engine = Node().GetDocument().GetStyleEngine();
    style_engine.SetInScrollMarkersAttachment(true);
    To<Element>(Node().EnclosingDOMNode())->ClearColumnPseudoElements();
    style_engine.SetInScrollMarkersAttachment(false);
  }

  // If we know the block-size of the fragmentainers in an outer fragmentation
  // context (if any), our columns may be constrained by that, meaning that we
  // may have to fragment earlier than what we would have otherwise, and, if
  // that's the case, that we may also not create overflowing columns (in the
  // inline axis), but rather finish the row and resume in the next row in the
  // next outer fragmentainer. Note that it is possible to be nested inside a
  // fragmentation context that doesn't know the block-size of its
  // fragmentainers. This would be in the first layout pass of an outer multicol
  // container, before any tentative column block-size has been calculated.
  is_constrained_by_outer_fragmentation_context_ =
      GetConstraintSpace().HasKnownFragmentainerBlockSize();

  container_builder_.SetIsBlockFragmentationContextRoot();

  intrinsic_block_size_ = BorderScrollbarPadding().block_start;

  BreakStatus break_status = LayoutChildren();
  if (break_status == BreakStatus::kNeedsEarlierBreak) {
    // We need to discard this layout and do it again. We found an earlier break
    // point that's more appealing than the one we ran out of space at.
    return RelayoutAndBreakEarlier<ColumnLayoutAlgorithm>(
        container_builder_.GetEarlyBreak());
  }
  DCHECK_EQ(break_status, BreakStatus::kContinue);

  intrinsic_block_size_ =
      std::max(intrinsic_block_size_, BorderScrollbarPadding().block_start);
  intrinsic_block_size_ += BorderScrollbarPadding().block_end;

  // Figure out how much space we've already been able to process in previous
  // fragments, if this multicol container participates in an outer
  // fragmentation context.
  LayoutUnit previously_consumed_block_size;
  if (const auto* token = GetBreakToken()) {
    previously_consumed_block_size = token->ConsumedBlockSize();
  }

  const LayoutUnit unconstrained_intrinsic_block_size = intrinsic_block_size_;
  intrinsic_block_size_ =
      ClampIntrinsicBlockSize(GetConstraintSpace(), Node(), GetBreakToken(),
                              BorderScrollbarPadding(), intrinsic_block_size_);

  LayoutUnit block_size = ComputeBlockSizeForFragment(
      GetConstraintSpace(), Node(), BorderPadding(),
      previously_consumed_block_size + intrinsic_block_size_,
      border_box_size.inline_size);

  container_builder_.SetFragmentsTotalBlockSize(block_size);
  container_builder_.SetIntrinsicBlockSize(intrinsic_block_size_);
  container_builder_.SetBlockOffsetForAdditionalColumns(
      CurrentContentBlockOffset(intrinsic_block_size_));

  PositionAnyUnclaimedListMarker();

  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    // In addition to establishing one, we're nested inside another
    // fragmentation context.
    FinishFragmentation(&container_builder_);

    // OOF positioned elements inside a nested fragmentation context are laid
    // out at the outermost context. If this multicol has OOF positioned
    // elements pending layout, store its node for later use.
    if (container_builder_.HasOutOfFlowFragmentainerDescendants()) {
      container_builder_.AddMulticolWithPendingOOFs(Node());
    }

    // Read the intrinsic block-size back, since it may have been reduced due to
    // fragmentation.
    intrinsic_block_size_ = container_builder_.IntrinsicBlockSize();
  } else {
#if DCHECK_IS_ON()
    // If we're not participating in a fragmentation context, no block
    // fragmentation related fields should have been set.
    container_builder_.CheckNoBlockFragmentation();
#endif
  }

  if (GetConstraintSpace().IsTableCell()) {
    FinalizeTableCellLayout(unconstrained_intrinsic_block_size,
                            &container_builder_);
  } else {
    AlignBlockContent(Style(), GetBreakToken(),
                      unconstrained_intrinsic_block_size, container_builder_);
  }

  container_builder_.HandleOofsAndSpecialDescendants();

  return container_builder_.ToBoxFragment();
}

MinMaxSizesResult ColumnLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput&) {
  const LayoutUnit override_intrinsic_inline_size =
      Node().OverrideIntrinsicContentInlineSize();
  if (override_intrinsic_inline_size != kIndefiniteSize) {
    const LayoutUnit size =
        BorderScrollbarPadding().InlineSum() + override_intrinsic_inline_size;
    return {{size, size}, /* depends_on_block_constraints */ false};
  }

  // First calculate the min/max sizes of columns.
  ConstraintSpace space = CreateConstraintSpaceForMinMax();
  FragmentGeometry fragment_geometry = CalculateInitialFragmentGeometry(
      space, Node(), /* break_token */ nullptr, /* is_intrinsic */ true);
  BlockLayoutAlgorithm algorithm({Node(), fragment_geometry, space});
  MinMaxSizesResult result =
      algorithm.ComputeMinMaxSizes(MinMaxSizesFloatInput());

  // How column-width affects min/max sizes is currently not defined in any
  // spec, but there used to be a definition, which everyone still follows to
  // some extent:
  // https://www.w3.org/TR/2016/WD-css-sizing-3-20160510/#multicol-intrinsic
  //
  // GitHub issue for getting this back into some spec:
  // https://github.com/w3c/csswg-drafts/issues/1742
  if (!Style().HasAutoColumnWidth()) {
    // One peculiarity in the (old and only) spec is that column-width may
    // shrink min intrinsic inline-size to become less than what the contents
    // require:
    //
    // "The min-content inline size of a multi-column element with a computed
    // column-width not auto is the smaller of its column-width and the largest
    // min-content inline-size contribution of its contents."
    const LayoutUnit column_width(Style().ColumnWidth());
    result.sizes.min_size = std::min(result.sizes.min_size, column_width);
    result.sizes.max_size = std::max(result.sizes.max_size, column_width);
    result.sizes.max_size =
        std::max(result.sizes.max_size, result.sizes.min_size);
  }

  // Now convert those column min/max values to multicol container min/max
  // values. We typically have multiple columns and also gaps between them.
  int column_count = Style().ColumnCount();
  DCHECK_GE(column_count, 1);
  LayoutUnit column_gap = ResolveUsedColumnGap(LayoutUnit(), Style());
  LayoutUnit gap_extra = column_gap * (column_count - 1);

  // Another peculiarity in the (old and only) spec (see above) is that
  // column-count (and therefore also column-gap) is ignored in intrinsic min
  // inline-size calculation, if column-width is specified.
  if (Style().HasAutoColumnWidth()) {
    result.sizes.min_size *= column_count;
    result.sizes.min_size += gap_extra;
  }
  result.sizes.max_size *= column_count;
  result.sizes.max_size += gap_extra;

  // The block layout algorithm skips spanners for min/max calculation (since
  // they shouldn't be part of the column-count multiplication above). Calculate
  // min/max inline-size for spanners now.
  if (!Node().ShouldApplyInlineSizeContainment())
    result.sizes.Encompass(ComputeSpannersMinMaxSizes(Node()).sizes);

  result.sizes += BorderScrollbarPadding().InlineSum();
  return result;
}

const PhysicalBoxFragment& ColumnLayoutAlgorithm::CreateEmptyColumn(
    const BlockNode& node,
    const ConstraintSpace& parent_space,
    const PhysicalBoxFragment& previous_column) {
  WritingMode writing_mode = parent_space.GetWritingMode();
  DCHECK(previous_column.IsColumnBox());
  const BlockBreakToken* break_token = previous_column.GetBreakToken();
  LogicalSize column_size =
      previous_column.Size().ConvertToLogical(writing_mode);
  ConstraintSpace child_space = CreateConstraintSpaceForFragmentainer(
      parent_space, kFragmentColumn, column_size,
      /*percentage_resolution_size=*/column_size, /*balance_columns=*/false,
      kBreakAppealLastResort);
  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(child_space, node, break_token);
  LayoutAlgorithmParams params(node, fragment_geometry, child_space,
                               break_token);
  SimplifiedOofLayoutAlgorithm child_algorithm(params, previous_column);
  child_algorithm.ResumeColumnLayout(break_token);
  return To<PhysicalBoxFragment>(
      child_algorithm.Layout()->GetPhysicalFragment());
}

MinMaxSizesResult ColumnLayoutAlgorithm::ComputeSpannersMinMaxSizes(
    const BlockNode& search_parent) const {
  MinMaxSizesResult result;
  for (LayoutInputNode child = search_parent.FirstChild(); child;
       child = child.NextSibling()) {
    const BlockNode* child_block = DynamicTo<BlockNode>(&child);
    if (!child_block)
      continue;
    MinMaxSizesResult child_result;
    if (!child_block->IsColumnSpanAll()) {
      // Spanners don't need to be a direct child of the multicol container, but
      // they need to be in its formatting context.
      if (child_block->CreatesNewFormattingContext())
        continue;
      child_result = ComputeSpannersMinMaxSizes(*child_block);
    } else {
      MinMaxConstraintSpaceBuilder builder(GetConstraintSpace(), Style(),
                                           *child_block, /* is_new_fc */ true);
      builder.SetAvailableBlockSize(ChildAvailableSize().block_size);
      const ConstraintSpace child_space = builder.ToConstraintSpace();
      child_result = ComputeMinAndMaxContentContribution(Style(), *child_block,
                                                         child_space);
    }
    result.sizes.Encompass(child_result.sizes);
  }
  return result;
}

BreakStatus ColumnLayoutAlgorithm::LayoutChildren() {
  MarginStrut margin_strut;
  MulticolPartWalker walker(Node(), GetBreakToken());
  while (!walker.IsFinished()) {
    auto entry = walker.Current();
    const auto* child_break_token = To<BlockBreakToken>(entry.break_token);

    // If this is regular column content (i.e. not a spanner), or we're at the
    // very start, perform column layout. If we're at the very start, and even
    // if the child is a spanner (which means that we won't be able to lay out
    // any column content at all), we still need to enter here, because that's
    // how we create a break token for the column content to resume at. With no
    // break token, we wouldn't be able to resume layout after the any initial
    // spanners.
    if (!entry.spanner) {
      const LayoutResult* result =
          LayoutRow(child_break_token, LayoutUnit(), &margin_strut);

      if (!result) {
        // An outer fragmentainer break was inserted before this row.
        DCHECK(GetConstraintSpace().HasBlockFragmentation());
        break;
      }

      walker.Next();

      const auto* next_column_token =
          To<BlockBreakToken>(result->GetPhysicalFragment().GetBreakToken());

      if (const auto* path = result->GetColumnSpannerPath()) {
        // We found a spanner, and if there's column content to resume at after
        // it, |next_column_token| will be set. Move the walker to the
        // spanner. We'll now walk that spanner and any sibling spanners, before
        // resuming at |next_column_token|.
        BlockNode spanner_node = GetSpannerFromPath(path);
        walker.MoveToSpanner(spanner_node, next_column_token);
        continue;
      }

      // If we didn't find a spanner, it either means that we're through
      // everything, or that column layout needs to continue from the next outer
      // fragmentainer.
      if (next_column_token)
        walker.AddNextColumnBreakToken(*next_column_token);

      break;
    }

    // Attempt to lay out one column spanner.

    BlockNode spanner_node = entry.spanner;

    // If this is the child we had previously determined to break before, do so
    // now and finish layout.
    if (early_break_ &&
        IsEarlyBreakTarget(*early_break_, container_builder_, spanner_node))
      break;

    // Handle any OOF fragmentainer descendants that were found before the
    // spanner.
    OutOfFlowLayoutPart(&container_builder_).HandleFragmentation();
    walker.UpdateNextColumnBreakToken(container_builder_.Children());

    BreakStatus break_status =
        LayoutSpanner(spanner_node, child_break_token, &margin_strut);

    walker.Next();

    if (break_status == BreakStatus::kNeedsEarlierBreak) {
      return break_status;
    }
    if (break_status == BreakStatus::kBrokeBefore ||
        container_builder_.HasInflowChildBreakInside()) {
      break;
    }
  }

  if (!walker.IsFinished() || container_builder_.HasInflowChildBreakInside()) {
    // We broke in the main flow. Let this multicol container take up any
    // remaining space.
    intrinsic_block_size_ =
        std::max(intrinsic_block_size_, FragmentainerSpaceLeftForChildren());

    // Go through any remaining parts that we didn't get to, and push them as
    // break tokens for the next (outer) fragmentainer to handle.
    for (; !walker.IsFinished(); walker.Next()) {
      auto entry = walker.Current();
      if (entry.break_token) {
        // Copy unhandled incoming break tokens, for the next (outer)
        // fragmentainer.
        container_builder_.AddBreakToken(entry.break_token);
      } else if (entry.spanner) {
        // Create break tokens for the spanners that were discovered (but not
        // handled) while laying out this (outer) fragmentainer, so that they
        // get resumed in the next one (or pushed again, if it won't fit there
        // either).
        container_builder_.AddBreakBeforeChild(
            entry.spanner, kBreakAppealPerfect, /* is_forced_break */ false);
      }
    }
  } else {
    // We've gone through all the content. This doesn't necessarily mean that
    // we're done fragmenting, since the multicol container may be taller than
    // what the content requires, which means that we might create more
    // (childless) fragments, if we're nested inside another fragmentation
    // context. In that case we must make sure to skip the contents when
    // resuming.
    container_builder_.SetHasSeenAllChildren();

    // TODO(mstensho): Truncate the child margin if it overflows the
    // fragmentainer, by using AdjustedMarginAfterFinalChildFragment().

    intrinsic_block_size_ += margin_strut.Sum();
  }

  return BreakStatus::kContinue;
}

struct ResultWithOffset {
  DISALLOW_NEW();

 public:
  Member<const LayoutResult> result;
  LogicalOffset offset;

  ResultWithOffset(const LayoutResult* result, LogicalOffset offset)
      : result(result), offset(offset) {}

  const PhysicalBoxFragment& Fragment() const {
    return To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  }

  void Trace(Visitor* visitor) const { visitor->Trace(result); }
};

const LayoutResult* ColumnLayoutAlgorithm::LayoutRow(
    const BlockBreakToken* next_column_token,
    LayoutUnit minimum_column_block_size,
    MarginStrut* margin_strut) {
  LogicalSize column_size(column_inline_size_, column_block_size_);

  // Calculate the block-offset by including any trailing margin from a previous
  // adjacent column spanner. We will not reset the margin strut just yet, as we
  // first need to figure out if there's any content at all inside the columns.
  // If there isn't, it should be possible to collapse the margin through the
  // row (and as far as the spec is concerned, the row won't even exist then).
  LayoutUnit row_offset = intrinsic_block_size_ + margin_strut->Sum();

  // If block-size is non-auto, subtract the space for content we've consumed in
  // previous fragments. This is necessary when we're nested inside another
  // fragmentation context.
  if (column_size.block_size != kIndefiniteSize) {
    if (GetBreakToken() && is_constrained_by_outer_fragmentation_context_) {
      column_size.block_size -= GetBreakToken()->ConsumedBlockSize();
    }

    // Subtract the space already taken in the current fragment (spanners and
    // earlier column rows).
    column_size.block_size -= CurrentContentBlockOffset(row_offset);

    column_size.block_size = column_size.block_size.ClampNegativeToZero();
  }

  bool may_resume_in_next_outer_fragmentainer = false;
  LayoutUnit available_outer_space = kIndefiniteSize;
  if (is_constrained_by_outer_fragmentation_context_) {
    available_outer_space =
        std::max(minimum_column_block_size,
                 FragmentainerSpaceLeftForChildren() - row_offset);
    DCHECK_GE(available_outer_space, LayoutUnit());

    // Determine if we should resume layout in the next outer fragmentation
    // context if we run out of space in the current one. This is always the
    // thing to do except when block-size is non-auto and short enough to fit in
    // the current outer fragmentainer. In such cases we'll allow inner columns
    // to overflow its outer fragmentainer (since the inner multicol is too
    // short to reach the outer fragmentation line).
    if (column_size.block_size == kIndefiniteSize ||
        column_size.block_size > available_outer_space)
      may_resume_in_next_outer_fragmentainer = true;
  }

  bool shrink_to_fit_column_block_size = false;

  // If column-fill is 'balance', we should of course balance. Additionally, we
  // need to do it if we're *inside* another multicol container that's
  // performing its initial column balancing pass. Otherwise we might report a
  // taller block-size that we eventually end up with, resulting in the outer
  // columns to be overstretched.
  bool balance_columns =
      Style().GetColumnFill() == EColumnFill::kBalance ||
      (GetConstraintSpace().HasBlockFragmentation() &&
       !GetConstraintSpace().HasKnownFragmentainerBlockSize());

  // If columns are to be balanced, we need to examine the contents of the
  // multicol container to figure out a good initial (minimal) column
  // block-size. We also need to do this if column-fill is 'auto' and the
  // block-size is unconstrained.
  bool has_content_based_block_size =
      balance_columns || (column_size.block_size == kIndefiniteSize &&
                          !is_constrained_by_outer_fragmentation_context_);

  if (has_content_based_block_size) {
    column_size.block_size = ResolveColumnAutoBlockSize(
        column_size, row_offset, available_outer_space, next_column_token,
        balance_columns);
  } else if (available_outer_space != kIndefiniteSize) {
    // Finally, resolve any remaining auto block-size, and make sure that we
    // don't take up more space than there's room for in the outer fragmentation
    // context.
    if (column_size.block_size > available_outer_space ||
        column_size.block_size == kIndefiniteSize) {
      // If the block-size of the inner multicol is unconstrained, we'll let the
      // outer fragmentainer context constrain it. However, if the inner
      // multicol only has content for one column (in the current row), and only
      // fills it partially, we need to shrink its block-size, to make room for
      // any content that follows the inner multicol, rather than eating the
      // entire fragmentainer.
      if (column_size.block_size == kIndefiniteSize)
        shrink_to_fit_column_block_size = true;
      column_size.block_size = available_outer_space;
    }
  }

  DCHECK_GE(column_size.block_size, LayoutUnit());

  // New column fragments won't be added to the fragment builder right away,
  // since we may need to delete them and try again with a different block-size
  // (colum balancing). Keep them in this list, and add them to the fragment
  // builder when we have the final column fragments. Or clear the list and
  // retry otherwise.
  HeapVector<ResultWithOffset, 16> new_columns;

  bool is_empty_spanner_parent = false;

  // Avoid suboptimal breaks (and overflow from monolithic content) inside a
  // nested multicol container if we can. If this multicol container may
  // continue in the next outer fragmentainer, and we have already made some
  // progress (either inside the multicol container itself (spanners or
  // block-start border/padding), or in the outer fragmentation context), it may
  // be better to push some of the content to the next outer fragmentainer and
  // retry there.
  bool may_have_more_space_in_next_outer_fragmentainer = false;
  if (may_resume_in_next_outer_fragmentainer &&
      !IsBreakInside(GetBreakToken())) {
    if (intrinsic_block_size_) {
      may_have_more_space_in_next_outer_fragmentainer = true;
    } else if (!GetConstraintSpace().IsAtFragmentainerStart()) {
      may_have_more_space_in_next_outer_fragmentainer = true;
    }
  }

  const LayoutResult* result = nullptr;
  std::optional<BreakAppeal> min_break_appeal;
  LayoutUnit intrinsic_block_size_contribution;

  do {
    const BlockBreakToken* column_break_token = next_column_token;
    bool has_violating_break = false;
    bool has_oof_fragmentainer_descendants = false;

    LayoutUnit column_inline_offset(BorderScrollbarPadding().inline_start);
    int actual_column_count = 0;
    int forced_break_count = 0;

    // Each column should calculate their own minimal space shortage. Find the
    // lowest value of those. This will serve as the column stretch amount, if
    // we determine that stretching them is necessary and possible (column
    // balancing).
    LayoutUnit minimal_space_shortage = kIndefiniteSize;

    min_break_appeal = std::nullopt;
    intrinsic_block_size_contribution = LayoutUnit();

    do {
      // Lay out one column. Each column will become a fragment.
      ConstraintSpace child_space = CreateConstraintSpaceForFragmentainer(
          GetConstraintSpace(), kFragmentColumn, column_size,
          ColumnPercentageResolutionSize(), balance_columns,
          min_break_appeal.value_or(kBreakAppealLastResort));

      FragmentGeometry fragment_geometry = CalculateInitialFragmentGeometry(
          child_space, Node(), GetBreakToken());

      LayoutAlgorithmParams params(Node(), fragment_geometry, child_space,
                                   column_break_token);
      params.column_spanner_path = spanner_path_;

      BlockLayoutAlgorithm child_algorithm(params);
      child_algorithm.SetBoxType(PhysicalFragment::kColumnBox);
      result = child_algorithm.Layout();
      const auto& column =
          To<PhysicalBoxFragment>(result->GetPhysicalFragment());
      intrinsic_block_size_contribution = column_size.block_size;
      if (shrink_to_fit_column_block_size) {
        // Shrink-to-fit the row block-size contribution from the first column
        // if we're nested inside another fragmentation context. The column
        // block-size that we use in auto-filled (non-balanced) inner multicol
        // containers with unconstrained block-size is set to the available
        // block-size in the outer fragmentation context. If we end up with just
        // one inner column in this row, we should shrink the inner multicol
        // container fragment, so that it doesn't take up the entire outer
        // fragmentainer needlessly. So clamp it to the total block-size of the
        // contents in the column (including overflow).
        //
        // TODO(layout-dev): It would be slightly nicer if we actually shrunk
        // the block-size of the column fragment (in
        // FinishFragmentationForFragmentainer()) instead of just cropping the
        // block-size of the multicol container here, but that would cause
```