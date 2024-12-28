Response:
The user wants to understand the functionality of the `inline_cursor.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose:** Analyze the code to determine the main function of the `InlineCursor` class and related functionalities.
2. **Explain its relation to web technologies:** Determine how the `InlineCursor` interacts with JavaScript, HTML, and CSS, providing illustrative examples.
3. **Illustrate logic through examples:** Create hypothetical input and output scenarios to demonstrate the logic within the code.
4. **Highlight potential user/programmer errors:** Identify common mistakes that might occur when using or interacting with this code.
5. **Summarize the functionality:** Provide a concise overview of the file's purpose based on the analysis.
这是 `blink/renderer/core/layout/inline/inline_cursor.cc` 文件的前半部分代码，主要定义了 `InlineCursor` 类及其相关辅助函数。根据代码内容，可以归纳出以下功能：

**核心功能：遍历和定位内联布局树**

`InlineCursor` 的主要目的是在内联布局的物理片段（Physical Fragments）层级结构中进行遍历和定位。它允许在构成内联内容的各个元素（如行盒、文本、内联盒子等）之间移动，并获取这些元素的相关信息，例如位置、大小、包含的文本等。

**与 JavaScript, HTML, CSS 的关系：**

`InlineCursor`  直接操作的是 Blink 引擎内部的布局结构，这些结构是根据 HTML 结构和 CSS 样式计算得出的。因此，`InlineCursor` 的功能与这三者都有密切关系：

* **HTML:** `InlineCursor` 遍历的元素对应于 HTML 标签在渲染树中的表示。例如，HTML 中的 `<span>`, `<b>`, `<br>` 等标签都会在内联布局中生成相应的片段项。
    * **示例:**  如果 HTML 是 `<div><span>Hello</span> <b>World</b></div>`，`InlineCursor` 可以遍历到包含 "Hello" 的文本片段，包含 "World" 的文本片段，以及包含 `<b>` 标签的内联盒子片段。

* **CSS:** CSS 样式决定了内联元素的布局方式，例如 `display: inline`, `display: inline-block`，以及文本的字体、大小、行高等属性。这些样式会影响物理片段的生成和布局，从而影响 `InlineCursor` 的遍历结果和获取到的信息。
    * **示例:**  如果 CSS 设置了 `span { font-weight: bold; }`，那么 `InlineCursor` 遍历到 `<span>` 对应的片段时，可以获取到应用了粗体样式的字体信息。

* **JavaScript:** JavaScript 可以通过 DOM API 获取和操作 HTML 元素，并修改 CSS 样式。这些操作可能会导致布局的重新计算，从而影响 `InlineCursor` 的状态和遍历结果。Blink 引擎内部也会使用类似 `InlineCursor` 的机制来实现例如文本选择、光标定位等功能，这些功能最终会暴露给 JavaScript API。
    * **示例:**  JavaScript 可以使用 `document.getSelection()` 获取用户选择的文本范围。Blink 内部可能会使用 `InlineCursor` 来定位选择的起始和结束位置。

**逻辑推理示例：**

假设我们有以下简单的 HTML 和 CSS：

```html
<p>This is <span>some</span> text.</p>
```

```css
p { line-height: 20px; }
span { color: blue; }
```

**假设输入：** 一个 `InlineCursor` 对象 `cursor` 已经定位到包含 "some" 文本的片段上。

**方法调用：** `cursor.CurrentLocalRect(0, 4)` （获取 "some" 前 4 个字符的局部矩形）

**预期输出：** 返回一个 `PhysicalRect` 对象，表示 "some" 这四个字符在其父容器片段中的局部坐标和大小。这个矩形的位置会受到 `<p>` 元素的 `line-height` 和 `<span>` 元素的颜色样式的影响（尽管颜色不直接影响位置和大小，但样式会影响布局）。

**用户或编程常见的使用错误：**

1. **在布局无效时使用 `InlineCursor`：** 如果在布局尚未完成或布局信息过时的情况下使用 `InlineCursor`，可能会得到不准确或无效的结果，甚至导致崩溃。
    * **示例：** 在 JavaScript 代码中，立即在修改了某个元素的样式后就尝试使用与该元素相关的 `InlineCursor` 操作，可能会出错，应该等待布局更新完成后再进行操作。

2. **错误地移动 `InlineCursor`：**  不理解 `MoveToNext()`, `MoveToPrevious()`, `MoveToFirstChild()`, `MoveToLastChild()` 等方法的行为，导致 `InlineCursor` 指向错误的位置。
    * **示例：**  期望 `MoveToNext()` 移动到下一个兄弟节点，但实际上在内联布局中，下一个“兄弟”节点可能在物理结构上并不相邻，需要理解内联布局的扁平化结构。

3. **假设内联布局的连续性：**  内联布局可能因为换行、浮动等因素而断开，不能简单地假设一个文本节点的所有部分都在同一个物理片段中。
    * **示例：**  一个很长的单词可能会被分成多行显示，`InlineCursor` 需要跨越不同的行盒才能遍历到整个单词。

**功能归纳（第1部分）：**

`blink/renderer/core/layout/inline/inline_cursor.cc` 文件（第一部分）主要定义了 `InlineCursor` 类，它提供了一种在 Blink 引擎的内联布局物理片段层级结构中进行高效遍历和定位的机制。这个类可以访问内联元素的布局信息，例如位置、大小、文本内容等，并为实现诸如文本选择、光标定位等更高级的功能奠定了基础。它与 HTML 的结构、CSS 的样式以及 JavaScript 的动态操作都有着紧密的联系。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_cursor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"

#include "base/containers/adapters.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_items.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_span.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"

namespace blink {
class HTMLBRElement;

namespace {

bool IsBidiControl(StringView string) {
  return string.length() == 1 && Character::IsBidiControl(string[0]);
}

LogicalRect ExpandedSelectionRectForSoftLineBreakIfNeeded(
    const LogicalRect& rect,
    const InlineCursor& cursor,
    const LayoutSelectionStatus& selection_status) {
  // Expand paint rect if selection covers multiple lines and
  // this fragment is at the end of line.
  if (selection_status.line_break == SelectSoftLineBreak::kNotSelected)
    return rect;
  const LayoutBlockFlow* const layout_block_flow = cursor.GetLayoutBlockFlow();
  if (layout_block_flow && layout_block_flow->ShouldTruncateOverflowingText())
    return rect;
  // Copy from InlineTextBoxPainter::PaintSelection.
  const LayoutUnit space_width(cursor.Current().Style().GetFont().SpaceWidth());
  return {rect.offset,
          {rect.size.inline_size + space_width, rect.size.block_size}};
}

// Expands selection height so that the selection rect fills entire line.
LogicalRect ExpandSelectionRectToLineHeight(
    const LogicalRect& rect,
    const LogicalRect& line_logical_rect) {
  // Unite the rect only in the block direction.
  const LayoutUnit selection_top =
      std::min(rect.offset.block_offset, line_logical_rect.offset.block_offset);
  const LayoutUnit selection_bottom =
      std::max(rect.BlockEndOffset(), line_logical_rect.BlockEndOffset());
  return {{rect.offset.inline_offset, selection_top},
          {rect.size.inline_size, selection_bottom - selection_top}};
}

LogicalRect ExpandSelectionRectToLineHeight(const LogicalRect& rect,
                                            const InlineCursor& cursor) {
  InlineCursor line(cursor);
  line.MoveToContainingLine();
  const PhysicalRect line_physical_rect(
      line.Current().OffsetInContainerFragment() -
          cursor.Current().OffsetInContainerFragment(),
      line.Current().Size());
  return ExpandSelectionRectToLineHeight(
      rect, cursor.Current().ConvertChildToLogical(line_physical_rect));
}

bool IsLastBRInPage(const LayoutObject& layout_object) {
  return layout_object.IsBR() && !layout_object.NextInPreOrder();
}

bool ShouldIgnoreForPositionForPoint(const FragmentItem& item) {
  switch (item.Type()) {
    case FragmentItem::kBox:
      if (auto* box_fragment = item.BoxFragment()) {
        if (box_fragment->IsInlineBox()) {
          // We ignore inline box to avoid to call |PositionForPointInChild()|
          // with empty inline box, e.g. <div>ab<b></b></div>.
          // // All/LayoutViewHitTestTest.EmptySpan needs this.
          return true;
        }
        if (box_fragment->IsBlockInInline()) {
          // "label-contains-other-interactive-content.html" reaches here.
          return false;
        }
        // Skip pseudo element ::before/::after
        // All/LayoutViewHitTestTest.PseudoElementAfter* needs this.
        return !item.GetLayoutObject()->NonPseudoNode();
      }
      // Skip virtually "culled" inline box, e.g. <span>foo</span>
      // "editing/selection/shift-click.html" reaches here.
      DCHECK(item.GetLayoutObject()->IsLayoutInline()) << item;
      return true;
    case FragmentItem::kGeneratedText:
      return true;
    case FragmentItem::kText:
      if (item.IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
        // See http://crbug.com/1217079
        NOTREACHED() << item;
      }
      // Returns true when |item.GetLayoutObject().IsStyleGenerated()|.
      // All/LayoutViewHitTestTest.PseudoElementAfter* needs this.
      return item.IsGeneratedText();
    case FragmentItem::kLine:
      return true;
    case FragmentItem::kInvalid:
      NOTREACHED();
  }
  return false;
}

bool ShouldIgnoreForPositionForPoint(const InlineCursor& line) {
  if (line.CurrentItem()->Type() != FragmentItem::kLine) {
    return false;
  }
  for (auto cursor = line.CursorForDescendants(); cursor; cursor.MoveToNext()) {
    if (cursor.CurrentItem()->IsBlockInInline()) {
      // We should enter block-in-inline. Following tests require this:
      //  * editing/pasteboard/paste-sanitize-crash-2.html
      //  * editing/selection/click-after-nested-block.html
      return false;
    }
    // See also |InlineCursor::TryMoveToFirstInlineLeafChild()|.
    if (cursor.Current().IsInlineLeaf())
      return false;
  }
  // There are no block-in-inline and inline leaf.
  // Note: editing/selection/last-empty-inline.html requires this to skip
  // empty <span> with padding.
  return true;
}

}  // namespace

inline void InlineCursor::MoveToItem(const ItemsSpan::iterator& iter) {
  DCHECK(HasRoot());
  DCHECK(iter >= items_.begin() && iter <= items_.end());
  if (iter != items_.end()) {
    current_.Set(iter);
    return;
  }
  MakeNull();
}

void InlineCursor::SetRoot(const PhysicalBoxFragment& box_fragment,
                           const FragmentItems& fragment_items,
                           ItemsSpan items) {
  DCHECK_EQ(box_fragment.Items(), &fragment_items);
  DCHECK(items.data() || !items.size());
  root_box_fragment_ = &box_fragment;
  fragment_items_ = &fragment_items;
  items_ = items;
  DCHECK(fragment_items_->IsSubSpan(items_));
  MoveToItem(items_.begin());
}

void InlineCursor::SetRoot(const PhysicalBoxFragment& box_fragment,
                           const FragmentItems& items) {
  SetRoot(box_fragment, items, items.Items());
}

bool InlineCursor::TrySetRootFragmentItems() {
  DCHECK(root_block_flow_);
  DCHECK(!fragment_items_ || fragment_items_->Equals(items_));
  if (!root_block_flow_->MayHaveFragmentItems()) [[unlikely]] {
#if EXPENSIVE_DCHECKS_ARE_ON()
    DCHECK(!root_block_flow_->PhysicalFragments().SlowHasFragmentItems());
#endif
    fragment_index_ = max_fragment_index_ + 1;
    return false;
  }
  for (; fragment_index_ <= max_fragment_index_; IncrementFragmentIndex()) {
    const PhysicalBoxFragment* fragment =
        root_block_flow_->GetPhysicalFragment(fragment_index_);
    DCHECK(fragment);
    if (const FragmentItems* items = fragment->Items()) {
      SetRoot(*fragment, *items);
      return true;
    }
  }
  return false;
}

void InlineCursor::SetRoot(const LayoutBlockFlow& block_flow) {
  DCHECK(&block_flow);
  DCHECK(!HasRoot());

  if (const wtf_size_t fragment_count = block_flow.PhysicalFragmentCount()) {
    root_block_flow_ = &block_flow;
    max_fragment_index_ = fragment_count - 1;
    ResetFragmentIndex();
    if (TrySetRootFragmentItems())
      return;
  }

  // We reach here in case of |ScrollANchor::NotifyBeforeLayout()| via
  // |LayoutText::PhysicalLinesBoundingBox()|
  // See external/wpt/css/css-scroll-anchoring/wrapped-text.html
}

InlineCursor::InlineCursor(const LayoutBlockFlow& block_flow) {
  SetRoot(block_flow);
}

InlineCursor::InlineCursor(const PhysicalBoxFragment& box_fragment,
                           const FragmentItems& fragment_items,
                           ItemsSpan items) {
  SetRoot(box_fragment, fragment_items, items);
}

InlineCursor::InlineCursor(const PhysicalBoxFragment& box_fragment,
                           const FragmentItems& items) {
  SetRoot(box_fragment, items);
}

InlineCursor::InlineCursor(const PhysicalBoxFragment& box_fragment) {
  if (const FragmentItems* items = box_fragment.Items()) {
    SetRoot(box_fragment, *items);
  }
}

InlineCursor::InlineCursor(const InlineBackwardCursor& backward_cursor)
    : InlineCursor(backward_cursor.cursor_) {
  MoveTo(backward_cursor.Current());
}

bool InlineCursor::operator==(const InlineCursor& other) const {
  if (current_.item_ != other.current_.item_)
    return false;
  DCHECK_EQ(items_.data(), other.items_.data());
  DCHECK_EQ(items_.size(), other.items_.size());
  DCHECK_EQ(fragment_items_, other.fragment_items_);
  DCHECK(current_.item_iter_ == other.current_.item_iter_);
  return true;
}

const LayoutBlockFlow* InlineCursor::GetLayoutBlockFlow() const {
  DCHECK_EQ(HasRoot(), !!root_box_fragment_);
  if (root_box_fragment_) {
    const LayoutObject* layout_object =
        root_box_fragment_->GetSelfOrContainerLayoutObject();
    DCHECK(layout_object);
    DCHECK(!layout_object->IsLayoutFlowThread());
    return To<LayoutBlockFlow>(layout_object);
  }
  NOTREACHED();
}

bool InlineCursorPosition::HasChildren() const {
  if (item_)
    return item_->HasChildren();
  NOTREACHED();
}

InlineCursor InlineCursor::CursorForDescendants() const {
  if (current_.item_) {
    unsigned descendants_count = current_.item_->DescendantsCount();
    if (descendants_count > 1) {
      DCHECK(root_box_fragment_);
      DCHECK(fragment_items_);
      return InlineCursor(
          *root_box_fragment_, *fragment_items_,
          ItemsSpan(&*(current_.item_iter_ + 1), descendants_count - 1));
    }
    return InlineCursor();
  }
  NOTREACHED();
}

InlineCursor InlineCursor::CursorForMovingAcrossFragmentainer() const {
  DCHECK(IsNotNull());
  if (IsBlockFragmented())
    return *this;
  InlineCursor cursor(*GetLayoutBlockFlow());
  const auto& item = *CurrentItem();
  while (cursor && !cursor.TryMoveTo(item))
    cursor.MoveToNextFragmentainer();
  DCHECK(cursor) << *this;
  return cursor;
}

void InlineCursor::ExpandRootToContainingBlock() {
  if (fragment_items_) {
    const unsigned index_diff = base::checked_cast<unsigned>(
        items_.data() - fragment_items_->Items().data());
    DCHECK_LT(index_diff, fragment_items_->Items().size());
    const unsigned item_index =
        base::checked_cast<unsigned>(current_.item_iter_ - items_.begin());
    items_ = fragment_items_->Items();
    // Update the iterator to the one for the new span.
    MoveToItem(items_.begin() + item_index + index_diff);
    return;
  }
  NOTREACHED();
}

bool InlineCursorPosition::HasSoftWrapToNextLine() const {
  DCHECK(IsLineBox());
  const InlineBreakToken* break_token = GetInlineBreakToken();
  return break_token && !break_token->IsForcedBreak();
}

bool InlineCursorPosition::IsInlineLeaf() const {
  if (IsHiddenForPaint()) {
    return false;
  }
  if (IsText()) {
    return !IsLayoutGeneratedText();
  }
  if (IsAtomicInline()) {
    return !IsListMarker();
  }
  return false;
}

bool InlineCursorPosition::IsPartOfCulledInlineBox(
    const LayoutInline& layout_inline) const {
  DCHECK(!layout_inline.ShouldCreateBoxFragment());
  DCHECK(*this);
  const LayoutObject* const layout_object = GetLayoutObject();
  // We use |IsInline()| to exclude floating and out-of-flow objects.
  if (!layout_object || layout_object->IsAtomicInlineLevel())
    return false;
  // When |Current()| is block-in-inline, e.g. <span><div>foo</div></span>, it
  // should be part of culled inline box[1].
  // [1]
  // external/wpt/shadow-dom/DocumentOrShadowRoot-prototype-elementFromPoint.html
  if (!layout_object->IsInline() && !layout_object->IsBlockInInline())
    return false;
  DCHECK(!layout_object->IsFloatingOrOutOfFlowPositioned());
  DCHECK(!BoxFragment() || !BoxFragment()->IsFormattingContextRoot());
  for (const LayoutObject* parent = layout_object->Parent(); parent;
       parent = parent->Parent()) {
    // Children of culled inline should be included.
    if (parent == &layout_inline)
      return true;
    // Grand children should be included only if children are also culled.
    if (const auto* parent_layout_inline = DynamicTo<LayoutInline>(parent)) {
      if (!parent_layout_inline->ShouldCreateBoxFragment())
        continue;
    }
    return false;
  }
  return false;
}

bool InlineCursor::IsLastLineInInlineBlock() const {
  DCHECK(Current().IsLineBox());
  if (!GetLayoutBlockFlow()->IsAtomicInlineLevel())
    return false;
  InlineCursor next_sibling(*this);
  for (;;) {
    next_sibling.MoveToNextSkippingChildren();
    if (!next_sibling)
      return true;
    if (next_sibling.Current().IsLineBox())
      return false;
    // There maybe other top-level objects such as floats, OOF, or list-markers.
  }
}

bool InlineCursor::IsBeforeSoftLineBreak() const {
  if (Current().IsLineBreak())
    return false;
  // Inline block is not be container line box.
  // See paint/selection/text-selection-inline-block.html.
  InlineCursor line(*this);
  line.MoveToContainingLine();
  if (line.IsLastLineInInlineBlock()) {
    // We don't paint a line break the end of inline-block
    // because if an inline-block is at the middle of line, we should not paint
    // a line break.
    // Old layout paints line break if the inline-block is at the end of line,
    // but since its complex to determine if the inline-block is at the end of
    // line on NG, we just cancels block-end line break painting for any
    // inline-block.
    return false;
  }
  InlineCursor last_leaf(line);
  last_leaf.MoveToLastLogicalLeaf();
  if (last_leaf != *this)
    return false;
  // Even If |fragment| is before linebreak, if its direction differs to line
  // direction, we don't paint line break. See
  // paint/selection/text-selection-newline-mixed-ltr-rtl.html.
  return line.Current().BaseDirection() == Current().ResolvedDirection();
}

bool InlineCursorPosition::CanHaveChildren() const {
  if (item_) {
    return item_->Type() == FragmentItem::kLine ||
           (item_->Type() == FragmentItem::kBox && !item_->IsAtomicInline());
  }
  NOTREACHED();
}

TextDirection InlineCursorPosition::BaseDirection() const {
  DCHECK(IsLineBox());
  if (item_)
    return item_->BaseDirection();
  NOTREACHED();
}

UBiDiLevel InlineCursorPosition::BidiLevel() const {
  if (IsText()) {
    if (IsLayoutGeneratedText()) {
      // TODO(yosin): Until we have clients, we don't support bidi-level for
      // ellipsis and soft hyphens. crbug.com/1423660
      return 0;
    }
    const auto& layout_text = *To<LayoutText>(GetLayoutObject());
    DCHECK(!layout_text.NeedsLayout()) << this;
    const auto* const items = layout_text.GetInlineItems();
    if (!items || items->size() == 0) {
      // In case of <br>, <wbr>, text-combine-upright, etc.
      return 0;
    }
    const TextOffsetRange offset = TextOffset();
    auto* const item =
        base::ranges::find_if(*items, [offset](const InlineItem& item) {
          return item.StartOffset() <= offset.start &&
                 item.EndOffset() >= offset.end;
        });
    CHECK(item != items->end(), base::NotFatalUntil::M130) << this;
    return item->BidiLevel();
  }

  if (IsAtomicInline()) {
    DCHECK(GetLayoutObject()->FragmentItemsContainer());
    const LayoutBlockFlow& block_flow =
        *GetLayoutObject()->FragmentItemsContainer();
    const auto& items =
        block_flow.GetInlineNodeData()->ItemsData(UsesFirstLineStyle()).items;
    const auto item = base::ranges::find(items, GetLayoutObject(),
                                         &InlineItem::GetLayoutObject);
    CHECK(item != items.end(), base::NotFatalUntil::M130) << this;
    return item->BidiLevel();
  }

  NOTREACHED();
}

const DisplayItemClient* InlineCursorPosition::GetSelectionDisplayItemClient()
    const {
  if (const auto* client = GetLayoutObject()->GetSelectionDisplayItemClient())
    return client;
  return GetDisplayItemClient();
}

const Node* InlineCursorPosition::GetNode() const {
  if (const LayoutObject* layout_object = GetLayoutObject())
    return layout_object->GetNode();
  return nullptr;
}

gfx::RectF InlineCursorPosition::ObjectBoundingBox(
    const InlineCursor& cursor) const {
  return item_->ObjectBoundingBox(cursor.Items());
}

void InlineCursorPosition::RecalcInkOverflow(
    const InlineCursor& cursor,
    InlinePaintContext* inline_context) const {
  DCHECK(item_);
  DCHECK_EQ(item_, cursor.Current().Item());
  PhysicalRect self_and_contents_rect;
  item_->GetMutableForPainting().RecalcInkOverflow(cursor, inline_context,
                                                   &self_and_contents_rect);
}

StringView InlineCursorPosition::Text(const InlineCursor& cursor) const {
  DCHECK(IsText());
  cursor.CheckValid(*this);
  if (item_)
    return item_->Text(cursor.Items());
  NOTREACHED();
}

PhysicalRect InlineCursor::CurrentLocalRect(unsigned start_offset,
                                            unsigned end_offset) const {
  DCHECK(Current().IsText());
  if (current_.item_) {
    return current_.item_->LocalRect(current_.item_->Text(*fragment_items_),
                                     start_offset, end_offset);
  }
  NOTREACHED();
}

PhysicalRect InlineCursor::CurrentLocalSelectionRectForText(
    const LayoutSelectionStatus& selection_status) const {
  const PhysicalRect selection_rect =
      CurrentLocalRect(selection_status.start, selection_status.end);
  LogicalRect logical_rect = Current().ConvertChildToLogical(selection_rect);
  if (Current()->IsSvgText()) {
    return Current().ConvertChildToPhysical(logical_rect);
  }
  // Let LocalRect for line break have a space width to paint line break
  // when it is only character in a line or only selected in a line.
  if (selection_status.start != selection_status.end &&
      Current().IsLineBreak() &&
      // This is for old compatible that old doesn't paint last br in a page.
      !IsLastBRInPage(*Current().GetLayoutObject())) {
    logical_rect.size.inline_size =
        LayoutUnit(Current().Style().GetFont().SpaceWidth());
  }
  const LogicalRect line_break_extended_rect =
      Current().IsLineBreak() ? logical_rect
                              : ExpandedSelectionRectForSoftLineBreakIfNeeded(
                                    logical_rect, *this, selection_status);
  const LogicalRect line_height_expanded_rect =
      ExpandSelectionRectToLineHeight(line_break_extended_rect, *this);
  const PhysicalRect physical_rect =
      Current().ConvertChildToPhysical(line_height_expanded_rect);
  return physical_rect;
}

PhysicalRect InlineCursor::CurrentLocalSelectionRectForReplaced() const {
  DCHECK(Current().GetLayoutObject()->IsLayoutReplaced());
  const PhysicalRect selection_rect = PhysicalRect({}, Current().Size());
  LogicalRect logical_rect = Current().ConvertChildToLogical(selection_rect);
  const LogicalRect line_height_expanded_rect =
      ExpandSelectionRectToLineHeight(logical_rect, *this);
  const PhysicalRect physical_rect =
      Current().ConvertChildToPhysical(line_height_expanded_rect);
  return physical_rect;
}

PhysicalRect InlineCursor::CurrentRectInBlockFlow() const {
  PhysicalRect rect = Current().RectInContainerFragment();
  // We'll now convert the offset from being relative to the containing fragment
  // to being relative to the containing LayoutBlockFlow. For writing modes that
  // don't flip the block direction, this is easy: just add the block-size
  // consumed in previous fragments.
  auto writing_direction = ContainerFragment().Style().GetWritingDirection();
  switch (writing_direction.GetWritingMode()) {
    case WritingMode::kHorizontalTb:
      rect.offset.top += previously_consumed_block_size_;
      break;
    case WritingMode::kSidewaysLr:
    case WritingMode::kVerticalLr:
      rect.offset.left += previously_consumed_block_size_;
      break;
    case WritingMode::kSidewaysRl:
    case WritingMode::kVerticalRl: {
      // For vertical-rl writing-mode it's a bit more complicated. We need to
      // convert to logical coordinates in the containing box fragment, in order
      // to add the consumed block-size to make it relative to the
      // LayoutBlockFlow ("flow thread coordinate space"), and then we convert
      // back to physical coordinates.
      const LayoutBlock* containing_block =
          Current().GetLayoutObject()->ContainingBlock();
      DCHECK_EQ(containing_block->StyleRef().GetWritingDirection(),
                ContainerFragment().Style().GetWritingDirection());
      LogicalOffset logical_offset = rect.offset.ConvertToLogical(
          writing_direction, ContainerFragment().Size(), rect.size);
      LogicalOffset logical_offset_in_flow_thread(
          logical_offset.inline_offset,
          logical_offset.block_offset + previously_consumed_block_size_);
      rect.offset = logical_offset_in_flow_thread.ConvertToPhysical(
          writing_direction, PhysicalSize(containing_block->Size()), rect.size);
      break;
    }
  };
  return rect;
}

LayoutUnit InlineCursor::CaretInlinePositionForOffset(unsigned offset) const {
  DCHECK(Current().IsText());
  if (current_.item_) {
    return current_.item_->CaretInlinePositionForOffset(
        current_.item_->Text(*fragment_items_), offset);
  }
  NOTREACHED();
}

LogicalRect InlineCursorPosition::ConvertChildToLogical(
    const PhysicalRect& physical_rect) const {
  return WritingModeConverter(
             {Style().GetWritingMode(), ResolvedOrBaseDirection()}, Size())
      .ToLogical(physical_rect);
}

PhysicalRect InlineCursorPosition::ConvertChildToPhysical(
    const LogicalRect& logical_rect) const {
  return WritingModeConverter(
             {Style().GetWritingMode(), ResolvedOrBaseDirection()}, Size())
      .ToPhysical(logical_rect);
}

PositionWithAffinity InlineCursor::PositionForPointInInlineFormattingContext(
    const PhysicalOffset& point,
    const PhysicalBoxFragment& container) {
  DCHECK(HasRoot());
  const auto writing_direction = container.Style().GetWritingDirection();
  const PhysicalSize& container_size = container.Size();
  const LayoutUnit point_block_offset =
      point
          .ConvertToLogical(writing_direction, container_size,
                            // |point| is actually a pixel with size 1x1.
                            PhysicalSize(LayoutUnit(1), LayoutUnit(1)))
          .block_offset;

  // Stores the closest line box child after |point| in the block direction.
  // Used if we can't find any child |point| falls in to resolve the position.
  InlineCursorPosition closest_line_after;
  LayoutUnit closest_line_after_block_offset = LayoutUnit::Min();

  // Stores the closest line box child before |point| in the block direction.
  // Used if we can't find any child |point| falls in to resolve the position.
  InlineCursorPosition closest_line_before;
  LayoutUnit closest_line_before_block_offset = LayoutUnit::Max();

  while (*this) {
    const FragmentItem* child_item = CurrentItem();
    DCHECK(child_item);
    if (child_item->Type() == FragmentItem::kLine) {
      if (ShouldIgnoreForPositionForPoint(*this)) {
        MoveToNextSkippingChildren();
        continue;
      }
      // Try to resolve if |point| falls in a line box in block direction.
      const LayoutUnit child_block_offset =
          child_item->OffsetInContainerFragment()
              .ConvertToLogical(writing_direction, container_size,
                                child_item->Size())
              .block_offset;
      if (point_block_offset < child_block_offset) {
        if (child_block_offset < closest_line_before_block_offset) {
          closest_line_before_block_offset = child_block_offset;
          closest_line_before = Current();
        }
        MoveToNextSkippingChildren();
        continue;
      }

      // Hitting on line bottom doesn't count, to match legacy behavior.
      const LayoutUnit child_block_end_offset =
          child_block_offset +
          child_item->Size()
              .ConvertToLogical(writing_direction.GetWritingMode())
              .block_size;
      if (point_block_offset >= child_block_end_offset) {
        if (child_block_end_offset > closest_line_after_block_offset) {
          closest_line_after_block_offset = child_block_end_offset;
          closest_line_after = Current();
        }
        MoveToNextSkippingChildren();
        continue;
      }

      if (const PositionWithAffinity child_position =
              PositionForPointInInlineBox(point))
        return child_position;
      MoveToNextSkippingChildren();
      continue;
    }
    DCHECK_NE(child_item->Type(), FragmentItem::kText);
    MoveToNext();
  }

  // At here, |point| is not inside any line in |this|:
  //   |closest_line_before|
  //   |point|
  //   |closest_line_after|
  if (closest_line_before) {
    MoveTo(closest_line_before);
    // Note: |move_caret_to_boundary| is true for Mac and Unix.
    const bool move_caret_to_boundary =
        To<LayoutBlockFlow>(Current().GetLayoutObject())
            ->ShouldMoveCaretToHorizontalBoundaryWhenPastTopOrBottom();
    if (move_caret_to_boundary) {
      // Tests[1-3] reach here.
      // [1] editing/selection/click-in-margins-inside-editable-div.html
      // [2] fast/writing-mode/flipped-blocks-hit-test-line-edges.html
      // [3] All/LayoutViewHitTestTest.HitTestHorizontal/4
      if (auto first_position = PositionForStartOfLine())
        return PositionWithAffinity(first_position.GetPosition());
    } else if (const PositionWithAffinity child_position =
                   PositionForPointInInlineBox(point))
      return child_position;
  }

  if (closest_line_after) {
    MoveTo(closest_line_after);
    // Note: |move_caret_to_boundary| is true for Mac and Unix.
    const bool move_caret_to_boundary =
        To<LayoutBlockFlow>(Current().GetLayoutObject())
            ->ShouldMoveCaretToHorizontalBoundaryWhenPastTopOrBottom();
    if (move_caret_to_boundary) {
      // Tests[1-3] reach here.
      // [1] editing/selection/click-in-margins-inside-editable-div.html
      // [2] fast/writing-mode/flipped-blocks-hit-test-line-edges.html
      // [3] All/LayoutViewHitTestTest.HitTestHorizontal/4
      if (auto last_position = PositionForEndOfLine())
        return PositionWithAffinity(last_position.GetPosition());
    } else if (const PositionWithAffinity child_position =
                   PositionForPointInInlineBox(point)) {
      // Test[1] reaches here.
      // [1] editing/selection/last-empty-inline.html
      return child_position;
    }
  }

  return PositionWithAffinity();
}

PositionWithAffinity InlineCursor::PositionForPointInInlineBox(
    const PhysicalOffset& point_in) const {
  const FragmentItem* container = CurrentItem();
  DCHECK(container);
  DCHECK(container->Type() == FragmentItem::kLine ||
         container->Type() == FragmentItem::kBox);
  const auto* const text_combine =
      DynamicTo<LayoutTextCombine>(container->GetLayoutObject());
  PhysicalOffset point;
  if (text_combine) [[unlikely]] {
    point = text_combine->AdjustOffsetForHitTest(point_in);
  } else {
    point = point_in;
  }
  const auto writing_direction = container->Style().GetWritingDirection();
  const PhysicalSize& container_size = container->Size();
  const LayoutUnit point_inline_offset =
      point
          .ConvertToLogical(writing_direction, container_size,
                            // |point| is actually a pixel with size 1x1.
                            PhysicalSize(LayoutUnit(1), LayoutUnit(1)))
          .inline_offset;

  // Stores the closest child before |point| in the inline direction. Used if we
  // can't find any child |point| falls in to resolve the position.
  InlineCursorPosition closest_child_before;
  LayoutUnit closest_child_before_inline_offset = LayoutUnit::Min();

  // Stores the closest child after |point| in the inline direction. Used if we
  // can't find any child |point| falls in to resolve the position.
  InlineCursorPosition closest_child_after;
  LayoutUnit closest_child_after_inline_offset = LayoutUnit::Max();

  InlineCursor descendants = CursorForDescendants();
  for (; descendants; descendants.MoveToNext()) {
    const FragmentItem* child_item = descendants.CurrentItem();
    DCHECK(child_item);
    if (ShouldIgnoreForPositionForPoint(*child_item))
      continue;
    const LayoutUnit child_inline_offset =
        child_item->OffsetInContainerFragment()
            .ConvertToLogical(writing_direction, container_size,
                              child_item->Size())
            .inline_offset;
    if (point_inline_offset < child_inline_offset) {
      if (child_item->IsFloating())
        continue;
      if (child_inline_offset < closest_child_after_inline_offset) {
        closest_child_after_inline_offset = child_inline_offset;
        closest_child_after = descendants.Current();
      }
      continue;
    }
    const LayoutUnit child_inline_end_offset =
        child_inline_offset +
        child_item->Size()
            .ConvertToLogical(writing_direction.GetWritingMode())
            .inline_size;
    if (point_inline_offset >= child_inline_end_offset) {
      if (child_item->IsFloating())
        continue;
      if (child_inline_end_offset > closest_child_before_inline_offset) {
        closest_child_before_inline_offset = child_inline_end_offset;
        closest_child_before = descendants.Current();
      }
      continue;
    }

    // |point_inline_offset| is in |child_item|.
    if (const PositionWithAffinity child_position =
            descendants.PositionForPointInChild(point))
      return child_position;
  }

  // Note: We don't snap a point before/after of "float" to "float",
  // |closest_child_after| and |closest_child_before| can not be a box for
  // "float".
  // Note: Float boxes are appeared in |FragmentItems| as DOM order, so,
  // "float:right" can be placed anywhere instead of at end of items.
  // See LayoutViewHitTest.Float{Left,Right}*
  if (closest_child_after) {
    descendants.MoveTo(closest_child_after);
    if (const PositionWithAffinity child_position =
            descendants.PositionForPointInChild(point))
      return child_position;
    if (closest_child_after->BoxFragment()) {
      DCHECK(!closest_child_after->IsFloating());
      // Hit test at left of "12"[1] and after "cd"[2] reache here.
      // "<span dir="rtl">12<b>&#x05E7;&#x05D0;43</b></span>ab"
      // [1] "editing/selection/caret-at-bidi-boundary.html"
      // [2] HitTestingTest.PseudoElementAfter
      if (const PositionWithAffinity child_position =
              descendants.PositionForPointInInlineBox(point))
        return child_position;
    }
  }

  if (closest_child_before) {
    descendants.MoveTo(closest_child_before);
    if (const PositionWithAffinity child_position =
            descendants.PositionForPointInChild(point))
      return child_position;
    if (closest_child_before->BoxFragment()) {
      DCHECK(!closest_child_before->IsFloating());
      // LayoutViewHitTest.HitTestHorizontal "Top-right corner (outside) of div"
      // reach here.
      if (const PositionWithAffinity child_position =
              descendants.PositionForPointInInlineBox(point))
        return child_position;
    }
  }

  return PositionWithAffinity();
}

PositionWithAffinity InlineCursor::PositionForPointInChild(
    const PhysicalOffset& point_in_container) const {
  DCHECK(CurrentItem());
  const FragmentItem& child_item = *CurrentItem();
  switch (child_item.Type()) {
    case FragmentItem::kText:
      return child_item.PositionForPointInText(
          point_in_container - child_item.OffsetInContainerFragment(), *this);
    case FragmentItem::kGeneratedText:
      break;
    case FragmentItem::kBox:
      if (const PhysicalBoxFragment* box_fragment = child_item.BoxFragment()) {
        if (!box_fragment->IsInlineBox()) {
          // In case of inline block with with block formatting context that
          // has block children[1].
          // Example: <b style="display:inline-block"><div>b</div></b>
          // [1] InlineCursorTest.PositionForPointInChildBlockChildren
          return child_item.GetLayoutObject()->PositionForPoint(
              point_in_container - child_item.OffsetInContainerFragment());
        }
      } else {
  
"""


```