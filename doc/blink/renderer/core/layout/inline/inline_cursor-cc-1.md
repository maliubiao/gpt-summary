Response:
The user wants a summary of the functionality of the `InlineCursor` class in the provided C++ code. I need to identify its purpose, how it relates to web technologies (JavaScript, HTML, CSS), provide examples of its logic with inputs and outputs, discuss common user/programming errors, and finally, give an overall summary.

**Plan:**

1. **Identify Core Functionality:** Analyze the methods of `InlineCursor` to understand its primary purpose. It seems to be a way to traverse and locate specific points within the inline layout of a web page.
2. **Relate to Web Technologies:** Explain how the concepts of inline layout, text nodes, and element positioning in HTML, CSS, and JavaScript relate to the actions performed by `InlineCursor`.
3. **Provide Logic Examples:** Choose a few representative methods and demonstrate their behavior with hypothetical input and expected output based on the code.
4. **Discuss Common Errors:** Think about potential mistakes developers might make when using or interacting with a class like `InlineCursor`.
5. **Summarize Functionality:**  Condense the findings into a concise description of the `InlineCursor`'s role.
这是 `blink/renderer/core/layout/inline/inline_cursor.cc` 文件的第二部分，延续了第一部分对 `InlineCursor` 类的功能描述。结合两部分的代码，我们可以归纳出 `InlineCursor` 类的主要功能如下：

**`InlineCursor` 类的主要功能归纳：**

`InlineCursor` 类是 Chromium Blink 引擎中用于在**内联布局**结构中进行**遍历和定位**的关键工具。它允许在由 `FragmentItem` 组成的链表中移动，这些 `FragmentItem` 代表了内联格式化上下文中布局对象的各个部分。

**核心功能点：**

1. **遍历内联布局结构:**
    *   提供了多种移动方法，允许在 `FragmentItem` 链表中向前、向后、移动到父节点、子节点、第一个/最后一个节点、特定类型的节点（如行框、叶子节点）等。
    *   支持跨越**片段容器 (Fragmentainer)** 进行遍历，这在内容被分割到多个页面或区域时非常重要。
    *   提供了用于跳过子节点的移动方法 (`MoveToNextSkippingChildren`)。

2. **定位到特定位置:**
    *   可以移动到与特定布局对象 (`LayoutObject`) 关联的第一个或下一个 `FragmentItem`。
    *   可以根据文本偏移量定位到文本节点内的精确位置 (`PositionForPointInText`)。
    *   可以定位到行的开始和结束位置 (`PositionForStartOfLine`, `PositionForEndOfLine`)。

3. **处理内联元素特性:**
    *   能够区分伪元素节点。
    *   能够处理被裁剪的内联元素 (`CulledInline`)，允许遍历构成被裁剪元素的 `FragmentItem`。
    *   能够识别和处理行分隔符 (`IsLineBreak`)。
    *   能够处理双向文本 (Bidi) 控制字符。

4. **与其他布局相关的概念集成:**
    *   与 `LayoutObject` 和 `FragmentItem` 类紧密关联，通过它们来访问和操作布局信息。
    *   能够识别和处理 `BlockInInline` 元素。

5. **辅助功能 (Accessibility) 相关:**
    *   某些移动方法（如 `MoveToNextInlineLeafOnLine`) 被提及与辅助功能需求有关。

6. **支持反向遍历:**
    *   提供了 `InlineBackwardCursor` 类，用于从后向前遍历内联布局结构。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`InlineCursor` 的功能直接服务于浏览器如何渲染和呈现 HTML 结构以及 CSS 样式。虽然 JavaScript 代码本身不直接操作 `InlineCursor`，但浏览器的渲染引擎会使用它来执行与布局相关的操作，这些操作最终会影响 JavaScript 可以查询和操作的 DOM 结构和几何属性。

*   **HTML:** `InlineCursor` 遍历的结构直接对应于 HTML 元素及其嵌套关系。例如，当 HTML 中有 `<p><span>text</span></p>` 时，`InlineCursor` 可以在 `<p>` 元素的行框内遍历到 `<span>` 元素的 `FragmentItem`，再到 `text` 节点的 `FragmentItem`。
*   **CSS:** CSS 的样式规则会影响内联元素的布局，例如 `display: inline`, `white-space`, `text-overflow` 等。`InlineCursor` 需要能够处理这些样式带来的布局变化。例如，`text-overflow: ellipsis` 会导致文本被裁剪，`InlineCursor` 提供了 `MoveToFirstForCulledInline` 和 `MoveToNextForCulledInline` 来处理这种情况。
*   **JavaScript:** JavaScript 可以通过 DOM API 获取元素的几何信息（例如 `getBoundingClientRect()`），或者操作文本选区 (Selection API)。这些 API 的底层实现会依赖于像 `InlineCursor` 这样的工具来定位和计算元素在页面上的位置。例如，当用户在网页上选择一段文本时，浏览器需要使用类似 `InlineCursor` 的机制来确定选区的起始和结束位置。

**逻辑推理的假设输入与输出：**

假设我们有一个简单的 HTML 结构：

```html
<p>This is <span>some</span> text.</p>
```

并且有一个 `InlineCursor` `cursor` 已经定位到 `<p>` 元素的行框 (Line Box)。

*   **假设输入:** `cursor` 当前指向 `<p>` 元素的 Line Box。
*   **调用:** `cursor.MoveToFirstLogicalLeaf()`
*   **输出:** `cursor` 将指向 "This is " 这个文本节点的 `FragmentItem`。这是因为在从左到右的语言中，这是行框内的第一个逻辑叶子节点。

*   **假设输入:** `cursor` 当前指向 "some" 这个 `<span>` 元素内的文本节点的 `FragmentItem`。
*   **调用:** `cursor.MoveToNextForSameLayoutObject()`
*   **输出:** 如果 "some" 这个文本节点被分割成多个 `FragmentItem`（由于换行或其他原因），`cursor` 将移动到表示 "some" 的下一个 `FragmentItem`。如果只有一个 `FragmentItem`，`cursor` 将变为 null。

*   **假设输入:** `cursor` 当前指向 `<p>` 元素的 Line Box。
*   **调用:** `cursor.PositionForEndOfLine()`
*   **输出:** 返回一个 `PositionWithAffinity` 对象，表示该行结束后的位置，通常是在 "." 之后。

**涉及用户或编程常见的使用错误举例说明：**

由于 `InlineCursor` 是 Blink 引擎内部使用的类，普通网页开发者不会直接使用它。然而，在 Blink 引擎的开发过程中，可能会出现以下使用错误：

1. **在没有 Root 的情况下调用需要 Root 的方法:**  许多 `InlineCursor` 的方法（例如移动方法）需要在初始化时设置 Root (`SetRoot`)。如果在没有 Root 的情况下调用这些方法，会导致程序崩溃或未定义行为。例如，如果在 `cursor` 没有 Root 的情况下调用 `cursor.MoveToNext()`，代码中会有 `DCHECK(HasRoot())` 检查。
2. **错误地假设遍历顺序:**  内联布局的遍历顺序可能受到双向文本的影响。错误地假设总是从左到右或从右到左遍历可能会导致逻辑错误。例如，在处理 RTL (Right-to-Left) 文本时，应该使用相应的逻辑来移动光标。
3. **忘记处理 `IsNull()` 情况:**  许多移动方法可能会导致 `InlineCursor` 变为 null，表示已经到达了布局结构的边界。没有正确检查 `IsNull()` 的情况可能会导致后续操作访问无效内存。
4. **在被裁剪的内联元素中遍历时未考虑特殊方法:**  对于设置了 `text-overflow: ellipsis` 的元素，直接使用通用的移动方法可能无法遍历到所有相关的 `FragmentItem`。开发者需要使用专门为被裁剪元素设计的方法 (`MoveToFirstForCulledInline`, `MoveToNextForCulledInline`)。

总而言之，`InlineCursor` 是 Blink 引擎中一个复杂但至关重要的类，它提供了在内联布局结构中精细化定位和遍历的能力，这对于文本渲染、光标定位、选区处理等核心浏览器功能至关重要。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/inline_cursor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// |LayoutInline| used to be culled.
      }
      DCHECK(child_item.GetLayoutObject()->IsLayoutInline()) << child_item;
      break;
    case FragmentItem::kLine:
    case FragmentItem::kInvalid:
      NOTREACHED();
  }
  return PositionWithAffinity();
}

PositionWithAffinity InlineCursor::PositionForPointInText(
    unsigned text_offset) const {
  DCHECK(Current().IsText()) << this;
  if (HasRoot())
    return Current()->PositionForPointInText(text_offset, *this);
  return PositionWithAffinity();
}

PositionWithAffinity InlineCursor::PositionForStartOfLine() const {
  DCHECK(Current().IsLineBox());
  InlineCursor first_leaf = CursorForDescendants();
  if (IsLtr(Current().BaseDirection()))
    first_leaf.MoveToFirstNonPseudoLeaf();
  else
    first_leaf.MoveToLastNonPseudoLeaf();
  if (!first_leaf)
    return PositionWithAffinity();
  const auto& layout_object = first_leaf.Current()->IsBlockInInline()
                                  ? first_leaf.Current()->BlockInInline()
                                  : *first_leaf.Current().GetLayoutObject();
  Node* const node = layout_object.NonPseudoNode();
  if (!node) {
    NOTREACHED() << "MoveToFirstLeaf returns invalid node: " << first_leaf;
  }
  if (!IsA<Text>(node))
    return PositionWithAffinity(Position::BeforeNode(*node));
  const unsigned text_offset =
      Current().BaseDirection() == first_leaf.Current().ResolvedDirection()
          ? first_leaf.Current().TextOffset().start
          : first_leaf.Current().TextOffset().end;
  return first_leaf.PositionForPointInText(text_offset);
}

PositionWithAffinity InlineCursor::PositionForEndOfLine() const {
  DCHECK(Current().IsLineBox());
  InlineCursor last_leaf = CursorForDescendants();
  if (IsLtr(Current().BaseDirection()))
    last_leaf.MoveToLastNonPseudoLeaf();
  else
    last_leaf.MoveToFirstNonPseudoLeaf();
  if (!last_leaf)
    return PositionWithAffinity();
  const auto& layout_object = last_leaf.Current()->IsBlockInInline()
                                  ? last_leaf.Current()->BlockInInline()
                                  : *last_leaf.Current().GetLayoutObject();
  Node* const node = layout_object.NonPseudoNode();
  if (!node) {
    NOTREACHED() << "MoveToLastLeaf returns invalid node: " << last_leaf;
  }
  if (IsA<HTMLBRElement>(node))
    return PositionWithAffinity(Position::BeforeNode(*node));
  if (!IsA<Text>(node))
    return PositionWithAffinity(Position::AfterNode(*node));
  const wtf_size_t text_offset = GetTextOffsetForEndOfLine(last_leaf);
  return last_leaf.PositionForPointInText(text_offset);
}

inline wtf_size_t InlineCursor::GetTextOffsetForEndOfLine(
    InlineCursor& last_leaf) const {
  wtf_size_t text_offset = last_leaf.Current().TextOffset().start;
  if (Current().BaseDirection() == last_leaf.Current().ResolvedDirection() &&
      !last_leaf.Current().IsLineBreak()) {
    text_offset = last_leaf.Current().TextOffset().end;
  }
  return text_offset;
}

void InlineCursor::MoveTo(const InlineCursorPosition& position) {
  CheckValid(position);
  current_ = position;
}

inline wtf_size_t InlineCursor::SpanBeginItemIndex() const {
  DCHECK(HasRoot());
  DCHECK(!items_.empty());
  DCHECK(fragment_items_->IsSubSpan(items_));
  const wtf_size_t delta = base::checked_cast<wtf_size_t>(
      items_.data() - fragment_items_->Items().data());
  DCHECK_LT(delta, fragment_items_->Items().size());
  return delta;
}

inline wtf_size_t InlineCursor::SpanIndexFromItemIndex(unsigned index) const {
  DCHECK(HasRoot());
  DCHECK(!items_.empty());
  DCHECK(fragment_items_->IsSubSpan(items_));
  if (items_.data() == fragment_items_->Items().data())
    return index;
  const wtf_size_t span_index = base::checked_cast<wtf_size_t>(
      fragment_items_->Items().data() - items_.data() + index);
  DCHECK_LT(span_index, items_.size());
  return span_index;
}

void InlineCursor::MoveTo(const FragmentItem& fragment_item) {
  if (TryMoveTo(fragment_item))
    return;
  NOTREACHED() << *this << " " << fragment_item;
}

bool InlineCursor::TryMoveTo(const FragmentItem& fragment_item) {
  DCHECK(HasRoot());
  // Note: We use address instead of iterator because we can't compare
  // iterators in different span. See |base::CheckedContiguousIterator<T>|.
  const ptrdiff_t index = &fragment_item - &*items_.begin();
  if (index < 0 || static_cast<size_t>(index) >= items_.size())
    return false;
  MoveToItem(items_.begin() + index);
  return true;
}

void InlineCursor::MoveTo(const InlineCursor& cursor) {
  if (cursor.current_.item_) {
    if (!fragment_items_)
      SetRoot(*cursor.root_box_fragment_, *cursor.fragment_items_);
    return MoveTo(*cursor.current_.item_);
  }
  *this = cursor;
}

void InlineCursor::MoveToParent() {
  wtf_size_t count = 0;
  if (!Current()) [[unlikely]] {
    return;
  }
  for (;;) {
    MoveToPrevious();
    if (!Current())
      return;
    ++count;
    if (Current()->DescendantsCount() > count)
      return;
  }
}

void InlineCursor::MoveToContainingLine() {
  DCHECK(!Current().IsLineBox());
  if (current_.item_) {
    while (current_.item_ && !Current().IsLineBox())
      MoveToPrevious();
    return;
  }
  NOTREACHED();
}

bool InlineCursor::IsAtFirst() const {
  if (const FragmentItem* item = Current().Item()) {
    return item == &items_.front();
  }
  return false;
}

void InlineCursor::MoveToFirst() {
  if (HasRoot()) {
    MoveToItem(items_.begin());
    return;
  }
  NOTREACHED();
}

void InlineCursor::MoveToFirstChild() {
  DCHECK(Current().CanHaveChildren());
  if (!TryMoveToFirstChild())
    MakeNull();
}

void InlineCursor::MoveToFirstLine() {
  if (HasRoot()) {
    auto iter =
        base::ranges::find(items_, FragmentItem::kLine, &FragmentItem::Type);
    if (iter != items_.end()) {
      MoveToItem(iter);
      return;
    }
    MakeNull();
    return;
  }
  NOTREACHED();
}

void InlineCursor::MoveToFirstLogicalLeaf() {
  DCHECK(Current().IsLineBox());
  // TODO(yosin): This isn't correct for mixed Bidi. Fix it. Besides, we
  // should compute and store it during layout.
  // TODO(yosin): We should check direction of each container instead of line
  // box.
  if (IsLtr(Current().Style().Direction())) {
    while (TryMoveToFirstChild())
      continue;
    return;
  }
  while (TryMoveToLastChild())
    continue;
}

void InlineCursor::MoveToFirstNonPseudoLeaf() {
  for (InlineCursor cursor = *this; cursor; cursor.MoveToNext()) {
    if (cursor.Current().IsLineBox())
      continue;
    if (cursor.Current()->IsBlockInInline()) {
      if (cursor.Current()->BlockInInline().NonPseudoNode()) {
        *this = cursor;
        return;
      }
      continue;
    }
    if (!cursor.Current().GetLayoutObject()->NonPseudoNode())
      continue;
    if (cursor.Current().IsText()) {
      // Note: We should not skip bidi control only text item to return
      // position after bibi control character, e.g.
      // <p dir=rtl>&#x202B;xyz ABC.&#x202C;</p>
      // See "editing/selection/home-end.html".
      DCHECK(!cursor.Current().IsLayoutGeneratedText()) << cursor;
      if (cursor.Current().IsLineBreak()) {
        // We ignore line break character, e.g. newline with white-space:pre,
        // like |MoveToLastNonPseudoLeaf()| as consistency.
        // See |ParameterizedVisibleUnitsLineTest.EndOfLineWithWhiteSpacePre|
        auto next = cursor;
        next.MoveToNext();
        if (next)
          continue;
      }
      *this = cursor;
      return;
    }
    if (cursor.Current().IsInlineLeaf()) {
      *this = cursor;
      return;
    }
  }
  MakeNull();
}

void InlineCursor::MoveToLastChild() {
  DCHECK(Current().CanHaveChildren());
  if (!TryMoveToLastChild())
    MakeNull();
}

void InlineCursor::MoveToLastLine() {
  DCHECK(HasRoot());
  auto iter = base::ranges::find(base::Reversed(items_), FragmentItem::kLine,
                                 &FragmentItem::Type);
  if (iter != items_.rend())
    MoveToItem(std::next(iter).base());
  else
    MakeNull();
}

void InlineCursor::MoveToLastLogicalLeaf() {
  DCHECK(Current().IsLineBox());
  // TODO(yosin): This isn't correct for mixed Bidi. Fix it. Besides, we
  // should compute and store it during layout.
  // TODO(yosin): We should check direction of each container instead of line
  // box.
  if (IsLtr(Current().Style().Direction())) {
    while (TryMoveToLastChild())
      continue;
    return;
  }
  while (TryMoveToFirstChild())
    continue;
}

void InlineCursor::MoveToLastNonPseudoLeaf() {
  // TODO(yosin): We should introduce |IsTruncated()| to avoid to use
  // |in_hidden_for_paint|. See also |LayoutText::GetTextBoxInfo()|.
  // When "text-overflow:ellipsis" specified, items usually are:
  //  [i+0] original non-truncated text (IsHiddenForPaint()=true)
  //  [i+1] truncated text
  //  [i+2] ellipsis (IsLayoutGeneratedText())
  // But this is also possible:
  //  [i+0] atomic inline box
  //  [i+1] ellipsis (IsLayoutGeneratedText())
  InlineCursor last_leaf;
  bool in_hidden_for_paint = false;
  for (InlineCursor cursor = *this; cursor; cursor.MoveToNext()) {
    if (cursor.Current().IsLineBox())
      continue;
    if (cursor.Current()->IsBlockInInline()) {
      if (cursor.Current()->BlockInInline().NonPseudoNode())
        last_leaf = cursor;
      continue;
    }
    if (!cursor.Current().GetLayoutObject()->NonPseudoNode())
      continue;
    if (cursor.Current().IsLineBreak() && last_leaf)
      break;
    if (cursor.Current().IsText()) {
      if (cursor.Current().IsLayoutGeneratedText()) {
        // |cursor| is at ellipsis.
        break;
      }
      if (in_hidden_for_paint && !cursor.Current().IsHiddenForPaint()) {
        // |cursor| is at truncated text.
        break;
      }
      in_hidden_for_paint = cursor.Current().IsHiddenForPaint();
      // Exclude bidi control only fragment, e.g.
      // <p dir=ltr>&#x202B;xyz ABC.&#x202C;</p> has
      //  [0] "\u202Bxyz "
      //  [1] "ABC"
      //  [2] "."
      //  [3] "\u202C"
      // See "editing/selection/home-end.html"
      if (IsBidiControl(cursor.Current().Text(cursor)))
        continue;
      last_leaf = cursor;
      continue;
    }
    if (cursor.Current().IsInlineLeaf())
      last_leaf = cursor;
  }
  *this = last_leaf;
}

void InlineCursor::MoveToNextInlineLeaf() {
  if (Current() && Current().IsInlineLeaf())
    MoveToNext();
  while (Current() && !Current().IsInlineLeaf())
    MoveToNext();
}

void InlineCursor::MoveToNextInlineLeafIgnoringLineBreak() {
  do {
    MoveToNextInlineLeaf();
  } while (Current() && Current().IsLineBreak());
}

void InlineCursor::MoveToNextInlineLeafOnLine() {
  MoveToLastForSameLayoutObject();
  if (IsNull())
    return;
  InlineCursor last_item = *this;
  MoveToContainingLine();
  InlineCursor cursor = CursorForDescendants();
  cursor.MoveTo(last_item);
  // Note: AX requires this for AccessibilityLayoutTest.NextOnLine.
  // If the cursor is on a container, move to the next content
  // not within the container.
  if (cursor.Current().IsInlineLeaf()) {
    cursor.MoveToNextInlineLeaf();
  } else {
    // Skip over descendants.
    cursor.MoveToNextSkippingChildren();  // Skip over descendants.
    // Ensure that a leaf is returned.
    if (cursor.Current() && !cursor.Current().IsInlineLeaf())
      cursor.MoveToNextInlineLeaf();
  }
  MoveTo(cursor);
  DCHECK(!cursor.Current() || cursor.Current().IsInlineLeaf())
      << "Must return an empty or inline leaf position, returned: "
      << cursor.CurrentMutableLayoutObject();
}

void InlineCursor::MoveToNextLine() {
  DCHECK(Current().IsLineBox());
  if (current_.item_) {
    do {
      MoveToNextSkippingChildren();
    } while (Current() && !Current().IsLineBox());
    return;
  }
  NOTREACHED();
}

void InlineCursor::MoveToNextLineIncludingFragmentainer() {
  MoveToNextLine();
  if (!Current() && max_fragment_index_ && CanMoveAcrossFragmentainer()) {
    MoveToNextFragmentainer();
    if (Current() && !Current().IsLineBox())
      MoveToFirstLine();
  }
}

void InlineCursor::MoveToPreviousInlineLeaf() {
  if (Current() && Current().IsInlineLeaf())
    MoveToPrevious();
  while (Current() && !Current().IsInlineLeaf())
    MoveToPrevious();
}

void InlineCursor::MoveToPreviousInlineLeafIgnoringLineBreak() {
  do {
    MoveToPreviousInlineLeaf();
  } while (Current() && Current().IsLineBreak());
}

void InlineCursor::MoveToPreviousInlineLeafOnLine() {
  if (IsNull())
    return;
  InlineCursor first_item = *this;
  MoveToContainingLine();
  InlineCursor cursor = CursorForDescendants();
  cursor.MoveTo(first_item);
  cursor.MoveToPreviousInlineLeaf();
  MoveTo(cursor);
}

void InlineCursor::MoveToPreviousLine() {
  // Note: List marker is sibling of line box.
  DCHECK(Current().IsLineBox());
  if (current_.item_) {
    do {
      MoveToPrevious();
    } while (Current() && !Current().IsLineBox());
    return;
  }
  NOTREACHED();
}

bool InlineCursor::TryMoveToFirstChild() {
  if (!Current().HasChildren())
    return false;
  MoveToItem(current_.item_iter_ + 1);
  return true;
}

bool InlineCursor::TryMoveToFirstInlineLeafChild() {
  while (IsNotNull()) {
    if (Current().IsInlineLeaf())
      return true;
    MoveToNext();
  }
  return false;
}

bool InlineCursor::TryMoveToLastChild() {
  if (!Current().HasChildren())
    return false;
  const auto end = current_.item_iter_ + CurrentItem()->DescendantsCount();
  MoveToNext();  // Move to the first child.
  DCHECK(!IsNull());
  while (true) {
    ItemsSpan::iterator previous = Current().item_iter_;
    DCHECK(previous < end);
    MoveToNextSkippingChildren();
    if (!Current() || Current().item_iter_ == end) {
      MoveToItem(previous);
      break;
    }
  }
  return true;
}

void InlineCursor::MoveToNext() {
  DCHECK(HasRoot());
  if (!current_.item_) [[unlikely]] {
    return;
  }
  // Expensive DCHECK as MoveToNext() is called frequently.
  DCHECK(current_.item_iter_ != items_.end());
  if (++current_.item_iter_ != items_.end()) {
    current_.item_ = &*current_.item_iter_;
    return;
  }
  MakeNull();
}

void InlineCursor::MoveToNextSkippingChildren() {
  DCHECK(HasRoot());
  if (!current_.item_) [[unlikely]] {
    return;
  }
  // If the current item has |DescendantsCount|, add it to move to the next
  // sibling, skipping all children and their descendants.
  if (wtf_size_t descendants_count = current_.item_->DescendantsCount())
    return MoveToItem(current_.item_iter_ + descendants_count);
  return MoveToNext();
}

void InlineCursor::MoveToPrevious() {
  DCHECK(HasRoot());
  if (!current_.item_) [[unlikely]] {
    return;
  }
  if (current_.item_iter_ == items_.begin())
    return MakeNull();
  --current_.item_iter_;
  current_.item_ = &*current_.item_iter_;
}

void InlineCursor::MoveToPreviousFragmentainer() {
  DCHECK(CanMoveAcrossFragmentainer());
  if (fragment_index_) {
    DecrementFragmentIndex();
    if (TrySetRootFragmentItems()) {
      MoveToItem(items_.end() - 1);
      return;
    }
  }
  MakeNull();
}

void InlineCursor::MoveToPreviousIncludingFragmentainer() {
  MoveToPrevious();
  if (!Current() && max_fragment_index_ && CanMoveAcrossFragmentainer())
    MoveToPreviousFragmentainer();
}

void InlineCursor::MoveToFirstIncludingFragmentainer() {
  if (!fragment_index_) {
    MoveToFirst();
    return;
  }

  ResetFragmentIndex();
  if (!TrySetRootFragmentItems())
    MakeNull();
}

void InlineCursor::MoveToNextFragmentainer() {
  DCHECK(CanMoveAcrossFragmentainer());
  if (fragment_index_ < max_fragment_index_) {
    IncrementFragmentIndex();
    if (TrySetRootFragmentItems())
      return;
  }
  MakeNull();
}

void InlineCursor::MoveToNextIncludingFragmentainer() {
  MoveToNext();
  if (!Current() && max_fragment_index_ && CanMoveAcrossFragmentainer())
    MoveToNextFragmentainer();
}

void InlineCursor::SlowMoveToForIfNeeded(const LayoutObject& layout_object) {
  while (Current() && Current().GetLayoutObject() != &layout_object)
    MoveToNextIncludingFragmentainer();
}

void InlineCursor::SlowMoveToFirstFor(const LayoutObject& layout_object) {
  MoveToFirstIncludingFragmentainer();
  SlowMoveToForIfNeeded(layout_object);
}

void InlineCursor::SlowMoveToNextForSameLayoutObject(
    const LayoutObject& layout_object) {
  MoveToNextIncludingFragmentainer();
  SlowMoveToForIfNeeded(layout_object);
}

void InlineCursor::MoveTo(const LayoutObject& layout_object) {
  DCHECK(layout_object.IsInLayoutNGInlineFormattingContext());
  if (layout_object.IsOutOfFlowPositioned()) [[unlikely]] {
    MakeNull();
    return;
  }

  // If this cursor is rootless, find the root of the inline formatting context.
  bool is_descendants_cursor = false;
  if (!HasRoot()) {
    const LayoutBlockFlow* root = layout_object.FragmentItemsContainer();
    DCHECK(root);
    SetRoot(*root);
    if (!HasRoot()) [[unlikely]] {
      MakeNull();
      return;
    }
    DCHECK(!IsDescendantsCursor());
  } else {
    is_descendants_cursor = IsDescendantsCursor();
  }

  wtf_size_t item_index = layout_object.FirstInlineFragmentItemIndex();
  if (!item_index) [[unlikely]] {
#if EXPENSIVE_DCHECKS_ARE_ON()
    const LayoutBlockFlow* root = layout_object.FragmentItemsContainer();
    InlineCursor check_cursor(*root);
    check_cursor.SlowMoveToFirstFor(layout_object);
    DCHECK(!check_cursor);
#endif
    MakeNull();
    return;
  }
  // |FirstInlineFragmentItemIndex| is 1-based. Convert to 0-based index.
  DCHECK_GT(item_index, 0UL);
  --item_index;

  // Find |FragmentItems| that contains |item_index|.
  DCHECK_EQ(is_descendants_cursor, IsDescendantsCursor());
  if (root_block_flow_) {
    DCHECK(!is_descendants_cursor);
    while (item_index >= fragment_items_->EndItemIndex()) {
      MoveToNextFragmentainer();
      if (!Current())
        return;
    }
    DCHECK_GE(item_index, fragment_items_->SizeOfEarlierFragments());
    item_index -= fragment_items_->SizeOfEarlierFragments();
#if EXPENSIVE_DCHECKS_ARE_ON()
    InlineCursor check_cursor(*root_block_flow_);
    check_cursor.SlowMoveToFirstFor(layout_object);
    DCHECK_EQ(check_cursor.Current().Item(),
              &fragment_items_->Items()[item_index]);
#endif
  } else {
    // If |this| is not rooted at |LayoutBlockFlow|, iterate |FragmentItems|
    // from |LayoutBlockFlow|.
    if (fragment_items_->HasItemIndex(item_index)) {
      DCHECK_GE(item_index, fragment_items_->SizeOfEarlierFragments());
      item_index -= fragment_items_->SizeOfEarlierFragments();
    } else {
      InlineCursor cursor;
      for (cursor.MoveTo(layout_object);;
           cursor.MoveToNextForSameLayoutObject()) {
        if (!cursor || cursor.fragment_items_->SizeOfEarlierFragments() >
                           fragment_items_->SizeOfEarlierFragments()) {
          MakeNull();
          return;
        }
        if (cursor.fragment_items_ == fragment_items_) {
          DCHECK_GE(cursor.Current().Item(), fragment_items_->Items().data());
          item_index = base::checked_cast<wtf_size_t>(
              cursor.Current().Item() - fragment_items_->Items().data());
          break;
        }
      }
    }
#if EXPENSIVE_DCHECKS_ARE_ON()
    const LayoutBlockFlow* root = layout_object.FragmentItemsContainer();
    InlineCursor check_cursor(*root);
    check_cursor.SlowMoveToFirstFor(layout_object);
    while (check_cursor && fragment_items_ != check_cursor.fragment_items_)
      check_cursor.SlowMoveToNextForSameLayoutObject(layout_object);
    DCHECK_EQ(check_cursor.Current().Item(),
              &fragment_items_->Items()[item_index]);
#endif

    // Skip items before |items_|, in case |this| is part of IFC.
    if (is_descendants_cursor) [[unlikely]] {
      const wtf_size_t span_begin_item_index = SpanBeginItemIndex();
      while (item_index < span_begin_item_index) [[unlikely]] {
        const FragmentItem& item = fragment_items_->Items()[item_index];
        const wtf_size_t next_delta = item.DeltaToNextForSameLayoutObject();
        if (!next_delta) {
          MakeNull();
          return;
        }
        item_index += next_delta;
      }
      if (item_index >= span_begin_item_index + items_.size()) [[unlikely]] {
        MakeNull();
        return;
      }
      DCHECK_GE(item_index, span_begin_item_index);
      item_index -= span_begin_item_index;
    }
  }

  DCHECK_LT(item_index, items_.size());
  current_.Set(items_.begin() + item_index);
}

void InlineCursor::MoveToNextForSameLayoutObjectExceptCulledInline() {
  if (!Current())
    return;
  if (wtf_size_t delta = current_.item_->DeltaToNextForSameLayoutObject()) {
    while (true) {
      // Return if the next index is in the current range.
      const wtf_size_t delta_to_end =
          base::checked_cast<wtf_size_t>(items_.end() - current_.item_iter_);
      if (delta < delta_to_end) {
        MoveToItem(current_.item_iter_ + delta);
        return;
      }

      // |this| is |IsDescendantsCursor| and the next item is out of the
      // specified range, or the next item is in following fragmentainers.
      if (!CanMoveAcrossFragmentainer())
        break;

      MoveToNextFragmentainer();
      if (!Current()) {
        NOTREACHED();
      }
      DCHECK_GE(delta, delta_to_end);
      delta -= delta_to_end;
    }
  }
  MakeNull();
}

void InlineCursor::MoveToLastForSameLayoutObject() {
  if (!Current())
    return;
  InlineCursorPosition last;
  do {
    last = Current();
    MoveToNextForSameLayoutObject();
  } while (Current());
  MoveTo(last);
}

//
// Functions to enumerate fragments that contribute to a culled inline.
//

// Traverse the |LayoutObject| tree in pre-order DFS and find a |LayoutObject|
// that contributes to the culled inline.
const LayoutObject* InlineCursor::CulledInlineTraversal::Find(
    const LayoutObject* child) const {
  while (child) {
    if (child->IsText())
      return child;

    if (child->IsBox()) {
      if (!child->IsFloatingOrOutOfFlowPositioned())
        return child;
      child = child->NextInPreOrderAfterChildren(layout_inline_);
      continue;
    }

    if (const auto* child_layout_inline = DynamicTo<LayoutInline>(child)) {
      if (child_layout_inline->ShouldCreateBoxFragment())
        return child;

      // A culled inline can be computed from its direct children, but when the
      // child is also culled, traverse its grand children.
      if (const LayoutObject* grand_child = child_layout_inline->FirstChild()) {
        child = grand_child;
        continue;
      }
    }

    child = child->NextInPreOrderAfterChildren(layout_inline_);
  }
  return nullptr;
}

void InlineCursor::CulledInlineTraversal::SetUseFragmentTree(
    const LayoutInline& layout_inline) {
  layout_inline_ = &layout_inline;
  use_fragment_tree_ = true;
}

const LayoutObject* InlineCursor::CulledInlineTraversal::MoveToFirstFor(
    const LayoutInline& layout_inline) {
  layout_inline_ = &layout_inline;
  use_fragment_tree_ = false;
  current_object_ = Find(layout_inline.FirstChild());
  return current_object_;
}

const LayoutObject* InlineCursor::CulledInlineTraversal::MoveToNext() {
  if (!current_object_)
    return nullptr;
  current_object_ =
      Find(current_object_->NextInPreOrderAfterChildren(layout_inline_));
  return current_object_;
}

void InlineCursor::MoveToFirstForCulledInline(
    const LayoutInline& layout_inline) {
  // When |this| is a descendant cursor, |this| may be limited to a very small
  // subset of the |LayoutObject| descendants, and that traversing
  // |LayoutObject| descendants is much more expensive. Prefer checking every
  // fragment in that case.
  if (IsDescendantsCursor()) {
    culled_inline_.SetUseFragmentTree(layout_inline);
    DCHECK(!CanMoveAcrossFragmentainer());
    MoveToFirst();
    while (Current() && !Current().IsPartOfCulledInlineBox(layout_inline))
      MoveToNext();
    return;
  }

  if (const LayoutObject* layout_object =
          culled_inline_.MoveToFirstFor(layout_inline)) {
    MoveTo(*layout_object);
    // This |MoveTo| may fail if |this| is a descendant cursor. Try the next
    // |LayoutObject|.
    MoveToNextCulledInlineDescendantIfNeeded();
  }
}

void InlineCursor::MoveToNextForCulledInline() {
  DCHECK(culled_inline_);
  if (culled_inline_.UseFragmentTree()) {
    const LayoutInline* layout_inline = culled_inline_.GetLayoutInline();
    DCHECK(layout_inline);
    DCHECK(!CanMoveAcrossFragmentainer());
    do {
      MoveToNext();
    } while (Current() && !Current().IsPartOfCulledInlineBox(*layout_inline));
    return;
  }

  MoveToNextForSameLayoutObjectExceptCulledInline();
  // If we're at the end of fragments for the current |LayoutObject| that
  // contributes to the current culled inline, find the next |LayoutObject|.
  MoveToNextCulledInlineDescendantIfNeeded();
}

void InlineCursor::MoveToNextCulledInlineDescendantIfNeeded() {
  DCHECK(culled_inline_);
  if (Current())
    return;

  while (const LayoutObject* layout_object = culled_inline_.MoveToNext()) {
    MoveTo(*layout_object);
    if (Current())
      return;
  }
}

void InlineCursor::ResetFragmentIndex() {
  fragment_index_ = 0;
  previously_consumed_block_size_ = LayoutUnit();
}

void InlineCursor::DecrementFragmentIndex() {
  DCHECK(fragment_index_);
  --fragment_index_;
  previously_consumed_block_size_ = LayoutUnit();
  if (!fragment_index_)
    return;
  // Note: |LayoutBox::GetPhysicalFragment(wtf_size_t)| is O(1).
  const auto& root_box_fragment =
      *root_block_flow_->GetPhysicalFragment(fragment_index_ - 1);
  if (const BlockBreakToken* break_token = root_box_fragment.GetBreakToken()) {
    previously_consumed_block_size_ = break_token->ConsumedBlockSize();
  }
}

void InlineCursor::IncrementFragmentIndex() {
  DCHECK_LE(fragment_index_, max_fragment_index_);
  fragment_index_++;
  if (!root_box_fragment_)
    return;
  if (const BlockBreakToken* break_token =
          root_box_fragment_->GetBreakToken()) {
    previously_consumed_block_size_ = break_token->ConsumedBlockSize();
  }
}

void InlineCursor::MoveToIncludingCulledInline(
    const LayoutObject& layout_object) {
  DCHECK(layout_object.IsInLayoutNGInlineFormattingContext()) << layout_object;

  culled_inline_.Reset();
  MoveTo(layout_object);
  if (Current() || !HasRoot())
    return;

  // If this is a culled inline, find fragments for descendant |LayoutObject|s
  // that contribute to the culled inline.
  if (const auto* layout_inline = DynamicTo<LayoutInline>(layout_object)) {
    if (!layout_inline->ShouldCreateBoxFragment())
      MoveToFirstForCulledInline(*layout_inline);
  }
}

void InlineCursor::MoveToNextForSameLayoutObject() {
  if (culled_inline_) [[unlikely]] {
    MoveToNextForCulledInline();
    return;
  }
  MoveToNextForSameLayoutObjectExceptCulledInline();
}

void InlineCursor::MoveToVisualLastForSameLayoutObject() {
  if (culled_inline_)
    MoveToVisualFirstOrLastForCulledInline(true);
  else
    MoveToLastForSameLayoutObject();
}

void InlineCursor::MoveToVisualFirstForSameLayoutObject() {
  if (culled_inline_)
    MoveToVisualFirstOrLastForCulledInline(false);
}

void InlineCursor::MoveToVisualFirstOrLastForCulledInline(bool last) {
  InlineCursorPosition found_position;
  std::optional<size_t> found_index;
  wtf_size_t found_fragment_index = 0;

  // Iterate through the remaining fragments to find the lowest/greatest index.
  for (; Current(); MoveToNextForSameLayoutObject()) {
    // Index of the current fragment into |fragment_items_|.
    size_t index = Current().Item() - fragment_items_->Items().data();
    DCHECK_LT(index, fragment_items_->Size());
    if (!found_index || (last && index > *found_index) ||
        (!last && index < *found_index)) {
      found_position = Current();
      found_index = index;
      found_fragment_index = fragment_index_;

      // Break if there cannot be any fragment lower/greater than this one.
      if ((last && index == fragment_items_->Size() - 1) ||
          (!last && index == 0))
        break;
    }
  }

  DCHECK(found_position);
  if (fragment_index_ > found_fragment_index) {
    while (fragment_index_ > found_fragment_index) {
      DecrementFragmentIndex();
    }
    CHECK(TrySetRootFragmentItems());
  }
  MoveTo(found_position);
}

//
// |InlineBackwardCursor| functions.
//
InlineBackwardCursor::InlineBackwardCursor(const InlineCursor& cursor)
    : cursor_(cursor) {
  if (cursor.HasRoot()) {
    DCHECK(!cursor || cursor.items_.begin() == cursor.Current().item_iter_);
    for (InlineCursor sibling(cursor); sibling;
         sibling.MoveToNextSkippingChildren()) {
      sibling_item_iterators_.push_back(sibling.Current().item_iter_);
    }
    current_index_ = sibling_item_iterators_.size();
    if (current_index_)
      current_.Set(sibling_item_iterators_[--current_index_]);
    return;
  }
  DCHECK(!cursor);
}

InlineCursor InlineBackwardCursor::CursorForDescendants() const {
  if (current_.item_) {
    InlineCursor cursor(cursor_);
    cursor.MoveToItem(sibling_item_iterators_[current_index_]);
    return cursor.CursorForDescendants();
  }
  NOTREACHED();
}

void InlineBackwardCursor::MoveToPreviousSibling() {
  if (current_index_) {
    if (current_.item_) {
      current_.Set(sibling_item_iterators_[--current_index_]);
      return;
    }
    NOTREACHED();
  }
  current_.Clear();
}

std::ostream& operator<<(std::ostream& ostream, const InlineCursor& cursor) {
  if (!cursor)
    return ostream << "InlineCursor()";
  DCHECK(cursor.HasRoot());
  return ostream << "InlineCursor(" << *cursor.CurrentItem() << ")";
}

std::ostream& operator<<(std::ostream& ostream, const InlineCursor* cursor) {
  if (!cursor)
    return ostream << "<null>";
  return ostream << *cursor;
}

#if DCHECK_IS_ON()
void InlineCursor::CheckValid(const InlineCursorPosition& position) const {
  if (position.Item()) {
    DCHECK(HasRoot());
    DCHECK_EQ(position.item_, &*position.item_iter_);
    const unsigned index =
        base::checked_cast<unsigned>(position.item_iter_ - items_.begin());
    DCHECK_LT(index, items_.size());
  }
}
#endif

}  // namespace blink
```