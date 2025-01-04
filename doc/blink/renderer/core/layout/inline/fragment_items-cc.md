Response:
Let's break down the thought process for analyzing the `fragment_items.cc` file.

1. **Understand the Core Purpose:** The filename itself, "fragment_items.cc," suggests it deals with items within fragments. Coupled with the directory "inline," it strongly hints at the management of layout items specifically within inline layout contexts in Blink.

2. **Identify Key Data Structures:**  The core class `FragmentItems` is the central entity. The constructor taking a `FragmentItemsBuilder` indicates a separate build process. The `items_` member (a `HeapVector<FragmentItem>`) is clearly the storage for these layout items. The presence of `text_content_` and `first_line_text_content_` hints at text handling.

3. **Analyze Key Methods (High-Level):**

    * **Constructors:**  How are `FragmentItems` created?  Copy constructor suggests the need for duplication.
    * **`FinalizeAfterLayout`:**  This sounds like a crucial post-layout step. The arguments (`LayoutResult`, `LayoutBlockFlow`) confirm its connection to layout.
    * **`ClearAssociatedFragments`:** Implies a relationship with layout objects and a need to detach.
    * **`CanReuseAll` and `EndOfReusableItems`:**  These strongly suggest optimization and caching mechanisms in layout.
    * **`IsContainerForCulledInline`:**  This points to handling optimization techniques like culling (skipping layout of invisible parts).
    * **`TryDirtyFirstLineFor` and `TryDirtyLastLineFor`:**  "Dirty" usually means invalidating for re-layout. These functions likely target specific lines.
    * **`DirtyLinesFromChangedChild` and `DirtyLinesFromNeedsLayout`:**  Triggering re-layout based on changes.
    * **`ReplaceBoxFragment`:** Modifying the structure of fragments.
    * **`LayoutObjectWillBeMoved` and `LayoutObjectWillBeDestroyed`:**  Handling object lifecycle events.

4. **Examine Relationships to Web Technologies (HTML, CSS, JavaScript):**

    * **Inline Layout:** The core purpose directly relates to how inline elements (like `<span>`, `<a>`, text nodes) are laid out based on CSS properties like `display: inline`, `white-space`, etc.
    * **Fragments:**  These are essential for handling line wrapping and pagination in CSS. When text or inline elements don't fit on a single line, they are broken into fragments.
    * **Text Content:** The `text_content_` and `first_line_text_content_` members directly relate to the text content within HTML elements.
    * **Line Boxes:** The code explicitly mentions `PhysicalLineBoxFragment`, which is a fundamental concept in CSS inline layout (the rectangular areas that contain inline content on a line).
    * **Floats:**  The code handles floats (`item.IsFloating()`) which are a core CSS layout mechanism.
    * **Ellipsis:**  The code mentions handling ellipses (`item.IsEllipsis()`), a common CSS feature for indicating overflowed text (`text-overflow: ellipsis`).
    * **Re-layout/Invalidation:** The "dirtying" functions are directly connected to how the browser decides which parts of the page need to be re-laid out after changes, which can be triggered by JavaScript manipulation of the DOM or CSS style changes.
    * **Culling:** The `IsContainerForCulledInline` function is tied to performance optimization strategies where parts of the layout that are not currently visible are skipped.

5. **Consider Logical Reasoning (Hypothetical Inputs and Outputs):**

    * **Input:** A `LayoutBlockFlow` representing a `<div>` containing inline text and a `<span>`.
    * **Output:** The `FinalizeAfterLayout` function would process the fragments generated for the text and the `<span>`, setting up the `FragmentItem` links and properties. It would determine if the `<span>` spans multiple lines (multiple fragments) and set the `IsLastForNode` flag accordingly.
    * **Input:**  A JavaScript change modifies the text content within the `<span>`.
    * **Output:** The `DirtyLinesFromChangedChild` function would be called, potentially marking the `FragmentItem`s associated with the `<span>`'s lines as dirty, triggering a re-layout of those lines.

6. **Identify Potential User/Programming Errors:**

    * **Incorrectly manipulating layout objects directly:**  Since `FragmentItems` manages layout information, directly changing layout objects without going through the proper Blink APIs could lead to inconsistencies and crashes.
    * **Caching assumptions:** Developers shouldn't make assumptions about how fragments are managed or reused without understanding the underlying Blink mechanisms. For example, assuming a particular `FragmentItem` will always be valid could lead to issues if the layout changes.
    * **Performance pitfalls:**  While Blink optimizes layout, performing excessive DOM manipulations or style changes can still lead to performance problems, and understanding how `FragmentItems` work can help developers write more efficient code.

7. **Refine and Structure:** Organize the findings into logical categories (Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors) with clear explanations and examples. Use code snippets or simplified descriptions where necessary. Ensure the language is clear and accessible.

By following this process, combining code analysis with knowledge of web technologies and layout concepts, we can effectively understand the role and function of a complex source code file like `fragment_items.cc`.
这是 `blink/renderer/core/layout/inline/fragment_items.cc` 文件的功能列表，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及一些逻辑推理、假设输入输出和常见错误。

**功能列举：**

`fragment_items.cc` 文件的核心作用是管理和维护在 **行内格式化上下文 (Inline Formatting Context, IFC)** 中生成的 **片段项 (Fragment Items)**。这些片段项代表了在布局过程中，行内元素（例如文本、`<span>` 等）被分割成不同片段的信息。

1. **存储片段项：** `FragmentItems` 类主要负责存储一个 `FragmentItem` 对象的集合 (`items_`)，这些对象描述了行内元素在不同布局片段中的信息。

2. **管理文本内容：** 存储与片段相关的文本内容 (`text_content_`, `first_line_text_content_`)，用于快速访问文本信息。

3. **关联布局对象和片段：** 记录哪个布局对象对应哪个片段项，通过 `LayoutObject::SetFirstInlineFragmentItemIndex()` 和 `FragmentItem::SetDeltaToNextForSameLayoutObject()` 等方法实现。

4. **处理行框（Line Box）：**  识别和处理行框片段 (`FragmentItem::kLine`)，这些片段代表了每一行文本。

5. **处理浮动元素：** 识别和处理浮动元素的片段项，并考虑它们对行内布局的影响。

6. **支持非连续的 IFC：**  处理由于浮动元素等原因导致的非连续的行内格式化上下文，即一个行内元素可能出现在不连续的片段中。

7. **优化重用：**  提供机制判断哪些片段项可以被重用 (`CanReuseAll`, `EndOfReusableItems`)，以提高布局性能。

8. **支持裁剪 (Culling)：**  判断一个容器片段是否包含被裁剪的行内元素的部分内容 (`IsContainerForCulledInline`)。裁剪是一种优化技术，用于跳过不可见内容的布局计算。

9. **标记脏数据 (Dirtying)：** 提供方法标记片段项为“脏” (`TryDirtyFirstLineFor`, `TryDirtyLastLineFor`, `DirtyLinesFromChangedChild`, `DirtyLinesFromNeedsLayout`)，表示需要重新布局。这在 DOM 结构或样式发生变化时触发。

10. **替换片段：** 提供替换片段项中关联的 `PhysicalBoxFragment` 的能力 (`ReplaceBoxFragment`)。

11. **处理布局对象的移动和销毁：**  在布局对象被移动或销毁时执行相应的清理操作 (`LayoutObjectWillBeMoved`, `LayoutObjectWillBeDestroyed`)，防止悬挂指针。

**与 JavaScript, HTML, CSS 的关系：**

`fragment_items.cc` 直接参与了浏览器渲染引擎处理 HTML、CSS 并最终展示在屏幕上的过程。

* **HTML:**  HTML 结构定义了页面上的元素，这些元素会被布局引擎处理。`FragmentItems` 负责管理这些行内元素的布局信息。例如，一个 `<span>` 元素内的文本可能会被分割成多个 `FragmentItem` 对象，如果它跨越了多行。

    ```html
    <div>
      This is some text in a <span>span element</span> that might wrap.
    </div>
    ```

* **CSS:** CSS 样式规则决定了元素的布局方式。例如，`display: inline`、`white-space`、`float` 等属性会直接影响行内元素的布局和 `FragmentItems` 的生成。

    * `display: inline`:  指定元素为行内元素，其内容会与其他行内元素排列在同一行。`FragmentItems` 会跟踪这些元素的片段。
    * `white-space`:  控制如何处理元素内的空白符，影响文本的换行和片段的生成。
    * `float`:  浮动元素会脱离正常的文档流，影响行内格式化上下文，`FragmentItems` 需要处理这些浮动元素对其他行内元素布局的影响.

* **JavaScript:** JavaScript 可以动态修改 HTML 结构和 CSS 样式。当 JavaScript 修改了影响布局的属性时，例如改变了元素的文本内容、添加或删除元素、修改元素的 `display` 属性等，会导致布局树的更新，并可能触发 `FragmentItems` 相关的操作，例如标记为“脏”需要重新布局。

    ```javascript
    // JavaScript 修改 span 元素的文本内容
    document.querySelector('span').textContent = 'This is new longer text that will likely wrap.';
    ```

    上述 JavaScript 代码执行后，`fragment_items.cc` 中的相关逻辑会被触发，因为文本内容的变化可能导致 `<span>` 元素需要被分割成不同的片段。

**逻辑推理、假设输入与输出：**

假设有一个 `<div>` 元素包含一些行内文本和一个 `<span>` 元素，样式如下：

```html
<div>
  This is some inline text before the <span>span element</span> and some text after.
</div>
```

```css
div {
  width: 200px;
}
span {
  color: blue;
}
```

**假设输入：**  Blink 布局引擎接收到上述 HTML 和 CSS。

**逻辑推理过程：**

1. **布局树构建：**  Blink 会根据 HTML 构建 DOM 树，并根据 CSS 构建 Style 树，然后结合两者构建布局树。
2. **行内格式化上下文创建：** `<div>` 元素创建了一个块级格式化上下文，而其内部的文本和 `<span>` 元素形成了行内格式化上下文。
3. **片段生成：**  布局引擎会开始处理行内元素。由于 `<div>` 的宽度有限，文本和 `<span>` 可能会被分割成多个片段。
4. **`FragmentItems` 创建和管理：**  对于 `<div>` 的每个 `PhysicalBoxFragment`（可能对应不同的行），都会有一个 `FragmentItems` 对象来管理其内部的片段。
5. **片段项创建：**  对于文本节点和 `<span>` 元素，会创建相应的 `FragmentItem` 对象。例如，"This is some inline text before the " 可能会是一个片段项，"span element" 可能是另一个， " and some text after." 可能是第三个。如果 `<span>` 元素内的文本很长，也可能被分割成多个片段项。
6. **关联布局对象：**  每个 `FragmentItem` 会关联到对应的布局对象（文本节点或 `LayoutInline` 对象 for `<span>`）。
7. **行框识别：**  会创建 `FragmentItem::kLine` 类型的片段项来表示每一行。

**可能的输出（`FinalizeAfterLayout` 后的状态）：**

假设文本换行了，`FragmentItems` 可能会包含以下 `FragmentItem` (简化描述)：

* **Line 1:**
    * Text Fragment: "This is some inline text before the "
    * Span Fragment (start): "span "
* **Line 2:**
    * Span Fragment (end): "element"
    * Text Fragment: " and some text after."

每个 `FragmentItem` 会记录其类型、关联的布局对象、是否是该布局对象的最后一个片段等信息。`LayoutObject` 对象会记录其第一个 `FragmentItem` 的索引。

**用户或编程常见的使用错误：**

1. **直接修改布局相关的属性而没有触发重绘/重排：**  虽然 JavaScript 可以直接访问和修改 DOM 元素的属性，但如果修改的是影响布局的属性（例如 `offsetWidth`, `offsetTop` 等）并且没有触发浏览器的重排/重绘，可能会导致获取到的值不是最新的，从而产生逻辑错误。Blink 内部会通过 `FragmentItems` 的 “脏” 机制来确保布局的正确性。

2. **过度依赖特定的布局行为：**  开发者不应该过度依赖特定浏览器的布局实现细节。例如，假设某个特定版本的 Chrome 对于某个复杂的行内布局总是生成相同数量的片段，并以此为基础编写逻辑，这可能会在其他浏览器或 Chrome 的未来版本中失效。

3. **在性能敏感的循环中频繁地查询布局信息：**  频繁地读取会触发强制同步布局的操作（layout thrashing），这会严重影响性能。例如，在一个循环中不断地读取元素的 `offsetWidth` 并修改另一个元素的样式。了解 `FragmentItems` 的作用可以帮助开发者理解哪些操作会触发布局，从而避免性能陷阱。

4. **错误地假设行内元素的布局方式：**  初学者可能认为行内元素只是简单地水平排列，而忽略了行框、基线、行高、`white-space` 等复杂的概念。`FragmentItems` 的存在正是为了处理这些复杂的行内布局场景。

总而言之，`fragment_items.cc` 是 Blink 渲染引擎中负责管理行内布局片段的关键组件，它在浏览器将 HTML、CSS 转换为用户可见页面的过程中起着至关重要的作用。理解其功能有助于开发者更好地理解浏览器的渲染机制，并避免一些常见的性能问题和布局错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/fragment_items.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/fragment_items.h"

#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_items_builder.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"

namespace blink {

namespace {

#if DCHECK_IS_ON()
void CheckNoItemsAreAssociated(const PhysicalBoxFragment& fragment) {
  if (const FragmentItems* fragment_items = fragment.Items()) {
    for (const FragmentItem& item : fragment_items->Items()) {
      if (item.Type() == FragmentItem::kLine) {
        continue;
      }
      if (const LayoutObject* layout_object = item.GetLayoutObject())
        DCHECK(!layout_object->FirstInlineFragmentItemIndex());
    }
  }
}

void CheckIsLast(const FragmentItem& item) {
  if (const PhysicalBoxFragment* fragment = item.BoxFragment()) {
    if (!fragment->IsInline()) {
      DCHECK(!fragment->IsInlineBox());
      DCHECK_EQ(item.IsLastForNode(), !fragment->GetBreakToken());
    }
  }
}
#endif

}  // namespace

FragmentItems::FragmentItems(FragmentItemsBuilder* builder)
    : text_content_(std::move(builder->text_content_)),
      first_line_text_content_(std::move(builder->first_line_text_content_)) {
  items_.ReserveInitialCapacity(builder->items_.size());
  std::transform(builder->items_.begin(), builder->items_.end(),
                 std::back_inserter(items_),
                 [](auto& item) { return std::move(item.item); });
}

FragmentItems::FragmentItems(const FragmentItems& other)
    : text_content_(other.text_content_),
      first_line_text_content_(other.first_line_text_content_),
      size_of_earlier_fragments_(other.size_of_earlier_fragments_),
      items_(other.items_) {
  for (const auto& other_item : other.items_) {
    // The |other| object is likely going to be freed after this copy. Detach
    // any |AbstractInlineTextBox|, as they store a pointer to an individual
    // |FragmentItem|.
    if (auto* layout_text =
            DynamicTo<LayoutText>(other_item.GetMutableLayoutObject()))
      layout_text->DetachAbstractInlineTextBoxesIfNeeded();
  }
}

bool FragmentItems::IsSubSpan(const Span& span) const {
  return span.empty() || (span.data() >= ItemsData() && !items_.empty() &&
                          &span.back() <= &items_.back());
}

void FragmentItems::FinalizeAfterLayout(
    const HeapVector<Member<const LayoutResult>, 1>& results,
    LayoutBlockFlow& container) {
  struct LastItem {
    const FragmentItem* item;
    wtf_size_t fragment_id;
    wtf_size_t item_index;
  };
  HeapHashMap<Member<const LayoutObject>, LastItem> last_items;
  ClearCollectionScope<HeapHashMap<Member<const LayoutObject>, LastItem>>
      clear_scope(&last_items);
  wtf_size_t item_index = 0;
  wtf_size_t line_fragment_id = FragmentItem::kInitialLineFragmentId;

  // If there are container fragments that don't have fragment items, or if
  // there are just floats there, the inline formatting context may be
  // non-contiguous, which means that a non-atomic inline may be non-contiguous
  // (e.g. it may exist in fragment 1, be absent in fragment 2, present again in
  // fragment 3). This requires some quite expensive calculations when setting
  // up the FragmentData objects.
  bool may_be_non_contiguous_ifc = false;

  for (const auto& result : results) {
    const auto& fragment =
        To<PhysicalBoxFragment>(result->GetPhysicalFragment());
    const FragmentItems* fragment_items = fragment.Items();
    if (!fragment_items) [[unlikely]] {
      may_be_non_contiguous_ifc = true;
      continue;
    }

    bool found_inflow_content = false;
    fragment_items->size_of_earlier_fragments_ = item_index;
    const Span items = fragment_items->Items();
    for (const FragmentItem& item : items) {
      ++item_index;
      if (item.Type() == FragmentItem::kLine) {
        DCHECK_EQ(item.DeltaToNextForSameLayoutObject(), 0u);
        item.SetFragmentId(line_fragment_id++);
        continue;
      } else if (!found_inflow_content) {
        // Resumed floats may take up all the space in the containing block
        // fragment, leaving no room for actual content inside the inline
        // formatting context. The non-atomic inline boxes themselves also don't
        // contribute to having inflow content, as they may just be wrappers
        // around such floats. We need something "real", such as text or a
        // non-atomic inline.
        found_inflow_content = !item.IsFloating() && !item.IsInlineBox();
      }
      LayoutObject* const layout_object = item.GetMutableLayoutObject();
      DCHECK(!layout_object->IsOutOfFlowPositioned());
      DCHECK(layout_object->IsInLayoutNGInlineFormattingContext());

      item.SetDeltaToNextForSameLayoutObject(0);
      const bool use_break_token =
          layout_object->IsFloating() || !layout_object->IsInline();
      if (use_break_token) [[unlikely]] {
        // Fragments that aren't really on a line, such as floats, will have
        // block break tokens if they continue in a subsequent fragmentainer, so
        // just check that. Floats in particular will continue as regular box
        // fragment children in subsequent fragmentainers, i.e. they will not be
        // fragment items (even if we're in an inline formatting context). So
        // we're not going to find the last fragment by just looking for items.
        DCHECK(item.BoxFragment() && !item.BoxFragment()->IsInlineBox());
        item.SetIsLastForNode(!item.BoxFragment()->GetBreakToken());
      } else {
        DCHECK(layout_object->IsInline());
        // This will be updated later if following fragments are found.
        item.SetIsLastForNode(true);
      }

      // If this is the first fragment, associate with |layout_object|.
      const auto last_item_result =
          last_items.insert(layout_object, LastItem{&item, 0, item_index});
      const bool is_first = last_item_result.is_new_entry;
      if (is_first) {
        item.SetFragmentId(0);
        layout_object->SetFirstInlineFragmentItemIndex(item_index);
        continue;
      }

      // Update the last item for |layout_object|.
      LastItem* last = &last_item_result.stored_value->value;
      const FragmentItem* last_item = last->item;
      DCHECK_EQ(last_item->DeltaToNextForSameLayoutObject(), 0u);
      const wtf_size_t last_index = last->item_index;
      DCHECK_GT(last_index, 0u);
      DCHECK_LT(last_index, fragment_items->EndItemIndex());
      DCHECK_LT(last_index, item_index);
      last_item->SetDeltaToNextForSameLayoutObject(item_index - last_index);
      // Because we found a following fragment, reset |IsLastForNode| for the
      // last item except:
      // a. |IsLastForNode| is computed from break token. The last item already
      //    has the correct value.
      // b. Ellipses for atomic inlines. |IsLastForNode| of the last box item
      //    should be set to ease handling of this edge case.
      if (!use_break_token && !(layout_object->IsBox() && item.IsEllipsis()))
        last_item->SetIsLastForNode(false);
#if DCHECK_IS_ON()
      CheckIsLast(*last_item);
#endif

      // Update this item.
      item.SetFragmentId(++last->fragment_id);
      last->item = &item;
      last->item_index = item_index;
    }

    if (!found_inflow_content) {
      may_be_non_contiguous_ifc = true;
    }
  }

  container.SetMayBeNonContiguousIfc(may_be_non_contiguous_ifc);

#if DCHECK_IS_ON()
  for (const auto& iter : last_items)
    CheckIsLast(*iter.value.item);
#endif
}

void FragmentItems::ClearAssociatedFragments(LayoutObject* container) {
  // Clear by traversing |LayoutObject| tree rather than |FragmentItem|
  // because a) we don't need to modify |FragmentItem|, and in general the
  // number of |LayoutObject| is less than the number of |FragmentItem|.
  for (LayoutObject* child = container->SlowFirstChild(); child;
       child = child->NextSibling()) {
    if (!child->IsInLayoutNGInlineFormattingContext() ||
        child->IsOutOfFlowPositioned()) [[unlikely]] {
      continue;
    }
    child->ClearFirstInlineFragmentItemIndex();

    // Children of |LayoutInline| are part of this inline formatting context,
    // but children of other |LayoutObject| (e.g., floats, oof, inline-blocks)
    // are not.
    if (child->IsLayoutInline())
      ClearAssociatedFragments(child);
  }
#if DCHECK_IS_ON()
  if (const auto* box = DynamicTo<LayoutBox>(container)) {
    for (const PhysicalBoxFragment& fragment : box->PhysicalFragments()) {
      CheckNoItemsAreAssociated(fragment);
    }
  }
#endif
}

// static
bool FragmentItems::CanReuseAll(InlineCursor* cursor) {
  for (; *cursor; cursor->MoveToNext()) {
    const FragmentItem& item = *cursor->Current().Item();
    // Ignore nested kLine items though their descendants affect the result.
    if (item.Type() == FragmentItem::kLine) {
      continue;
    }
    if (!item.CanReuse())
      return false;
  }
  return true;
}

const FragmentItem* FragmentItems::EndOfReusableItems(
    const PhysicalBoxFragment& container) const {
  const FragmentItem* last_line_start = &front();
  for (InlineCursor cursor(container, *this); cursor;) {
    const FragmentItem& item = *cursor.Current();
    if (item.IsDirty())
      return &item;

    // Top-level fragments that are not line box cannot be reused; e.g., oof
    // or list markers.
    if (item.Type() != FragmentItem::kLine) {
      return &item;
    }

    // If there is a dirty item in the middle of a line, its previous line is
    // not reusable, because the dirty item may affect the previous line to wrap
    // differently.
    InlineCursor line = cursor.CursorForDescendants();
    if (!CanReuseAll(&line))
      return last_line_start;

    const PhysicalLineBoxFragment& line_box_fragment = *item.LineBoxFragment();

    // Abort if the line propagated its descendants to outside of the line.
    // They are propagated through LayoutResult, which we don't cache.
    if (line_box_fragment.HasPropagatedDescendants())
      return &item;

    // Abort if we are an empty line-box. We don't have any content, and might
    // resolve the BFC block-offset at the incorrect position.
    if (line_box_fragment.IsEmptyLineBox())
      return &item;

    // Abort reusing block-in-inline because it may need to set
    // |PreviousInflowData|.
    if (line_box_fragment.IsBlockInInline()) [[unlikely]] {
      return &item;
    }

    // TODO(kojii): Running the normal layout code at least once for this
    // child helps reducing the code to setup internal states after the
    // partial. Remove the last fragment if it is the end of the
    // fragmentation to do so, but we should figure out how to setup the
    // states without doing this.
    if (!line_box_fragment.GetBreakToken()) {
      return &item;
    }

    last_line_start = &item;
    cursor.MoveToNextSkippingChildren();
  }
  return nullptr;  // all items are reusable.
}

bool FragmentItems::IsContainerForCulledInline(
    const LayoutInline& layout_inline,
    bool* is_first_container,
    bool* is_last_container,
    bool* child_has_any_child_items) const {
  DCHECK(!layout_inline.HasInlineFragments());
  const wtf_size_t start_idx = size_of_earlier_fragments_;
  const wtf_size_t end_idx = EndItemIndex();
  const LayoutObject* next_descendant;
  bool found_item = false;
  bool has_float_ahead = false;
  *is_first_container = true;
  *child_has_any_child_items = false;
  for (const LayoutObject* descendant = layout_inline.FirstChild(); descendant;
       descendant = next_descendant) {
    wtf_size_t item_idx = descendant->FirstInlineFragmentItemIndex();
    if (descendant->IsBox() || item_idx)
      next_descendant = descendant->NextInPreOrderAfterChildren(&layout_inline);
    else
      next_descendant = descendant->NextInPreOrder(&layout_inline);
    if (!item_idx)
      continue;
    *child_has_any_child_items = true;

    // |FirstInlineFragmentItemIndex| is 1-based. Convert to 0-based index.
    item_idx--;

    if (item_idx >= end_idx) {
      if (!found_item && descendant->IsFloating()) {
        // Keep looking if we haven't found anything here. Even if this float
        // starts in a later container, there may still be something to be found
        // in this container. A float may be pushed to the next fragmentainer,
        // while subsequent in-flow content may still fit in this container.
        has_float_ahead = true;
        continue;
      }
      // This descendant starts in a later container. So this isn't the last
      // container for the culled inline.
      *is_last_container = false;
      return found_item;
    }

    if (item_idx < start_idx) {
      // This descendant doesn't start here. But does it occur here?
      *is_first_container = false;
      InlineCursor cursor;
      for (cursor.MoveTo(*descendant); cursor.Current() && item_idx < end_idx;
           cursor.MoveToNextForSameLayoutObject()) {
        item_idx += cursor.Current()->DeltaToNextForSameLayoutObject();
        if (item_idx >= start_idx) {
          if (item_idx >= end_idx) {
            // The descendant occurs in a later container. So this isn't the
            // last container for the culled inline.
            *is_last_container = false;
            return found_item;
          }
          // The descendant occurs here. Proceed to figure out if it ends here
          // as well.
          found_item = true;
        }
      }
      continue;
    }

    // This descendant starts here. Does it end here as well?
    found_item = true;
    const FragmentItem* item = &items_[item_idx - start_idx];
    do {
      if (const wtf_size_t delta = item->DeltaToNextForSameLayoutObject()) {
        item_idx += delta;
        if (item_idx >= end_idx) {
          // This descendant also occurs in a later container. So this isn't the
          // last container for the culled inline.
          *is_last_container = false;
          return true;
        }
        item = &items_[item_idx - start_idx];
      } else {
        item = nullptr;
      }
    } while (item);
  }

  // If we didn't find anything that occurs in a later container, this is the
  // last container for the culled inline.
  *is_last_container = !has_float_ahead;
  return found_item;
}

// static
bool FragmentItems::TryDirtyFirstLineFor(const LayoutObject& layout_object,
                                         const LayoutBlockFlow& container) {
  DCHECK(layout_object.IsDescendantOf(&container));
  InlineCursor cursor(container);
  cursor.MoveTo(layout_object);
  if (!cursor)
    return false;
  DCHECK(cursor.Current().Item());
  DCHECK_EQ(&layout_object, cursor.Current().GetLayoutObject());
  cursor.Current()->SetDirty();
  return true;
}

// static
bool FragmentItems::TryDirtyLastLineFor(const LayoutObject& layout_object,
                                        const LayoutBlockFlow& container) {
  DCHECK(layout_object.IsDescendantOf(&container));
  InlineCursor cursor(container);
  cursor.MoveTo(layout_object);
  if (!cursor)
    return false;
  cursor.MoveToLastForSameLayoutObject();
  DCHECK(cursor.Current().Item());
  DCHECK_EQ(&layout_object, cursor.Current().GetLayoutObject());
  cursor.Current()->SetDirty();
  return true;
}

// static
void FragmentItems::DirtyLinesFromChangedChild(
    const LayoutObject& child,
    const LayoutBlockFlow& container) {
  if (child.IsInLayoutNGInlineFormattingContext() &&
      !child.IsFloatingOrOutOfFlowPositioned()) {
    if (TryDirtyFirstLineFor(child, container))
      return;
  }

  // If |child| is new, or did not generate fragments, mark the fragments for
  // previous |LayoutObject| instead.
  for (const LayoutObject* current = &child;;) {
    if (const LayoutObject* previous = current->PreviousSibling()) {
      while (const auto* layout_inline = DynamicTo<LayoutInline>(previous)) {
        if (const LayoutObject* last_child = layout_inline->LastChild())
          previous = last_child;
        else
          break;
      }
      current = previous;
      if (current->IsFloatingOrOutOfFlowPositioned()) [[unlikely]] {
        continue;
      }
      if (current->IsInLayoutNGInlineFormattingContext()) {
        if (TryDirtyLastLineFor(*current, container))
          return;
      }
      continue;
    }

    current = current->Parent();
    if (!current || current->IsLayoutBlockFlow()) {
      DirtyFirstItem(container);
      return;
    }
    DCHECK(current->IsLayoutInline());
    if (current->IsInLayoutNGInlineFormattingContext()) {
      if (TryDirtyFirstLineFor(*current, container))
        return;
    }
  }
}

// static
void FragmentItems::DirtyFirstItem(const LayoutBlockFlow& container) {
  for (const PhysicalBoxFragment& fragment : container.PhysicalFragments()) {
    if (const FragmentItems* items = fragment.Items()) {
      items->front().SetDirty();
      return;
    }
  }
}

// static
void FragmentItems::DirtyLinesFromNeedsLayout(
    const LayoutBlockFlow& container) {
  DCHECK(base::ranges::any_of(
      container.PhysicalFragments(),
      [](const PhysicalBoxFragment& fragment) { return fragment.HasItems(); }));

  // Mark dirty for the first top-level child that has |NeedsLayout|.
  //
  // TODO(kojii): We could mark first descendant to increase reuse
  // opportunities. Doing this complicates the logic, especially when culled
  // inline is involved, and common case is to append to large IFC. Choose
  // simpler logic and faster to check over more reuse opportunities.
  const auto writing_mode = container.StyleRef().GetWritingMode();
  for (LayoutObject* child = container.FirstChild(); child;
       child = child->NextSibling()) {
    // NeedsLayout is not helpful for an orthogonal writing-mode root because
    // its NeedsLayout flag is cleared during the ComputeMinMaxSizes() step of
    // the container.
    if (child->NeedsLayout() ||
        !IsParallelWritingMode(writing_mode,
                               child->StyleRef().GetWritingMode())) {
      DirtyLinesFromChangedChild(*child, container);
      return;
    }
  }
}

// static
bool FragmentItems::ReplaceBoxFragment(
    const PhysicalBoxFragment& old_fragment,
    const PhysicalBoxFragment& new_fragment,
    const PhysicalBoxFragment& containing_fragment) {
  for (InlineCursor cursor(containing_fragment); cursor; cursor.MoveToNext()) {
    const FragmentItem* item = cursor.Current().Item();
    if (item->BoxFragment() != &old_fragment)
      continue;
    item->GetMutableForCloning().ReplaceBoxFragment(new_fragment);
    return true;
  }
  return false;
}

// static
void FragmentItems::LayoutObjectWillBeMoved(const LayoutObject& layout_object) {
  InlineCursor cursor;
  cursor.MoveTo(layout_object);
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    const FragmentItem* item = cursor.Current().Item();
    item->LayoutObjectWillBeMoved();
  }
}

// static
void FragmentItems::LayoutObjectWillBeDestroyed(
    const LayoutObject& layout_object) {
  InlineCursor cursor;
  cursor.MoveTo(layout_object);
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    const FragmentItem* item = cursor.Current().Item();
    item->LayoutObjectWillBeDestroyed();
  }
}

#if DCHECK_IS_ON()
void FragmentItems::CheckAllItemsAreValid() const {
  for (const FragmentItem& item : Items()) {
    DCHECK(!item.IsLayoutObjectDestroyedOrMoved());
  }
}
#endif

void FragmentItems::Trace(Visitor* visitor) const {
  visitor->Trace(items_);
}

}  // namespace blink

"""

```