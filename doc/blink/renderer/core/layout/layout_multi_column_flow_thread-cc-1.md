Response:
My thinking process to analyze the code and answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code snippet from `layout_multi_column_flow_thread.cc`. It specifically wants connections to HTML, CSS, JavaScript, examples of logical reasoning (with input/output), and common usage errors. Since this is part 2 of 2, the final instruction emphasizes summarizing the *entire* functionality (across both parts).

2. **Initial Code Scan (High-Level):** I first quickly read through the code, looking for keywords and patterns related to multi-column layout. I notice function names like `CreateAndInsertMultiColumnSet`, `DestroySpannerPlaceholder`, `FlowThreadDescendantWasInserted`, `FlowThreadDescendantWillBeRemoved`, `FlowThreadDescendantStyleWillChange`, `FlowThreadDescendantStyleDidChange`, and `ToggleSpannersInSubtree`. These names strongly suggest the code manages the dynamic creation and manipulation of the multi-column layout structure.

3. **Identify Key Data Structures:**  I see references to `LayoutMultiColumnSet` and `LayoutMultiColumnSpannerPlaceholder`. These are likely the core data structures used to represent the columns and elements spanning multiple columns within the multi-column layout. The code also manipulates the parent-child relationships of `LayoutObject` instances.

4. **Focus on Core Functions:** I then focus on understanding the purpose of the most prominent functions:

    * **Insertion/Removal Functions (`FlowThreadDescendantWasInserted`, `FlowThreadDescendantWillBeRemoved`):** These functions manage the insertion and removal of content within the multi-column flow. They ensure the column sets and spanner placeholders are correctly updated when elements are added or removed. I note the logic around `object_after_subtree` and inserting at the beginning/end. The removal logic handles merging column sets when content is removed between spanners.

    * **Style Change Handlers (`FlowThreadDescendantStyleWillChange`, `FlowThreadDescendantStyleDidChange`):** These functions react to style changes that might affect the multi-column layout. They handle cases where elements become or cease to be column spanners or when the ability of a container to hold spanners changes. The logic around `NeedsToInsertIntoFlowThread` and `NeedsToRemoveFromFlowThread` is crucial here.

    * **Spanner Management (`CreateAndInsertSpannerPlaceholder`, `DestroySpannerPlaceholder`, `ToggleSpannersInSubtree`):** These functions manage the creation, destruction, and toggling of spanner placeholders based on style changes.

    * **Geometry Calculation (`LocationInternal`, `Size`, `UpdateGeometry`):** These functions calculate and update the position and size of the multi-column flow thread.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**  I start connecting the code's functionality to web technologies:

    * **CSS:** The code directly implements the behavior defined by the CSS `column-span` property. When an element has `column-span: all`, a `LayoutMultiColumnSpannerPlaceholder` is created. Changes to CSS properties like `position` can trigger the insertion or removal of elements from the flow thread.

    * **HTML:** The structure of the HTML document influences how the multi-column layout is formed. The order of elements and the presence of elements with `column-span: all` determine the creation of column sets and spanners.

    * **JavaScript:**  While the C++ code doesn't directly interact with JavaScript, JavaScript manipulation of the DOM (adding/removing elements, changing styles) will indirectly trigger the execution of these C++ functions to update the layout.

6. **Identify Logical Reasoning and Examples:** I look for conditional logic within the functions and try to construct simple scenarios to illustrate the input and output:

    * **Insertion:**  Imagine inserting an element before a spanner. The code checks if a column set exists and creates one if necessary.
    * **Removal:**  Imagine removing content between two spanners. The code identifies the adjacent spanners and removes the intermediate column set.

7. **Consider User/Programming Errors:** I think about common mistakes developers might make when working with multi-column layouts that could relate to this code:

    * Incorrectly nesting spanners (though the code prevents this).
    * Dynamically adding/removing elements with JavaScript and expecting the layout to update seamlessly (which this code aims to facilitate).

8. **Structure the Answer:** I organize the findings into the requested categories: functionality, relationship to web technologies, logical reasoning, and potential errors. I provide concrete examples where possible.

9. **Synthesize the Summary (Part 2):** For the final summary, I combine the knowledge gained from analyzing this snippet with the understanding that this is "part 2 of 2". I focus on the core responsibilities of this specific part, which seem to be handling dynamic updates (insertion, removal, style changes) to the multi-column layout, and geometry calculation. I avoid repeating details that were likely covered in "part 1" (like the initial creation of the layout).

10. **Refine and Review:** I review my answer for clarity, accuracy, and completeness, ensuring it directly addresses all parts of the request. I double-check the examples and logical deductions.

This iterative process of scanning, focusing, connecting, and exemplifying helps me dissect the C++ code and provide a comprehensive answer that addresses all aspects of the request.
好的，这是对`blink/renderer/core/layout/layout_multi_column_flow_thread.cc` 文件第二部分的分析和功能归纳。

**功能列举 (基于提供的第二部分代码):**

这部分代码主要负责在多列布局中，当子元素被插入、移除或者样式发生变化时，动态维护和调整多列布局的结构，包括：

1. **处理子元素插入 (`FlowThreadDescendantWasInserted`):**
   - 当一个新的子元素被插入到多列容器中时，该函数负责确保新元素被正确地放置到一个列集中 (`LayoutMultiColumnSet`)。
   - 如果插入位置在跨列元素 (`LayoutMultiColumnSpannerPlaceholder`) 之前，它会创建或找到合适的列集。
   - 如果插入位置在多列容器的末尾，它会确保末尾存在一个列集。

2. **处理子元素移除 (`FlowThreadDescendantWillBeRemoved`):**
   - 当一个子元素（或子树）将被从多列容器中移除时，该函数负责清理相关的多列结构。
   - 它会移除不再需要的跨列占位符 (`LayoutMultiColumnSpannerPlaceholder`)。
   - 如果移除的内容导致相邻的两个跨列元素之间不再有内容，它会合并或移除中间的空列集 (`LayoutMultiColumnSet`)。

3. **处理子元素样式变化 (`FlowThreadDescendantStyleWillChange`, `FlowThreadDescendantStyleDidChange`):**
   - **`FlowThreadDescendantStyleWillChange`:** 在子元素的样式即将发生变化时调用。它会判断样式变化是否会导致该元素需要被移出多列流（例如，变成绝对定位）。如果需要移出，则调用 `FlowThreadDescendantWillBeRemoved`。它还会记录一些状态，用于后续 `FlowThreadDescendantStyleDidChange` 的处理。
   - **`FlowThreadDescendantStyleDidChange`:** 在子元素的样式变化之后调用。它会判断样式变化是否会导致该元素需要被插入多列流（例如，从绝对定位变为静态定位）。如果需要插入，则调用 `FlowThreadDescendantWasInserted`。
   - 特别地，它会处理元素从普通内容变为跨列元素，或从跨列元素变为普通内容的情况，并相应地创建或销毁跨列占位符。
   - 它还会处理多列容器自身是否能包含跨列元素状态的变化，并据此调整容器内已有的跨列元素。

4. **切换子树中的跨列元素 (`ToggleSpannersInSubtree`):**
   - 当多列容器自身是否能包含跨列元素的状态发生变化时，该函数会遍历其子树，将符合条件的普通元素转换为跨列元素，或将跨列元素变回普通元素。

5. **计算多列流的布局信息 (`LocationInternal`, `Size`, `UpdateGeometry`):**
   - 这部分函数负责计算并缓存多列流的位置和尺寸。
   - `UpdateGeometry` 遍历多列容器的物理片段（PhysicalFragment），计算出整个多列流的逻辑尺寸和位置。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **CSS:**
    * `column-span: all;` CSS 属性直接触发了 `LayoutMultiColumnSpannerPlaceholder` 的创建和管理。当一个元素的 CSS `column-span` 属性被设置为 `all` 时，`FlowThreadDescendantStyleDidChange` 会检测到这个变化，并调用 `CreateAndInsertSpannerPlaceholder` 来创建一个占位符。
    * CSS 定位属性 (`position: absolute`, `position: fixed`) 的变化会影响元素是否在多列流中。当一个元素从 `position: static` 变为 `position: absolute` 时，`FlowThreadDescendantStyleWillChange` 会调用 `FlowThreadDescendantWillBeRemoved` 将其移出多列结构。反之，当从 `position: absolute` 变为 `position: static` 时，`FlowThreadDescendantStyleDidChange` 会调用 `FlowThreadDescendantWasInserted` 将其重新插入。
    * 多列容器的 `column-width` 和 `column-count` 等属性决定了列集的创建和布局。虽然这段代码没有直接处理这些属性，但它们是多列布局的基础，影响着这里代码的执行环境。

* **HTML:**
    * HTML 元素的结构和顺序决定了多列布局的内容和排列。当 HTML 结构发生变化（例如，通过 JavaScript 添加或删除元素）时，会触发 `FlowThreadDescendantWasInserted` 和 `FlowThreadDescendantWillBeRemoved` 等函数来更新多列布局。

* **JavaScript:**
    * JavaScript 可以动态地修改 HTML 结构和 CSS 样式。例如，JavaScript 可以添加一个新的 `<div>` 元素到多列容器中，或者修改一个元素的 `column-span` 属性。这些操作会间接地触发这段 C++ 代码的执行，以保持渲染引擎内部多列布局结构与 DOM 和 CSS 的一致性。

**逻辑推理的假设输入与输出:**

**假设输入 1 (插入元素):**

* 多列容器当前有两个列集和一个跨列元素，结构如下： `[列集 1] [跨列元素] [列集 2]`
* JavaScript 在 "列集 1" 和 "跨列元素" 之间插入一个新的 `<div>` 元素。

**输出 1:**

* `FlowThreadDescendantWasInserted` 被调用。
* 代码检测到插入位置在一个跨列元素之前。
* 因为在跨列元素之前已经存在 "列集 1"，所以新插入的 `<div>` 元素会被添加到 "列集 1" 中。
* 多列结构保持为：`[列集 1 (包含新 div)] [跨列元素] [列集 2]`

**假设输入 2 (移除元素):**

* 多列容器当前有三个列集和两个跨列元素，结构如下： `[跨列元素 A] [列集 1] [跨列元素 B] [列集 2]`
* JavaScript 移除 "列集 1" 中的所有内容。

**输出 2:**

* 当 "列集 1" 中的最后一个元素被移除时，`FlowThreadDescendantWillBeRemoved` 被调用。
* 代码检测到被移除内容前后是两个跨列元素 ("跨列元素 A" 和 "跨列元素 B")。
* 因此，"列集 1" 会被销毁，"跨列元素 A" 和 "跨列元素 B" 会相邻。
* 多列结构变为：`[跨列元素 A] [跨列元素 B] [列集 2]` (注意：如果 "列集 2" 之前没有其他内容，并且 "跨列元素 B" 是最后一个元素，那么 "列集 2" 也可能被移除)。

**常见的使用错误举例说明:**

* **手动操作内部布局对象:**  开发者不应该尝试直接操作 `LayoutMultiColumnSet` 或 `LayoutMultiColumnSpannerPlaceholder` 等内部布局对象。这些对象由渲染引擎管理，直接修改可能导致状态不一致和崩溃。例如，尝试通过 JavaScript 获取并删除一个 `LayoutMultiColumnSet` 对象是错误的。

* **不理解跨列元素的限制:** 开发者可能会尝试在跨列元素内部创建新的多列布局，或者嵌套跨列元素。虽然浏览器可能会有一定的容错性，但这通常是不被支持的，并且可能导致意外的布局结果。这段代码中的逻辑会尽量维护一致性，例如，在处理样式变化时，会确保跨列元素不会嵌套。

* **过度依赖 JavaScript 操作 DOM 来实现复杂的多列布局动态效果:** 虽然 JavaScript 可以实现动态效果，但过度使用可能会导致频繁的布局计算和性能问题。理解 CSS 多列布局的原理，并尽量利用 CSS 来实现静态布局，可以提高性能。

**功能归纳 (基于提供的第二部分代码):**

这部分 `LayoutMultiColumnFlowThread` 的代码主要负责 **动态维护多列布局的结构** 以响应子元素的插入、移除和样式变化。它确保在这些操作发生后，多列容器内部的列集 (`LayoutMultiColumnSet`) 和跨列占位符 (`LayoutMultiColumnSpannerPlaceholder`) 能够正确地创建、销毁和调整，以反映最新的 DOM 结构和 CSS 样式。 此外，它还负责计算和缓存多列流的布局信息，为渲染过程提供必要的几何数据。 简而言之，这部分代码是多列布局在动态变化时保持一致性和正确性的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_multi_column_flow_thread.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
nerPlaceholder* placeholder =
              object_after_subtree->SpannerPlaceholder()) {
        // If inserted right before a spanner, we need to make sure that there's
        // a set for us there.
        LayoutBox* previous = placeholder->PreviousSiblingMultiColumnBox();
        if (!previous || !previous->IsLayoutMultiColumnSet())
          CreateAndInsertMultiColumnSet(placeholder);
      } else {
        // Otherwise, since |objectAfterSubtree| isn't a spanner, it has to mean
        // that there's already a set for that content. We can use it for this
        // layoutObject too.
        DCHECK(MapDescendantToColumnSet(object_after_subtree));
        DCHECK_EQ(MapDescendantToColumnSet(layout_object),
                  MapDescendantToColumnSet(object_after_subtree));
      }
    } else {
      // Inserting at the end. Then we just need to make sure that there's a
      // column set at the end.
      LayoutBox* last_column_box = LastMultiColumnBox();
      if (!last_column_box || !last_column_box->IsLayoutMultiColumnSet())
        CreateAndInsertMultiColumnSet();
    }
  }
}

void LayoutMultiColumnFlowThread::FlowThreadDescendantWillBeRemoved(
    LayoutObject* descendant) {
  NOT_DESTROYED();
  // This method ensures that the list of column sets and spanner placeholders
  // reflects the multicol content that we'll be left with after removal of a
  // descendant (or descendant subtree). See the header file for more
  // information. Removing content may mean that we need to remove column sets
  // and/or spanner placeholders.
  if (is_being_evacuated_)
    return;
  if (ShouldSkipInsertedOrRemovedChild(this, *descendant))
    return;
  bool had_containing_placeholder =
      ContainingColumnSpannerPlaceholder(descendant);
  bool processed_something = false;
  LayoutObject* next;
  // Remove spanner placeholders that are no longer needed, and merge column
  // sets around them.
  for (LayoutObject* layout_object = descendant; layout_object;
       layout_object = next) {
    if (layout_object != descendant &&
        ShouldSkipInsertedOrRemovedChild(this, *layout_object)) {
      next = layout_object->NextInPreOrderAfterChildren(descendant);
      continue;
    }
    processed_something = true;
    LayoutMultiColumnSpannerPlaceholder* placeholder =
        layout_object->SpannerPlaceholder();
    if (!placeholder) {
      next = layout_object->NextInPreOrder(descendant);
      continue;
    }
    next = layout_object->NextInPreOrderAfterChildren(
        descendant);  // It's a spanner. Its children are of no interest to us.
    DestroySpannerPlaceholder(placeholder);
  }
  if (had_containing_placeholder || !processed_something)
    return;  // No column content will be removed, so we can stop here.

  // Column content will be removed. Does this mean that we should destroy a
  // column set?
  LayoutMultiColumnSpannerPlaceholder* adjacent_previous_spanner_placeholder =
      nullptr;
  LayoutObject* previous_layout_object =
      PreviousInPreOrderSkippingOutOfFlow(this, descendant);
  if (previous_layout_object && previous_layout_object != this) {
    adjacent_previous_spanner_placeholder =
        ContainingColumnSpannerPlaceholder(previous_layout_object);
    if (!adjacent_previous_spanner_placeholder)
      return;  // Preceded by column content. Set still needed.
  }
  LayoutMultiColumnSpannerPlaceholder* adjacent_next_spanner_placeholder =
      nullptr;
  LayoutObject* next_layout_object =
      NextInPreOrderAfterChildrenSkippingOutOfFlow(this, descendant);
  if (next_layout_object) {
    adjacent_next_spanner_placeholder =
        ContainingColumnSpannerPlaceholder(next_layout_object);
    if (!adjacent_next_spanner_placeholder)
      return;  // Followed by column content. Set still needed.
  }
  // We have now determined that, with the removal of |descendant|, we should
  // remove a column set. Locate it and remove it. Do it without involving
  // mapDescendantToColumnSet(), as that might be very slow. Deduce the right
  // set from the spanner placeholders that we've already found.
  LayoutMultiColumnSet* column_set_to_remove;
  if (adjacent_next_spanner_placeholder) {
    LayoutBox* sibling =
        adjacent_next_spanner_placeholder->PreviousSiblingMultiColumnBox();
    CHECK(sibling->IsLayoutMultiColumnSet());
    column_set_to_remove = To<LayoutMultiColumnSet>(sibling);
    DCHECK(
        !adjacent_previous_spanner_placeholder ||
        column_set_to_remove ==
            adjacent_previous_spanner_placeholder->NextSiblingMultiColumnBox());
  } else if (adjacent_previous_spanner_placeholder) {
    LayoutBox* sibling =
        adjacent_previous_spanner_placeholder->NextSiblingMultiColumnBox();
    CHECK(sibling->IsLayoutMultiColumnSet());
    column_set_to_remove = To<LayoutMultiColumnSet>(sibling);
  } else {
    // If there were no adjacent spanners, it has to mean that there's only one
    // column set, since it's only spanners that may cause creation of
    // multiple sets.
    column_set_to_remove = FirstMultiColumnSet();
    DCHECK(column_set_to_remove);
    DCHECK(!column_set_to_remove->NextSiblingMultiColumnSet());
  }
  DCHECK(column_set_to_remove);
  column_set_to_remove->Destroy();
}

static inline bool NeedsToReinsertIntoFlowThread(
    const LayoutBoxModelObject& object,
    const ComputedStyle& old_style,
    const ComputedStyle& new_style) {
  // If we've become (or are about to become) a container for absolutely
  // positioned descendants, or if we're no longer going to be one, we need to
  // re-evaluate the need for column sets. There may be out-of-flow descendants
  // further down that become part of the flow thread, or cease to be part of
  // the flow thread, because of this change.
  if (object.ComputeIsFixedContainer(&old_style) !=
      object.ComputeIsFixedContainer(&new_style)) {
    return true;
  }
  return old_style.GetPosition() != new_style.GetPosition();
}

static inline bool NeedsToRemoveFromFlowThread(
    const LayoutBoxModelObject& object,
    const ComputedStyle& old_style,
    const ComputedStyle& new_style) {
  // This function is called BEFORE computed style update. If an in-flow
  // descendant goes out-of-flow, we may have to remove column sets and spanner
  // placeholders. Note that we may end up with false positives here, since some
  // out-of-flow descendants still need to be associated with a column set. This
  // is the case when the containing block of the soon-to-be out-of-flow
  // positioned descendant is contained by the same flow thread as the
  // descendant currently is inside. It's too early to check for that, though,
  // since the descendant at this point is still in-flow positioned. We'll
  // detect this and re-insert it into the flow thread when computed style has
  // been updated.
  return (new_style.HasOutOfFlowPosition() &&
          !old_style.HasOutOfFlowPosition()) ||
         NeedsToReinsertIntoFlowThread(object, old_style, new_style);
}

static inline bool NeedsToInsertIntoFlowThread(
    const LayoutMultiColumnFlowThread* flow_thread,
    const LayoutBoxModelObject* descendant,
    const ComputedStyle& old_style,
    const ComputedStyle& new_style) {
  // This function is called AFTER computed style update. If an out-of-flow
  // descendant goes in-flow, we may have to insert column sets and spanner
  // placeholders.
  bool toggled_out_of_flow =
      new_style.HasOutOfFlowPosition() != old_style.HasOutOfFlowPosition();
  if (toggled_out_of_flow) {
    // If we're no longer out-of-flow, we definitely need the descendant to be
    // associated with a column set.
    if (!new_style.HasOutOfFlowPosition())
      return true;
    const auto* containing_flow_thread =
        descendant->ContainingBlock()->FlowThreadContainingBlock();
    // If an out-of-flow positioned descendant is still going to be contained by
    // this flow thread, the descendant needs to be associated with a column
    // set.
    if (containing_flow_thread == flow_thread)
      return true;
  }
  return NeedsToReinsertIntoFlowThread(*flow_thread, old_style, new_style);
}

void LayoutMultiColumnFlowThread::FlowThreadDescendantStyleWillChange(
    LayoutBoxModelObject* descendant,
    StyleDifference diff,
    const ComputedStyle& new_style) {
  NOT_DESTROYED();
  toggle_spanners_if_needed_ = false;
  if (NeedsToRemoveFromFlowThread(*descendant, descendant->StyleRef(),
                                  new_style)) {
    FlowThreadDescendantWillBeRemoved(descendant);
#if DCHECK_IS_ON()
    style_changed_object_ = nullptr;
#endif
    return;
  }
#if DCHECK_IS_ON()
  style_changed_object_ = descendant;
#endif
  // Keep track of whether this object was of such a type that it could contain
  // column-span:all descendants. If the style change in progress changes this
  // state, we need to look for spanners to add or remove in the subtree of
  // |descendant|.
  toggle_spanners_if_needed_ = true;
  could_contain_spanners_ =
      CanContainSpannerInParentFragmentationContext(*descendant);
}

void LayoutMultiColumnFlowThread::FlowThreadDescendantStyleDidChange(
    LayoutBoxModelObject* descendant,
    StyleDifference diff,
    const ComputedStyle& old_style) {
  NOT_DESTROYED();

#if DCHECK_IS_ON()
  const auto* style_changed_box = style_changed_object_;
  style_changed_object_ = nullptr;
#endif

  bool toggle_spanners_if_needed = toggle_spanners_if_needed_;
  toggle_spanners_if_needed_ = false;

  if (NeedsToInsertIntoFlowThread(this, descendant, old_style,
                                  descendant->StyleRef())) {
    FlowThreadDescendantWasInserted(descendant);
    return;
  }
  if (DescendantIsValidColumnSpanner(descendant)) {
    // We went from being regular column content to becoming a spanner.
    DCHECK(!descendant->SpannerPlaceholder());

    // First remove this as regular column content. Note that this will walk the
    // entire subtree of |descendant|. There might be spanners there (which
    // won't be spanners anymore, since we're not allowed to nest spanners),
    // whose placeholders must die.
    FlowThreadDescendantWillBeRemoved(descendant);

    CreateAndInsertSpannerPlaceholder(
        To<LayoutBox>(descendant),
        NextInPreOrderAfterChildrenSkippingOutOfFlow(this, descendant));
    return;
  }

  if (!toggle_spanners_if_needed)
    return;

  if (could_contain_spanners_ ==
      CanContainSpannerInParentFragmentationContext(*descendant))
    return;

#if DCHECK_IS_ON()
  // Make sure that we were preceded by a call to
  // flowThreadDescendantStyleWillChange() with the same descendant as we have
  // now.
  if (style_changed_box)
    DCHECK_EQ(style_changed_box, descendant);
#endif

  ToggleSpannersInSubtree(descendant);
}

void LayoutMultiColumnFlowThread::ToggleSpannersInSubtree(
    LayoutBoxModelObject* descendant) {
  NOT_DESTROYED();
  DCHECK_NE(could_contain_spanners_,
            CanContainSpannerInParentFragmentationContext(*descendant));

  // If there are no spanners at all in this multicol container, there's no
  // need to look for any to remove.
  if (could_contain_spanners_ && !HasAnyColumnSpanners(*this))
    return;

  bool walk_children;
  for (LayoutObject* object = descendant->NextInPreOrder(descendant); object;
       object = walk_children
                    ? object->NextInPreOrder(descendant)
                    : object->NextInPreOrderAfterChildren(descendant)) {
    walk_children = false;
    if (!object->IsBox())
      continue;
    auto& box = To<LayoutBox>(*object);
    if (could_contain_spanners_) {
      // Remove all spanners (turn them into regular column content), as we can
      // no longer contain them.
      if (box.IsColumnSpanAll()) {
        DestroySpannerPlaceholder(box.SpannerPlaceholder());
        continue;
      }
    } else if (DescendantIsValidColumnSpanner(object)) {
      // We can now contain spanners, and we found a candidate. Turn it into a
      // spanner, if it's not already one. We have to check if it's already a
      // spanner, because in some cases we incorrectly think that we need to
      // toggle spanners. One known case is when some ancestor changes
      // writing-mode (which is an inherited property). Writing mode roots
      // establish block formatting context (which means that there can be no
      // column spanners inside). When changing the style on one object in the
      // tree at a time, we're going to see writing mode roots that are not
      // going to remain writing mode roots when all objects have been updated
      // (because then all will have got the same writing mode).
      if (!box.IsColumnSpanAll()) {
        CreateAndInsertSpannerPlaceholder(
            &box, NextInPreOrderAfterChildrenSkippingOutOfFlow(this, &box));
      }
      continue;
    }
    walk_children = CanContainSpannerInParentFragmentationContext(box);
  }
}

LayoutPoint LayoutMultiColumnFlowThread::LocationInternal() const {
  NOT_DESTROYED();
  if (!HasValidCachedGeometry() && EverHadLayout()) {
    // const_cast in order to update the cached value.
    const_cast<LayoutMultiColumnFlowThread*>(this)->UpdateGeometry();
  }
  return frame_location_;
}

PhysicalSize LayoutMultiColumnFlowThread::Size() const {
  NOT_DESTROYED();
  if (!HasValidCachedGeometry() && EverHadLayout()) {
    // const_cast in order to update the cached value.
    const_cast<LayoutMultiColumnFlowThread*>(this)->UpdateGeometry();
  }
  return frame_size_;
}

void LayoutMultiColumnFlowThread::UpdateGeometry() {
  NOT_DESTROYED();
  SetHasValidCachedGeometry(true);
  frame_location_ = LayoutPoint();
  LogicalSize thread_size;
  const LayoutBlockFlow* container = MultiColumnBlockFlow();
  if (container->PhysicalFragmentCount() == 0u) {
    frame_size_ = PhysicalSize();
    return;
  }
  const auto* first_fragment = container->GetPhysicalFragment(0);
  WritingModeConverter converter(first_fragment->Style().GetWritingDirection());
  bool has_processed_first_column_in_flow_thread = false;
  const BlockBreakToken* break_token = nullptr;
  for (const auto& container_fragment : container->PhysicalFragments()) {
    for (const auto& link : container_fragment.Children()) {
      const auto& child_fragment = To<PhysicalBoxFragment>(*link);
      if (!child_fragment.IsFragmentainerBox()) {
        continue;
      }
      LogicalSize logical_size = FragmentainerLogicalCapacity(child_fragment);
      thread_size.block_size += logical_size.block_size;
      if (!has_processed_first_column_in_flow_thread) {
        // The offset of the flow thread is the same as that of the first
        // column.
        frame_location_ = LayoutBoxUtils::ComputeLocation(
            child_fragment, link.Offset(), container_fragment, break_token);

        thread_size.inline_size = logical_size.inline_size;
        has_processed_first_column_in_flow_thread = true;
      }
    }
    break_token = container_fragment.GetBreakToken();
    if (!break_token || break_token->IsRepeated() ||
        break_token->IsAtBlockEnd()) {
      break;
    }
  }
  frame_size_ = converter.ToPhysical(thread_size);
}

}  // namespace blink
```