Response:
The user is asking for a summary of the functionality of the `PhysicalBoxFragment` class in the Chromium Blink rendering engine, based on the provided C++ code snippet.

Here's a breakdown of the thinking process to arrive at the summary:

1. **Identify the core purpose:** The class name `PhysicalBoxFragment` strongly suggests that this class represents a fragment of a layout box. The code confirms this by managing properties like size, offset, and children.

2. **Analyze key methods and data members:**  Read through the methods and data members to understand their roles. Look for patterns and connections.

    * **Fragmentation:** Methods like `UpdateOutOfFlowFragmentChild`, `GetBreakToken`, and the mention of "monolithic overflow (printing)" clearly indicate a role in handling layout fragmentation, especially for out-of-flow positioned elements.

    * **Overflow:**  Methods like `UpdateOverflow`, `SetInkOverflow`, `RecalcInkOverflow`, and `ComputeSelfInkOverflow` are central to managing different types of overflow (scrollable and ink).

    * **Outline:**  The `AddSelfOutlineRects` and `AddOutlineRects` methods point to functionality for drawing outlines around boxes.

    * **Positioning (hit testing):** The `PositionForPoint` family of methods is crucial for determining the location within a fragment based on a given point, which is vital for things like mouse clicks and text selection. The logic within these methods deals with different layout scenarios (block flow, tables, etc.).

    * **Children Management:** The presence of `Children()` and methods interacting with children fragments (`RecalcContentsInkOverflow`, `AddOutlineRectsForNormalChildren`, `PositionForPointByClosestChild`) highlights its role as a container for other fragments.

    * **Ink Overflow:**  Specific methods like `SetInkOverflow` and `RecalcInkOverflow` suggest this class is responsible for calculating and managing the "ink overflow," which is the area where ink-related effects (like shadows and decorations) might paint outside the normal content box.

3. **Connect to web technologies:** Consider how these functionalities relate to HTML, CSS, and JavaScript:

    * **HTML:** The structure of HTML documents directly translates into the hierarchy of layout boxes and their fragments. The `PhysicalBoxFragment` represents a part of this visual structure.

    * **CSS:** CSS properties like `overflow`, `outline`, `position: absolute/fixed`, and properties that affect ink overflow (e.g., `box-shadow`, `text-decoration`) directly influence the behavior and calculations within `PhysicalBoxFragment`.

    * **JavaScript:** While `PhysicalBoxFragment` is a C++ class, its effects are visible through the browser's rendering. JavaScript can trigger layout changes that necessitate the creation, modification, and usage of `PhysicalBoxFragment` objects. Hit-testing, which involves `PositionForPoint`, is often triggered by JavaScript events.

4. **Infer logical reasoning:**  Examine the conditional statements and loops within the methods to understand the underlying logic. Consider potential inputs and outputs. For example, in `PositionForPointByClosestChild`, the logic iterates through children to find the closest one to a given point. Inputs could be a point within the fragment, and the output would be the position within the closest child.

5. **Identify potential user/programming errors:** Think about how incorrect CSS or JavaScript could lead to issues related to this class. For example, setting `overflow: hidden` might prevent certain ink overflow effects from being visible, or incorrect positioning of elements could lead to unexpected fragment arrangements.

6. **Synthesize the information into a concise summary:**  Group related functionalities and express them clearly. Use the insights gained from the previous steps to create a comprehensive yet understandable overview. Since this is part 2, focus on the functionalities presented in this specific snippet.

7. **Review and refine:** Ensure the summary is accurate, covers the key aspects of the code, and is easy to understand for someone familiar with web development concepts. Specifically for part 2, focus on the functionalities *only* within this provided snippet and acknowledge the context of it being part of a larger class.
这是`blink/renderer/core/layout/physical_box_fragment.cc`文件的第二部分，延续了第一部分对`PhysicalBoxFragment`类的功能定义。基于提供的代码片段，我们可以归纳出以下功能：

**核心功能延续：处理盒子的物理布局信息，特别是与分片、溢出和定位相关的方面。**

具体功能点如下：

1. **更新溢出碎片子元素信息：**
   - `UpdateOutOfFlowFragmentChild(const PhysicalBoxFragment& new_child, const PhysicalBoxFragment& placeholder_fragmentainer)`：  当添加一个脱离文档流（out-of-flow）的子元素分片时，会更新当前分片的 `has_out_of_flow_fragment_child_` 标志。
   - **与CSS的关系：** 当CSS中使用了 `position: absolute` 或 `position: fixed` 时，会创建脱离文档流的元素。这个方法就是处理这些元素的布局分片。
   - **假设输入与输出：**
     - **假设输入：** 一个新的脱离文档流的 `PhysicalBoxFragment` (`new_child`) 和其占位符容器的 `PhysicalBoxFragment` (`placeholder_fragmentainer`)。
     - **输出：** 当前 `PhysicalBoxFragment` 对象的 `has_out_of_flow_fragment_child_` 标志被设置为 `true`。如果占位符容器有断点信息或锚点查询信息，也会被合并到当前分片中。
   - **逻辑推理：**  脱离文档流的元素可能会影响父容器的布局和滚动行为，因此需要记录是否有这样的子元素。

2. **更新溢出信息：**
   - `MutableForOofFragmentation::UpdateOverflow()`： 重新计算分片的滚动溢出区域，并更新到分片的样式信息中。
   - **与CSS的关系：**  与CSS的 `overflow` 属性相关。决定了当内容超出盒子大小时如何显示。
   - **逻辑推理：** 当盒子的内容或子元素发生变化时，可能需要重新计算溢出区域。

3. **设置和重新计算 Ink Overflow（墨水溢出）：**
   - `SetInkOverflow(const PhysicalRect& self, const PhysicalRect& contents)`： 设置分片的墨水溢出区域。
   - `RecalcInkOverflow(const PhysicalRect& contents)`： 基于内容区域重新计算墨水溢出区域。
   - `RecalcInkOverflow()`：  重新计算自身的墨水溢出区域，并可能将计算结果复制到拥有该分片的 `LayoutBox` 对象。
   - **与CSS的关系：**  与影响绘制效果的CSS属性相关，例如 `box-shadow`, `text-decoration` 等。墨水溢出区域定义了这些效果可能绘制的范围。
   - **用户或编程常见的使用错误：**  如果CSS中设置了较大的 `box-shadow`，但父元素的 `overflow` 设置为 `hidden`，可能会导致阴影被裁剪，但墨水溢出计算仍然会包含阴影的范围。

4. **计算自身的 Ink Overflow：**
   - `ComputeSelfInkOverflow() const`：  计算自身（不包括子元素）的墨水溢出区域，考虑了边框、轮廓等因素。
   - **与CSS的关系：** 直接关联到边框 (`border`)、轮廓 (`outline`) 以及其他视觉溢出相关的 CSS 属性。
   - **逻辑推理：**  不同类型的盒子（例如 `TableRow`）可能有特殊的墨水溢出计算规则。

5. **添加轮廓线矩形：**
   - `AddSelfOutlineRects(...)` 和 `AddOutlineRects(...)`：  用于收集分片的轮廓线矩形，这些矩形用于绘制元素的轮廓。
   - **与CSS的关系：**  与CSS的 `outline` 属性直接相关。
   - **逻辑推理：**  轮廓线的绘制需要考虑元素自身以及子元素的形状和位置。对于内联盒子，需要特殊处理以合并所有分片的轮廓。

6. **根据点查找位置：**
   - `PositionForPoint(PhysicalOffset point) const`：  给定一个物理偏移量，找到该点在分片内的逻辑位置，常用于点击测试和文本选择。
   - `PositionForPointByClosestChild(PhysicalOffset point_in_contents) const`：  如果直接点击到子元素，则找到距离该点最近的子元素，并在子元素中查找位置。
   - `PositionForPointInBlockFlowDirection(PhysicalOffset point_in_contents) const`：  在块级布局流中，根据点的垂直位置查找相应的子元素并确定位置。
   - `PositionForPointInTable(PhysicalOffset point_in_contents) const`：  在表格布局中查找点击位置。
   - `PositionForPointRespectingEditingBoundaries(...) const`： 在考虑编辑边界的情况下，查找点击位置。
   - **与JavaScript, HTML, CSS的关系：**  当用户在浏览器中点击某个位置时，浏览器需要确定点击发生在哪个元素上。`PositionForPoint` 系列方法就是实现这种 "hit testing" 的关键。不同的布局方式（块级、内联、表格等）需要不同的查找策略。
   - **假设输入与输出：**
     - **假设输入：**  一个相对于当前分片的物理坐标点。
     - **输出：**  一个 `PositionWithAffinity` 对象，表示该点在分片内容中的逻辑位置，包括节点和偏移量信息。
   - **逻辑推理：**  需要考虑不同的布局模式和子元素的排列方式来精确确定点击位置。例如，在块级布局中，垂直位置是主要的判断依据；在表格中，则需要考虑行列的结构。

7. **计算溢出裁剪边距外延：**
   - `OverflowClipMarginOutsets() const`： 计算溢出裁剪边距的外延尺寸。
   - **与CSS的关系：**  与CSS的 `overflow-clip-margin` 属性相关，该属性定义了内容可以溢出盒子边框多远而不被裁剪。

8. **调试和一致性检查（DCHECK_IS_ON）：**
   - `InvalidateInkOverflow()`: 使墨水溢出信息失效，用于调试。
   - `AllowPostLayoutScope`:  一个用于控制是否允许进行后布局阶段操作的辅助类。
   - `CheckSameForSimplifiedLayout(...) const`:  在简化布局场景下，检查当前分片与其他分片的状态是否一致。
   - `CheckIntegrity() const`:  检查分片的内部状态是否一致，例如子元素的类型标志是否正确。
   - `AssertFragmentTreeSelf() const` 和 `AssertFragmentTreeChildren(...) const`:  用于断言分片树的结构是否符合预期。
   - **编程常见的使用错误：**  在进行性能优化时，可能会尝试使用简化布局。`CheckSameForSimplifiedLayout` 可以帮助开发者发现简化布局是否导致了不一致的状态。

9. **追踪（Tracing）：**
   - `TraceAfterDispatch(Visitor* visitor) const`:  用于在垃圾回收或调试时追踪对象之间的引用关系。

**总结来说，`PhysicalBoxFragment` 的这部分代码主要负责处理盒子的物理布局细节，特别关注以下方面：**

* **分片管理：** 处理脱离文档流元素的碎片信息。
* **溢出控制：** 计算和管理滚动溢出和墨水溢出区域。
* **轮廓绘制：** 收集用于绘制元素轮廓的矩形信息。
* **点击测试：** 提供根据屏幕坐标查找元素内容位置的功能，这是浏览器事件处理的基础。
* **调试和一致性检查：** 提供一系列用于调试和确保布局信息一致性的方法。

这些功能是浏览器渲染引擎核心布局流程的关键组成部分，确保了网页内容能够正确地显示和交互。

### 提示词
```
这是目录为blink/renderer/core/layout/physical_box_fragment.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
DCHECK(new_child->IsOutOfFlowPositioned());
    fragment_.has_out_of_flow_fragment_child_ = true;
  }

  // The existing break token may need to be updated, because of monolithic
  // overflow (printing).
  if (const BlockBreakToken* new_break_token =
          placeholder_fragmentainer.GetBreakToken()) {
    if (const BlockBreakToken* old_break_token = fragment_.GetBreakToken()) {
      old_break_token->GetMutableForOofFragmentation().Merge(*new_break_token);
    } else {
      fragment_.break_token_ = new_break_token;
    }
  }

  // Copy over any additional anchor queries.
  if (const PhysicalAnchorQuery* query =
          placeholder_fragmentainer.AnchorQuery()) {
    if (!fragment_.oof_data_) {
      fragment_.oof_data_ = MakeGarbageCollected<OofData>();
    }
    for (auto entry : *query) {
      fragment_.oof_data_->AnchorQuery().insert(entry.key, entry.value);
    }
  }

  UpdateOverflow();
}

void PhysicalBoxFragment::MutableForOofFragmentation::UpdateOverflow() {
  PhysicalRect overflow =
      ScrollableOverflowCalculator::RecalculateScrollableOverflowForFragment(
          fragment_, /* has_block_fragmentation */ true);
  fragment_.GetMutableForStyleRecalc().SetScrollableOverflow(overflow);
}

void PhysicalBoxFragment::SetInkOverflow(const PhysicalRect& self,
                                         const PhysicalRect& contents) {
  SetInkOverflowType(
      ink_overflow_.Set(InkOverflowType(), self, contents, Size()));
}

void PhysicalBoxFragment::RecalcInkOverflow(const PhysicalRect& contents) {
  const PhysicalRect self_rect = ComputeSelfInkOverflow();
  SetInkOverflow(self_rect, contents);
}

void PhysicalBoxFragment::RecalcInkOverflow() {
  DCHECK(CanUseFragmentsForInkOverflow());
  const LayoutObject* layout_object = GetSelfOrContainerLayoutObject();
  DCHECK(layout_object);
  DCHECK(
      !DisplayLockUtilities::LockedAncestorPreventingPrePaint(*layout_object));

  PhysicalRect contents_rect;
  if (!layout_object->ChildPrePaintBlockedByDisplayLock())
    contents_rect = RecalcContentsInkOverflow();
  RecalcInkOverflow(contents_rect);

  // Copy the computed values to the |OwnerBox| if |this| is the last fragment.

  // Fragmentainers may or may not have |BreakToken|s, and that
  // |CopyVisualOverflowFromFragments| cannot compute stitched coordinate for
  // them. See crbug.com/1197561.
  if (IsFragmentainerBox()) [[unlikely]] {
    return;
  }

  if (GetBreakToken()) {
    DCHECK_NE(this, &OwnerLayoutBox()->PhysicalFragments().back());
    return;
  }
  DCHECK_EQ(this, &OwnerLayoutBox()->PhysicalFragments().back());

  // We need to copy to the owner box, but |OwnerLayoutBox| should be equal to
  // |GetLayoutObject| except for column boxes, and since we early-return for
  // column boxes, |GetMutableLayoutObject| should do the work.
  DCHECK_EQ(MutableOwnerLayoutBox(), GetMutableLayoutObject());
  LayoutBox* owner_box = To<LayoutBox>(GetMutableLayoutObject());
  DCHECK(owner_box);
  DCHECK(owner_box->PhysicalFragments().Contains(*this));
  owner_box->CopyVisualOverflowFromFragments();
}

// Recalculate ink overflow of children. Returns the contents ink overflow
// for |this|.
PhysicalRect PhysicalBoxFragment::RecalcContentsInkOverflow() {
  DCHECK(GetSelfOrContainerLayoutObject());
  DCHECK(!DisplayLockUtilities::LockedAncestorPreventingPrePaint(
      *GetSelfOrContainerLayoutObject()));
  DCHECK(
      !GetSelfOrContainerLayoutObject()->ChildPrePaintBlockedByDisplayLock());

  PhysicalRect contents_rect;
  if (const FragmentItems* items = Items()) {
    InlineCursor cursor(*this, *items);
    InlinePaintContext child_inline_context;
    contents_rect = FragmentItem::RecalcInkOverflowForCursor(
        &cursor, &child_inline_context);

    // Add text decorations and emphasis mark ink over flow for combined
    // text.
    const auto* const text_combine =
        DynamicTo<LayoutTextCombine>(GetLayoutObject());
    if (text_combine) [[unlikely]] {
      // Reset the cursor for text combine to provide a current item for
      // decorations.
      InlineCursor text_combine_cursor(*this, *items);
      contents_rect.Unite(
          text_combine->RecalcContentsInkOverflow(text_combine_cursor));
    }

    // Even if this turned out to be an inline formatting context with
    // fragment items (handled above), we need to handle floating descendants.
    // If a float is block-fragmented, it is resumed as a regular box fragment
    // child, rather than becoming a fragment item.
    if (!HasFloatingDescendantsForPaint())
      return contents_rect;
  }

  for (const PhysicalFragmentLink& child : PostLayoutChildren()) {
    const auto* child_fragment = DynamicTo<PhysicalBoxFragment>(child.get());
    if (!child_fragment || child_fragment->HasSelfPaintingLayer())
      continue;
    DCHECK(!child_fragment->IsOutOfFlowPositioned());

    PhysicalRect child_rect;
    if (child_fragment->CanUseFragmentsForInkOverflow()) {
      child_fragment->GetMutableForPainting().RecalcInkOverflow();
      child_rect = child_fragment->InkOverflowRect();
    } else {
      LayoutBox* child_layout_object = child_fragment->MutableOwnerLayoutBox();
      DCHECK(child_layout_object);
      DCHECK(!child_layout_object->CanUseFragmentsForVisualOverflow());
      child_layout_object->RecalcVisualOverflow();
      // TODO(crbug.com/1144203): Reconsider this when fragment-based ink
      // overflow supports block fragmentation. Never allow flow threads to
      // propagate overflow up to a parent.
      DCHECK_EQ(child_fragment->IsColumnBox(),
                child_layout_object->IsLayoutFlowThread());
      if (child_fragment->IsColumnBox())
        continue;
      child_rect = child_layout_object->VisualOverflowRect();
    }
    child_rect.offset += child.offset;
    contents_rect.Unite(child_rect);
  }
  return contents_rect;
}

PhysicalRect PhysicalBoxFragment::ComputeSelfInkOverflow() const {
  DCHECK_EQ(PostLayout(), this);
  const ComputedStyle& style = Style();

  PhysicalRect ink_overflow(LocalRect());
  if (IsTableRow()) [[unlikely]] {
    // This is necessary because table-rows paints beyond border box if it
    // contains rowspanned cells.
    for (const PhysicalFragmentLink& child : PostLayoutChildren()) {
      const auto& child_fragment = To<PhysicalBoxFragment>(*child);
      if (!child_fragment.IsTableCell()) {
        continue;
      }
      const auto* child_layout_object =
          To<LayoutTableCell>(child_fragment.GetLayoutObject());
      if (child_layout_object->ComputedRowSpan() == 1)
        continue;
      PhysicalRect child_rect;
      if (child_fragment.CanUseFragmentsForInkOverflow())
        child_rect = child_fragment.InkOverflowRect();
      else
        child_rect = child_layout_object->VisualOverflowRect();
      child_rect.offset += child.offset;
      ink_overflow.Unite(child_rect);
    }
  }

  if (!style.HasVisualOverflowingEffect())
    return ink_overflow;

  ink_overflow.Expand(style.BoxDecorationOutsets());

  if (style.HasOutline() && IsOutlineOwner()) {
    UnionOutlineRectCollector collector;
    LayoutObject::OutlineInfo info;
    // The result rects are in coordinates of this object's border box.
    AddSelfOutlineRects(PhysicalOffset(),
                        style.OutlineRectsShouldIncludeBlockInkOverflow(),
                        collector, &info);
    PhysicalRect rect = collector.Rect();
    rect.Inflate(LayoutUnit(OutlinePainter::OutlineOutsetExtent(style, info)));
    ink_overflow.Unite(rect);
  }
  return ink_overflow;
}

#if DCHECK_IS_ON()
void PhysicalBoxFragment::InvalidateInkOverflow() {
  SetInkOverflowType(ink_overflow_.Invalidate(InkOverflowType()));
}
#endif

void PhysicalBoxFragment::AddSelfOutlineRects(
    const PhysicalOffset& additional_offset,
    OutlineType outline_type,
    OutlineRectCollector& collector,
    LayoutObject::OutlineInfo* info) const {
  if (info) {
    if (IsSvgText())
      *info = LayoutObject::OutlineInfo::GetUnzoomedFromStyle(Style());
    else
      *info = LayoutObject::OutlineInfo::GetFromStyle(Style());
  }

  if (ShouldIncludeBlockInkOverflow(outline_type) &&
      IsA<HTMLAnchorElement>(GetNode())) {
    outline_type = OutlineType::kIncludeBlockInkOverflowForAnchor;
  }

  AddOutlineRects(additional_offset, outline_type,
                  /* container_relative */ false, collector);
}

void PhysicalBoxFragment::AddOutlineRects(
    const PhysicalOffset& additional_offset,
    OutlineType outline_type,
    OutlineRectCollector& collector) const {
  AddOutlineRects(additional_offset, outline_type,
                  /* container_relative */ true, collector);
}

void PhysicalBoxFragment::AddOutlineRects(
    const PhysicalOffset& additional_offset,
    OutlineType outline_type,
    bool inline_container_relative,
    OutlineRectCollector& collector) const {
  DCHECK_EQ(PostLayout(), this);

  if (IsInlineBox()) {
    AddOutlineRectsForInlineBox(additional_offset, outline_type,
                                inline_container_relative, collector);
    return;
  }
  DCHECK(IsOutlineOwner());

  // For anonymous blocks, the children add outline rects.
  if (!IsAnonymousBlock() || GetBoxType() == kPageBorderBox) {
    if (IsSvgText()) {
      if (Items()) {
        collector.AddRect(PhysicalRect::EnclosingRect(
            GetLayoutObject()->ObjectBoundingBox()));
      }
    } else {
      collector.AddRect(PhysicalRect(additional_offset, Size()));
    }
  }

  if (ShouldIncludeBlockInkOverflow(outline_type) && !HasNonVisibleOverflow() &&
      !HasControlClip(*this)) {
    // Tricky code ahead: we pass a 0,0 additional_offset to
    // AddOutlineRectsForNormalChildren, and add it in after the call.
    // This is necessary because AddOutlineRectsForNormalChildren expects
    // additional_offset to be an offset from containing_block.
    // Since containing_block is our layout object, offset must be 0,0.
    // https://crbug.com/968019
    std::unique_ptr<OutlineRectCollector> child_collector =
        collector.ForDescendantCollector();
    AddOutlineRectsForNormalChildren(
        *child_collector, PhysicalOffset(), outline_type,
        To<LayoutBoxModelObject>(GetLayoutObject()));
    collector.Combine(child_collector.get(), additional_offset);

    if (ShouldIncludeBlockInkOverflowForAnchorOnly(outline_type)) {
      for (const auto& child : PostLayoutChildren()) {
        if (!child->IsOutOfFlowPositioned()) {
          continue;
        }

        AddOutlineRectsForDescendant(
            child, collector, additional_offset, outline_type,
            To<LayoutBoxModelObject>(GetLayoutObject()));
      }
    }
  }
  // TODO(kojii): Needs inline_element_continuation logic from
  // LayoutBlockFlow::AddOutlineRects?
}

void PhysicalBoxFragment::AddOutlineRectsForInlineBox(
    PhysicalOffset additional_offset,
    OutlineType outline_type,
    bool container_relative,
    OutlineRectCollector& collector) const {
  DCHECK_EQ(PostLayout(), this);
  DCHECK(IsInlineBox());

  const PhysicalBoxFragment* container =
      InlineContainerFragmentIfOutlineOwner();
  if (!container)
    return;

  // In order to compute united outlines, collect all rectangles of inline
  // fragments for |LayoutInline| if |this| is the first inline fragment.
  // Otherwise return none.
  //
  // When |LayoutInline| is block fragmented, unite rectangles for each block
  // fragment.
  DCHECK(GetLayoutObject());
  DCHECK(GetLayoutObject()->IsLayoutInline());
  const auto* layout_object = To<LayoutInline>(GetLayoutObject());
  std::unique_ptr<OutlineRectCollector> cursor_collector =
      collector.ForDescendantCollector();
  InlineCursor cursor(*container);
  cursor.MoveTo(*layout_object);
  DCHECK(cursor);
  const PhysicalOffset this_offset_in_container =
      cursor.Current()->OffsetInContainerFragment();
#if DCHECK_IS_ON()
  bool has_this_fragment = false;
#endif
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    const InlineCursorPosition& current = cursor.Current();
#if DCHECK_IS_ON()
    has_this_fragment = has_this_fragment || current.BoxFragment() == this;
#endif
    if (!current.Size().IsZero()) {
      const PhysicalBoxFragment* fragment = current.BoxFragment();
      DCHECK(fragment);
      if (!fragment->IsOpaque() && !fragment->IsSvg()) {
        cursor_collector->AddRect(current.RectInContainerFragment());
      }
    }

    // Add descendants if any, in the container-relative coordinate.
    if (!current.HasChildren())
      continue;
    InlineCursor descendants = cursor.CursorForDescendants();
    AddOutlineRectsForCursor(*cursor_collector, PhysicalOffset(), outline_type,
                             layout_object, &descendants);
  }
#if DCHECK_IS_ON()
  DCHECK(has_this_fragment);
#endif
  // TODO(vmpstr): Is this correct? Should AddOutlineRectsForDescendants below
  // be skipped?
  if (cursor_collector->IsEmpty()) {
    return;
  }

  // At this point, |rects| are in the container coordinate space.
  // Adjust the rectangles using |additional_offset| and |container_relative|.
  if (!container_relative)
    additional_offset -= this_offset_in_container;
  collector.Combine(cursor_collector.get(), additional_offset);

  if (ShouldIncludeBlockInkOverflowForAnchorOnly(outline_type) &&
      !HasNonVisibleOverflow() && !HasControlClip(*this)) {
    for (const auto& child : container->PostLayoutChildren()) {
      if (!child->IsOutOfFlowPositioned() ||
          child->GetLayoutObject()->ContainerForAbsolutePosition() !=
              layout_object) {
        continue;
      }

      AddOutlineRectsForDescendant(child, collector, additional_offset,
                                   outline_type, layout_object);
    }
  }
}

PositionWithAffinity PhysicalBoxFragment::PositionForPoint(
    PhysicalOffset point) const {
  if (layout_object_->IsBox() && !layout_object_->IsLayoutNGObject()) {
    // Layout engine boundary. Enter legacy PositionForPoint().
    return layout_object_->PositionForPoint(point);
  }

  const PhysicalOffset point_in_contents =
      IsScrollContainer()
          ? point + PhysicalOffset(PixelSnappedScrolledContentOffset())
          : point;

  if (!layout_object_->ChildPaintBlockedByDisplayLock()) {
    if (const FragmentItems* items = Items()) {
      InlineCursor cursor(*this, *items);
      if (const PositionWithAffinity position =
              cursor.PositionForPointInInlineFormattingContext(
                  point_in_contents, *this))
        return AdjustForEditingBoundary(position);
      return layout_object_->CreatePositionWithAffinity(0);
    }
  }

  if (IsA<LayoutBlockFlow>(*layout_object_) &&
      layout_object_->ChildrenInline()) {
    // Here |this| may have out-of-flow children without inline children, we
    // don't find closest child of |point| for out-of-flow children.
    // See WebFrameTest.SmartClipData
    return layout_object_->CreatePositionWithAffinity(0);
  }

  if (layout_object_->IsTable())
    return PositionForPointInTable(point_in_contents);

  if (ShouldUsePositionForPointInBlockFlowDirection(*layout_object_))
    return PositionForPointInBlockFlowDirection(point_in_contents);

  return PositionForPointByClosestChild(point_in_contents);
}

PositionWithAffinity PhysicalBoxFragment::PositionForPointByClosestChild(
    PhysicalOffset point_in_contents) const {
  if (layout_object_->ChildPaintBlockedByDisplayLock()) {
    // If this node is DisplayLocked, then Children() will have invalid layout
    // information.
    return AdjustForEditingBoundary(
        FirstPositionInOrBeforeNode(*layout_object_->GetNode()));
  }

  PhysicalFragmentLink closest_child = {nullptr};
  LayoutUnit shortest_distance = LayoutUnit::Max();
  bool found_hit_test_candidate = false;
  const PhysicalSize pixel_size(LayoutUnit(1), LayoutUnit(1));
  const PhysicalRect point_rect(point_in_contents, pixel_size);

  // This is a general-purpose algorithm for finding the nearest child. There
  // may be cases where want to introduce specialized algorithms that e.g. takes
  // the progression direction into account (so that we can break earlier, or
  // even add special behavior). Children in block containers progress in the
  // block direction, for instance, while table cells progress in the inline
  // direction. Flex containers may progress in the inline direction, reverse
  // inline direction, block direction or reverse block direction. Multicol
  // containers progress both in the inline direction (columns) and block
  // direction (column rows and spanners).
  for (const PhysicalFragmentLink& child : Children()) {
    const auto& box_fragment = To<PhysicalBoxFragment>(*child.fragment);
    bool is_hit_test_candidate = IsHitTestCandidate(box_fragment);
    if (!is_hit_test_candidate) {
      if (found_hit_test_candidate)
        continue;
      // We prefer valid hit-test candidates, but if there are no such children,
      // we'll lower our requirements somewhat. The exact reasoning behind the
      // details here is unknown, but it is something that evolved during
      // WebKit's early years.
      if (box_fragment.Style().Visibility() != EVisibility::kVisible ||
          (box_fragment.Children().empty() && !box_fragment.IsBlockFlow())) {
        continue;
      }
    }

    PhysicalRect child_rect(child.offset, child->Size());
    LayoutUnit horizontal_distance;
    if (child_rect.X() > point_rect.X())
      horizontal_distance = child_rect.X() - point_rect.X();
    else if (point_rect.Right() > child_rect.Right())
      horizontal_distance = point_rect.Right() - child_rect.Right();
    LayoutUnit vertical_distance;
    if (child_rect.Y() > point_rect.Y())
      vertical_distance = child_rect.Y() - point_rect.Y();
    else if (point_rect.Bottom() > child_rect.Bottom())
      vertical_distance = point_rect.Bottom() - child_rect.Bottom();

    if (!horizontal_distance && !vertical_distance) {
      // We actually hit a child. We're done.
      closest_child = child;
      break;
    }

    const LayoutUnit distance = horizontal_distance * horizontal_distance +
                                vertical_distance * vertical_distance;

    if (shortest_distance > distance ||
        (is_hit_test_candidate && !found_hit_test_candidate)) {
      // This child is either closer to the point than any previous child, or
      // this is the first child that is an actual hit-test candidate.
      shortest_distance = distance;
      closest_child = child;
      found_hit_test_candidate = is_hit_test_candidate;
    }
  }

  if (!closest_child.fragment)
    return layout_object_->FirstPositionInOrBeforeThis();
  return To<PhysicalBoxFragment>(*closest_child)
      .PositionForPoint(point_in_contents - closest_child.offset);
}

PositionWithAffinity PhysicalBoxFragment::PositionForPointInBlockFlowDirection(
    PhysicalOffset point_in_contents) const {
  // Note: Children of <table> and "columns" are not laid out in block flow
  // direction.
  DCHECK(!layout_object_->IsTable()) << this;
  DCHECK(ShouldUsePositionForPointInBlockFlowDirection(*layout_object_))
      << this;

  if (layout_object_->ChildPaintBlockedByDisplayLock()) {
    // If this node is DisplayLocked, then Children() will have invalid layout
    // information.
    return AdjustForEditingBoundary(
        FirstPositionInOrBeforeNode(*layout_object_->GetNode()));
  }

  const bool blocks_are_flipped = Style().IsFlippedBlocksWritingMode();
  WritingModeConverter converter(Style().GetWritingDirection(), Size());
  const LogicalOffset logical_point_in_contents =
      converter.ToLogical(point_in_contents, PhysicalSize());

  // Loop over block children to find a child logically below
  // |point_in_contents|.
  const PhysicalFragmentLink* last_candidate_box = nullptr;
  for (const PhysicalFragmentLink& child : Children()) {
    const auto& box_fragment = To<PhysicalBoxFragment>(*child.fragment);
    if (!IsHitTestCandidate(box_fragment))
      continue;
    // We hit child if our click is above the bottom of its padding box (like
    // IE6/7 and FF3).
    const LogicalRect logical_child_rect =
        converter.ToLogical(PhysicalRect(child.offset, box_fragment.Size()));
    if (logical_point_in_contents.block_offset <
            logical_child_rect.BlockEndOffset() ||
        (blocks_are_flipped && logical_point_in_contents.block_offset ==
                                   logical_child_rect.BlockEndOffset())) {
      // |child| is logically below |point_in_contents|.
      return PositionForPointRespectingEditingBoundaries(
          To<PhysicalBoxFragment>(*child.fragment),
          point_in_contents - child.offset);
    }

    // |last_candidate_box| is logical above |point_in_contents|.
    last_candidate_box = &child;
  }

  // Here all children are logically above |point_in_contents|.
  if (last_candidate_box) {
    // editing/selection/block-with-positioned-lastchild.html reaches here.
    return PositionForPointRespectingEditingBoundaries(
        To<PhysicalBoxFragment>(*last_candidate_box->fragment),
        point_in_contents - last_candidate_box->offset);
  }

  // We only get here if there are no hit test candidate children below the
  // click.
  return PositionForPointByClosestChild(point_in_contents);
}

PositionWithAffinity PhysicalBoxFragment::PositionForPointInTable(
    PhysicalOffset point_in_contents) const {
  DCHECK(layout_object_->IsTable()) << this;
  if (!layout_object_->NonPseudoNode())
    return PositionForPointByClosestChild(point_in_contents);

  // Adjust for writing-mode:vertical-rl
  const LayoutUnit adjusted_left = Style().IsFlippedBlocksWritingMode()
                                       ? Size().width - point_in_contents.left
                                       : point_in_contents.left;
  if (adjusted_left < 0 || adjusted_left > Size().width ||
      point_in_contents.top < 0 || point_in_contents.top > Size().height) {
    // |point_in_contents| is outside of <table>.
    // See editing/selection/click-before-and-after-table.html
    if (adjusted_left <= Size().width / 2)
      return layout_object_->FirstPositionInOrBeforeThis();
    return layout_object_->LastPositionInOrAfterThis();
  }

  return PositionForPointByClosestChild(point_in_contents);
}

PositionWithAffinity
PhysicalBoxFragment::PositionForPointRespectingEditingBoundaries(
    const PhysicalBoxFragment& child,
    PhysicalOffset point_in_child) const {
  Node* const child_node = child.NonPseudoNode();
  if (!child.IsCSSBox() || !child_node)
    return child.PositionForPoint(point_in_child);

  // First make sure that the editability of the parent and child agree.
  // TODO(layout-dev): Could we just walk the DOM tree instead here?
  const LayoutObject* ancestor = layout_object_;
  while (ancestor && !ancestor->NonPseudoNode())
    ancestor = ancestor->Parent();
  if (!ancestor || !ancestor->Parent() ||
      (ancestor->HasLayer() && ancestor->Parent()->IsLayoutView()) ||
      IsEditable(*ancestor->NonPseudoNode()) == IsEditable(*child_node)) {
    return child.PositionForPoint(point_in_child);
  }

  // If editiability isn't the same in the ancestor and the child, then we
  // return a visible position just before or after the child, whichever side is
  // closer.
  WritingModeConverter converter(child.Style().GetWritingDirection(),
                                 child.Size());
  const LogicalOffset logical_point_in_child =
      converter.ToLogical(point_in_child, PhysicalSize());
  const LayoutUnit logical_child_inline_size =
      converter.ToLogical(child.Size()).inline_size;
  if (logical_point_in_child.inline_offset < logical_child_inline_size / 2)
    return child.GetLayoutObject()->PositionBeforeThis();
  return child.GetLayoutObject()->PositionAfterThis();
}

PhysicalBoxStrut PhysicalBoxFragment::OverflowClipMarginOutsets() const {
  DCHECK(Style().OverflowClipMargin());
  DCHECK(ShouldApplyOverflowClipMargin());
  DCHECK(!IsScrollContainer());

  const auto& overflow_clip_margin = Style().OverflowClipMargin();
  PhysicalBoxStrut outsets;

  // First inset the overflow rect based on the reference box. The
  // |child_overflow_rect| initialized above assumes clipping to
  // border-box.
  switch (overflow_clip_margin->GetReferenceBox()) {
    case StyleOverflowClipMargin::ReferenceBox::kBorderBox:
      break;
    case StyleOverflowClipMargin::ReferenceBox::kPaddingBox:
      outsets -= Borders();
      break;
    case StyleOverflowClipMargin::ReferenceBox::kContentBox:
      outsets -= Borders();
      outsets -= Padding();
      break;
  }

  // Now expand the rect based on the given margin. The margin only
  // applies if the side is a painted with this child fragment.
  outsets += PhysicalBoxStrut(overflow_clip_margin->GetMargin());
  outsets.TruncateSides(SidesToInclude());

  return outsets;
}

#if DCHECK_IS_ON()
PhysicalBoxFragment::AllowPostLayoutScope::AllowPostLayoutScope() {
  ++allow_count_;
}

PhysicalBoxFragment::AllowPostLayoutScope::~AllowPostLayoutScope() {
  DCHECK(allow_count_);
  --allow_count_;
}

void PhysicalBoxFragment::CheckSameForSimplifiedLayout(
    const PhysicalBoxFragment& other,
    bool check_same_block_size,
    bool check_no_fragmentation) const {
  DCHECK_EQ(layout_object_, other.layout_object_);

  LogicalSize size = size_.ConvertToLogical(Style().GetWritingMode());
  LogicalSize other_size =
      other.size_.ConvertToLogical(Style().GetWritingMode());
  DCHECK_EQ(size.inline_size, other_size.inline_size);
  if (check_same_block_size)
    DCHECK_EQ(size.block_size, other_size.block_size);

  if (check_no_fragmentation) {
    // "simplified" layout doesn't work within a fragmentation context.
    DCHECK(!break_token_ && !other.break_token_);
  }

  DCHECK_EQ(type_, other.type_);
  DCHECK_EQ(sub_type_, other.sub_type_);
  DCHECK_EQ(style_variant_, other.style_variant_);
  DCHECK_EQ(is_hidden_for_paint_, other.is_hidden_for_paint_);
  DCHECK_EQ(is_opaque_, other.is_opaque_);
  DCHECK_EQ(is_block_in_inline_, other.is_block_in_inline_);
  DCHECK_EQ(is_math_fraction_, other.is_math_fraction_);
  DCHECK_EQ(is_math_operator_, other.is_math_operator_);

  // |has_floating_descendants_for_paint_| can change during simplified layout.
  DCHECK_EQ(has_adjoining_object_descendants_,
            other.has_adjoining_object_descendants_);
  DCHECK_EQ(may_have_descendant_above_block_start_,
            other.may_have_descendant_above_block_start_);
  DCHECK_EQ(bit_field_.get<HasDescendantsForTablePartFlag>(),
            other.bit_field_.get<HasDescendantsForTablePartFlag>());
  DCHECK_EQ(IsFragmentationContextRoot(), other.IsFragmentationContextRoot());

  // `depends_on_percentage_block_size_` can change within out-of-flow
  // simplified layout (a different position-try rule can be selected).
  if (!IsOutOfFlowPositioned()) {
    DCHECK_EQ(depends_on_percentage_block_size_,
              other.depends_on_percentage_block_size_);
  }

  DCHECK_EQ(is_fieldset_container_, other.is_fieldset_container_);
  DCHECK_EQ(is_table_part_, other.is_table_part_);
  DCHECK_EQ(is_painted_atomically_, other.is_painted_atomically_);
  DCHECK_EQ(has_collapsed_borders_, other.has_collapsed_borders_);

  DCHECK_EQ(HasItems(), other.HasItems());
  DCHECK_EQ(IsInlineFormattingContext(), other.IsInlineFormattingContext());
  DCHECK_EQ(IncludeBorderTop(), other.IncludeBorderTop());
  DCHECK_EQ(IncludeBorderRight(), other.IncludeBorderRight());
  DCHECK_EQ(IncludeBorderBottom(), other.IncludeBorderBottom());
  DCHECK_EQ(IncludeBorderLeft(), other.IncludeBorderLeft());

  // The oof_positioned_descendants_ vector can change during "simplified"
  // layout. This occurs when an OOF-descendant changes from "fixed" to
  // "absolute" (or visa versa) changing its containing block.

  DCHECK(FirstBaseline() == other.FirstBaseline());
  DCHECK(LastBaseline() == other.LastBaseline());

  if (IsTable()) {
    DCHECK_EQ(TableGridRect(), other.TableGridRect());

    if (TableColumnGeometries()) {
      DCHECK(other.TableColumnGeometries());
      DCHECK(*TableColumnGeometries() == *other.TableColumnGeometries());
    } else {
      DCHECK(!other.TableColumnGeometries());
    }

    DCHECK_EQ(TableCollapsedBorders(), other.TableCollapsedBorders());

    if (TableCollapsedBordersGeometry()) {
      DCHECK(other.TableCollapsedBordersGeometry());
      TableCollapsedBordersGeometry()->CheckSameForSimplifiedLayout(
          *other.TableCollapsedBordersGeometry());
    } else {
      DCHECK(!other.TableCollapsedBordersGeometry());
    }
  }

  if (IsTableCell()) {
    DCHECK_EQ(TableCellColumnIndex(), other.TableCellColumnIndex());
  }

  DCHECK(Borders() == other.Borders());
  DCHECK(Padding() == other.Padding());
  // NOTE: The |InflowBounds| can change if scrollbars are added/removed.
}

// Check our flags represent the actual children correctly.
void PhysicalBoxFragment::CheckIntegrity() const {
  bool has_inflow_blocks = false;
  bool has_inlines = false;
  bool has_line_boxes = false;
  bool has_floats = false;
  bool has_list_markers = false;

  for (const PhysicalFragmentLink& child : Children()) {
    if (child->IsFloating())
      has_floats = true;
    else if (child->IsOutOfFlowPositioned())
      ;  // OOF can be in the fragment tree regardless of |HasItems|.
    else if (child->IsLineBox())
      has_line_boxes = true;
    else if (child->IsListMarker())
      has_list_markers = true;
    else if (child->IsInline())
      has_inlines = true;
    else
      has_inflow_blocks = true;
  }

  // If we have line boxes, |IsInlineFormattingContext()| is true, but the
  // reverse is not always true.
  if (has_line_boxes || has_inlines) {
    DCHECK(IsInlineFormattingContext());
  }

  // If display-locked, we may not have any children.
  DCHECK(layout_object_);
  if (layout_object_ && layout_object_->ChildPaintBlockedByDisplayLock())
    return;

  if (has_line_boxes) {
    DCHECK(HasItems());
  }

  if (has_line_boxes) {
    DCHECK(!has_inlines);
    DCHECK(!has_inflow_blocks);
    // The following objects should be in the items, not in the tree. One
    // exception is that floats may occur as regular fragments in the tree
    // after a fragmentainer break.
    DCHECK(!has_floats || !IsFirstForNode());
    DCHECK(!has_list_markers);
  }
}

void PhysicalBoxFragment::AssertFragmentTreeSelf() const {
  DCHECK(!IsInlineBox());
  DCHECK(OwnerLayoutBox());
  DCHECK_EQ(this, PostLayout());
}

void PhysicalBoxFragment::AssertFragmentTreeChildren(
    bool allow_destroyed_or_moved) const {
  if (const FragmentItems* items = Items()) {
    for (InlineCursor cursor(*this, *items); cursor; cursor.MoveToNext()) {
      const FragmentItem& item = *cursor.Current();
      if (item.IsLayoutObjectDestroyedOrMoved()) {
        DCHECK(allow_destroyed_or_moved);
        continue;
      }
      if (const auto* box = item.BoxFragment()) {
        DCHECK(!box->IsLayoutObjectDestroyedOrMoved());
        if (!box->IsInlineBox())
          box->AssertFragmentTreeSelf();
      }
    }
  }

  for (const PhysicalFragmentLink& child : Children()) {
    if (child->IsLayoutObjectDestroyedOrMoved()) {
      DCHECK(allow_destroyed_or_moved);
      continue;
    }
    if (const auto* box =
            DynamicTo<PhysicalBoxFragment>(child.fragment.Get())) {
      box->AssertFragmentTreeSelf();
    }
  }
}
#endif

void PhysicalBoxFragment::TraceAfterDispatch(Visitor* visitor) const {
  visitor->Trace(children_);
  visitor->Trace(rare_data_);
  // |HasItems()| and |ConstHasRareData()| are const and set
  // in ctor so they do not cause TOCTOU.
  if (HasItems())
    visitor->Trace(*ComputeItemsAddress());
  PhysicalFragment::TraceAfterDispatch(visitor);
}

}  // namespace blink
```