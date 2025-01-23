Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. I need to analyze the code, identify its main purpose, and explain its relation to web technologies like JavaScript, HTML, and CSS. I also need to discuss potential usage errors and provide hypothetical input/output scenarios if logical deductions are involved.

**Plan:**

1. **Identify the core functionality:** The code seems to be involved in calculating the containing block information for out-of-flow (OOF) elements (absolute and fixed positioning) within the Blink rendering engine. It also handles the layout of these OOF elements, particularly in scenarios involving fragmentation and multicolumn layouts.

2. **Relate to web technologies:**
    *   **CSS:** This code directly implements CSS positioning concepts (`position: absolute`, `position: fixed`). It also interacts with CSS properties related to writing direction, borders, margins, and grid layouts.
    *   **HTML:** The layout process ultimately positions HTML elements on the page.
    *   **JavaScript:** While the C++ code itself doesn't directly involve JavaScript, the layout calculated by this code influences how JavaScript interacts with the DOM and element positioning (e.g., `getBoundingClientRect()`).

3. **Logical reasoning and examples:** The code calculates offsets and sizes based on containing blocks and fragmentainers. I can create simple scenarios with nested elements and different positioning values to illustrate the logic.

4. **Common usage errors:**  Incorrectly understanding containing block relationships in CSS can lead to unexpected layout results. I can provide examples of such errors.

5. **Focus on the provided snippet:** This is part 2 of 5, so I need to synthesize the functionality demonstrated in this specific portion of the code.
这是`blink/renderer/core/layout/out_of_flow_layout_part.cc`文件的第二部分，主要负责计算和处理**包含块 (containing block)** 的信息，以及在布局过程中处理**行内 (inline)** 的包含块，特别是针对**分段 (fragmentation)** 场景。

**功能归纳:**

1. **计算 Out-of-flow 元素的包含块信息:**
    *   `GetContainingBlockInfo(const LayoutObject&)` 函数负责确定给定 `LayoutObject` 的包含块信息。
    *   它会考虑元素的 `position` 属性（`absolute` 或 `fixed`），以及元素是否位于 Grid 布局中。
    *   如果元素位于分段容器 (fragmentainer) 内，它会考虑祖先分段容器的信息。
    *   它会缓存已计算的包含块信息，以避免重复计算。
    *   对于 `absolute` 定位的元素，如果没有明确的包含块，则使用初始包含块（viewport）。
    *   对于 `fixed` 定位的元素，包含块通常是 viewport。

2. **计算行内包含块信息:**
    *   `ComputeInlineContainingBlocks(const HeapVector<LogicalOofPositionedNode>&)` 函数处理那些拥有行内包含块的 Out-of-flow 元素。
    *   它遍历候选的 Out-of-flow 元素，并为每个元素的行内包含块收集几何信息（起始和结束片段的边界）。
    *   `ComputeInlineContainerGeometry` 函数实际计算行内包含块的几何形状。

3. **为分段容器计算行内包含块信息:**
    *   `ComputeInlineContainingBlocksForFragmentainer(const HeapVector<LogicalOofNodeForFragmentation>&)` 函数专门处理位于分段容器内的 Out-of-flow 元素的行内包含块。
    *   它会收集共享相同包含块的行内容器信息。
    *   `ComputeInlineContainerGeometryForFragmentainer` 函数计算在分段上下文中的行内包含块几何形状。

4. **添加行内包含块信息:**
    *   `AddInlineContainingBlockInfo(...)` 函数将计算出的行内包含块信息添加到 `containing_blocks_map_` 中。
    *   它会根据起始和结束片段的物理矩形计算出行内包含块的逻辑矩形。
    *   它会考虑书写方向、边框等因素。
    *   对于分段的情况，它会调整起始偏移量以考虑构建器的书写模式。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

*   **CSS:**
    *   **`position: absolute`**:  `GetContainingBlockInfo` 函数会查找最近的 `position` 不为 `static` 的祖先元素作为 `absolute` 定位元素的包含块。
        ```html
        <div style="position: relative;">
          <div style="position: absolute; top: 10px; left: 20px;"></div>
        </div>
        ```
        在这个例子中，内部 `div` 的包含块是外部 `div`。`GetContainingBlockInfo` 会遍历父元素找到这个 `relative` 定位的 `div`。
    *   **`position: fixed`**: `GetContainingBlockInfo` 函数会将 viewport 视为 `fixed` 定位元素的包含块。
        ```html
        <div style="position: fixed; bottom: 0; right: 0;"></div>
        ```
        这个 `div` 的位置始终相对于浏览器窗口。
    *   **Grid 布局 (`display: grid`)**: 如果 Out-of-flow 元素被放置在 Grid 区域内，`GetContainingBlockInfo` 会识别出 Grid 容器并使用 `GridAreaContainingBlockInfo`。
        ```html
        <div style="display: grid;">
          <div style="grid-area: a;"></div>
          <div style="position: absolute; top: 10px; left: 20px; grid-area: a;"></div>
        </div>
        ```
        绝对定位的 `div` 的包含块将是它所在的 Grid 区域。
    *   **行内元素和包含块**: `ComputeInlineContainingBlocks` 和 `AddInlineContainingBlockInfo` 处理 Out-of-flow 元素的包含块是行内元素的情况。例如，一个 `position: absolute` 的元素，它的包含块可能是一个 `<span>` 元素。
        ```html
        <p>这是一个 <span style="display: inline-block;">行内块</span> <div style="position: absolute; top: 10px; left: 20px;">绝对定位元素</div> </p>
        ```
        虽然这个例子中 `span` 是 `inline-block`，但概念类似，`ComputeInlineContainingBlocks` 会计算 `div` 的包含块信息，即使包含块是行内元素片段。
    *   **分段 (Fragmentation)**:  `ComputeInlineContainingBlocksForFragmentainer` 涉及到多列布局或分页等场景，Out-of-flow 元素的包含块可能跨越多个片段。

*   **HTML:**  HTML 结构定义了元素的父子关系，这直接影响了包含块的查找过程。

*   **JavaScript:**  JavaScript 可以通过 DOM API 获取元素的布局信息，例如 `getBoundingClientRect()`。这个方法返回的坐标是相对于元素的包含块的。本代码的计算结果直接影响了这些 JavaScript API 的返回值。

**逻辑推理的假设输入与输出:**

假设有一个 `position: absolute` 的 `div` 元素，其父元素是一个 `position: relative` 的 `div`，并且父元素有内边距和边框。

**假设输入:**

*   `LayoutObject` 指向绝对定位的 `div` 元素。
*   父 `div` 的样式：`position: relative; padding: 10px; border: 5px solid black;`
*   父 `div` 的布局信息（例如，大小和偏移量）。

**逻辑推理:**

`GetContainingBlockInfo` 函数会向上遍历 DOM 树，找到父 `div`，因为它的 `position` 属性是 `relative`。然后，它会计算父 `div` 的内容区域，减去内边距和边框。

**假设输出:**

一个 `ContainingBlockInfo` 对象，其中包含：

*   包含块的书写方向。
*   包含块是否是滚动容器。
*   包含块的内容区域的逻辑矩形（偏移量和大小），偏移量会考虑父元素的内边距和边框。
*   包含块相对于其包含块的相对偏移量。
*   包含块相对于其包含块的偏移量。

**涉及用户或者编程常见的使用错误，请举例说明:**

*   **误解包含块:**  初学者经常会错误地认为包含块总是父元素，而忽略了 `position` 属性的影响。
    ```html
    <div>
      <div style="position: absolute; top: 0; left: 0;"></div>
    </div>
    ```
    如果外部 `div` 的 `position` 是 `static`（默认值），那么内部 `div` 的包含块将是初始包含块（viewport），而不是外部 `div`。这会导致 `top: 0; left: 0;` 相对于浏览器窗口而不是外部 `div` 的左上角。
*   **忘记设置包含块的 `position`**:  期望一个绝对定位元素相对于某个父元素定位，但忘记给父元素设置 `position: relative;` 或其他非 `static` 值。
*   **在分段容器中错误地理解包含块**: 在多列布局或分页等场景中，绝对定位元素的包含块可能会跨越多个列或页面片段，这可能会导致布局上的困惑。
*   **行内包含块的复杂性**:  当 Out-of-flow 元素的包含块是行内元素时，其行为可能不如块级包含块直观，例如，包含块的尺寸可能难以确定。

总之，这部分代码是 Blink 引擎中负责确定和计算 Out-of-flow 元素及其行内包含块信息的关键组成部分，它直接关系到 CSS 定位属性的实现和最终的页面布局。理解这部分代码的功能有助于深入理解浏览器如何渲染网页以及处理复杂的布局场景。

### 提示词
```
这是目录为blink/renderer/core/layout/out_of_flow_layout_part.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
er_descendant.containing_block.Fragment();
      const LayoutObject* containing_block =
          containing_block_fragment->GetLayoutObject();
      DCHECK(containing_block);

      bool is_placed_within_grid_area =
          IsPlacedWithinGridArea(containing_block);
      auto it = containing_blocks_map_.find(containing_block);
      if (it != containing_blocks_map_.end() && !is_placed_within_grid_area)
        return it->value;

      const auto writing_direction =
          containing_block->StyleRef().GetWritingDirection();
      LogicalSize size = containing_block_fragment->Size().ConvertToLogical(
          writing_direction.GetWritingMode());
      size.block_size =
          LayoutBoxUtils::TotalBlockSize(*To<LayoutBox>(containing_block));

      // TODO(1079031): This should eventually include scrollbar and border.
      BoxStrut border = To<PhysicalBoxFragment>(containing_block_fragment)
                            ->Borders()
                            .ConvertToLogical(writing_direction);

      if (is_placed_within_grid_area) {
        return GridAreaContainingBlockInfo(
            *To<LayoutGrid>(containing_block),
            *To<LayoutGrid>(containing_block)->LayoutData(), border, size);
      }

      LogicalSize content_size = ShrinkLogicalSize(size, border);
      LogicalOffset container_offset =
          LogicalOffset(border.inline_start, border.block_start);
      container_offset += fragmentainer_descendant.containing_block.Offset();

      ContainingBlockInfo containing_block_info{
          writing_direction, containing_block_fragment->IsScrollContainer(),
          LogicalRect(container_offset, content_size),
          fragmentainer_descendant.containing_block.RelativeOffset(),
          fragmentainer_descendant.containing_block.Offset()};

      return containing_blocks_map_
          .insert(containing_block, containing_block_info)
          .stored_value->value;
    }
  }

  if (IsPlacedWithinGridArea(container_object)) {
    return GridAreaContainingBlockInfo(
        *To<LayoutGrid>(container_object),
        container_builder_->GetGridLayoutData(), container_builder_->Borders(),
        {container_builder_->InlineSize(),
         container_builder_->FragmentBlockSize()});
  }

  return node_style.GetPosition() == EPosition::kAbsolute
             ? default_containing_block_info_for_absolute_
             : default_containing_block_info_for_fixed_;
}

void OutOfFlowLayoutPart::ComputeInlineContainingBlocks(
    const HeapVector<LogicalOofPositionedNode>& candidates) {
  InlineContainingBlockUtils::InlineContainingBlockMap
      inline_container_fragments;

  for (auto& candidate : candidates) {
    if (candidate.inline_container.container &&
        !inline_container_fragments.Contains(
            candidate.inline_container.container)) {
      InlineContainingBlockUtils::InlineContainingBlockGeometry
          inline_geometry = {};
      inline_container_fragments.insert(
          candidate.inline_container.container.Get(), inline_geometry);
    }
  }

  // Fetch the inline start/end fragment geometry.
  InlineContainingBlockUtils::ComputeInlineContainerGeometry(
      &inline_container_fragments, container_builder_);

  LogicalSize container_builder_size = container_builder_->Size();
  PhysicalSize container_builder_physical_size = ToPhysicalSize(
      container_builder_size, GetConstraintSpace().GetWritingMode());
  AddInlineContainingBlockInfo(
      inline_container_fragments,
      default_containing_block_info_for_absolute_.writing_direction,
      container_builder_physical_size);
}

void OutOfFlowLayoutPart::ComputeInlineContainingBlocksForFragmentainer(
    const HeapVector<LogicalOofNodeForFragmentation>& descendants) {
  struct InlineContainingBlockInfo {
    InlineContainingBlockUtils::InlineContainingBlockMap map;
    // The relative offset of the inline's containing block to the
    // fragmentation context root.
    LogicalOffset relative_offset;
    // The offset of the containing block relative to the fragmentation context
    // root (not including any relative offset).
    LogicalOffset offset_to_fragmentation_context;
  };

  HeapHashMap<Member<const LayoutBox>, InlineContainingBlockInfo>
      inline_containg_blocks;

  // Collect the inline containers by shared containing block.
  for (auto& descendant : descendants) {
    if (descendant.inline_container.container) {
      DCHECK(descendant.containing_block.Fragment());
      const LayoutBox* containing_block = To<LayoutBox>(
          descendant.containing_block.Fragment()->GetLayoutObject());

      InlineContainingBlockUtils::InlineContainingBlockGeometry
          inline_geometry = {};
      inline_geometry.relative_offset =
          descendant.inline_container.relative_offset;
      auto it = inline_containg_blocks.find(containing_block);
      if (it != inline_containg_blocks.end()) {
        if (!it->value.map.Contains(descendant.inline_container.container)) {
          it->value.map.insert(descendant.inline_container.container.Get(),
                               inline_geometry);
        }
        continue;
      }
      InlineContainingBlockUtils::InlineContainingBlockMap inline_containers;
      inline_containers.insert(descendant.inline_container.container.Get(),
                               inline_geometry);
      InlineContainingBlockInfo inline_info{
          inline_containers, descendant.containing_block.RelativeOffset(),
          descendant.containing_block.Offset()};
      inline_containg_blocks.insert(containing_block, inline_info);
    }
  }

  for (auto& inline_containg_block : inline_containg_blocks) {
    const LayoutBox* containing_block = inline_containg_block.key;
    InlineContainingBlockInfo& inline_info = inline_containg_block.value;

    LogicalSize size(LayoutBoxUtils::InlineSize(*containing_block),
                     LayoutBoxUtils::TotalBlockSize(*containing_block));
    PhysicalSize container_builder_physical_size =
        ToPhysicalSize(size, containing_block->StyleRef().GetWritingMode());

    // Fetch the inline start/end fragment geometry.
    InlineContainingBlockUtils::ComputeInlineContainerGeometryForFragmentainer(
        containing_block, container_builder_physical_size, &inline_info.map);

    AddInlineContainingBlockInfo(
        inline_info.map, containing_block->StyleRef().GetWritingDirection(),
        container_builder_physical_size, inline_info.relative_offset,
        inline_info.offset_to_fragmentation_context,
        /* adjust_for_fragmentation */ true);
  }
}

void OutOfFlowLayoutPart::AddInlineContainingBlockInfo(
    const InlineContainingBlockUtils::InlineContainingBlockMap&
        inline_container_fragments,
    const WritingDirectionMode container_writing_direction,
    PhysicalSize container_builder_size,
    LogicalOffset containing_block_relative_offset,
    LogicalOffset containing_block_offset,
    bool adjust_for_fragmentation) {
  // Transform the start/end fragments into a ContainingBlockInfo.
  for (const auto& block_info : inline_container_fragments) {
    DCHECK(block_info.value.has_value());

    // The calculation below determines the size of the inline containing block
    // rect.
    //
    // To perform this calculation we:
    // 1. Determine the start_offset "^", this is at the logical-start (wrt.
    //    default containing block), of the start fragment rect.
    // 2. Determine the end_offset "$", this is at the logical-end (wrt.
    //    default containing block), of the end  fragment rect.
    // 3. Determine the logical rectangle defined by these two offsets.
    //
    // Case 1a: Same direction, overlapping fragments.
    //      +---------------
    // ---> |^*****-------->
    //      +*----*---------
    //       *    *
    // ------*----*+
    // ----> *****$| --->
    // ------------+
    //
    // Case 1b: Different direction, overlapping fragments.
    //      +---------------
    // ---> ^******* <-----|
    //      *------*--------
    //      *      *
    // -----*------*
    // |<-- *******$ --->
    // ------------+
    //
    // Case 2a: Same direction, non-overlapping fragments.
    //             +--------
    // --------->  |^ ----->
    //             +*-------
    //              *
    // --------+    *
    // ------->|    $ --->
    // --------+
    //
    // Case 2b: Same direction, non-overlapping fragments.
    //             +--------
    // --------->  ^ <-----|
    //             *--------
    //             *
    // --------+   *
    // | <------   $  --->
    // --------+
    //
    // Note in cases [1a, 2a] we need to account for the inline borders of the
    // rectangles, where-as in [1b, 2b] we do not. This is handled by the
    // is_same_direction check(s).
    //
    // Note in cases [2a, 2b] we don't allow a "negative" containing block size,
    // we clamp negative sizes to zero.
    const ComputedStyle* inline_cb_style = block_info.key->Style();
    DCHECK(inline_cb_style);

    const auto inline_writing_direction =
        inline_cb_style->GetWritingDirection();
    BoxStrut inline_cb_borders = ComputeBordersForInline(*inline_cb_style);
    DCHECK_EQ(container_writing_direction.GetWritingMode(),
              inline_writing_direction.GetWritingMode());

    bool is_same_direction =
        container_writing_direction == inline_writing_direction;

    // Step 1 - determine the start_offset.
    const PhysicalRect& start_rect =
        block_info.value->start_fragment_union_rect;
    LogicalOffset start_offset = start_rect.offset.ConvertToLogical(
        container_writing_direction, container_builder_size, start_rect.size);

    // Make sure we add the inline borders, we don't need to do this in the
    // inline direction if the blocks are in opposite directions.
    start_offset.block_offset += inline_cb_borders.block_start;
    if (is_same_direction)
      start_offset.inline_offset += inline_cb_borders.inline_start;

    // Step 2 - determine the end_offset.
    const PhysicalRect& end_rect = block_info.value->end_fragment_union_rect;
    LogicalOffset end_offset = end_rect.offset.ConvertToLogical(
        container_writing_direction, container_builder_size, end_rect.size);

    // Add in the size of the fragment to get the logical end of the fragment.
    end_offset += end_rect.size.ConvertToLogical(
        container_writing_direction.GetWritingMode());

    // Make sure we subtract the inline borders, we don't need to do this in the
    // inline direction if the blocks are in opposite directions.
    end_offset.block_offset -= inline_cb_borders.block_end;
    if (is_same_direction)
      end_offset.inline_offset -= inline_cb_borders.inline_end;

    // Make sure we don't end up with a rectangle with "negative" size.
    end_offset.inline_offset =
        std::max(end_offset.inline_offset, start_offset.inline_offset);
    end_offset.block_offset =
        std::max(end_offset.block_offset, start_offset.block_offset);

    // Step 3 - determine the logical rectangle.

    // Determine the logical size of the containing block.
    LogicalSize inline_cb_size = {
        end_offset.inline_offset - start_offset.inline_offset,
        end_offset.block_offset - start_offset.block_offset};
    DCHECK_GE(inline_cb_size.inline_size, LayoutUnit());
    DCHECK_GE(inline_cb_size.block_size, LayoutUnit());

    if (adjust_for_fragmentation) {
      // When fragmenting, the containing block will not be associated with the
      // current builder. Thus, we need to adjust the start offset to take the
      // writing mode of the builder into account.
      PhysicalSize physical_size =
          ToPhysicalSize(inline_cb_size, GetConstraintSpace().GetWritingMode());
      start_offset =
          start_offset
              .ConvertToPhysical(container_writing_direction,
                                 container_builder_size, physical_size)
              .ConvertToLogical(GetConstraintSpace().GetWritingDirection(),
                                container_builder_size, physical_size);
    }

    // Subtract out the inline relative offset, if set, so that it can be
    // applied after fragmentation is performed on the fragmentainer
    // descendants.
    DCHECK((block_info.value->relative_offset == LogicalOffset() &&
            containing_block_relative_offset == LogicalOffset() &&
            containing_block_offset == LogicalOffset()) ||
           container_builder_->IsBlockFragmentationContextRoot());
    LogicalOffset container_offset =
        start_offset - block_info.value->relative_offset;
    LogicalOffset total_relative_offset =
        containing_block_relative_offset + block_info.value->relative_offset;

    // The offset of the container is currently relative to the containing
    // block. Add the offset of the containng block to the fragmentation context
    // root so that it is relative to the fragmentation context root, instead.
    container_offset += containing_block_offset;

    // If an OOF has an inline containing block, the OOF offset that is written
    // back to legacy is relative to the containing block of the inline rather
    // than the inline itself. |containing_block_offset| will be used when
    // calculating this OOF offset. However, there may be some relative offset
    // between the containing block and the inline container that should be
    // included in the final OOF offset that is written back to legacy. Adjust
    // for that relative offset here.
    containing_blocks_map_.insert(
        block_info.key.Get(),
        ContainingBlockInfo{
            inline_writing_direction,
            /* is_scroll_container */ false,
            LogicalRect(container_offset, inline_cb_size),
            total_relative_offset,
            containing_block_offset - block_info.value->relative_offset});
  }
}

void OutOfFlowLayoutPart::LayoutCandidates(
    HeapVector<LogicalOofPositionedNode>* candidates) {
  while (candidates->size() > 0) {
    if (!has_block_fragmentation_ ||
        container_builder_->IsInitialColumnBalancingPass()) {
      ComputeInlineContainingBlocks(*candidates);
    }
    for (auto& candidate : *candidates) {
      LayoutBox* layout_box = candidate.box;
      if (!container_builder_->IsBlockFragmentationContextRoot()) {
        SaveStaticPositionOnPaintLayer(layout_box, candidate.static_position);
      }
      if (IsContainingBlockForCandidate(candidate)) {
        if (has_block_fragmentation_) {
          container_builder_->SetHasOutOfFlowInFragmentainerSubtree(true);
          if (!container_builder_->IsInitialColumnBalancingPass()) {
            LogicalOofNodeForFragmentation fragmentainer_descendant(candidate);
            container_builder_->AdjustFragmentainerDescendant(
                fragmentainer_descendant);
            container_builder_
                ->AdjustFixedposContainingBlockForInnerMulticols();
            container_builder_->AddOutOfFlowFragmentainerDescendant(
                fragmentainer_descendant);
            continue;
          }
        }

        NodeInfo node_info = SetupNodeInfo(candidate);
        NodeToLayout node_to_layout = {node_info, CalculateOffset(node_info)};
        const LayoutResult* result = LayoutOOFNode(node_to_layout);
        PhysicalBoxStrut physical_margins =
            node_to_layout.offset_info.node_dimensions.margins
                .ConvertToPhysical(
                    node_info.node.Style().GetWritingDirection());
        BoxStrut margins = physical_margins.ConvertToLogical(
            container_builder_->GetWritingDirection());
        container_builder_->AddResult(
            *result, result->OutOfFlowPositionedOffset(), margins,
            /* relative_offset */ std::nullopt, &candidate.inline_container);
        container_builder_->SetHasOutOfFlowFragmentChild(true);
        if (container_builder_->IsInitialColumnBalancingPass()) {
          container_builder_->PropagateTallestUnbreakableBlockSize(
              result->TallestUnbreakableBlockSize());
        }
      } else {
        container_builder_->AddOutOfFlowDescendant(candidate);
      }
    }

    // Sweep any candidates that might have been added.
    // This happens when an absolute container has a fixed child.
    candidates->Shrink(0);
    container_builder_->SwapOutOfFlowPositionedCandidates(candidates);
  }
}

void OutOfFlowLayoutPart::HandleMulticolsWithPendingOOFs(
    BoxFragmentBuilder* container_builder) {
  if (!container_builder->HasMulticolsWithPendingOOFs())
    return;

  FragmentBuilder::MulticolCollection multicols_handled;
  FragmentBuilder::MulticolCollection multicols_with_pending_oofs;
  container_builder->SwapMulticolsWithPendingOOFs(&multicols_with_pending_oofs);
  DCHECK(!multicols_with_pending_oofs.empty());

  while (!multicols_with_pending_oofs.empty()) {
    for (auto& multicol : multicols_with_pending_oofs) {
      DCHECK(!multicols_handled.Contains(multicol.key));
      LayoutOOFsInMulticol(BlockNode(multicol.key), multicol.value);
      multicols_handled.insert(multicol.key, multicol.value);
    }
    multicols_with_pending_oofs.clear();

    // Additional inner multicols may have been added while handling outer
    // ones. Add those that we haven't seen yet, and handle them.
    FragmentBuilder::MulticolCollection new_multicols;
    container_builder->SwapMulticolsWithPendingOOFs(&new_multicols);
    for (auto& multicol : new_multicols) {
      if (!multicols_handled.Contains(multicol.key)) {
        multicols_with_pending_oofs.insert(multicol.key, multicol.value);
      }
    }
  }
}

void OutOfFlowLayoutPart::LayoutOOFsInMulticol(
    const BlockNode& multicol,
    const MulticolWithPendingOofs<LogicalOffset>* multicol_info) {
  HeapVector<LogicalOofNodeForFragmentation> oof_nodes_to_layout;
  ClearCollectionScope<HeapVector<LogicalOofNodeForFragmentation>>
      oof_nodes_scope(&oof_nodes_to_layout);
  HeapVector<MulticolChildInfo> multicol_children;
  ClearCollectionScope<HeapVector<MulticolChildInfo>> multicol_scope(
      &multicol_children);

  const BlockBreakToken* current_column_break_token = nullptr;
  const BlockBreakToken* previous_multicol_break_token = nullptr;

  LayoutUnit column_inline_progression = kIndefiniteSize;
  LogicalOffset multicol_offset = multicol_info->multicol_offset;

  // Create a simplified container builder for multicol children. It cannot be
  // used to generate a fragment (since no size has been set, for one), but is
  // suitable for holding child fragmentainers while we're cloning them.
  ConstraintSpace limited_multicol_constraint_space =
      CreateConstraintSpaceForMulticol(multicol);
  FragmentGeometry limited_fragment_geometry = CalculateInitialFragmentGeometry(
      limited_multicol_constraint_space, multicol, /* break_token */ nullptr);
  BoxFragmentBuilder limited_multicol_container_builder =
      CreateContainerBuilderForMulticol(multicol,
                                        limited_multicol_constraint_space,
                                        limited_fragment_geometry);
  // The block size that we set on the multicol builder doesn't matter since
  // we only care about the size of the fragmentainer children when laying out
  // the remaining OOFs.
  limited_multicol_container_builder.SetFragmentsTotalBlockSize(LayoutUnit());

  WritingDirectionMode writing_direction =
      multicol.Style().GetWritingDirection();
  const PhysicalBoxFragment* last_fragment_with_fragmentainer = nullptr;

  // Accumulate all of the pending OOF positioned nodes that are stored inside
  // |multicol|.
  for (auto& multicol_fragment : multicol.GetLayoutBox()->PhysicalFragments()) {
    const auto* multicol_box_fragment =
        To<PhysicalBoxFragment>(&multicol_fragment);

    const ComputedStyle& style = multicol_box_fragment->Style();
    const WritingModeConverter converter(writing_direction,
                                         multicol_box_fragment->Size());
    wtf_size_t current_column_index = kNotFound;

    if (column_inline_progression == kIndefiniteSize) {
      // TODO(almaher): This should eventually include scrollbar, as well.
      BoxStrut border_padding =
          multicol_box_fragment->Borders().ConvertToLogical(writing_direction) +
          multicol_box_fragment->Padding().ConvertToLogical(writing_direction);
      LayoutUnit available_inline_size =
          multicol_box_fragment->Size()
              .ConvertToLogical(writing_direction.GetWritingMode())
              .inline_size -
          border_padding.InlineSum();
      column_inline_progression =
          ColumnInlineProgression(available_inline_size, style);
    }

    // Collect the children of the multicol fragments.
    for (auto& child :
         multicol_box_fragment->GetMutableChildrenForOutOfFlow().Children()) {
      const auto* fragment = child.get();
      LogicalOffset offset =
          converter.ToLogical(child.Offset(), fragment->Size());
      if (fragment->IsFragmentainerBox()) {
        current_column_break_token =
            To<BlockBreakToken>(fragment->GetBreakToken());
        current_column_index = multicol_children.size();
        last_fragment_with_fragmentainer = multicol_box_fragment;
      }

      limited_multicol_container_builder.AddChild(*fragment, offset);
      multicol_children.emplace_back(MulticolChildInfo());
    }

    // If a column fragment is updated with OOF children, we may need to update
    // the reference to its break token in its parent's break token. There
    // should be at most one column break token per parent break token
    // (representing the last column laid out in that fragment). Thus, search
    // for |current_column_break_token| in |multicol_box_fragment|'s list of
    // child break tokens and update the stored MulticolChildInfo if found.
    const BlockBreakToken* break_token = multicol_box_fragment->GetBreakToken();
    if (current_column_index != kNotFound && break_token &&
        break_token->ChildBreakTokens().size()) {
      // If there is a column break token, it will be the last item in its
      // parent's list of break tokens.
      const auto children = break_token->ChildBreakTokens();
      const BlockBreakToken* child_token =
          To<BlockBreakToken>(children[children.size() - 1].Get());
      if (child_token == current_column_break_token) {
        MulticolChildInfo& child_info = multicol_children[current_column_index];
        child_info.parent_break_token = break_token;
      }
    }

    // Convert the OOF fragmentainer descendants to the logical coordinate space
    // and store the resulting nodes inside |oof_nodes_to_layout|.
    HeapVector<LogicalOofNodeForFragmentation> oof_fragmentainer_descendants;
    limited_multicol_container_builder.SwapOutOfFlowFragmentainerDescendants(
        &oof_fragmentainer_descendants);
    for (const auto& descendant : oof_fragmentainer_descendants) {
      if (oof_nodes_to_layout.empty() &&
          multicol_info->fixedpos_containing_block.Fragment() &&
          previous_multicol_break_token) {
        // At this point, the multicol offset is the offset from the fixedpos
        // containing block to the first multicol fragment holding OOF
        // fragmentainer descendants. Update this offset such that it is the
        // offset from the fixedpos containing block to the top of the first
        // multicol fragment.
        multicol_offset.block_offset -=
            previous_multicol_break_token->ConsumedBlockSize();
      }

      // If the containing block is not set, that means that the inner multicol
      // was its containing block, and the OOF will be laid out elsewhere. Also
      // skip descendants whose containing block is a column spanner, because
      // those need to be laid out further up in the tree.
      if (!descendant.containing_block.Fragment() ||
          descendant.containing_block.IsInsideColumnSpanner()) {
        continue;
      }
      oof_nodes_to_layout.push_back(descendant);
    }
    previous_multicol_break_token = break_token;
  }
  // When an OOF's CB is a spanner (or a descendant of a spanner), we will lay
  // out the OOF at the next fragmentation context root ancestor. As such, we
  // remove any such OOF nodes from the nearest multicol's list of OOF
  // descendants during OOF node propagation, which may cause
  // |oof_nodes_to_layout| to be empty. Return early if this is the case.
  if (oof_nodes_to_layout.empty())
    return;

  DCHECK(!limited_multicol_container_builder
              .HasOutOfFlowFragmentainerDescendants());

  // Any candidates in the children of the inner multicol have already been
  // propagated properly when the inner multicol was laid out.
  //
  // During layout of the OOF positioned descendants, which is about to take
  // place, new candidates may be discovered (when there's a fixedpos inside an
  // abspos, for instance), that will be transferred to the actual fragment
  // builder further below.
  limited_multicol_container_builder.ClearOutOfFlowPositionedCandidates();

  wtf_size_t old_fragment_count =
      limited_multicol_container_builder.Children().size();

  LogicalOffset fragmentainer_progression(column_inline_progression,
                                          LayoutUnit());

  // Layout the OOF positioned elements inside the inner multicol.
  OutOfFlowLayoutPart inner_part(&limited_multicol_container_builder);
  inner_part.outer_container_builder_ =
      outer_container_builder_ ? outer_container_builder_ : container_builder_;
  inner_part.LayoutFragmentainerDescendants(
      &oof_nodes_to_layout, fragmentainer_progression,
      multicol_info->fixedpos_containing_block.Fragment(), &multicol_children);

  wtf_size_t new_fragment_count =
      limited_multicol_container_builder.Children().size();

  if (old_fragment_count != new_fragment_count) {
    DCHECK_GT(new_fragment_count, old_fragment_count);
    // We created additional fragmentainers to hold OOFs, and this is in a
    // nested fragmentation context. This means that the multicol fragment has
    // already been created, and we will therefore need to replace one of those
    // fragments. Locate the last multicol container fragment that already has
    // fragmentainers, and append all new fragmentainers there. Note that this
    // means that we may end up with more inner fragmentainers than what we
    // actually have room for (so that they'll overflow in the inline
    // direction), because we don't attempt to put fragmentainers into
    // additional multicol fragments in outer fragmentainers. This is an
    // implementation limitation which we can hopefully live with.
    DCHECK(last_fragment_with_fragmentainer);
    LayoutBox& box = *last_fragment_with_fragmentainer->MutableOwnerLayoutBox();
    wtf_size_t fragment_count = box.PhysicalFragmentCount();
    DCHECK_GE(fragment_count, 1u);
    const LayoutResult* old_result = nullptr;
    wtf_size_t fragment_idx = fragment_count - 1;
    do {
      old_result = box.GetLayoutResult(fragment_idx);
      if (&old_result->GetPhysicalFragment() ==
          last_fragment_with_fragmentainer) {
        break;
      }
      DCHECK_GT(fragment_idx, 0u);
      fragment_idx--;
    } while (true);

    // We have located the right multicol container fragment to update.
    const auto& existing_fragment =
        To<PhysicalBoxFragment>(old_result->GetPhysicalFragment());
    WritingModeConverter converter(
        existing_fragment.Style().GetWritingDirection(),
        existing_fragment.Size());
    LayoutUnit additional_column_block_size;

    // Append the new fragmentainers to the multicol container fragment.
    auto fragment_mutator = existing_fragment.GetMutableForOofFragmentation();
    for (wtf_size_t i = old_fragment_count; i < new_fragment_count; i++) {
      const LogicalFragmentLink& child =
          limited_multicol_container_builder.Children()[i];
      fragment_mutator.AddChildFragmentainer(
          *To<PhysicalBoxFragment>(child.get()), child.offset);
      additional_column_block_size +=
          converter.ToLogical(child.fragment->Size()).block_size;
    }
    fragment_mutator.UpdateOverflow();

    // We've already written back to legacy for |multicol|, but if we added
    // new columns to hold any OOF descendants, we need to extend the final
    // size of the legacy flow thread to encompass those new columns.
    multicol.MakeRoomForExtraColumns(additional_column_block_size);
  }

  // Any descendants should have been handled in
  // LayoutFragmentainerDescendants(). However, if there were any candidates
  // found, pass them back to |container_builder_| so they can continue
  // propagating up the tree.
  DCHECK(
      !limited_multicol_container_builder.HasOutOfFlowPositionedDescendants());
  DCHECK(!limited_multicol_container_builder
              .HasOutOfFlowFragmentainerDescendants());
  limited_multicol_container_builder.TransferOutOfFlowCandidates(
      container_builder_, multicol_offset, multicol_info);

  // Add any inner multicols with OOF descendants that may have propagated up
  // while laying out the direct OOF descendants of the current multicol.
  FragmentBuilder::MulticolCollection multicols_with_pending_oofs;
  limited_multicol_container_builder.SwapMulticolsWithPendingOOFs(
      &multicols_with_pending_oofs);
  for (auto& descendant : multicols_with_pending_oofs) {
    container_builder_->AddMulticolWithPendingOOFs(BlockNode(descendant.key),
                                                   descendant.value);
  }
}

void OutOfFlowLayoutPart::LayoutFragmentainerDescendants(
    HeapVector<LogicalOofNodeForFragmentation>* descendants,
    LogicalOffset fragmentainer_progression,
    bool outer_context_has_fixedpos_container,
    HeapVector<MulticolChildInfo>* multicol_children) {
  multicol_children_ = multicol_children;
  outer_context_has_fixedpos_container_ = outer_context_has_fixedpos_container;
  DCHECK(multicol_children_ || !outer_context_has_fixedpos_container_);

  BoxFragmentBuilder* builder_for_anchor_query = container_builder_;
  if (outer_container_builder_) {
    // If this is an inner layout of the nested block fragmentation, and if this
    // block fragmentation context is block fragmented, |multicol_children|
    // doesn't have correct block offsets of fragmentainers anchor query needs.
    // Calculate the anchor query from the outer block fragmentation context
    // instead in order to get the correct offsets.
    for (const MulticolChildInfo& multicol_child : *multicol_children) {
      if (multicol_child.parent_break_token) {
        builder_for_anchor_query = outer_container_builder_;
        break;
      }
    }
  }
  LogicalAnchorQueryMap stitched_anchor_queries(
      *builder_for_anchor_query->Node().GetLayoutBox(),
      builder_for_anchor_query->Children(),
      builder_for_anchor_query->GetWritingDirection());

  const bool may_have_anchors_on_oof =
      std::any_of(descendants->begin(), descendants->end(),
                  [](const LogicalOofPositionedNode& node) {
                    return node.box->MayHaveAnchorQuery();
                  });

  HeapVector<HeapVector<NodeToLayout>> descendants_to_layout;
  ClearCollectionScope<HeapVector<HeapVector<NodeToLayout>>>
      descendants_to_layout_scope(&descendants_to_layout);

  // List of repeated fixed-positioned elements. Elements will be added as they
  // are discovered (which might not happen in the first iteration, if they are
  // nested inside another OOFs).
  HeapVector<NodeToLayout> repeated_fixedpos_descendants;
  ClearCollectionScope<HeapVector<NodeToLayout>>
      repeated_fixedpos_descendants_scope(&repeated_fixedpos_descendants);

  // The fragmentainer index at which we have to resume repetition of
  // fixed-positioned elements, if additional fragmentainers are added. We'll
  // add repeated elements to every fragmentainer that exists, but if there's a
  // nested OOF that triggers creation of additional fragmentainers, we'll need
  // to add the fixed-positioned elements to those as well.
  wtf_size_t previous_repeaded_fixedpos_resume_idx = WTF::kNotFound;

  while (descendants->size() > 0) {
    ComputeInlineContainingBlocksForFragmentainer(*descendants);

    // When there are anchor queries, each containing block should be laid out
    // separately. This loop chunks |descendants| by their containing blocks, if
    // they have anchor queries.
    base::span<LogicalOofNodeForFragmentation> descendants_span =
        base::make_span(*descendants);
    for (;;) {
      bool has_new_descendants_span = false;
      // The CSS containing block of the last descendant, to group |descendants|
      // by the CSS containing block.
      const LayoutObject* last_css_containing_block = nullptr;

      /
```