Response:
The user wants a summary of the functionalities of the `BlockNode` class in the provided Chromium Blink source code. I need to go through the code snippets and identify the key actions and responsibilities of this class. I should also look for connections to web technologies (JavaScript, HTML, CSS), examples of logical reasoning with inputs and outputs, and potential user/developer errors. Since this is part 2 of 3, I should focus on summarizing the functionalities presented in this specific chunk of code.

Here's a breakdown of the functionalities I can identify:

1. **Repeating Layout:**  The code deals with repeating layout fragments, especially for elements that might need to render multiple times (like in pagination or multicolumn layouts).
2. **Finalizing Layout Results:**  After repeated layout, the code handles the finalization of the layout results, ensuring the layout tree is consistent.
3. **Preparing for Layout:** There's a function to perform pre-layout tasks, specifically for scroll anchoring and updating list item markers.
4. **Finishing Layout:**  This is a core function that handles storing layout results, dealing with SVG roots, and copying fragment items.
5. **Storing Layout Results:**  This function focuses on saving the computed layout results back to the `LayoutBox`.
6. **Computing Min/Max Sizes:**  The code includes logic for calculating the minimum and maximum sizes of the block, taking into account various factors like orthogonal flows, aspect ratios, and cached values.
7. **Navigating Siblings/Children:**  There are methods for accessing the next sibling and the first child of the block node, with special handling for inline elements and display locks.
8. **Accessing Special Children:** The code provides ways to access specific child elements like the legend of a fieldset or the fieldset content.
9. **Getting Empty Line Size:**  A function to determine the size of an empty line within the block.
10. **Copying Fragment Data:**  This involves transferring the computed layout information (like positions) back to the underlying `LayoutBox`.
11. **Placing Children:**  The code contains logic to position child elements within the block, handling both normal block flow and multicolumn scenarios.
12. **Handling Multicolumn Layout:**  There are specific functions to manage the layout of content within multicolumn containers.
13. **Finishing Page Container Layout:**  A dedicated function for handling the layout of page container elements.
14. **Copying Fragment Items:**  Deals with positioning inline elements and replaced content within the block.
15. **Identifying Inline Formatting Context Roots:**  A function to determine if the block is the root of an inline formatting context.
16. **Checking Inline Level and Aspect Ratio:** Methods to check if the block is inline-level and if it has an aspect ratio defined.

Now I need to structure this information into a concise summary, including connections to web technologies and potential errors, while remembering this is the second part of a larger description.
这是 `blink/renderer/core/layout/block_node.cc` 文件的第二部分，主要负责 `BlockNode` 类中与布局过程相关的操作，特别是涉及到重复布局、布局结果的存储和最终化、以及子元素的定位等。以下是其功能的归纳：

**核心功能归纳:**

1. **处理可重复布局的根节点 (Handling Repeatable Root Layout):**
    *   **深拷贝布局结果 (`LayoutRepeatableRoot`):**  当需要重复布局时（例如，分页或者多列布局），此函数会深拷贝之前的布局结果，为新的片段（fragment）做准备。它会创建特殊的 "repeat" 中断令牌 (break token)，用于正确维护片段的顺序和信息。
    *   **完成可重复根节点的布局 (`FinishRepeatableRoot`):** 在所有重复片段生成后，此函数负责最终化这些片段的布局。它会深拷贝整个子树，并更新 `LayoutBox` 中的布局结果向量，包括设置正确的带有序列号的中断令牌。

    **与 CSS 的关系:** 这部分功能直接关联到 CSS 的分页属性 (e.g., `break-after: always`) 和多列布局属性 (`column-count`, `column-break-after`)。
    *   **例子:**  一个设置了 `break-after: always` 的 `div` 元素，当内容超过一页时，`LayoutRepeatableRoot` 会被调用来创建下一页的布局片段。

2. **布局的准备和完成 (Preparing and Finishing Layout):**
    *   **布局前的准备 (`PrepareForLayout`):**  执行布局前的必要操作，例如通知滚动锚定 (scroll anchoring) 以及更新列表项的标记文本。
        *   **与 CSS 的关系:** 滚动锚定与 CSSOM 滚动 API 相关，列表项标记与 CSS 列表属性 (`list-style-type`, `list-style-image`) 相关。
        *   **例子:** 当一个可滚动区域即将进行布局时，`PrepareForLayout` 会通知滚动锚定机制。
    *   **布局完成后的处理 (`FinishLayout`):**  在布局计算完成后执行的操作，包括存储布局结果、处理 SVG 根元素的布局、以及复制片段项 (fragment items)。
        *   **与 CSS 的关系:**  涉及到所有影响盒子模型和内容渲染的 CSS 属性，例如 `width`, `height`, `padding`, `border`, `margin`, `display`, 以及 SVG 相关的属性。
        *   **例子:**  在计算完一个 `div` 元素的布局后，`FinishLayout` 会将计算出的尺寸和位置信息存储起来。

3. **布局结果的存储 (Storing Layout Results):**
    *   **将结果存储到 LayoutBox (`StoreResultInLayoutBox`):**  负责将计算出的 `LayoutResult` 对象存储到对应的 `LayoutBox` 中。这涉及到根据中断令牌来确定存储的位置，并清理后续不再需要的旧结果。

4. **计算最小和最大尺寸 (Computing Minimum and Maximum Sizes):**
    *   **计算最小和最大尺寸 (`ComputeMinMaxSizes`):**  计算元素的最小和最大内联尺寸，这对于 flexbox 和 grid 布局至关重要。它会考虑正交书写模式、宽高比、缓存等因素。
        *   **与 CSS 的关系:**  直接关联到 `min-width`, `max-width`, `min-height`, `max-height`, `aspect-ratio` 以及 flexbox 和 grid 的相关属性。
        *   **假设输入与输出:**
            *   **假设输入:**  一个 `div` 元素，CSS 设置了 `min-width: 100px; max-width: 200px;`。
            *   **输出:**  `ComputeMinMaxSizes` 会计算出最小内联尺寸为 100px，最大内联尺寸为 200px (可能还会考虑内容本身的最小/最大尺寸贡献)。

5. **访问兄弟节点和子节点 (Accessing Siblings and Children):**
    *   **获取下一个兄弟节点 (`NextSibling`):**  返回布局树中的下一个兄弟 `BlockNode`。会跳过内联元素。
    *   **获取第一个子节点 (`FirstChild`):**  返回布局树中的第一个子 `BlockNode`。会处理 display lock 的情况，并跳过内联元素。

6. **访问特定的子元素 (Accessing Specific Child Elements):**
    *   **获取渲染后的 legend 元素 (`GetRenderedLegend`):**  用于获取 `fieldset` 元素的 `legend` 子元素。
    *   **获取 fieldset 的内容区域 (`GetFieldsetContent`):**  用于获取 `fieldset` 元素的匿名内容容器。

    **与 HTML 的关系:**  直接关联到 HTML 结构，特别是 `fieldset` 和 `legend` 元素。

7. **获取空行的高度 (Getting Empty Line Block Size):**
    *   **计算空行的块状尺寸 (`EmptyLineBlockSize`):**  返回元素中空行的逻辑高度，通常由 `line-height` 决定。
        *   **与 CSS 的关系:**  与 CSS 的 `line-height` 属性直接相关。

8. **复制片段数据到 LayoutBox (Copying Fragment Data to LayoutBox):**
    *   **将片段数据复制到 LayoutBox (`CopyFragmentDataToLayoutBox`):**  将计算出的片段数据（例如子元素的位置）写回到 `LayoutBox` 中。会处理多列布局的情况。
    *   **在 LayoutBox 中放置子元素 (`PlaceChildrenInLayoutBox`):**  根据计算出的偏移量放置子元素。
    *   **在 FlowThread 中放置子元素 (`PlaceChildrenInFlowThread`):**  专门处理多列布局中子元素的定位。
    *   **复制子片段的位置 (`CopyChildFragmentPosition`):**  将子元素的片段位置信息复制到其对应的 `LayoutBox` 中。

9. **多列布局相关 (Multicolumn Layout Related):**
    *   **为额外的列腾出空间 (`MakeRoomForExtraColumns`):**  在多列布局中，为新增的列扩展空间。

    **与 CSS 的关系:**  直接关联到 CSS 的多列布局属性 (`column-count`, `column-width`, `column-gap`, `column-rule`)。

10. **完成页面容器的布局 (Finishing Page Container Layout):**
    *   **完成页面容器布局 (`FinishPageContainerLayout`):**  专门用于处理页面容器（例如，分页上下文中的根元素）的布局结果存储。

11. **复制片段项到 LayoutBox (Copying Fragment Items to LayoutBox):**
    *   **将片段项复制到 LayoutBox (`CopyFragmentItemsToLayoutBox`):**  处理内联元素和替换元素的位置设置。

12. **判断是否是内联格式化上下文的根 (Identifying Inline Formatting Context Root):**
    *   **判断是否是内联格式化上下文的根 (`IsInlineFormattingContextRoot`):**  检查该 `BlockNode` 是否是内联格式化上下文的根。

13. **判断是否是内联级别和是否有宽高比 (Checking Inline Level and Aspect Ratio):**
    *   **判断是否是内联级别 (`IsInlineLevel`, `IsAtomicInlineLevel`):**  检查该 `BlockNode` 是否是内联元素。
    *   **判断是否在顶层或视图转换层 (`IsInTopOrViewTransitionLayer`):** 检查元素是否在顶层或视图转换层。
    *   **判断是否有宽高比 (`HasAspectRatio`):**  检查该 `BlockNode` 是否设置了宽高比。
    *   **获取宽高比 (`GetAspectRatio`):**  返回该 `BlockNode` 的宽高比。

**潜在的用户或编程常见使用错误 (Potential User or Programming Errors):**

*   **假设输入与输出 (针对 `FinishLayout` 的缓存逻辑):**
    *   **假设输入:**  一个 `div` 元素首次布局成功。
    *   **正确输出:**  布局结果被缓存。
    *   **错误场景:**  在某些情况下，子元素的布局可能被篡改（例如，通过 JavaScript 直接修改样式），但父元素仍然使用缓存的布局结果。
    *   **错误后果:**  页面渲染不正确，因为缓存的父元素布局结果与实际的子元素布局不一致。
    *   **代码中的应对:**  `FinishLayout` 中的 `clear_trailing_results` 逻辑旨在避免这种情况，当检测到可能存在缓存问题时，会清除后续的布局结果，强制重新布局。

*   **假设输入与输出 (针对 `ComputeMinMaxSizes` 中正交流的布局):**
    *   **假设输入:**  一个垂直书写模式的容器包含一个水平书写模式的子元素。
    *   **正确输出:**  `ComputeMinMaxSizes` 会触发子元素的布局来准确计算其尺寸。
    *   **错误场景:**  如果在计算 MinMax 时不进行布局，直接使用边框和内边距计算，对于内容依赖尺寸的元素（例如，`width: auto` 的块级元素），计算结果会不准确。
    *   **代码中的应对:**  `ComputeMinMaxSizes` 中针对正交流的情况会调用 `Layout` 来确保尺寸计算的准确性。

总而言之，这部分代码涵盖了 `BlockNode` 在布局流程中的核心职责，从处理重复布局到最终确定元素及其子元素的位置和尺寸，并与 CSS 的各种布局特性紧密相关。它也考虑了性能优化，例如通过缓存来避免不必要的重复计算。

### 提示词
```
这是目录为blink/renderer/core/layout/block_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
a deep clone.
    result = LayoutResult::Clone(*box_->GetLayoutResult(0));
  }

  wtf_size_t index = FragmentIndex(break_token);
  const auto& fragment = To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  // We need to create a special "repeat" break token, which will be the
  // incoming break token when generating the next fragment. This is needed in
  // order to get the sequence numbers right, which is important when adding the
  // result to the LayoutBox, and it's also needed by pre-paint / paint.
  const BlockBreakToken* outgoing_break_token =
      BlockBreakToken::CreateRepeated(*this, index);
  auto mutator = fragment.GetMutableForCloning();
  mutator.SetBreakToken(outgoing_break_token);
  if (!is_first) {
    mutator.ClearIsFirstForNode();

    // Any OOFs whose containing block is an ancestor of the repeated section is
    // not to be repeated.
    mutator.ClearPropagatedOOFs();

    box_->SetLayoutResult(result, index);
  }

  if (!constraint_space.ShouldRepeat()) {
    FinishRepeatableRoot();
  }

  return result;
}

void BlockNode::FinishRepeatableRoot() const {
  DCHECK(!DisableLayoutSideEffectsScope::IsDisabled());

  // This is the last fragment. It won't be repeated again. We have already
  // created fragments for the repeated nodes, but the cloning was shallow.
  // We're now ready to deep-clone the entire subtree for each repeated
  // fragment, and update the layout result vector in the LayoutBox, including
  // setting correct break tokens with sequence numbers.

  // First remove the outgoing break token from the last fragment, that was set
  // in LayoutRepeatableRoot().
  const PhysicalBoxFragment& last_fragment = box_->PhysicalFragments().back();
  auto mutator = last_fragment.GetMutableForCloning();
  mutator.SetBreakToken(nullptr);

  box_->FinalizeLayoutResults();

  wtf_size_t fragment_count = box_->PhysicalFragmentCount();
  DCHECK_GE(fragment_count, 1u);
  box_->ClearNeedsLayout();
  for (wtf_size_t i = 1; i < fragment_count; i++) {
    const PhysicalBoxFragment& physical_fragment =
        *box_->GetPhysicalFragment(i);
    bool is_first = i == 1;
    bool is_last = i + 1 == fragment_count;
    FragmentRepeater repeater(is_first, is_last);
    repeater.CloneChildFragments(physical_fragment);
  }
}

void BlockNode::PrepareForLayout() const {
  auto* block = DynamicTo<LayoutBlock>(box_.Get());
  if (block && block->IsScrollContainer()) {
    DCHECK(block->GetScrollableArea());
    if (block->GetScrollableArea()->ShouldPerformScrollAnchoring())
      block->GetScrollableArea()->GetScrollAnchor()->NotifyBeforeLayout();
  }

  // TODO(layoutng) Can UpdateMarkerTextIfNeeded call be moved
  // somewhere else? List items need up-to-date markers before layout.
  if (IsListItem())
    To<LayoutListItem>(box_.Get())->UpdateMarkerTextIfNeeded();
}

void BlockNode::FinishLayout(
    LayoutBlockFlow* block_flow,
    const ConstraintSpace& constraint_space,
    const BlockBreakToken* break_token,
    const LayoutResult* layout_result,
    const std::optional<PhysicalSize>& old_box_size) const {
  // Computing MinMax after layout. Do not modify the |LayoutObject| tree, paint
  // properties, and other global states.
  if (DisableLayoutSideEffectsScope::IsDisabled()) {
    box_->AddMeasureLayoutResult(layout_result);
    return;
  }

  if (layout_result->Status() != LayoutResult::kSuccess) {
    // Layout aborted, but there may be results from a previous layout lying
    // around. They are fine to keep, but since we aborted, it means that we
    // want to attempt layout again. Be sure to miss the cache.
    box_->SetShouldSkipLayoutCache(true);
    return;
  }

  const auto& physical_fragment =
      To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());

  if (auto* svg_root = DynamicTo<LayoutSVGRoot>(GetLayoutBox())) {
    // Calculate the new content rect for SVG roots.
    PhysicalRect content_rect = physical_fragment.LocalRect();
    content_rect.Contract(physical_fragment.Borders() +
                          physical_fragment.Padding());

    if (!svg_root->NeedsLayout()) {
      svg_root->SetNeedsLayout(layout_invalidation_reason::kSizeChanged,
                               kMarkOnlyThis);
    }
    svg_root->LayoutRoot(content_rect);
  }

  // If we miss the cache for one result (fragment), we need to clear the
  // remaining ones, to make sure that we don't hit the cache for subsequent
  // fragments. If we re-lay out (which is what we just did), there's no way to
  // tell what happened in this subtree. Some fragment vector in the subtree may
  // have been tampered with, which would cause trouble if we start hitting the
  // cache again later on.
  bool clear_trailing_results =
      break_token || box_->PhysicalFragmentCount() > 1;

  StoreResultInLayoutBox(layout_result, break_token, clear_trailing_results);

  if (block_flow) {
    const FragmentItems* items = physical_fragment.Items();
    bool has_inline_children = items || HasInlineChildren(block_flow);

    // Don't consider display-locked objects as having any children.
    if (has_inline_children && box_->ChildLayoutBlockedByDisplayLock()) {
      has_inline_children = false;
      // It could be the case that our children are already clean at the time
      // the lock was acquired. This means that |box_| self dirty bits might be
      // set, and child dirty bits might not be. We clear the self bits since we
      // want to treat the |box_| as layout clean, even when locked. However,
      // here we also skip appending paint fragments for inline children. This
      // means that we potentially can end up in a situation where |box_| is
      // completely layout clean, but its inline children didn't append the
      // paint fragments to it, which causes problems. In order to solve this,
      // we set a child dirty bit on |box_| ensuring that when the lock
      // is removed, or update is forced, we will visit this box again and
      // properly create the paint fragments. See https://crbug.com/962614.
      box_->SetChildNeedsLayout(kMarkOnlyThis);
    }

    if (has_inline_children) {
      if (items)
        CopyFragmentItemsToLayoutBox(physical_fragment, *items, break_token);
    } else {
      // We still need to clear |InlineNodeData| in case it had inline
      // children.
      block_flow->ClearInlineNodeData();
    }
  } else {
    DCHECK(!physical_fragment.HasItems());
  }

  if (!layout_result->GetPhysicalFragment().GetBreakToken()) {
    DCHECK(old_box_size);
    if (box_->Size() != *old_box_size) {
      box_->SizeChanged();
    }
  }
  CopyFragmentDataToLayoutBox(constraint_space, *layout_result, break_token);
}

void BlockNode::StoreResultInLayoutBox(const LayoutResult* result,
                                       const BlockBreakToken* break_token,
                                       bool clear_trailing_results) const {
  const auto& fragment = To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  wtf_size_t fragment_idx = 0;

  if (fragment.IsOnlyForNode()) {
    box_->SetCachedLayoutResult(std::move(result), 0);
  } else {
    // Add all layout results (and fragments) generated from a node to a list in
    // the layout object. Some extra care is required to correctly overwrite
    // intermediate layout results: The sequence number of an incoming break
    // token corresponds with the fragment index in the layout object (off by 1,
    // though). When writing back a layout result, we remove any fragments in
    // the layout box at higher indices than that of the one we're writing back.
    fragment_idx = FragmentIndex(break_token);
    box_->SetLayoutResult(std::move(result), fragment_idx);
  }

  if (clear_trailing_results)
    box_->ShrinkLayoutResults(fragment_idx + 1);
}

MinMaxSizesResult BlockNode::ComputeMinMaxSizes(
    WritingMode container_writing_mode,
    const SizeType type,
    const ConstraintSpace& constraint_space,
    const MinMaxSizesFloatInput float_input) const {
  // TODO(layoutng) Can UpdateMarkerTextIfNeeded call be moved
  // somewhere else? List items need up-to-date markers before layout.
  if (IsListItem())
    To<LayoutListItem>(box_.Get())->UpdateMarkerTextIfNeeded();

  // There is a path below for which we don't need to compute the (relatively)
  // expensive geometry.
  std::optional<FragmentGeometry> cached_fragment_geometry;
  auto IntrinsicFragmentGeometry = [&]() -> FragmentGeometry& {
    if (!cached_fragment_geometry) {
      cached_fragment_geometry =
          CalculateInitialFragmentGeometry(constraint_space, *this,
                                           /* break_token */ nullptr,
                                           /* is_intrinsic */ true);
    }
    return *cached_fragment_geometry;
  };

  const bool is_in_perform_layout = box_->GetFrameView()->IsInPerformLayout();
  // In some scenarios, GridNG and FlexNG will run layout on their items during
  // MinMaxSizes computation. Instead of running (and possible caching incorrect
  // results), when we're not performing layout, just use border + padding.
  if (!is_in_perform_layout &&
      (IsGrid() ||
       (IsFlexibleBox() && Style().ResolvedIsColumnFlexDirection()))) {
    const FragmentGeometry& fragment_geometry = IntrinsicFragmentGeometry();
    const BoxStrut border_padding =
        fragment_geometry.border + fragment_geometry.padding;
    MinMaxSizes sizes;
    sizes.min_size = border_padding.InlineSum();
    sizes.max_size = sizes.min_size;
    return MinMaxSizesResult(sizes, /* depends_on_block_constraints */ false);
  }

  bool is_orthogonal_flow_root =
      !IsParallelWritingMode(container_writing_mode, Style().GetWritingMode());

  // If we're orthogonal, run layout to compute the sizes.
  if (is_orthogonal_flow_root) {
    // If we have an aspect ratio, we may be able to avoid laying out the
    // child as an optimization, if performance testing shows this to be
    // important.

    MinMaxSizes sizes;
    CHECK(is_in_perform_layout);

    // If we're computing MinMax after layout, we need to disable side effects
    // so that |Layout| does not update the |LayoutObject| tree and other global
    // states.
    std::optional<DisableLayoutSideEffectsScope> disable_side_effects;
    if (!GetLayoutBox()->NeedsLayout())
      disable_side_effects.emplace();

    const LayoutResult* layout_result = Layout(constraint_space);
    DCHECK_EQ(layout_result->Status(), LayoutResult::kSuccess);
    sizes = LogicalFragment({container_writing_mode, TextDirection::kLtr},
                            layout_result->GetPhysicalFragment())
                .InlineSize();
    const bool depends_on_block_constraints =
        Style().LogicalWidth().HasAuto() ||
        Style().LogicalWidth().HasPercentOrStretch() ||
        Style().LogicalMinWidth().HasPercentOrStretch() ||
        Style().LogicalMaxWidth().HasPercentOrStretch();
    return MinMaxSizesResult(sizes, depends_on_block_constraints);
  }

  // Returns if we are (directly) dependent on any block constraints.
  auto DependsOnBlockConstraints = [&]() -> bool {
    return Style().LogicalHeight().HasPercentOrStretch() ||
           Style().LogicalMinHeight().HasPercentOrStretch() ||
           Style().LogicalMaxHeight().HasPercentOrStretch() ||
           (Style().LogicalHeight().HasAuto() &&
            constraint_space.IsBlockAutoBehaviorStretch());
  };

  // Directly handle replaced elements, caching doesn't have substantial gains
  // as most layouts are interested in the min/max content contribution which
  // calls `ComputeReplacedSize` directly. This is mainly used by flex.
  if (IsReplaced()) {
    MinMaxSizes sizes;
    sizes = IntrinsicFragmentGeometry().border_box_size.inline_size;
    return {sizes, DependsOnBlockConstraints()};
  }

  const bool has_aspect_ratio = !Style().AspectRatio().IsAuto();
  if (has_aspect_ratio && type == SizeType::kContent) {
    const FragmentGeometry& fragment_geometry = IntrinsicFragmentGeometry();
    const BoxStrut border_padding =
        fragment_geometry.border + fragment_geometry.padding;
    if (fragment_geometry.border_box_size.block_size != kIndefiniteSize) {
      const LayoutUnit inline_size_from_ar = InlineSizeFromAspectRatio(
          border_padding, Style().LogicalAspectRatio(),
          Style().BoxSizingForAspectRatio(),
          fragment_geometry.border_box_size.block_size);
      return MinMaxSizesResult({inline_size_from_ar, inline_size_from_ar},
                               DependsOnBlockConstraints(),
                               /* applied_aspect_ratio */ true);
    }
  }

  bool can_use_cached_intrinsic_inline_sizes =
      CanUseCachedIntrinsicInlineSizes(constraint_space, float_input, *this);

  // Ensure the cache is invalid if we know we can't use our cached sizes.
  if (!can_use_cached_intrinsic_inline_sizes) {
    box_->SetIntrinsicLogicalWidthsDirty(kMarkOnlyThis);
  }

  std::optional<MinMaxSizesResult> result;

  // Use our cached sizes if we don't have a descendant which depends on our
  // block constraints.
  if (can_use_cached_intrinsic_inline_sizes &&
      !box_->IntrinsicLogicalWidthsDependsOnBlockConstraints()) {
    result = box_->CachedIndefiniteIntrinsicLogicalWidths();
  }

  // We might still be able to use the cached values for a specific initial
  // block-size.
  if (!result && can_use_cached_intrinsic_inline_sizes &&
      !UseParentPercentageResolutionBlockSizeForChildren()) {
    result = box_->CachedIntrinsicLogicalWidths(
        IntrinsicFragmentGeometry().border_box_size.block_size);
  }

  if (!result) {
    const FragmentGeometry& fragment_geometry = IntrinsicFragmentGeometry();
    result = ComputeMinMaxSizesWithAlgorithm(
        LayoutAlgorithmParams(*this, fragment_geometry, constraint_space),
        float_input);

    const BoxStrut border_padding =
        fragment_geometry.border + fragment_geometry.padding;
    if (auto min_size = ContentMinimumInlineSize(*this, border_padding)) {
      result->sizes.min_size = *min_size;
    }

    // Update the cache with this intermediate value.
    box_->SetIntrinsicLogicalWidths(
        fragment_geometry.border_box_size.block_size, *result);
    if (IsTableCell()) {
      To<LayoutTableCell>(box_.Get())
          ->SetIntrinsicLogicalWidthsBorderSizes(
              constraint_space.TableCellBorders());
    }
  }

  if (has_aspect_ratio) {
    const FragmentGeometry& fragment_geometry = IntrinsicFragmentGeometry();
    if (fragment_geometry.border_box_size.block_size == kIndefiniteSize) {
      // If the block size will be computed from the aspect ratio, we need
      // to take the max-block-size into account.
      // https://drafts.csswg.org/css-sizing-4/#aspect-ratio
      const BoxStrut border_padding =
          fragment_geometry.border + fragment_geometry.padding;
      const MinMaxSizes min_max = ComputeMinMaxInlineSizesFromAspectRatio(
          constraint_space, *this, border_padding);
      result->sizes.min_size =
          min_max.ClampSizeToMinAndMax(result->sizes.min_size);
      result->sizes.max_size =
          min_max.ClampSizeToMinAndMax(result->sizes.max_size);
    }
  }

  // Determine if we are dependent on the block-constraints.
  // We report to our parent if we depend on the %-block-size if we used the
  // input %-block-size, or one of children said it depended on this.
  result->depends_on_block_constraints =
      (DependsOnBlockConstraints() ||
       UseParentPercentageResolutionBlockSizeForChildren()) &&
      (result->depends_on_block_constraints || has_aspect_ratio);
  return *result;
}

LayoutInputNode BlockNode::NextSibling() const {
  LayoutObject* next_sibling = box_->NextSibling();

  // We may have some LayoutInline(s) still within the tree (due to treating
  // inline-level floats and/or OOF-positioned nodes as block-level), we need
  // to skip them and clear layout.
  while (next_sibling && next_sibling->IsInline()) {
#if DCHECK_IS_ON()
    if (!next_sibling->IsText()) {
      next_sibling->ShowLayoutTreeForThis();
    }
    DCHECK(next_sibling->IsText());
#endif
    // TODO(layout-dev): Clearing needs-layout within this accessor is an
    // unexpected side-effect. There may be additional invalidations that need
    // to be performed.
    next_sibling->ClearNeedsLayout();
    next_sibling = next_sibling->NextSibling();
  }

  if (!next_sibling)
    return nullptr;

  return BlockNode(To<LayoutBox>(next_sibling));
}

LayoutInputNode BlockNode::FirstChild() const {
  // If this layout is blocked by a display-lock, then we pretend this node has
  // no children.
  if (ChildLayoutBlockedByDisplayLock()) {
    return nullptr;
  }
  auto* block = DynamicTo<LayoutBlock>(box_.Get());
  if (!block) [[unlikely]] {
    return BlockNode(box_->FirstChildBox());
  }
  auto* child = GetLayoutObjectForFirstChildNode(block);
  if (!child)
    return nullptr;
  if (!AreNGBlockFlowChildrenInline(block))
    return BlockNode(To<LayoutBox>(child));

  InlineNode inline_node(To<LayoutBlockFlow>(block));
  if (!inline_node.IsBlockLevel())
    return std::move(inline_node);

  // At this point we have a node which is empty or only has floats and
  // OOF-positioned nodes. We treat all children as block-level, even though
  // they are within a inline-level LayoutBlockFlow.

  // We may have some LayoutInline(s) still within the tree (due to treating
  // inline-level floats and/or OOF-positioned nodes as block-level), we need
  // to skip them and clear layout.
  while (child && child->IsInline()) {
    // TODO(layout-dev): Clearing needs-layout within this accessor is an
    // unexpected side-effect. There may be additional invalidations that need
    // to be performed.
    DCHECK(child->IsText());
    child->ClearNeedsLayout();
    child = child->NextSibling();
  }

  if (!child)
    return nullptr;

  DCHECK(child->IsFloatingOrOutOfFlowPositioned());
  return BlockNode(To<LayoutBox>(child));
}

BlockNode BlockNode::GetRenderedLegend() const {
  if (!IsFieldsetContainer())
    return nullptr;
  return BlockNode(
      LayoutFieldset::FindInFlowLegend(*To<LayoutBlock>(box_.Get())));
}

BlockNode BlockNode::GetFieldsetContent() const {
  if (!IsFieldsetContainer())
    return nullptr;
  return BlockNode(
      To<LayoutFieldset>(box_.Get())->FindAnonymousFieldsetContentBox());
}

LayoutUnit BlockNode::EmptyLineBlockSize(
    const BlockBreakToken* incoming_break_token) const {
  // Only return a line-height for the first fragment.
  if (IsBreakInside(incoming_break_token))
    return LayoutUnit();
  return box_->LogicalHeightForEmptyLine();
}

String BlockNode::ToString() const {
  return String::Format("BlockNode: %s",
                        GetLayoutBox()->ToString().Ascii().c_str());
}

void BlockNode::CopyFragmentDataToLayoutBox(
    const ConstraintSpace& constraint_space,
    const LayoutResult& layout_result,
    const BlockBreakToken* previous_break_token) const {
  const auto& physical_fragment =
      To<PhysicalBoxFragment>(layout_result.GetPhysicalFragment());
  bool is_last_fragment = !physical_fragment.GetBreakToken();

  // TODO(mstensho): This should always be done by the parent algorithm, since
  // we may have auto margins, which only the parent is able to resolve. Remove
  // the following line when all layout modes do this properly.
  UpdateMarginPaddingInfoIfNeeded(constraint_space, physical_fragment);

  auto* block_flow = DynamicTo<LayoutBlockFlow>(box_.Get());
  LayoutMultiColumnFlowThread* flow_thread = GetFlowThread(block_flow);

  // Position the children inside the box. We skip this if display-lock prevents
  // child layout.
  if (!ChildLayoutBlockedByDisplayLock()) {
    if (flow_thread) [[unlikely]] {
      // Hold off writing legacy data for the entire multicol container until
      // done with the last fragment (we may have multiple if nested within
      // another fragmentation context). This way we'll get everything in order.
      // We'd otherwise mess up in complex cases of nested column balancing. The
      // column layout algorithms may retry layout for a given fragment, which
      // would confuse the code that writes back to legacy objects, so that we
      // wouldn't always update column sets or establish fragmentainer groups
      // correctly.
      if (is_last_fragment) {
        const BlockBreakToken* incoming_break_token = nullptr;
        for (const PhysicalBoxFragment& multicol_fragment :
             box_->PhysicalFragments()) {
          PlaceChildrenInFlowThread(flow_thread, constraint_space,
                                    multicol_fragment, incoming_break_token);
          incoming_break_token = multicol_fragment.GetBreakToken();
        }
      }
    } else {
      PlaceChildrenInLayoutBox(physical_fragment, previous_break_token);
    }
  }

  if (!is_last_fragment) [[unlikely]] {
    return;
  }

  box_->SetNeedsOverflowRecalc(
      LayoutObject::OverflowRecalcType::kOnlyVisualOverflowRecalc);
  box_->SetScrollableOverflowFromLayoutResults();
  box_->UpdateAfterLayout();

  if (flow_thread && Style().HasColumnRule()) [[unlikely]] {
    // Issue full invalidation, in case the number of column rules have changed.
    box_->ClearNeedsLayoutWithFullPaintInvalidation();
  } else {
    box_->ClearNeedsLayout();
  }

  // We should notify the display lock that we've done layout on self, and if
  // it's not blocked, on children.
  if (auto* context = box_->GetDisplayLockContext()) {
    if (!ChildLayoutBlockedByDisplayLock())
      context->DidLayoutChildren();
  }
}

void BlockNode::PlaceChildrenInLayoutBox(
    const PhysicalBoxFragment& physical_fragment,
    const BlockBreakToken* previous_break_token,
    bool needs_invalidation_check) const {
  for (const auto& child_fragment : physical_fragment.Children()) {
    // Skip any line-boxes we have as children, this is handled within
    // InlineNode at the moment.
    if (!child_fragment->IsBox())
      continue;

    const auto& box_fragment = *To<PhysicalBoxFragment>(child_fragment.get());
    if (!box_fragment.IsFirstForNode())
      continue;

    // The offset for an OOF positioned node that is added as a child of a
    // fragmentainer box is handled by
    // OutOfFlowLayoutPart::AddOOFToFragmentainer().
    if (physical_fragment.IsFragmentainerBox() &&
        child_fragment->IsOutOfFlowPositioned()) [[unlikely]] {
      continue;
    }

    CopyChildFragmentPosition(box_fragment, child_fragment.offset,
                              physical_fragment, previous_break_token,
                              needs_invalidation_check);
  }
}

void BlockNode::PlaceChildrenInFlowThread(
    LayoutMultiColumnFlowThread* flow_thread,
    const ConstraintSpace& space,
    const PhysicalBoxFragment& physical_fragment,
    const BlockBreakToken* previous_container_break_token) const {
  // Stitch the contents of the columns together in the legacy flow thread, and
  // update the position and size of column sets, spanners and spanner
  // placeholders. Create fragmentainer groups as needed. When in a nested
  // fragmentation context, we need one fragmentainer group for each outer
  // fragmentainer in which the column contents occur. All this ensures that the
  // legacy layout tree is sufficiently set up, so that DOM position/size
  // querying APIs (such as offsetTop and offsetLeft) work correctly. We still
  // rely on the legacy engine for this.
  //
  // This rather complex piece of machinery is described to some extent in the
  // design document for legacy multicol:
  // https://www.chromium.org/developers/design-documents/multi-column-layout

  WritingModeConverter converter(space.GetWritingDirection(),
                                 physical_fragment.Size());

  const BlockBreakToken* previous_column_break_token = nullptr;
  LayoutUnit flow_thread_offset;

  if (IsBreakInside(previous_container_break_token)) {
    // This multicol container is nested inside another fragmentation context,
    // and this isn't its first fragment. Locate the break token for the
    // previous inner column contents, so that we include the correct amount of
    // consumed block-size in the child offsets. If there's a break token for
    // column contents, we'll find it at the back.
    const auto& child_break_tokens =
        previous_container_break_token->ChildBreakTokens();
    if (!child_break_tokens.empty()) {
      const auto* token = To<BlockBreakToken>(child_break_tokens.back().Get());
      // We also create break tokens for spanners, so we need to check.
      if (token->InputNode() == *this) {
        previous_column_break_token = token;
      }
    }
  }

  for (const auto& child : physical_fragment.Children()) {
    const auto& child_fragment = To<PhysicalBoxFragment>(*child);
    const auto* child_box = To<LayoutBox>(child_fragment.GetLayoutObject());
    if (child_box && child_box != box_) {
      CopyChildFragmentPosition(child_fragment, child.offset,
                                physical_fragment);
      continue;
    }

    DCHECK(!child_box);

    // Each anonymous child of a multicol container constitutes one column.
    // Position each child fragment in the first column that they occur,
    // relatively to the block-start of the flow thread.
    //
    // We may fail to detect visual movement of flow thread children if the
    // child re-uses a cached result, since the LayoutBox's frame_rect_ is in
    // the flow thread coordinate space. If the column block-size or inline-size
    // has changed, we might miss paint invalidation, unless we request it to be
    // checked explicitly. We only need to do this for direct flow thread
    // children, since movement detection works fine for descendants. If it's
    // not detected during layout (due to cache hits), it will be detected
    // during pre-paint.
    //
    // TODO(mstensho): Get rid of this in the future if we become able to
    // compare visual offsets rather than flow thread offsets.
    PlaceChildrenInLayoutBox(child_fragment, previous_column_break_token,
                             /* needs_invalidation_check */ true);

    // If the multicol container has inline children, there may still be floats
    // there, but they aren't stored as child fragments of |column| in that case
    // (but rather inside fragment items). Make sure that they get positioned,
    // too.
    if (const FragmentItems* items = child_fragment.Items()) {
      CopyFragmentItemsToLayoutBox(child_fragment, *items,
                                   previous_column_break_token);
    }

    previous_column_break_token = child_fragment.GetBreakToken();
  }

  if (!physical_fragment.GetBreakToken()) {
    flow_thread->FinishLayoutFromNG(flow_thread_offset);
  }
}

// Copies data back to the legacy layout tree for a given child fragment.
void BlockNode::CopyChildFragmentPosition(
    const PhysicalBoxFragment& child_fragment,
    PhysicalOffset offset,
    const PhysicalBoxFragment& container_fragment,
    const BlockBreakToken* previous_container_break_token,
    bool needs_invalidation_check) const {
  auto* layout_box = To<LayoutBox>(child_fragment.GetMutableLayoutObject());
  if (!layout_box)
    return;

  if (child_fragment.GetBoxType() == PhysicalFragment::kPageContainer ||
      child_fragment.GetBoxType() == PhysicalFragment::kPageBorderBox) {
    // These fragment types don't need to write anything back to their
    // LayoutBox. Furthermore, they have no parent, so the check below would
    // fail.
    return;
  }

  DCHECK(layout_box->Parent()) << "Should be called on children only.";

  LayoutPoint point = LayoutBoxUtils::ComputeLocation(
      child_fragment, offset, container_fragment,
      previous_container_break_token);
  layout_box->SetLocation(point);

  if (needs_invalidation_check)
    layout_box->SetShouldCheckForPaintInvalidation();
}

void BlockNode::MakeRoomForExtraColumns(LayoutUnit block_size) const {
  auto* block_flow = DynamicTo<LayoutBlockFlow>(GetLayoutBox());
  DCHECK(block_flow && block_flow->MultiColumnFlowThread());
  MultiColumnFragmentainerGroup& last_group =
      block_flow->MultiColumnFlowThread()
          ->LastMultiColumnSet()
          ->LastFragmentainerGroup();
  last_group.ExtendLogicalBottomInFlowThread(block_size);
}

void BlockNode::FinishPageContainerLayout(const LayoutResult* result) const {
  DCHECK_EQ(result->Status(), LayoutResult::kSuccess);
  DCHECK(result->GetPhysicalFragment().GetBoxType() ==
             PhysicalFragment::kPageContainer ||
         result->GetPhysicalFragment().GetBoxType() ==
             PhysicalFragment::kPageBorderBox);
  DCHECK(
      To<PhysicalBoxFragment>(result->GetPhysicalFragment()).IsOnlyForNode());
  StoreResultInLayoutBox(result, /*BlockBreakToken=*/nullptr);
}

void BlockNode::CopyFragmentItemsToLayoutBox(
    const PhysicalBoxFragment& container,
    const FragmentItems& items,
    const BlockBreakToken* previous_break_token) const {
  LayoutUnit previously_consumed_block_size;
  if (previous_break_token) {
    previously_consumed_block_size =
        previous_break_token->ConsumedBlockSizeForLegacy();
  }
  bool initial_container_is_flipped = Style().IsFlippedBlocksWritingMode();
  for (InlineCursor cursor(container, items); cursor; cursor.MoveToNext()) {
    if (const PhysicalBoxFragment* child = cursor.Current().BoxFragment()) {
      // Replaced elements and inline blocks need Location() set relative to
      // their block container. Similarly for block-in-inline anonymous wrapper
      // blocks, but those may actually fragment, so we need to make sure that
      // we only do this when at the first fragment.
      if (!child->IsFirstForNode())
        continue;

      LayoutObject* layout_object = child->GetMutableLayoutObject();
      if (!layout_object)
        continue;
      if (auto* layout_box = DynamicTo<LayoutBox>(layout_object)) {
        PhysicalOffset maybe_flipped_offset =
            cursor.Current().OffsetInContainerFragment();
        if (initial_container_is_flipped) {
          maybe_flipped_offset.left = container.Size().width -
                                      child->Size().width -
                                      maybe_flipped_offset.left;
        }
        if (container.Style().IsHorizontalWritingMode())
          maybe_flipped_offset.top += previously_consumed_block_size;
        else
          maybe_flipped_offset.left += previously_consumed_block_size;
        layout_box->SetLocation(maybe_flipped_offset.ToLayoutPoint());
        if (layout_box->HasSelfPaintingLayer()) [[unlikely]] {
          layout_box->Layer()->SetNeedsVisualOverflowRecalc();
        }
#if DCHECK_IS_ON()
        layout_box->InvalidateVisualOverflowForDCheck();
#endif
        continue;
      }

      // Legacy compatibility. This flag is used in paint layer for
      // invalidation.
      if (auto* layout_inline = DynamicTo<LayoutInline>(layout_object)) {
        if (layout_inline->HasSelfPaintingLayer()) [[unlikely]] {
          layout_inline->Layer()->SetNeedsVisualOverflowRecalc();
        }
      }
    }
  }
}

bool BlockNode::IsInlineFormattingContextRoot(
    InlineNode* first_child_out) const {
  if (const auto* block = DynamicTo<LayoutBlockFlow>(box_.Get())) {
    if (!AreNGBlockFlowChildrenInline(block))
      return false;
    LayoutInputNode first_child = FirstChild();
    if (first_child.IsInline()) {
      if (first_child_out)
        *first_child_out = To<InlineNode>(first_child);
      return true;
    }
  }
  return false;
}

bool BlockNode::IsInlineLevel() const {
  return GetLayoutBox()->IsInline();
}

bool BlockNode::IsAtomicInlineLevel() const {
  // LayoutObject::IsAtomicInlineLevel() returns true for e.g., <img
  // style="display: block">. Check IsInline() as well.
  return GetLayoutBox()->IsAtomicInlineLevel() && GetLayoutBox()->IsInline();
}

bool BlockNode::IsInTopOrViewTransitionLayer() const {
  return GetLayoutBox()->IsInTopOrViewTransitionLayer();
}

bool BlockNode::HasAspectRatio() const {
  if (!Style().AspectRatio().IsAuto()) {
    DCHECK(!GetAspectRatio().IsEmpty());
    return true;
  }
  LayoutBox* layout_object = GetLayoutBox();
  if (!layout_object->IsImage() && !IsA<LayoutVideo>(layout_object) &&
      !layout_object->IsCanvas() && !layout_object->IsSVGRoot()) {
    return false;
  }

  // Retrieving this and throwing it away is wasteful. We could make this method
  // return Optional<LogicalSize> that returns the aspect_ratio if there is one.
  return !GetAspectRatio().IsEmpty();
}

LogicalSize BlockNode::GetAspectRatio() const {
  // The CSS parser will ensure that this will only be set if the feature
  // is enabled.
  const EAspectRatioType ar_type = Style().AspectRatio().GetType();
  if (ar_type == EAspectRatioType::kRatio ||
      (ar_type == EAspectR
```