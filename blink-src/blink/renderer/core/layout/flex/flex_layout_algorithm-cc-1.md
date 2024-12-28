Response:
My thought process for summarizing the provided code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of a specific section of a C++ file (`flex_layout_algorithm.cc`) within the Chromium Blink rendering engine. It's the *second part* of a larger file, which implies it builds upon previous concepts and will be further extended.

2. **Identify Key Areas:**  I skim the code, looking for distinct sections or logical blocks. The comments and function names are crucial here. I see things like:
    * Setting up flex items (constructing `algorithm_.all_items_`).
    * The main `Layout()` and `LayoutInternal()` functions, suggesting the core layout process.
    * Handling different layout scenarios (needs earlier break, relayout, no fragmentation).
    * Placing flex items (`PlaceFlexItems`).
    * Calculating intrinsic block size (`CalculateTotalIntrinsicBlockSize`).
    * Applying reversals for `wrap-reverse` and `flex-direction: reverse`.
    * Distributing space (`InitialContentPositionOffset`).
    * Determining final positions and sizes of items (`GiveItemsFinalPositionAndSize`, `GiveItemsFinalPositionAndSizeForFragmentation`).
    * Handling fragmentation.
    * Dealing with baselines.

3. **Focus on the Core Logic:**  The `LayoutInternal()` function seems central. I note its steps:
    * Handling break tokens (for multi-fragment layouts).
    * Placing items.
    * Calculating total block size.
    * Applying reversals.
    * Determining final positions and sizes (potentially differently for fragmented layouts).
    * Setting intrinsic and total block sizes on the `container_builder_`.
    * Handling DevTools information.
    * Finishing fragmentation.
    * Setting reading flow elements and handling out-of-flow items.
    * Propagating break values.
    * Storing break token data.
    * Handling out-of-flow positioned items.

4. **Group Related Functions:** Several functions seem to work together: `PlaceFlexItems` populates the `algorithm_`, then `ComputeNextFlexLine` (within `PlaceFlexItems` but not shown in the snippet) likely iterates through them, and finally, `GiveItemsFinalPositionAndSize` or `GiveItemsFinalPositionAndSizeForFragmentation` uses the results to position elements.

5. **Identify Key Data Structures:** The code manipulates `NGFlexLine` and `NGFlexItem` objects. These seem to represent the layout of individual lines and items within the flex container. The `algorithm_` object (of type `FlexibleBoxAlgorithm`) appears to hold the core logic for flex layout calculations. `container_builder_` is responsible for building the layout result.

6. **Pay Attention to Conditionals and Special Cases:** I notice blocks of code dealing with:
    * Fragmentation (`InvolvedInBlockFragmentation`).
    * Reverse layouts.
    * Different alignment options.
    * Intrinsic sizes.
    * Handling indefinite sizes.
    * Break properties.

7. **Formulate High-Level Summary Points:**  Based on the above, I start drafting summary points, focusing on the main actions and goals of this code section. I try to use clear and concise language.

8. **Refine and Organize:** I review my initial summary, looking for areas to improve clarity, conciseness, and organization. I group related functionalities together. I make sure to mention the key data structures and the flow of the main layout process. I also ensure I address the "part 2 of 4" aspect, noting that it contributes to the overall flexbox layout.

9. **Consider the "Part 2" Aspect:** Since this is part 2, I emphasize that it's a crucial stage where the initial item information is processed, lines are formed, and initial sizing is determined, leading up to the final positioning and rendering in later stages.

10. **Review Against the Code:** I quickly re-scan the code to ensure my summary accurately reflects the major operations. I check if I missed any significant functionality.

This iterative process of skimming, identifying key components, understanding the flow, and then summarizing and refining allows me to create a comprehensive yet concise overview of the code's functionality, as seen in the example answer.
这是 `blink/renderer/core/layout/flex/flex_layout_algorithm.cc` 文件的第二部分，它主要负责**执行 Flexbox 布局算法的核心逻辑**。  在前一部分可能已经收集了 flex 容器和 flex 项目的信息，这部分则基于这些信息进行计算和布局。

**功能归纳:**

这部分代码的主要功能可以归纳为以下几点：

1. **执行主布局流程:**  `Layout()` 和 `LayoutInternal()` 函数是入口，负责协调整个 flexbox 的布局过程。它会根据不同的情况（例如需要提前打断、需要重新布局等）选择合适的执行路径。

2. **Flex 项目的放置 (PlaceFlexItems):**
   - 构建并追加 `FlexItem` 对象到 `algorithm_` 中，这些对象包含了 flex 项目的各种尺寸信息和约束。
   - 循环调用 `algorithm_.ComputeNextFlexLine()` 来计算每一行的 flex 项目。
   - 确定每一行的主轴尺寸，并冻结非弹性项目。
   - 通过 `line->ResolveFlexibleLengths()` 解决弹性项目的长度。
   - 计算每个 flex 项目在其所在行内的最终主轴尺寸。
   - 根据计算出的主轴尺寸，构建用于子元素布局的约束空间 (`BuildSpaceForLayout`)。
   - 对子元素进行布局 (`flex_item.ng_input_node_.Layout`)，或者在某些情况下可以跳过布局，直接计算交叉轴尺寸。
   - 计算每一行的项目位置 (`line->ComputeLineItemsPosition()`)。
   - 记录每一行的剩余自由空间、交叉轴尺寸和基线信息。

3. **计算总的内部块级尺寸 (CalculateTotalIntrinsicBlockSize):**  根据 flex 容器的内容和是否有空行等因素，计算 flex 容器的内部块级尺寸。

4. **应用反转 (ApplyReversals):**  根据 `flex-wrap: wrap-reverse` 和 `flex-direction: row-reverse` 或 `column-reverse` 属性，反转行或行内项目的顺序。

5. **计算项目的最终位置和尺寸 (GiveItemsFinalPositionAndSize):**
   - 计算交叉轴的自由空间，并根据 `align-content` 属性分配这些空间到行之间。
   - 遍历每一行，计算每一行的起始交叉轴偏移量。
   - 遍历每一行的项目，计算每个项目的主轴偏移量。
   - 根据 `justify-content` 属性分配主轴的剩余空间到项目之间。
   - 计算每个 flex 项目的最终偏移量，并将其添加到容器的布局结果中。
   - 处理基线对齐。
   - 处理与分片相关的布局信息。

6. **处理分片 (Fragmentation) 的布局 (GiveItemsFinalPositionAndSizeForFragmentation):**  当 flex 容器参与块级分片时，此函数负责计算项目在每个分片中的位置和尺寸。它会考虑之前的分片信息，并处理跨分片的布局。

7. **设置阅读顺序元素 (SetReadingFlowElements):**  将布局完成的 flex 行设置为阅读顺序元素，用于辅助功能等。

8. **处理脱离文档流的定位元素 (HandleOutOfFlowPositionedItems):** 处理 flex 容器内的绝对定位或固定定位的子元素。

9. **处理布局结果:**  将计算出的布局信息存储到 `container_builder_` 中，最终生成 `LayoutResult`。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这个 C++ 代码直接对应了 CSS Flexbox 布局规范在浏览器渲染引擎中的实现。

* **HTML:** HTML 结构定义了 flex 容器和 flex 项目。例如：
  ```html
  <div style="display: flex;">
    <div>Item 1</div>
    <div>Item 2</div>
  </div>
  ```
  这段 HTML 代码定义了一个 flex 容器和两个 flex 项目。

* **CSS:** CSS 样式决定了 flexbox 的行为，例如 `display: flex`, `flex-direction`, `justify-content`, `align-items`, `flex-wrap` 等。
  - **`display: flex;`**:  声明一个元素为 flex 容器，这段 C++ 代码会处理这个容器的布局。
  - **`flex-direction: column;`**: 决定了主轴方向，会影响 `is_column_` 变量，从而影响主轴和交叉轴的计算方式。
  - **`justify-content: space-between;`**:  决定了主轴上剩余空间的分配方式，对应 `GiveItemsFinalPositionAndSize` 函数中对 `justify_content` 的处理，例如 `InitialContentPositionOffset` 函数会根据这个属性计算初始偏移。
  - **`align-items: center;`**:  决定了项目在交叉轴上的对齐方式，虽然这部分代码片段可能没有直接体现 `align-items` 的处理，但在完整的 flex 布局算法中，会根据此属性计算项目的交叉轴偏移。
  - **`flex-wrap: wrap;`**:  决定了项目是否换行，会影响 `algorithm_.ComputeNextFlexLine()` 的行为，以及交叉轴自由空间的计算。
  - **`flex-basis`, `flex-grow`, `flex-shrink`**: 这些属性决定了 flex 项目的弹性，`line->ResolveFlexibleLengths()` 函数会根据这些属性计算弹性项目的最终尺寸。

* **Javascript:** Javascript 可以动态地修改 HTML 结构和 CSS 样式，从而触发 flexbox 的重新布局。当 Javascript 修改了与 flexbox 相关的属性时，渲染引擎会重新调用这部分 C++ 代码来更新布局。

**逻辑推理的假设输入与输出:**

假设有以下 CSS 和 HTML：

**输入 (CSS):**
```css
.container {
  display: flex;
  width: 200px;
  height: 100px;
  justify-content: center;
  align-items: flex-start;
}
.item {
  width: 50px;
  height: 30px;
}
```

**输入 (HTML):**
```html
<div class="container">
  <div class="item">Item 1</div>
  <div class="item">Item 2</div>
</div>
```

**代码片段中可能涉及的逻辑推理和计算:**

1. **主轴尺寸计算:** `PlaceFlexItems` 会计算每个 item 的主轴尺寸 (width)。由于 `flex-basis` 默认为 `auto`，且 item 指定了 `width: 50px`，所以 item 的主轴尺寸初步认为是 50px。

2. **行内项目放置:** `algorithm_.ComputeNextFlexLine()` 会将两个 item 放在同一行，因为容器宽度足够。

3. **主轴剩余空间:** 容器主轴内容区域为 200px，两个 item 总宽度为 100px，剩余空间为 100px。

4. **主轴对齐 (justify-content):** `GiveItemsFinalPositionAndSize` 中，根据 `justify-content: center`，剩余的 100px 会被平均分配到 item 的两侧，每个 item 前后各有 50px 的空隙。

5. **交叉轴尺寸:** 每个 item 的交叉轴尺寸 (height) 为 30px。

6. **交叉轴对齐 (align-items):**  虽然代码片段中可能没有直接体现，但完整的 flex 布局中，`align-items: flex-start` 会使 item 在交叉轴方向上与行的起始位置对齐。

**可能的输出 (部分，与代码片段相关):**

- 每个 `FlexItem` 对象的 `main_axis_final_size` 将为 50px。
- `line->remaining_free_space_` 在放置项目后为 100px。
- 在 `GiveItemsFinalPositionAndSize` 中，Item 1 的主轴偏移量计算为 `(200 - 100) / 2 = 50px`。
- Item 2 的主轴偏移量计算为 `50px (Item 1 start) + 50px (Item 1 width) = 100px`。
- 每个 item 的交叉轴偏移量将取决于行的起始交叉轴位置（可能为 0）加上 item 的 margin。

**用户或编程常见的使用错误举例:**

1. **忘记设置 `display: flex`:** 如果父元素没有设置 `display: flex`，那么子元素不会按照 flexbox 的规则进行布局，这段代码也不会被执行。

2. **主轴尺寸超出容器:** 如果 flex 项目的主轴尺寸总和超过了 flex 容器的主轴尺寸，且 `flex-wrap: nowrap` (默认)，可能会导致内容溢出。

3. **弹性属性设置不当:**  错误地设置 `flex-grow`, `flex-shrink`, `flex-basis` 可能会导致项目尺寸不符合预期，例如，所有项目都设置了 `flex-grow: 1`，但容器空间不足，可能会导致项目被挤压。

4. **对齐属性理解错误:**  不理解 `justify-content` 和 `align-items` 的区别，或者在主轴或交叉轴上没有足够剩余空间时，对齐属性可能不会产生预期的效果。例如，如果只有单个 flex 项目，`justify-content: space-between` 将不会产生任何间距。

5. **在分片环境中对 flex 项目的期望不准确:**  在分页或多列布局等分片环境中，flex 项目的布局可能会受到分片边界的影响，需要特别注意。

总而言之，这部分代码是 Chromium Blink 引擎中实现 CSS Flexbox 布局算法的关键组成部分，它负责根据 CSS 样式计算 flex 容器内项目的精确位置和尺寸，并处理各种复杂的布局场景，包括换行、对齐和分片等。

Prompt: 
```
这是目录为blink/renderer/core/layout/flex/flex_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
ribution));
        }
      }

      return main_size;
    })();

    // Spec calls this "flex base size"
    // https://www.w3.org/TR/css-flexbox-1/#algo-main-item
    // Blink's FlexibleBoxAlgorithm expects it to be content + scrollbar widths,
    // but no padding or border.
    DCHECK_GE(flex_base_border_box, main_axis_border_padding);
    const LayoutUnit flex_base_content_size =
        flex_base_border_box - main_axis_border_padding;

    std::optional<Length> auto_min_length;
    if (algorithm_.ShouldApplyMinSizeAutoForChild(*child.GetLayoutBox())) {
      const LayoutUnit content_size_suggestion = ([&]() -> LayoutUnit {
        const LayoutUnit content_size =
            is_main_axis_inline_axis
                ? MinMaxSizesFunc(SizeType::kContent).sizes.min_size
                : BlockSizeFunc(SizeType::kContent);

        // For non-replaced elements with an aspect-ratio ensure the size
        // provided by the aspect-ratio encompasses the min-intrinsic size.
        if (!child.IsReplaced() && !child_style.AspectRatio().IsAuto()) {
          return std::max(
              content_size,
              is_main_axis_inline_axis
                  ? MinMaxSizesFunc(SizeType::kIntrinsic).sizes.min_size
                  : BlockSizeFunc(SizeType::kIntrinsic));
        }

        return content_size;
      })();
      DCHECK_GE(content_size_suggestion, main_axis_border_padding);

      const LayoutUnit specified_size_suggestion = ([&]() -> LayoutUnit {
        const Length& specified_length_in_main_axis =
            is_horizontal_flow_ ? child_style.Width() : child_style.Height();
        if (specified_length_in_main_axis.HasAuto()) {
          return LayoutUnit::Max();
        }
        const LayoutUnit resolved_size =
            is_main_axis_inline_axis
                ? ResolveMainInlineLength(
                      flex_basis_space, child_style,
                      border_padding_in_child_writing_mode, MinMaxSizesFunc,
                      specified_length_in_main_axis, /* auto_length */ nullptr)
                : ResolveMainBlockLength(flex_basis_space, child_style,
                                         border_padding_in_child_writing_mode,
                                         specified_length_in_main_axis,
                                         /* auto_length */ nullptr,
                                         BlockSizeFunc);

        // Coerce an indefinite size to LayoutUnit::Max().
        return resolved_size == kIndefiniteSize ? LayoutUnit::Max()
                                                : resolved_size;
      })();

      LayoutUnit auto_min_size =
          std::min(specified_size_suggestion, content_size_suggestion);
      if (child_style.BoxSizing() == EBoxSizing::kContentBox) {
        auto_min_size -= main_axis_border_padding;
      }
      DCHECK_GE(auto_min_size, LayoutUnit());
      auto_min_length = Length::Fixed(auto_min_size);
    }

    MinMaxSizes min_max_sizes_in_main_axis_direction =
        is_main_axis_inline_axis
            ? ComputeMinMaxInlineSizes(
                  flex_basis_space, child, border_padding_in_child_writing_mode,
                  base::OptionalToPtr(auto_min_length), MinMaxSizesFunc,
                  TransferredSizesMode::kIgnore)
            : ComputeMinMaxBlockSizes(
                  flex_basis_space, child, border_padding_in_child_writing_mode,
                  base::OptionalToPtr(auto_min_length), BlockSizeFunc);

    min_max_sizes_in_main_axis_direction -= main_axis_border_padding;
    DCHECK_GE(min_max_sizes_in_main_axis_direction.min_size, LayoutUnit());
    DCHECK_GE(min_max_sizes_in_main_axis_direction.max_size, LayoutUnit());

    const BoxStrut scrollbars = ComputeScrollbarsForNonAnonymous(child);

    auto AspectRatioProvidesBlockMainSize = [&]() -> bool {
      if (is_main_axis_inline_axis) {
        return false;
      }
      if (child.IsReplaced()) {
        return false;
      }
      return child.HasAspectRatio() && InlineSizeFunc() != kIndefiniteSize;
    };

    // For flex-items whose main-axis is the block-axis we treat the initial
    // block-size as indefinite if:
    //  - The flex container has an indefinite main-size.
    //  - The used flex-basis is indefinite.
    //  - The aspect-ratio doesn't provide the main-size.
    //
    // See: // https://drafts.csswg.org/css-flexbox/#definite-sizes
    const bool is_initial_block_size_indefinite =
        is_column_ && !is_main_axis_inline_axis &&
        ChildAvailableSize().block_size == kIndefiniteSize &&
        is_used_flex_basis_indefinite && !AspectRatioProvidesBlockMainSize();

    const auto container_writing_direction =
        GetConstraintSpace().GetWritingDirection();
    bool is_last_baseline =
        FlexibleBoxAlgorithm::AlignmentForChild(Style(), child_style) ==
        ItemPosition::kLastBaseline;
    const auto baseline_writing_mode = DetermineBaselineWritingMode(
        container_writing_direction, child_writing_mode,
        /* is_parallel_context */ !is_column_);
    const auto baseline_group = DetermineBaselineGroup(
        container_writing_direction, baseline_writing_mode,
        /* is_parallel_context */ !is_column_, is_last_baseline,
        /* is_flipped */ is_wrap_reverse);
    algorithm_
        .emplace_back(child.Style(), flex_base_content_size,
                      min_max_sizes_in_main_axis_direction,
                      main_axis_border_padding, physical_child_margins,
                      scrollbars, baseline_writing_mode, baseline_group,
                      is_initial_block_size_indefinite,
                      is_used_flex_basis_indefinite, depends_on_min_max_sizes)
        .ng_input_node_ = child;
    // Save the layout result so that we can maybe reuse it later.
    if (layout_result && !is_main_axis_inline_axis) {
      algorithm_.all_items_.back().layout_result_ = layout_result;
    }
    algorithm_.all_items_.back().max_content_contribution_ =
        max_content_contribution;
  }
}

const LayoutResult* FlexLayoutAlgorithm::Layout() {
  auto* result = LayoutInternal();
  switch (result->Status()) {
    case LayoutResult::kNeedsEarlierBreak:
      // If we found a good break somewhere inside this block, re-layout and
      // break at that location.
      DCHECK(result->GetEarlyBreak());
      return RelayoutAndBreakEarlier<FlexLayoutAlgorithm>(
          *result->GetEarlyBreak(), &column_early_breaks_);
    case LayoutResult::kNeedsRelayoutWithNoChildScrollbarChanges:
      DCHECK(!ignore_child_scrollbar_changes_);
      return Relayout<FlexLayoutAlgorithm>(
          kRelayoutIgnoringChildScrollbarChanges);
    case LayoutResult::kDisableFragmentation:
      DCHECK(GetConstraintSpace().HasBlockFragmentation());
      return RelayoutWithoutFragmentation<FlexLayoutAlgorithm>();
    case LayoutResult::kNeedsRelayoutWithRowCrossSizeChanges:
      return RelayoutWithNewRowSizes();
    default:
      return result;
  }
}

const LayoutResult* FlexLayoutAlgorithm::LayoutInternal() {
  // Freezing the scrollbars for the sub-tree shouldn't be strictly necessary,
  // but we do this just in case we trigger an unstable layout.
  std::optional<PaintLayerScrollableArea::FreezeScrollbarsScope>
      freeze_scrollbars;
  if (ignore_child_scrollbar_changes_)
    freeze_scrollbars.emplace();

  PaintLayerScrollableArea::DelayScrollOffsetClampScope delay_clamp_scope;

  Vector<EBreakBetween> row_break_between_outputs;
  HeapVector<NGFlexLine> flex_line_outputs;
  HeapVector<Member<LayoutBox>> oof_children;
  FlexBreakTokenData::FlexBreakBeforeRow break_before_row =
      FlexBreakTokenData::kNotBreakBeforeRow;
  ClearCollectionScope<HeapVector<NGFlexLine>> scope(&flex_line_outputs);

  bool use_empty_line_block_size;
  if (IsBreakInside(GetBreakToken())) {
    const auto* flex_data =
        To<FlexBreakTokenData>(GetBreakToken()->TokenData());
    total_intrinsic_block_size_ = flex_data->intrinsic_block_size;
    flex_line_outputs = flex_data->flex_lines;
    row_break_between_outputs = flex_data->row_break_between;
    break_before_row = flex_data->break_before_row;
    oof_children = flex_data->oof_children;

    use_empty_line_block_size =
        flex_line_outputs.empty() && Node().HasLineIfEmpty();
  } else {
    PlaceFlexItems(&flex_line_outputs, &oof_children);

    use_empty_line_block_size =
        flex_line_outputs.empty() && Node().HasLineIfEmpty();
    CalculateTotalIntrinsicBlockSize(use_empty_line_block_size);
  }

  total_block_size_ = ComputeBlockSizeForFragment(
      GetConstraintSpace(), Node(), BorderPadding(),
      total_intrinsic_block_size_, container_builder_.InlineSize());

  if (!IsBreakInside(GetBreakToken())) {
    ApplyReversals(&flex_line_outputs);
    LayoutResult::EStatus status = GiveItemsFinalPositionAndSize(
        &flex_line_outputs, &row_break_between_outputs);
    if (status != LayoutResult::kSuccess) {
      return container_builder_.Abort(status);
    }
  }

  LayoutUnit previously_consumed_block_size;
  if (GetBreakToken()) [[unlikely]] {
    previously_consumed_block_size = GetBreakToken()->ConsumedBlockSize();
  }

  intrinsic_block_size_ = BorderScrollbarPadding().block_start;
  LayoutUnit block_size;
  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    if (use_empty_line_block_size) {
      intrinsic_block_size_ =
          (total_intrinsic_block_size_ - BorderScrollbarPadding().block_end -
           previously_consumed_block_size)
              .ClampNegativeToZero();
    }

    LayoutResult::EStatus status =
        GiveItemsFinalPositionAndSizeForFragmentation(
            &flex_line_outputs, &row_break_between_outputs, &break_before_row);
    if (status != LayoutResult::kSuccess) {
      return container_builder_.Abort(status);
    }

    intrinsic_block_size_ = ClampIntrinsicBlockSize(
        GetConstraintSpace(), Node(), GetBreakToken(), BorderScrollbarPadding(),
        intrinsic_block_size_ + BorderScrollbarPadding().block_end);

    block_size = ComputeBlockSizeForFragment(
        GetConstraintSpace(), Node(), BorderPadding(),
        previously_consumed_block_size + intrinsic_block_size_,
        container_builder_.InlineSize());
  } else {
    intrinsic_block_size_ = total_intrinsic_block_size_;
    block_size = total_block_size_;
  }

  container_builder_.SetIntrinsicBlockSize(intrinsic_block_size_);
  container_builder_.SetFragmentsTotalBlockSize(block_size);

  if (has_column_percent_flex_basis_)
    container_builder_.SetHasDescendantThatDependsOnPercentageBlockSize(true);
  if (layout_info_for_devtools_) [[unlikely]] {
    container_builder_.TransferFlexLayoutData(
        std::move(layout_info_for_devtools_));
  }

  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    BreakStatus break_status = FinishFragmentation(&container_builder_);
    if (break_status != BreakStatus::kContinue) {
      if (break_status == BreakStatus::kNeedsEarlierBreak) {
        return container_builder_.Abort(LayoutResult::kNeedsEarlierBreak);
      }
      DCHECK_EQ(break_status, BreakStatus::kDisableFragmentation);
      return container_builder_.Abort(LayoutResult::kDisableFragmentation);
    }
  } else {
#if DCHECK_IS_ON()
    // If we're not participating in a fragmentation context, no block
    // fragmentation related fields should have been set.
    container_builder_.CheckNoBlockFragmentation();
#endif
  }

  SetReadingFlowElements(flex_line_outputs);
  HandleOutOfFlowPositionedItems(oof_children);

  // For rows, the break-before of the first row and the break-after of the
  // last row are propagated to the container. For columns, treat the set
  // of columns as a single row and propagate the combined break-before rules
  // for the first items in each column and break-after rules for last items in
  // each column.
  if (GetConstraintSpace().ShouldPropagateChildBreakValues()) {
    DCHECK(!row_break_between_outputs.empty());
    container_builder_.SetInitialBreakBefore(row_break_between_outputs.front());
    container_builder_.SetPreviousBreakAfter(row_break_between_outputs.back());
  }

  if (GetConstraintSpace().HasBlockFragmentation()) {
    container_builder_.SetBreakTokenData(
        MakeGarbageCollected<FlexBreakTokenData>(
            container_builder_.GetBreakTokenData(), flex_line_outputs,
            row_break_between_outputs, oof_children,
            total_intrinsic_block_size_, break_before_row));
  }

#if DCHECK_IS_ON()
  if (!IsBreakInside(GetBreakToken()) && !cross_size_adjustments_) {
    CheckFlexLines(flex_line_outputs);
  }
#endif

  // Un-freeze descendant scrollbars before we run the OOF layout part.
  freeze_scrollbars.reset();

  container_builder_.HandleOofsAndSpecialDescendants();

  return container_builder_.ToBoxFragment();
}

void FlexLayoutAlgorithm::PlaceFlexItems(
    HeapVector<NGFlexLine>* flex_line_outputs,
    HeapVector<Member<LayoutBox>>* oof_children,
    bool is_computing_multiline_column_intrinsic_size) {
  DCHECK(oof_children || is_computing_multiline_column_intrinsic_size);
  ConstructAndAppendFlexItems(is_computing_multiline_column_intrinsic_size
                                  ? Phase::kColumnWrapIntrinsicSize
                                  : Phase::kLayout,
                              oof_children);

  flex_line_outputs->reserve(algorithm_.NumItems());

  FlexLine* line;
  while ((line = algorithm_.ComputeNextFlexLine())) {
    line->SetContainerMainInnerSize(
        MainAxisContentExtent(line->sum_hypothetical_main_size_));
    line->FreezeInflexibleItems();
    while (!line->ResolveFlexibleLengths()) {
      continue;
    }

    if (layout_info_for_devtools_) [[unlikely]] {
      layout_info_for_devtools_->lines.push_back(DevtoolsFlexInfo::Line());
    }

    flex_line_outputs->push_back(NGFlexLine(line->line_items_.size()));
    for (wtf_size_t i = 0; i < line->line_items_.size(); ++i) {
      FlexItem& flex_item = line->line_items_[i];
      NGFlexItem& flex_item_output = flex_line_outputs->back().line_items[i];

      flex_item_output.ng_input_node = flex_item.ng_input_node_;
      flex_item_output.main_axis_final_size = flex_item.FlexedBorderBoxSize();
      flex_item_output.is_initial_block_size_indefinite =
          flex_item.is_initial_block_size_indefinite_;
      flex_item_output.is_used_flex_basis_indefinite =
          flex_item.is_used_flex_basis_indefinite_;

      ConstraintSpace child_space = BuildSpaceForLayout(
          flex_item.ng_input_node_, flex_item.FlexedBorderBoxSize(),
          flex_item.is_initial_block_size_indefinite_,
          flex_item.max_content_contribution_);

      // We need to get the item's cross axis size given its new main size. If
      // the new main size is the item's inline size, then we have to do a
      // layout to get its new block size. But if the new main size is the
      // item's block size, we can skip layout in some cases and just calculate
      // the inline size from the constraint space.
      // Even when we only need inline size, we have to lay out the item if:
      //  * this is the item's last chance to layout (i.e. doesn't stretch), OR
      //  * the item has not yet been laid out. (ComputeLineItemsPosition
      //    relies on the fragment's baseline, which comes from the post-layout
      //    fragment)
      if (DoesItemStretch(flex_item.ng_input_node_) &&
          flex_item.layout_result_) {
        DCHECK(!flex_item.MainAxisIsInlineAxis());
        BoxStrut border = ComputeBorders(child_space, flex_item.ng_input_node_);
        BoxStrut padding =
            ComputePadding(child_space, flex_item.ng_input_node_.Style());
        if (flex_item.ng_input_node_.IsReplaced()) {
          LogicalSize logical_border_box_size = ComputeReplacedSize(
              flex_item.ng_input_node_, child_space, border + padding);
          flex_item.cross_axis_size_ = logical_border_box_size.inline_size;
        } else {
          flex_item.cross_axis_size_ = ComputeInlineSizeForFragment(
              child_space, flex_item.ng_input_node_, border + padding);
        }
      } else if (is_computing_multiline_column_intrinsic_size) {
        flex_item.cross_axis_size_ = *flex_item.max_content_contribution_;
      } else {
        DCHECK((child_space.CacheSlot() == LayoutResultCacheSlot::kLayout) ||
               !flex_item.layout_result_);
        flex_item.layout_result_ = flex_item.ng_input_node_.Layout(
            child_space, nullptr /*break token*/);
        // TODO(layout-dev): Handle abortions caused by block fragmentation.
        DCHECK_EQ(flex_item.layout_result_->Status(), LayoutResult::kSuccess);
        flex_item.cross_axis_size_ =
            is_horizontal_flow_
                ? flex_item.layout_result_->GetPhysicalFragment().Size().height
                : flex_item.layout_result_->GetPhysicalFragment().Size().width;
      }
    }
    line->ComputeLineItemsPosition();
    flex_line_outputs->back().main_axis_free_space =
        line->remaining_free_space_;
    flex_line_outputs->back().line_cross_size = line->cross_axis_extent_;
    flex_line_outputs->back().major_baseline = line->max_major_ascent_;
    flex_line_outputs->back().minor_baseline = line->max_minor_ascent_;
  }
}

void FlexLayoutAlgorithm::CalculateTotalIntrinsicBlockSize(
    bool use_empty_line_block_size) {
  total_intrinsic_block_size_ = BorderScrollbarPadding().block_start;

  if (use_empty_line_block_size)
    total_intrinsic_block_size_ += Node().EmptyLineBlockSize(GetBreakToken());
  else
    total_intrinsic_block_size_ += algorithm_.IntrinsicContentBlockSize();

  total_intrinsic_block_size_ = ClampIntrinsicBlockSize(
      GetConstraintSpace(), Node(), GetBreakToken(), BorderScrollbarPadding(),
      total_intrinsic_block_size_ + BorderScrollbarPadding().block_end);
}

void FlexLayoutAlgorithm::ApplyReversals(
    HeapVector<NGFlexLine>* flex_line_outputs) {
  if (Style().FlexWrap() == EFlexWrap::kWrapReverse) {
    flex_line_outputs->Reverse();
  }

  if (Style().ResolvedIsReverseFlexDirection()) {
    for (auto& flex_line : *flex_line_outputs)
      flex_line.line_items.Reverse();
  }
}

namespace {

LayoutUnit InitialContentPositionOffset(const StyleContentAlignmentData& data,
                                        ContentPosition safe_position,
                                        LayoutUnit free_space,
                                        unsigned number_of_items,
                                        bool is_reverse) {
  switch (data.Distribution()) {
    case ContentDistributionType::kDefault:
      break;
    case ContentDistributionType::kSpaceBetween:
      if (free_space > LayoutUnit() && number_of_items > 1) {
        return LayoutUnit();
      }
      // Fallback to 'flex-start'.
      return is_reverse ? free_space : LayoutUnit();
    case ContentDistributionType::kSpaceAround:
      if (free_space > LayoutUnit() && number_of_items) {
        return free_space / (2 * number_of_items);
      }
      // Fallback to 'safe center'.
      return (free_space / 2).ClampNegativeToZero();
    case ContentDistributionType::kSpaceEvenly:
      if (free_space > LayoutUnit() && number_of_items) {
        return free_space / (number_of_items + 1);
      }
      // Fallback to 'safe center'.
      return (free_space / 2).ClampNegativeToZero();
    case ContentDistributionType::kStretch:
      // Fallback to 'flex-start'.
      return is_reverse ? free_space : LayoutUnit();
  }

  ContentPosition position = data.GetPosition();
  if (free_space <= LayoutUnit() &&
      data.Overflow() == OverflowAlignment::kSafe) {
    position = safe_position;
  }

  switch (position) {
    case ContentPosition::kCenter:
      return free_space / 2;
    case ContentPosition::kStart:
      return LayoutUnit();
    case ContentPosition::kEnd:
      return free_space;
    case ContentPosition::kFlexEnd:
      return is_reverse ? LayoutUnit() : free_space;
    case ContentPosition::kFlexStart:
    case ContentPosition::kNormal:
    case ContentPosition::kBaseline:
    case ContentPosition::kLastBaseline:
      return is_reverse ? free_space : LayoutUnit();
    case ContentPosition::kLeft:
    case ContentPosition::kRight:
      NOTREACHED();
  }
}

}  // namespace

LayoutResult::EStatus FlexLayoutAlgorithm::GiveItemsFinalPositionAndSize(
    HeapVector<NGFlexLine>* flex_line_outputs,
    Vector<EBreakBetween>* row_break_between_outputs) {
  DCHECK(!IsBreakInside(GetBreakToken()));

  const bool should_propagate_row_break_values =
      GetConstraintSpace().ShouldPropagateChildBreakValues();
  if (should_propagate_row_break_values) {
    DCHECK(row_break_between_outputs);
    // The last row break between will store the final break-after to be
    // propagated to the container.
    if (!is_column_) {
      *row_break_between_outputs = Vector<EBreakBetween>(
          flex_line_outputs->size() + 1, EBreakBetween::kAuto);
    } else {
      // For flex columns, we only need to store two values - one for
      // the break-before value of all combined columns, and the second for
      // for the break-after values for all combined columns.
      *row_break_between_outputs =
          Vector<EBreakBetween>(2, EBreakBetween::kAuto);
    }
  }

  // Nothing to do if we don't have any flex-lines.
  if (flex_line_outputs->empty()) {
    return LayoutResult::kSuccess;
  }

  const auto& style = Style();
  const WritingDirectionMode writing_direction =
      GetConstraintSpace().GetWritingDirection();
  const bool is_reverse_direction = style.ResolvedIsReverseFlexDirection();

  const StyleContentAlignmentData justify_content =
      FlexibleBoxAlgorithm::ResolvedJustifyContent(style);
  const StyleContentAlignmentData align_content =
      FlexibleBoxAlgorithm::ResolvedAlignContent(style);

  // Determine the cross-axis free-space.
  const wtf_size_t num_lines = flex_line_outputs->size();
  const LayoutUnit cross_axis_content_size =
      (is_column_ ? (container_builder_.InlineSize() -
                     BorderScrollbarPadding().InlineSum())
                  : (total_block_size_ - BorderScrollbarPadding().BlockSum()))
          .ClampNegativeToZero();
  LayoutUnit cross_axis_free_space = cross_axis_content_size;
  for (const NGFlexLine& line : *flex_line_outputs) {
    cross_axis_free_space -= line.line_cross_size;
  }
  cross_axis_free_space -= (num_lines - 1) * algorithm_.gap_between_lines_;

  if (!algorithm_.IsMultiline()) {
    // A single line flexbox will always be the cross-axis content-size.
    flex_line_outputs->back().line_cross_size = cross_axis_content_size;
    cross_axis_free_space = LayoutUnit();
  } else if (cross_axis_free_space >= LayoutUnit() &&
             align_content.Distribution() ==
                 ContentDistributionType::kStretch) {
    // Stretch lines in a multi-line flexbox to the available free-space.
    const LayoutUnit delta = cross_axis_free_space / num_lines;
    for (NGFlexLine& line : *flex_line_outputs) {
      line.line_cross_size += delta;
    }
    cross_axis_free_space = LayoutUnit();
  }

  // -webkit-box has a weird quirk - an RTL box will overflow as if it was LTR.
  // NOTE: We should attempt to remove this in the future.
  const ContentPosition safe_justify_position =
      style.IsDeprecatedWebkitBox() && !is_column_ &&
              style.Direction() == TextDirection::kRtl
          ? ContentPosition::kEnd
          : ContentPosition::kStart;

  const LayoutUnit space_between_lines =
      FlexibleBoxAlgorithm::ContentDistributionSpaceBetweenChildren(
          cross_axis_free_space, align_content, num_lines);
  LayoutUnit cross_axis_offset =
      (is_column_ ? BorderScrollbarPadding().inline_start
                  : BorderScrollbarPadding().block_start) +
      InitialContentPositionOffset(align_content, ContentPosition::kStart,
                                   cross_axis_free_space, num_lines,
                                   style.FlexWrap() == EFlexWrap::kWrapReverse);

  BaselineAccumulator baseline_accumulator(style);
  LayoutResult::EStatus status = LayoutResult::kSuccess;

  for (wtf_size_t flex_line_idx = 0; flex_line_idx < flex_line_outputs->size();
       ++flex_line_idx) {
    NGFlexLine& line_output = (*flex_line_outputs)[flex_line_idx];
    line_output.cross_axis_offset = cross_axis_offset;

    bool is_first_line = flex_line_idx == 0;
    bool is_last_line = flex_line_idx == flex_line_outputs->size() - 1;
    if (!InvolvedInBlockFragmentation(container_builder_) && !is_column_) {
      baseline_accumulator.AccumulateLine(line_output, is_first_line,
                                          is_last_line);
    }

    const wtf_size_t line_items_size = line_output.line_items.size();
    const LayoutUnit space_between_items =
        FlexibleBoxAlgorithm::ContentDistributionSpaceBetweenChildren(
            line_output.main_axis_free_space, justify_content, line_items_size);
    LayoutUnit main_axis_offset =
        (is_column_ ? BorderScrollbarPadding().block_start
                    : BorderScrollbarPadding().inline_start) +
        InitialContentPositionOffset(justify_content, safe_justify_position,
                                     line_output.main_axis_free_space,
                                     line_items_size, is_reverse_direction);

    for (wtf_size_t flex_item_idx = 0;
         flex_item_idx < line_output.line_items.size(); ++flex_item_idx) {
      NGFlexItem& flex_item = line_output.line_items[flex_item_idx];
      FlexItem* item = algorithm_.FlexItemAtIndex(flex_line_idx, flex_item_idx);

      const LayoutResult* layout_result = nullptr;
      if (DoesItemStretch(flex_item.ng_input_node)) {
        ConstraintSpace child_space = BuildSpaceForLayout(
            flex_item.ng_input_node, flex_item.main_axis_final_size,
            flex_item.is_initial_block_size_indefinite,
            /* override_inline_size */ std::nullopt,
            line_output.line_cross_size);
        layout_result =
            flex_item.ng_input_node.Layout(child_space,
                                           /* break_token */ nullptr);
      } else {
        DCHECK(item);
        layout_result = item->layout_result_;
      }

      flex_item.has_descendant_that_depends_on_percentage_block_size =
          layout_result->HasDescendantThatDependsOnPercentageBlockSize();
      flex_item.margin_block_end = item->MarginBlockEnd();

      if (should_propagate_row_break_values) {
        const auto& item_style = flex_item.Style();
        auto item_break_before = JoinFragmentainerBreakValues(
            item_style.BreakBefore(), layout_result->InitialBreakBefore());
        auto item_break_after = JoinFragmentainerBreakValues(
            item_style.BreakAfter(), layout_result->FinalBreakAfter());

        // The break-before and break-after values of flex items in a flex row
        // are propagated to the row itself. Accumulate the BreakBetween values
        // for each row ahead of time so that they can be stored on the break
        // token for future use.
        //
        // https://drafts.csswg.org/css-flexbox-1/#pagination
        if (!is_column_) {
          (*row_break_between_outputs)[flex_line_idx] =
              JoinFragmentainerBreakValues(
                  (*row_break_between_outputs)[flex_line_idx],
                  item_break_before);
          (*row_break_between_outputs)[flex_line_idx + 1] =
              JoinFragmentainerBreakValues(
                  (*row_break_between_outputs)[flex_line_idx + 1],
                  item_break_after);
        } else {
          // Treat all columns as a "row" of columns, and accumulate the initial
          // and final break values for all columns, which will be propagated to
          // the container.
          if (flex_item_idx == 0) {
            (*row_break_between_outputs)[0] = JoinFragmentainerBreakValues(
                (*row_break_between_outputs)[0], item_break_before);
          }
          if (flex_item_idx == line_output.line_items.size() - 1) {
            (*row_break_between_outputs)[1] = JoinFragmentainerBreakValues(
                (*row_break_between_outputs)[1], item_break_after);
          }
        }
      }

      const auto& physical_fragment =
          To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());
      const LogicalBoxFragment fragment(writing_direction, physical_fragment);
      const LayoutUnit cross_axis_size =
          is_column_ ? fragment.InlineSize() : fragment.BlockSize();

      main_axis_offset += item->FlowAwareMarginStart();

      flex_item.offset =
          FlexOffset(main_axis_offset,
                     cross_axis_offset +
                         item->CrossAxisOffset(line_output, cross_axis_size));
      const LogicalOffset offset = flex_item.offset.ToLogicalOffset(is_column_);

      main_axis_offset += item->FlexedBorderBoxSize() +
                          item->FlowAwareMarginEnd() + space_between_items +
                          algorithm_.gap_between_items_;

      if (!InvolvedInBlockFragmentation(container_builder_)) {
        container_builder_.AddResult(
            *layout_result, offset,
            item->physical_margins_.ConvertToLogical(writing_direction));
        baseline_accumulator.AccumulateItem(fragment, offset.block_offset,
                                            is_first_line, is_last_line);
      } else {
        flex_item.total_remaining_block_size = fragment.BlockSize();
      }

      if (PropagateFlexItemInfo(item, flex_line_idx, offset,
                                physical_fragment.Size()) ==
          LayoutResult::kNeedsRelayoutWithNoChildScrollbarChanges) {
        status = LayoutResult::kNeedsRelayoutWithNoChildScrollbarChanges;
      }
    }

    cross_axis_offset += line_output.line_cross_size + space_between_lines +
                         algorithm_.gap_between_lines_;
  }

  if (auto first_baseline = baseline_accumulator.FirstBaseline())
    container_builder_.SetFirstBaseline(*first_baseline);
  if (auto last_baseline = baseline_accumulator.LastBaseline())
    container_builder_.SetLastBaseline(*last_baseline);

  // TODO(crbug.com/1131352): Avoid control-specific handling.
  if (Node().IsSlider()) {
    DCHECK(!InvolvedInBlockFragmentation(container_builder_));
    container_builder_.ClearBaselines();
  }

  // Signal if we need to relayout with new child scrollbar information.
  return status;
}

LayoutResult::EStatus
FlexLayoutAlgorithm::GiveItemsFinalPositionAndSizeForFragmentation(
    HeapVector<NGFlexLine>* flex_line_outputs,
    Vector<EBreakBetween>* row_break_between_outputs,
    FlexBreakTokenData::FlexBreakBeforeRow* break_before_row) {
  DCHECK(InvolvedInBlockFragmentation(container_builder_));
  DCHECK(flex_line_outputs);
  DCHECK(row_break_between_outputs);
  DCHECK(break_before_row);

  FlexItemIterator item_iterator(*flex_line_outputs, GetBreakToken(),
                                 is_column_);

  Vector<bool> has_inflow_child_break_inside_line(flex_line_outputs->size(),
                                                  false);
  bool needs_earlier_break_in_column = false;
  LayoutResult::EStatus status = LayoutResult::kSuccess;
  LayoutUnit fragmentainer_space = FragmentainerSpaceLeftForChildren();

  HeapVector<FlexColumnBreakInfo> column_break_info;
  if (is_column_) {
    column_break_info =
        HeapVector<FlexColumnBreakInfo>(flex_line_outputs->size());
  }

  LayoutUnit previously_consumed_block_size;
  LayoutUnit offset_in_stitched_container;
  if (IsBreakInside(GetBreakToken())) {
    previously_consumed_block_size = GetBreakToken()->ConsumedBlockSize();
    offset_in_stitched_container = previously_consumed_block_size;

    if (Style().BoxDecorationBreak() == EBoxDecorationBreak::kClone &&
        offset_in_stitched_container != LayoutUnit::Max()) {
      // We want to deal with item offsets that we would have had had we not
      // been fragmented, and then add unused space caused by fragmentation, and
      // then calculate a block-offset relatively to the current fragment. In
      // the slicing box decoration model, that's simply about adding and
      // subtracting previously consumed block-size.
      //
      // For the cloning box decoration model, we need to subtract space used by
      // all cloned box decorations that wouldn't have been there in the slicing
      // model. That is: all box decorations from previous fragments, except the
      // initial block-start decoration of the first fragment.
      int preceding_fragment_count = GetBreakToken()->SequenceNumber() + 1;
      offset_in_stitched_container -=
          preceding_fragment_count * BorderScrollbarPadding().BlockSum() -
          BorderScrollbarPadding().block_start;
    }
  }

  BaselineAccumulator baseline_accumul
"""


```