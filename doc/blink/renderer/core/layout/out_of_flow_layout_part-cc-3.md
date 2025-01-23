Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. They are specifically interested in:

1. **General Functionality:** What does this code do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logical Reasoning:** What are some examples of input and output for this code?
4. **Common Usage Errors:** What mistakes might developers make when interacting with this code (or related systems)?
5. **Overall Function:** A concise summary of its purpose.

Let's break down the code step by step to understand its core responsibilities.

**Code Analysis:**

The code primarily deals with the layout of out-of-flow positioned elements (elements with `position: absolute` or `position: fixed`). It calculates the position and size of these elements within a containing block, considering various CSS properties and the fragmentation context.

**Key Actions:**

* **Static Position Conversion:** Converts static position information between different writing modes and container sizes.
* **Inset Modified Containing Block (IMCB) Calculation:** Computes the available space for the out-of-flow element, considering insets and alignment.
* **CSS Feature Counting:** Tracks the usage of `justify-self` and `align-self` properties on out-of-flow elements.
* **Border and Padding Calculation:** Determines the space occupied by borders and padding.
* **Replaced Element Size Calculation:** Handles the sizing of replaced elements (like `<img>` or `<video>`) within the available space.
* **Anchor Center Position Calculation:** Determines the anchor point for CSS anchor positioning.
* **Offset Information Calculation:** Calculates the final offset, size, and margin of the out-of-flow element.
* **Scroll Offset Range Calculation:** Determines the range within which the element fits without overflowing.
* **Fragment Generation:** Creates layout fragments for the out-of-flow element, especially in the context of fragmentation (like multi-column layouts or pagination).
* **Layout in Fragmentainers:** Manages the layout of out-of-flow elements within fragmentainers.
* **Containing Block Determination:** Checks if a given element acts as a containing block for another out-of-flow element.
* **Handling Fragmentation:**  Deals with how out-of-flow elements are handled across different fragments (like columns or pages).
* **Offset Adjustments:** Accounts for relative positioning and offsets related to fixed-position containing blocks.
* **Interaction with LayoutResult:**  Updates the `LayoutResult` object with the calculated position, size, and other information.

**Connecting to Web Technologies:**

* **CSS:** This code directly implements the layout rules defined by CSS for out-of-flow positioning, including properties like `position`, `top`, `right`, `bottom`, `left`, `inset`, `width`, `height`, `margin`, `padding`, `border`, `justify-self`, `align-self`, and writing modes.
* **HTML:** The code operates on the structure of the HTML document (the DOM) to identify elements that need to be laid out.
* **JavaScript:**  While this specific C++ code doesn't directly interact with JavaScript, JavaScript can modify the CSS properties of elements, which in turn will trigger this layout code to re-calculate the positions of out-of-flow elements. JavaScript can also interact with layout information (e.g., using `getBoundingClientRect`).

**Hypothesized Input and Output:**

Let's consider a simple scenario:

**Input (Hypothetical):**

* An HTML element: `<div style="position: absolute; top: 10px; left: 20px; width: 100px; height: 50px;"></div>`
* The containing block has a top padding of 5px and a left padding of 10px.
* The writing mode is horizontal-top-to-bottom.

**Processing (Logical Steps within the code):**

1. The `static_position` would be initially (0, 0).
2. `ComputeInsetModifiedContainingBlock` would calculate the available space, considering the container's padding.
3. `ComputeBorders` and `ComputePadding` would determine the element's border and padding sizes (assuming they are 0 in this example).
4. `ComputeOofInlineDimensions` and `ComputeOofBlockDimensions` would determine the element's size based on the CSS `width` and `height`.
5. The `offset_info.offset` would be calculated based on the `top` and `left` values, relative to the container's padding box.

**Output (Hypothetical):**

* `offset_info.offset.inline_offset`: 20px
* `offset_info.offset.block_offset`: 10px
* `node_dimensions.size.inline_size`: 100px
* `node_dimensions.size.block_size`: 50px

**Common Usage Errors:**

* **Incorrectly assuming the containing block:** Developers might misunderstand which element acts as the containing block for an absolutely positioned element, leading to unexpected positioning. For example, if no ancestor has `position: relative`, `absolute`, or `fixed`, the initial containing block (the viewport) will be used.
* **Forgetting about margins:** Margins on absolutely positioned elements collapse with the containing block's edges in certain scenarios, which can be surprising.
* **Not accounting for padding and borders:**  Positioning values like `top` and `left` are relative to the *padding edge* of the containing block, not the border edge.
* **Conflicting positioning properties:** Specifying both `left` and `right` (or `top` and `bottom`) without a defined width or height can lead to over-constrained situations, and the browser will have to resolve the conflict based on CSS rules.
* **Issues with fragmentation:** When dealing with multi-column layouts or pagination, developers might not fully understand how absolutely positioned elements behave within these contexts, potentially leading to elements appearing in unexpected columns or pages.

**Summary of Functionality (Part 4):**

This section of `OutOfFlowLayoutPart::Layout` focuses on the core logic of calculating the position and dimensions of an out-of-flow element *within a specific fragmentainer*. It takes the initially calculated offset information and generates the final layout fragment for the element. This involves potentially performing the actual layout of the element within the fragmentainer's constraints. It also handles scenarios where the out-of-flow element needs to be split across fragmentainers (fragmentation). The code carefully manages the offset adjustments needed when dealing with fragmentation and fixed-position elements within fragmented contexts. It also interacts with the `LayoutResult` object to store the computed layout information.
这是 `blink/renderer/core/layout/out_of_flow_layout_part.cc` 文件的第 4 部分，主要负责 **在一个特定的分片容器 (fragmentainer) 中布局 out-of-flow (绝对定位或固定定位) 的元素**。它在前几部分计算出的初步布局信息的基础上，生成最终的布局片段，并处理跨分片容器的情况。

以下是具体的功能点，并结合与 JavaScript, HTML, CSS 的关系进行说明：

**核心功能:**

1. **生成布局片段 (GenerateFragment):**
   -  负责为 out-of-flow 元素生成实际的布局片段 (`LayoutResult`)。
   -  这可能发生在两种情况下：
      - **估计元素块大小:**  在计算绝对定位元素的初始位置时，需要先估计其块大小，此时会使用容器的可用大小进行布局。
      - **计算最终片段:**  在绝对定位计算完成后，知道元素的最终块大小，生成最终的布局片段。
   - **与 CSS 的关系:**  布局片段的生成会受到 CSS 属性的影响，例如 `width`, `height`, `box-sizing`, `writing-mode` 等。
   - **与 HTML 的关系:**  针对不同的 HTML 元素类型 (例如 replaced 元素)，布局逻辑可能会有所不同。

2. **在分片容器中布局 out-of-flow 元素 (LayoutOOFsInFragmentainer):**
   -  处理在一个分片容器中布局多个 out-of-flow 元素的过程。
   -  它会迭代待布局的 out-of-flow 元素，并调用 `AddOOFToFragmentainer` 来将每个元素添加到当前的分片容器中。
   -  **与 CSS 的关系:**  分片容器的概念与 CSS 的多列布局 (`column-count`, `column-width`) 和分页 (`break-before`, `break-after`) 等属性相关。
   -  **逻辑推理 - 假设输入与输出:**
      - **假设输入:**  一个包含多个绝对定位元素的容器，并且该容器是一个多列布局的容器。
      - **输出:**  每个绝对定位元素会被放置在适当的列中，其位置根据 `top`, `left`, `right`, `bottom` 等 CSS 属性计算得出。

3. **将 out-of-flow 元素添加到分片容器 (AddOOFToFragmentainer):**
   -  这是将一个 out-of-flow 元素添加到特定分片容器的核心函数。
   -  它会调用 `LayoutOOFNode` 进行元素的布局，并获取布局结果 (`LayoutResult`)。
   -  **处理相对定位偏移:**  应用 out-of-flow 元素自身或其祖先的相对定位偏移。
   -  **处理固定定位偏移:**  处理固定定位元素的偏移，使其相对于视口或指定的包含块。
   -  **处理跨分片容器:**  如果 out-of-flow 元素的大小超过了当前分片容器的剩余空间，它会生成一个 `BlockBreakToken`，指示需要在下一个分片容器中继续布局。
   -  **更新容器信息:**  将布局结果中的锚点信息、粘性后代信息等传播回容器构建器 (`container_builder_`).
   -  **与 CSS 的关系:**  此函数处理诸如 `position: absolute`, `position: fixed`, `top`, `left`, `right`, `bottom`, `margin`, 以及与分片相关的 CSS 属性。
   -  **与 JavaScript 的关系:**  JavaScript 可以动态修改元素的 CSS 属性，导致此函数被重新调用以更新布局。
   -  **逻辑推理 - 假设输入与输出:**
      - **假设输入:** 一个 `position: absolute` 的 `div` 元素，其 `top: 10px; left: 20px;`，以及一个分片容器的偏移量。
      - **输出:** 该 `div` 元素在分片容器中的最终偏移量会是分片容器的偏移量加上 `(10px, 20px)`。

4. **获取分片容器的约束空间 (GetFragmentainerConstraintSpace):**
   -  为指定的索引处的分片容器创建一个 `ConstraintSpace` 对象，用于指导其内部元素的布局。
   -  约束空间包含了分片容器的尺寸、书写模式等信息。
   -  **与 CSS 的关系:**  分片容器的约束空间直接受到 CSS 分片属性的影响，例如容器的尺寸、书写模式等。

5. **计算 out-of-flow 元素的起始分片索引和相对偏移 (ComputeStartFragmentIndexAndRelativeOffset):**
   -  确定一个 out-of-flow 元素应该从哪个分片容器开始布局，并计算相对于该分片容器的初始偏移量。
   -  这对于正确地跨多个分片容器布局 out-of-flow 元素至关重要。
   -  **与 CSS 的关系:**  此功能与 CSS 的分片属性密切相关，例如在多列布局或分页中，需要确定元素应该出现在哪一列或哪一页。
   -  **逻辑推理 - 假设输入与输出:**
      - **假设输入:**  一个高度为 `500px` 的绝对定位元素，以及一个包含多个分片容器的布局，每个分片容器的高度为 `200px`。
      - **输出:**  该元素的起始分片索引可能是 0，相对偏移可能是 `(0, 0)`，如果它完全位于第一个分片容器内。如果它跨越多个分片容器，起始索引仍然是 0，但后续的布局会处理跨越的情况。

**与 JavaScript, HTML, CSS 的关系举例:**

- **HTML:**  当 HTML 结构中包含设置了 `position: absolute` 或 `position: fixed` 的元素时，此代码会被触发来计算这些元素的布局。
- **CSS:**  CSS 属性，例如 `top`, `left`, `right`, `bottom`, `width`, `height`, `margin`, `padding`, 以及与分片相关的属性 (`column-count`, `break-before` 等)，都会直接影响此代码的执行逻辑和计算结果。例如，修改一个绝对定位元素的 `left` 值，会导致此代码重新计算其在分片容器中的位置。
- **JavaScript:**  JavaScript 可以动态地修改元素的 CSS 属性，从而间接地影响此代码的执行。例如，使用 JavaScript 动态创建一个 `position: fixed` 的元素并添加到 DOM 中，此代码会被调用来确定该元素在视口中的位置。

**逻辑推理 - 假设输入与输出 (更具体的例子):**

假设我们有以下 HTML 和 CSS:

```html
<div style="column-count: 2; height: 300px; position: relative;">
  <div style="position: absolute; top: 50px; left: 20px; width: 100px; height: 50px;"></div>
</div>
```

**假设输入:**

- 容器的列数为 2，高度为 300px。
- 绝对定位的 `div` 元素的 `top` 为 50px，`left` 为 20px，宽度为 100px，高度为 50px。

**处理过程 (代码内部逻辑):**

1. **确定起始分片容器:** `ComputeStartFragmentIndexAndRelativeOffset` 会确定该绝对定位元素应该从哪个列（分片容器）开始布局。这可能取决于之前的元素布局情况。
2. **计算偏移:**  `AddOOFToFragmentainer` 会计算元素在起始分片容器中的偏移量。由于 `top: 50px; left: 20px;`，相对于容器的 padding box，元素的起始位置会被计算出来。
3. **生成布局片段:** `GenerateFragment` 会根据计算出的位置和尺寸生成该元素的布局片段。

**输出:**

- 该绝对定位的 `div` 元素会被放置在第一列（假设空间足够），其相对于该列的偏移量会接近 `(50px, 20px)`，具体还需要考虑容器的 padding 等因素。

**用户或编程常见的使用错误:**

- **错误地假设包含块:**  对于 `position: absolute` 的元素，如果没有设置 `position: relative`, `position: absolute`, 或 `position: fixed` 的祖先元素，其包含块将是初始包含块 (通常是视口)。这可能导致开发者预期元素相对于某个父元素定位，但实际并非如此。
- **忽略分片容器的影响:**  在多列布局或分页等场景中，开发者可能会忽略分片容器对绝对定位元素布局的影响，导致元素出现在错误的列或页面中。
- **过度依赖绝对定位:**  过度使用绝对定位可能会导致布局难以维护和响应式不足。
- **没有考虑滚动容器:**  如果绝对定位元素的包含块是可滚动的，那么元素的定位是相对于包含块的滚动原点，而不是视口的原点 (除非是 `position: fixed`)。

**总结一下它的功能:**

作为 `blink/renderer/core/layout/out_of_flow_layout_part.cc` 文件的第 4 部分，此代码段的核心功能是 **在分片容器的上下文中，负责对 out-of-flow (绝对定位和固定定位) 的元素进行布局计算和片段生成**。它处理了跨分片容器的布局，并确保 out-of-flow 元素能够按照 CSS 规则正确地定位和渲染在页面上。 它利用之前步骤计算的信息，并生成最终的布局结果，为后续的渲染和合成阶段做准备。

### 提示词
```
这是目录为blink/renderer/core/layout/out_of_flow_layout_part.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
tatic_position = static_position
                        .ConvertToPhysical({node_info.default_writing_direction,
                                            container_physical_content_size})
                        .ConvertToLogical({candidate_writing_direction,
                                           container_physical_content_size});

  const InsetModifiedContainingBlock imcb = ComputeInsetModifiedContainingBlock(
      node_info.node, space.AvailableSize(), alignment, insets, static_position,
      container_writing_direction, candidate_writing_direction);

  {
    auto& document = node_info.node.GetDocument();
    if (alignment.inline_alignment.GetPosition() != ItemPosition::kNormal) {
      if (insets.inline_start && insets.inline_end) {
        UseCounter::Count(document,
                          WebFeature::kOutOfFlowJustifySelfBothInsets);
      } else if (insets.inline_start || insets.inline_end) {
        UseCounter::Count(document,
                          WebFeature::kOutOfFlowJustifySelfSingleInset);
      } else {
        UseCounter::Count(document, WebFeature::kOutOfFlowJustifySelfNoInsets);
      }
    }

    if (alignment.block_alignment.GetPosition() != ItemPosition::kNormal) {
      if (insets.block_start && insets.block_end) {
        UseCounter::Count(document, WebFeature::kOutOfFlowAlignSelfBothInsets);
      } else if (insets.block_start || insets.block_end) {
        UseCounter::Count(document, WebFeature::kOutOfFlowAlignSelfSingleInset);
      } else {
        UseCounter::Count(document, WebFeature::kOutOfFlowAlignSelfNoInsets);
      }
    }
  }

  const BoxStrut border_padding = ComputeBorders(space, node_info.node) +
                                  ComputePadding(space, candidate_style);

  std::optional<LogicalSize> replaced_size;
  if (node_info.node.IsReplaced()) {
    // Create a new space with the IMCB size, and stretch constraints.
    ConstraintSpaceBuilder builder(candidate_style.GetWritingMode(),
                                   candidate_style.GetWritingDirection(),
                                   /* is_new_fc */ true);
    builder.SetAvailableSize(imcb.Size());
    builder.SetPercentageResolutionSize(space.PercentageResolutionSize());
    builder.SetReplacedPercentageResolutionSize(
        space.PercentageResolutionSize());

    const bool is_parallel =
        IsParallelWritingMode(container_writing_direction.GetWritingMode(),
                              candidate_writing_direction.GetWritingMode());
    const ItemPosition inline_position =
        (is_parallel ? candidate_style.JustifySelf()
                     : candidate_style.AlignSelf())
            .GetPosition();
    const bool is_inline_stretch = !imcb.has_auto_inline_inset &&
                                   inline_position == ItemPosition::kStretch;
    if (is_inline_stretch) {
      builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchExplicit);
    }
    const ItemPosition block_position =
        (is_parallel ? candidate_style.AlignSelf()
                     : candidate_style.JustifySelf())
            .GetPosition();
    const bool is_block_stretch =
        !imcb.has_auto_block_inset && block_position == ItemPosition::kStretch;
    if (is_block_stretch) {
      builder.SetBlockAutoBehavior(AutoSizeBehavior::kStretchExplicit);
    }

    replaced_size =
        ComputeReplacedSize(node_info.node, builder.ToConstraintSpace(),
                            border_padding, ReplacedSizeMode::kNormal);
  }

  const LogicalAnchorCenterPosition anchor_center_position =
      ComputeAnchorCenterPosition(candidate_style, alignment,
                                  candidate_writing_direction,
                                  space.AvailableSize());

  OffsetInfo offset_info;
  LogicalOofDimensions& node_dimensions = offset_info.node_dimensions;
  offset_info.inline_size_depends_on_min_max_sizes = ComputeOofInlineDimensions(
      node_info.node, candidate_style, space, imcb, anchor_center_position,
      alignment, border_padding, replaced_size, container_insets,
      container_writing_direction, &node_dimensions);

  PhysicalToLogicalGetter has_non_auto_inset(
      candidate_writing_direction, candidate_style,
      &ComputedStyle::IsTopInsetNonAuto, &ComputedStyle::IsRightInsetNonAuto,
      &ComputedStyle::IsBottomInsetNonAuto, &ComputedStyle::IsLeftInsetNonAuto);

  // Calculate the inline scroll offset range where the inline dimension fits.
  std::optional<InsetModifiedContainingBlock> imcb_for_position_fallback;
  std::optional<LayoutUnit> inline_scroll_min;
  std::optional<LayoutUnit> inline_scroll_max;
  if (try_fit_available_space) {
    imcb_for_position_fallback = ComputeIMCBForPositionFallback(
        space.AvailableSize(), alignment, insets, static_position,
        candidate_style, container_writing_direction,
        candidate_writing_direction);
    offset_info.imcb_for_position_order = imcb_for_position_fallback;
    if (!CalculateNonOverflowingRangeInOneAxis(
            node_dimensions.MarginBoxInlineStart(),
            node_dimensions.MarginBoxInlineEnd(),
            imcb_for_position_fallback->inline_start,
            imcb_for_position_fallback->InlineEndOffset(),
            container_insets.inline_start, container_insets.inline_end,
            has_non_auto_inset.InlineStart(), has_non_auto_inset.InlineEnd(),
            &inline_scroll_min, &inline_scroll_max)) {
      return std::nullopt;
    }
  }

  // We may have already pre-computed our block-dimensions when determining
  // our min/max sizes, only run if needed.
  if (node_dimensions.size.block_size == kIndefiniteSize) {
    offset_info.initial_layout_result = ComputeOofBlockDimensions(
        node_info.node, candidate_style, space, imcb, anchor_center_position,
        alignment, border_padding, replaced_size, container_insets,
        container_writing_direction, &node_dimensions);
  }

  // Calculate the block scroll offset range where the block dimension fits.
  std::optional<LayoutUnit> block_scroll_min;
  std::optional<LayoutUnit> block_scroll_max;
  if (try_fit_available_space) {
    if (!CalculateNonOverflowingRangeInOneAxis(
            node_dimensions.MarginBoxBlockStart(),
            node_dimensions.MarginBoxBlockEnd(),
            imcb_for_position_fallback->block_start,
            imcb_for_position_fallback->BlockEndOffset(),
            container_insets.block_start, container_insets.block_end,
            has_non_auto_inset.BlockStart(), has_non_auto_inset.BlockEnd(),
            &block_scroll_min, &block_scroll_max)) {
      return std::nullopt;
    }
  }

  offset_info.block_estimate = node_dimensions.size.block_size;
  offset_info.container_content_size =
      container_physical_content_size.ConvertToLogical(
          candidate_writing_direction.GetWritingMode());

  // Calculate the offsets.
  const BoxStrut inset =
      node_dimensions.inset.ConvertToPhysical(candidate_writing_direction)
          .ConvertToLogical(node_info.default_writing_direction);

  // |inset| is relative to the container's padding-box. Convert this to being
  // relative to the default container's border-box.
  offset_info.offset = container_rect.offset;
  offset_info.offset.inline_offset += inset.inline_start;
  offset_info.offset.block_offset += inset.block_start;

  // Calculate the absolutized insets to be stored on |LayoutResult|.
  // |node_dimensions.inset| doesn't include margins, but |insets| do. We add
  // margins into |used_insets| for the calculation, and then remove them at the
  // end.
  const BoxStrut used_insets = node_dimensions.inset - node_dimensions.margins;
  BoxStrut insets_to_store;
  insets_to_store.inline_start =
      insets.inline_start.value_or(used_insets.inline_start);
  insets_to_store.inline_end =
      insets.inline_end.value_or(used_insets.inline_end);
  insets_to_store.block_start =
      insets.block_start.value_or(used_insets.block_start);
  insets_to_store.block_end = insets.block_end.value_or(used_insets.block_end);
  offset_info.insets_for_get_computed_style =
      insets_to_store.ConvertToPhysical(candidate_writing_direction)
          .ConvertToLogical(node_info.default_writing_direction);

  if (try_fit_available_space) {
    out_non_overflowing_range->containing_block_range =
        LogicalScrollRange{inline_scroll_min, inline_scroll_max,
                           block_scroll_min, block_scroll_max}
            .ToPhysical(candidate_writing_direction);
    out_non_overflowing_range->anchor_object = GetPositionAnchorObject(
        node_info.node, candidate_style, anchor_evaluator.AnchorQuery());
  }

  bool anchor_center_x = anchor_center_position.inline_offset.has_value();
  bool anchor_center_y = anchor_center_position.block_offset.has_value();
  if (!candidate_writing_direction.IsHorizontal()) {
    std::swap(anchor_center_x, anchor_center_y);
  }
  offset_info.needs_scroll_adjustment_in_x =
      anchor_center_x || anchor_evaluator.NeedsScrollAdjustmentInX();
  offset_info.needs_scroll_adjustment_in_y =
      anchor_center_y || anchor_evaluator.NeedsScrollAdjustmentInY();

  return offset_info;
}

const LayoutResult* OutOfFlowLayoutPart::Layout(
    const NodeToLayout& oof_node_to_layout,
    const ConstraintSpace* fragmentainer_constraint_space,
    bool is_last_fragmentainer_so_far) {
  const OffsetInfo& offset_info = oof_node_to_layout.offset_info;

  const LayoutResult* layout_result = offset_info.initial_layout_result;
  // Reset the layout result computed earlier to allow fragmentation in the next
  // layout pass, if needed. Also do this if we're inside repeatable content, as
  // the pre-computed layout result is unusable then.
  if (fragmentainer_constraint_space ||
      GetConstraintSpace().IsInsideRepeatableContent()) {
    layout_result = nullptr;
  }

  // Skip this step if we produced a fragment that can be reused when
  // estimating the block-size.
  if (!layout_result) {
    layout_result =
        GenerateFragment(oof_node_to_layout, fragmentainer_constraint_space,
                         is_last_fragmentainer_so_far);
  }

  DCHECK_EQ(layout_result->Status(), LayoutResult::kSuccess);

  layout_result->GetMutableForOutOfFlow().SetOutOfFlowInsetsForGetComputedStyle(
      offset_info.insets_for_get_computed_style);

  layout_result->GetMutableForOutOfFlow().SetOutOfFlowPositionedOffset(
      offset_info.offset);

  layout_result->GetMutableForOutOfFlow().SetNeedsScrollAdjustment(
      offset_info.needs_scroll_adjustment_in_x,
      offset_info.needs_scroll_adjustment_in_y);

  layout_result->GetMutableForOutOfFlow().SetNonOverflowingScrollRanges(
      offset_info.non_overflowing_scroll_ranges);

  layout_result->GetMutableForOutOfFlow().SetAccessibilityAnchor(
      offset_info.accessibility_anchor);

  layout_result->GetMutableForOutOfFlow().SetDisplayLocksAffectedByAnchors(
      offset_info.display_locks_affected_by_anchors);

  const BlockNode& node = oof_node_to_layout.node_info.node;

  UpdatePositionVisibilityAfterLayout(offset_info, node,
                                      container_builder_->AnchorQuery());

  if (AXObjectCache* cache = node.GetDocument().ExistingAXObjectCache()) {
    cache->CSSAnchorChanged(node.GetLayoutBox());
  }

  return layout_result;
}

bool OutOfFlowLayoutPart::IsContainingBlockForCandidate(
    const LogicalOofPositionedNode& candidate) {
  // Fragmentainers are not allowed to be containing blocks.
  if (container_builder_->IsFragmentainerBoxType())
    return false;

  EPosition position = candidate.Node().Style().GetPosition();

  // Candidates whose containing block is inline are always positioned inside
  // closest parent block flow.
  if (candidate.inline_container.container) {
    DCHECK(candidate.inline_container.container
               ->CanContainOutOfFlowPositionedElement(position));
    return container_builder_->GetLayoutObject() ==
           candidate.box->ContainingBlock();
  }
  return (is_absolute_container_ && position == EPosition::kAbsolute) ||
         (is_fixed_container_ && position == EPosition::kFixed);
}

// The fragment is generated in one of these two scenarios:
// 1. To estimate candidate's block size, in this case block_size is
//    container's available size.
// 2. To compute final fragment, when block size is known from the absolute
//    position calculation.
const LayoutResult* OutOfFlowLayoutPart::GenerateFragment(
    const NodeToLayout& oof_node_to_layout,
    const ConstraintSpace* fragmentainer_constraint_space,
    bool is_last_fragmentainer_so_far) {
  const NodeInfo& node_info = oof_node_to_layout.node_info;
  const OffsetInfo& offset_info = oof_node_to_layout.offset_info;
  const BlockBreakToken* break_token = oof_node_to_layout.break_token;
  const BlockNode& node = node_info.node;
  const auto& style = node.Style();
  const LayoutUnit block_offset = offset_info.offset.block_offset;

  LayoutUnit inline_size = offset_info.node_dimensions.size.inline_size;
  LayoutUnit block_size = offset_info.block_estimate.value_or(
      offset_info.container_content_size.block_size);
  LogicalSize logical_size(inline_size, block_size);
  // Convert from logical size in the writing mode of the child to the logical
  // size in the writing mode of the container. That's what the constraint space
  // builder expects.
  PhysicalSize physical_size =
      ToPhysicalSize(logical_size, style.GetWritingMode());
  LogicalSize available_size =
      physical_size.ConvertToLogical(GetConstraintSpace().GetWritingMode());
  bool is_repeatable = false;

  ConstraintSpaceBuilder builder(GetConstraintSpace(),
                                 style.GetWritingDirection(),
                                 /* is_new_fc */ true);
  builder.SetAvailableSize(available_size);
  builder.SetPercentageResolutionSize(offset_info.container_content_size);
  builder.SetIsFixedInlineSize(true);
  builder.SetIsHiddenForPaint(node_info.is_hidden_for_paint);

  // In some cases we will need the fragment size in order to calculate the
  // offset. We may have to lay out to get the fragment size. For block
  // fragmentation, we *need* to know the block-offset before layout. In other
  // words, in that case, we may have to lay out, calculate the offset, and then
  // lay out again at the correct block-offset.
  if (offset_info.block_estimate.has_value() &&
      (!fragmentainer_constraint_space || !offset_info.initial_layout_result)) {
    builder.SetIsFixedBlockSize(true);
  }

  if (fragmentainer_constraint_space) {
    if (container_builder_->Node().IsPaginatedRoot() &&
        style.GetPosition() == EPosition::kFixed &&
        !oof_node_to_layout.containing_block_fragment) {
      // Paginated fixed-positioned elements are repeated on every page, if
      // contained by the initial containing block (i.e. when not contained by a
      // transformed element or similar) and may therefore not fragment.
      builder.SetShouldRepeat(true);
      builder.SetIsInsideRepeatableContent(true);
      builder.DisableMonolithicOverflowPropagation();
      is_repeatable = true;
    } else {
      // Note that we pass the pristine size of the fragmentainer here, which
      // means that we're not going to make room for any cloned borders that
      // might exist in the containing block chain of the OOF. This is
      // reasonable in a way, since they are out of flow after all, but, then
      // again, it's not really defined how out of flow positioned descendants
      // should behave when contained by something with cloned box decorations.
      //
      // See https://github.com/w3c/csswg-drafts/issues/10553
      SetupSpaceBuilderForFragmentation(
          *fragmentainer_constraint_space, node,
          fragmentainer_constraint_space->FragmentainerOffset() + block_offset,
          fragmentainer_constraint_space->FragmentainerBlockSize(),
          node_info.requires_content_before_breaking, &builder);

      // Out-of-flow positioned elements whose containing block is inside
      // clipped overflow shouldn't generate any additional fragmentainers. Just
      // place everything in the last fragmentainer. This is similar to what
      // LayoutAlgorithm::RelayoutWithoutFragmentation() does for in-flow
      // content overflowing a clipped ancestor, except that in this case we
      // know up front that we should disable fragmentation.
      //
      // Note that this approach isn't perfect. We don't know where (in which
      // fragmentainer) the clipped container ends. It may have ended in some
      // fragmentainer earlier than the last one, in which case we should have
      // finished this OOF there. But we have no (easy) way of telling where
      // that might be. But as long as the OOF doesn't contribute to any
      // additional fragmentainers, we should be (pretty) good.
      if (node_info.containing_block.IsFragmentedInsideClippedContainer()) {
        if (is_last_fragmentainer_so_far) {
          builder.DisableFurtherFragmentation();
        }
        builder.DisableMonolithicOverflowPropagation();
      }
    }
  } else if (container_builder_->IsInitialColumnBalancingPass()) {
    SetupSpaceBuilderForFragmentation(
        GetConstraintSpace(), node,
        GetConstraintSpace().FragmentainerOffset() + block_offset,
        GetConstraintSpace().FragmentainerBlockSize(),
        /*requires_content_before_breaking=*/false, &builder);
  }
  ConstraintSpace space = builder.ToConstraintSpace();

  if (is_repeatable)
    return node.LayoutRepeatableRoot(space, break_token);
  return node.Layout(space, break_token);
}

void OutOfFlowLayoutPart::LayoutOOFsInFragmentainer(
    HeapVector<NodeToLayout>& pending_descendants,
    wtf_size_t index,
    LogicalOffset fragmentainer_progression,
    bool has_oofs_in_later_fragmentainer,
    LayoutUnit* monolithic_overflow,
    bool* has_actual_break_inside,
    HeapVector<NodeToLayout>* fragmented_descendants) {
  wtf_size_t num_children = ChildCount();
  bool is_new_fragment = index >= num_children;
  bool is_last_fragmentainer_so_far = index + 1 >= num_children;

  DCHECK(fragmented_descendants);
  HeapVector<NodeToLayout> descendants_continued;
  ClearCollectionScope<HeapVector<NodeToLayout>> descendants_continued_scope(
      &descendants_continued);
  std::swap(*fragmented_descendants, descendants_continued);

  // If |index| is greater than the number of current children, and there are no
  // OOF children to be added, we will still need to add an empty fragmentainer
  // in its place. We also need to update the fragmentainer in case of
  // overflowed monolithic content (may happen in pagination for printing), or
  // if this is the hitherto last fragmentainer (it needs to be updated with an
  // outgoing break token, if nothing else).
  //
  // Otherwise, return early since there is no work to do.
  if (pending_descendants.empty() && descendants_continued.empty() &&
      *monolithic_overflow <= LayoutUnit() && !is_new_fragment &&
      !is_last_fragmentainer_so_far) {
    return;
  }

  // If we are a new fragment, find a non-spanner fragmentainer as a basis.
  wtf_size_t last_fragmentainer_index = index;
  while (last_fragmentainer_index >= num_children ||
         !GetChildFragment(last_fragmentainer_index).IsFragmentainerBox()) {
    DCHECK_GT(num_children, 0u);
    last_fragmentainer_index--;
  }

  const LogicalFragmentLink& container_link =
      FragmentationContextChildren()[last_fragmentainer_index];
  const BlockNode& node = container_builder_->Node();
  LogicalOffset fragmentainer_offset = container_link.offset;
  if (is_new_fragment) {
    // The fragmentainer being requested doesn't exist yet. This just means that
    // there are OOFs past the last fragmentainer that hold in-flow content.
    // Create and append an empty fragmentainer. Creating a fragmentainer is
    // algorithm-specific and not necessarily a trivial job, so leave it to the
    // fragmentation context algorithms.
    //
    // Afterwards we'll run SimplifiedOofLayoutAlgorithm and merge the results
    // from that algorithm into the new empty fragmentainer.
    const PhysicalBoxFragment& previous_fragmentainer =
        GetChildFragment(last_fragmentainer_index);
    const PhysicalBoxFragment* new_fragmentainer;
    if (node.IsPaginatedRoot()) {
      bool needs_total_page_count;
      new_fragmentainer = &PaginatedRootLayoutAlgorithm::CreateEmptyPage(
          node, GetConstraintSpace(), index, previous_fragmentainer,
          &needs_total_page_count);
      needs_total_page_count_ |= needs_total_page_count;
      additional_pages_were_added_ = true;
    } else {
      new_fragmentainer = &ColumnLayoutAlgorithm::CreateEmptyColumn(
          node, GetConstraintSpace(), previous_fragmentainer);
    }
    fragmentainer_offset += fragmentainer_progression;
    AddFragmentainer(*new_fragmentainer, fragmentainer_offset);
    DCHECK_EQ(index + 1, ChildCount());
  }

  const ConstraintSpace& space = GetFragmentainerConstraintSpace(index);
  const PhysicalBoxFragment* fragmentainer = &GetChildFragment(index);
  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);
  LayoutAlgorithmParams params(node, fragment_geometry, space,
                               PreviousFragmentainerBreakToken(index));
  // This algorithm will be used to add new OOFs. The existing fragment passed
  // is the last fragmentainer created so far.
  SimplifiedOofLayoutAlgorithm algorithm(params, *fragmentainer);

  if (has_oofs_in_later_fragmentainer) {
    algorithm.SetHasSubsequentChildren();
  }

  // Layout any OOF elements that are a continuation of layout first.
  for (auto& descendant : descendants_continued) {
    AddOOFToFragmentainer(descendant, &space, fragmentainer_offset, index,
                          is_last_fragmentainer_so_far, has_actual_break_inside,
                          &algorithm, fragmented_descendants);
  }
  // Once we've laid out the OOF elements that are a continuation of layout,
  // we can layout the OOF elements that start layout in the current
  // fragmentainer.
  for (auto& descendant : pending_descendants) {
    AddOOFToFragmentainer(descendant, &space, fragmentainer_offset, index,
                          is_last_fragmentainer_so_far, has_actual_break_inside,
                          &algorithm, fragmented_descendants);
  }

  // Don't update the builder when performing column balancing.
  if (column_balancing_info_) {
    return;
  }

  const LayoutResult* fragmentainer_result = algorithm.Layout();
  const auto& new_fragmentainer =
      To<PhysicalBoxFragment>(fragmentainer_result->GetPhysicalFragment());

  // The new fragmentainer was just prepared by the algorithm as a temporary
  // placeholder fragmentainer which will be "poured" into the existing one, and
  // then forgotten. This will add new OOFs (and whatever relevant info they
  // propagated).
  fragmentainer->GetMutableForOofFragmentation().Merge(new_fragmentainer);

  if (const BlockBreakToken* break_token = fragmentainer->GetBreakToken()) {
    *monolithic_overflow = break_token->MonolithicOverflow();
  } else {
    *monolithic_overflow = LayoutUnit();
  }
}

void OutOfFlowLayoutPart::AddOOFToFragmentainer(
    NodeToLayout& descendant,
    const ConstraintSpace* fragmentainer_space,
    LogicalOffset fragmentainer_offset,
    wtf_size_t index,
    bool is_last_fragmentainer_so_far,
    bool* has_actual_break_inside,
    SimplifiedOofLayoutAlgorithm* algorithm,
    HeapVector<NodeToLayout>* fragmented_descendants) {
  const LayoutResult* result = LayoutOOFNode(descendant, fragmentainer_space,
                                             is_last_fragmentainer_so_far);
  DCHECK_EQ(result->Status(), LayoutResult::kSuccess);

  // Apply the relative positioned offset now that fragmentation is complete.
  LogicalOffset oof_offset = result->OutOfFlowPositionedOffset();
  LogicalOffset relative_offset =
      descendant.node_info.base_container_info.relative_offset;
  LogicalOffset adjusted_offset = oof_offset + relative_offset;

  // In the case where an OOF descendant of |descendant| has its containing
  // block outside the current fragmentation context, we will want to apply an
  // additional offset to |oof_offset| in PropagateOOFPositionedInfo() such that
  // it's the offset relative to the current builder rather than the offset such
  // that all fragmentainers are stacked on top of each other.
  LogicalOffset offset_adjustment = fragmentainer_offset;

  result->GetMutableForOutOfFlow().SetOutOfFlowPositionedOffset(
      adjusted_offset);

  LogicalOffset additional_fixedpos_offset;
  if (descendant.node_info.fixedpos_containing_block.Fragment()) {
    additional_fixedpos_offset =
        descendant.offset_info.original_offset -
        descendant.node_info.fixedpos_containing_block.Offset();
    // Currently, |additional_fixedpos_offset| is the offset from the top of
    // |descendant| to the fixedpos containing block. Adjust this so that it
    // includes the block contribution of |descendant| from previous
    // fragmentainers. This ensures that any fixedpos descendants in the current
    // fragmentainer have the correct static position.
    if (descendant.break_token) {
      additional_fixedpos_offset.block_offset +=
          descendant.break_token->ConsumedBlockSize();
    }
  } else if (outer_context_has_fixedpos_container_) {
    // If the fixedpos containing block is in an outer fragmentation context,
    // we should adjust any fixedpos static positions such that they are
    // relative to the top of the inner multicol. These will eventually be
    // updated again with the offset from the multicol to the fixedpos
    // containing block such that the static positions are relative to the
    // containing block.
    DCHECK(multicol_children_);
    for (wtf_size_t i = std::min(index, multicol_children_->size()); i > 0u;
         i--) {
      MulticolChildInfo& column_info = (*multicol_children_)[i - 1];
      if (column_info.parent_break_token) {
        additional_fixedpos_offset.block_offset +=
            column_info.parent_break_token->ConsumedBlockSize();
        break;
      }
    }
  }

  const auto& physical_fragment =
      To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  const BlockBreakToken* break_token = physical_fragment.GetBreakToken();
  if (break_token) {
    // We must continue layout in the next fragmentainer. Update any information
    // in NodeToLayout, and add the node to |fragmented_descendants|.
    NodeToLayout fragmented_descendant = descendant;
    fragmented_descendant.break_token = break_token;
    if (!break_token->IsRepeated()) {
      // Fragmented nodes usually resume at the block-start of the next
      // fragmentainer. One exception is if there's fragmentainer overflow
      // caused by monolithic content in paged media. Then we need to move past
      // that.
      fragmented_descendant.offset_info.offset.block_offset =
          break_token->MonolithicOverflow();
      *has_actual_break_inside = true;
    }
    fragmented_descendants->emplace_back(fragmented_descendant);
  }

  // Figure out if the current OOF affects column balancing. Then return since
  // we don't want to add the OOFs to the builder until the current columns have
  // completed layout.
  if (column_balancing_info_) {
    LayoutUnit space_shortage = CalculateSpaceShortage(
        *fragmentainer_space, result, oof_offset.block_offset,
        fragmentainer_space->FragmentainerBlockSize());
    column_balancing_info_->PropagateSpaceShortage(space_shortage);
    // We don't check the break appeal of the layout result to determine if
    // there is a violating break because OOFs aren't affected by the various
    // break rules. However, OOFs aren't pushed to the next fragmentainer if
    // they don't fit (when they are monolithic). Use |has_violating_break| to
    // tell the column algorithm when this happens so that it knows to attempt
    // to expand the columns in such cases.
    if (!column_balancing_info_->has_violating_break) {
      if (space_shortage > LayoutUnit() && !physical_fragment.GetBreakToken()) {
        column_balancing_info_->has_violating_break = true;
      }
    }
    return;
  }

  // Propagate new data to the |container_builder_| manually. Unlike when in
  // regular layout, MutableForOofFragmentation / SimplifiedOofLayoutAlgorithm
  // won't do this for us.
  container_builder_->PropagateChildAnchors(
      physical_fragment, oof_offset + relative_offset + offset_adjustment);
  container_builder_->PropagateStickyDescendants(physical_fragment);
  LayoutUnit containing_block_adjustment =
      container_builder_->BlockOffsetAdjustmentForFragmentainer(
          fragmentainer_consumed_block_size_);
  if (result->GetPhysicalFragment().NeedsOOFPositionedInfoPropagation()) {
    container_builder_->PropagateOOFPositionedInfo(
        result->GetPhysicalFragment(), oof_offset, relative_offset,
        offset_adjustment,
        /* inline_container */ nullptr, containing_block_adjustment,
        &descendant.node_info.containing_block,
        &descendant.node_info.fixedpos_containing_block,
        &descendant.node_info.fixedpos_inline_container,
        additional_fixedpos_offset);
  }
  algorithm->AppendOutOfFlowResult(result);

  // Copy the offset of the OOF node back to legacy such that it is relative
  // to its containing block rather than the fragmentainer that it is being
  // added to.
  if (!descendant.break_token) {
    const auto* container =
        To<PhysicalBoxFragment>(descendant.containing_block_fragment.Get());

    if (!container) {
      // If we're paginated, we don't have a containing block fragment, but we
      // need one now, to calcualte the position correctly for the legacy
      // engine. Just pick the first page, which actually happens to be defined
      // as the initial containing block:
      // https://www.w3.org/TR/CSS22/page.html#page-box
      DCHECK(container_builder_->Node().IsPaginatedRoot());
      container = &GetChildFragment(0);
    }

    LogicalOffset legacy_offset =
        descendant.offset_info.original_offset -
        descendant.node_info.base_container_info.offset_to_border_box;
    descendant.node_info.node.CopyChildFragmentPosition(
        physical_fragment,
        legacy_offset.ConvertToPhysical(
            container->Style().GetWritingDirection(), container->Size(),
            physical_fragment.Size()),
        *container, /* previous_container_break_token */ nullptr);
  }
}

ConstraintSpace OutOfFlowLayoutPart::GetFragmentainerConstraintSpace(
    wtf_size_t index) {
  DCHECK_LT(index, ChildCount());
  const PhysicalBoxFragment& fragment = GetChildFragment(index);
  DCHECK(fragment.IsFragmentainerBox());
  const WritingMode container_writing_mode =
      container_builder_->Style().GetWritingMode();
  LogicalSize fragmentainer_size =
      fragment.Size().ConvertToLogical(container_writing_mode);
  LogicalSize percentage_resolution_size =
      LogicalSize(fragmentainer_size.inline_size,
                  container_builder_->ChildAvailableSize().block_size);

  // In the current implementation it doesn't make sense to restrict imperfect
  // breaks inside OOFs, since we never break and resume OOFs in a subsequent
  // outer fragmentainer anyway (we'll always stay in the current outer
  // fragmentainer and just create overflowing columns in the current row,
  // rather than moving to the next one).
  BreakAppeal min_break_appeal = kBreakAppealLastResort;

  return CreateConstraintSpaceForFragmentainer(
      GetConstraintSpace(), GetFragmentainerType(), fragmentainer_size,
      percentage_resolution_size, /* balance_columns */ false,
      min_break_appeal);
}

// Compute in which fragmentainer the OOF element will start its layout and
// position the offset relative to that fragmentainer.
void OutOfFlowLayoutPart::ComputeStartFragmentIndexAndRelativeOffset(
    WritingMode default_writing_mode,
    LayoutUnit block_estimate,
    std::optional<LayoutUnit> clipped_container_block_offset,
    wtf_size_t* start_index,
    LogicalOffset* offset) const {
  // The sum of all previous fragmentainers' block size.
  LayoutUnit used_block_size;
  // The sum of all previous fragmentainers' block size + the current one.
  LayoutUnit current_max_block_size;
  // The block size for the last fragmentainer we encountered.
  LayoutUnit fragmentainer_block_size;

  LayoutUnit target_block_offset = offset->block_offset;
  if (clipped_container_block_offset &&
      container_builder_->Node().IsPaginatedRoot()) {
    // If we're printing, and we have an OOF inside a clipped container, prevent
    // the start fragmentainer from precedin
```