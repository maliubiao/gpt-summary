Response:
The user wants a summary of the functionality of the provided C++ code snippet from `length_utils.cc`. I need to go through each function and understand its purpose. Then, I need to identify connections to web technologies (JavaScript, HTML, CSS) and illustrate these connections with examples. If any logical deductions are made in the code, I need to create hypothetical inputs and their corresponding outputs. Finally, I need to pinpoint potential user or programming errors related to these functionalities and provide examples.

Here's a breakdown of the functions and their apparent purposes:

1. **`CalculateBorderPaddingAndScrollbar`**: Calculates the effective border, padding, and scrollbar sizes for a given layout node.
2. **`CalculateInitialFragmentGeometry` (two versions)**: Determines the initial geometry (size) of a layout fragment. The second version is a convenience wrapper for the first.
3. **`ShrinkLogicalSize`**:  Reduces a logical size by a given amount (insets), clamping the result to zero if it becomes negative.
4. **`CalculateChildAvailableSize`**: Calculates the available size for a child element based on its parent's size and padding.
5. **`AdjustChildPercentageSize`**:  Handles percentage size calculations for children, considering quirks mode.
6. **`CalculateChildPercentageSize`**: Calculates the percentage-based size for a child element.
7. **`CalculateReplacedChildPercentageSize`**: Specifically calculates percentage sizes for replaced child elements (like images or iframes).
8. **`ClampIntrinsicBlockSize`**:  Adjusts the intrinsic block size of an element, considering factors like size containment and viewport filling.
9. **`CalculateMinMaxSizesIgnoringChildren`**: Computes the minimum and maximum sizes of an element without considering its children.
10. **`AddScrollbarFreeze`**: Determines if scrollbars have appeared or disappeared between layout passes.

Now I can start generating the response, keeping in mind the three parts requested by the user.
```cpp
llbar_padding = border_padding + scrollbar;

  if (node.IsReplaced()) {
    const auto border_box_size = ComputeReplacedSize(
        node, space, border_padding,
        is_intrinsic ? ReplacedSizeMode::kIgnoreInlineLengths
                     : ReplacedSizeMode::kNormal);
    return {border_box_size, border, scrollbar, padding};
  }

  const LayoutUnit inline_size =
      is_intrinsic ? kIndefiniteSize
                   : ComputeInlineSizeForFragment(space, node, border_padding,
                                                  min_max_sizes_func);

  if (inline_size != kIndefiniteSize &&
      inline_size < border_scrollbar_padding.InlineSum() &&
      scrollbar.InlineSum() && !space.IsAnonymous()) [[unlikely]] {
    // Clamp the inline size of the scrollbar, unless it's larger than the
    // inline size of the content box, in which case we'll return that instead.
    // Scrollbar handling is quite bad in such situations, and this method here
    // is just to make sure that left-hand scrollbars don't mess up scrollWidth.
    // For the full story, visit http://crbug.com/724255.
    const auto content_box_inline_size =
        inline_size - border_padding.InlineSum();
    if (scrollbar.InlineSum() > content_box_inline_size) {
      if (scrollbar.inline_end) {
        DCHECK(!scrollbar.inline_start);
        scrollbar.inline_end = content_box_inline_size;
      } else {
        DCHECK(scrollbar.inline_start);
        scrollbar.inline_start = content_box_inline_size;
      }
    }
  }

  const auto default_block_size = CalculateDefaultBlockSize(
      space, node, break_token, border_scrollbar_padding);
  const auto block_size = ComputeInitialBlockSizeForFragment(
      space, node, border_padding, default_block_size, inline_size);

  return {LogicalSize(inline_size, block_size), border, scrollbar, padding};
}

FragmentGeometry CalculateInitialFragmentGeometry(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BlockBreakToken* break_token,
    bool is_intrinsic) {
  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    return node.ComputeMinMaxSizes(space.GetWritingMode(), type, space);
  };

  return CalculateInitialFragmentGeometry(space, node, break_token,
                                          MinMaxSizesFunc, is_intrinsic);
}

LogicalSize ShrinkLogicalSize(LogicalSize size, const BoxStrut& insets) {
  if (size.inline_size != kIndefiniteSize) {
    size.inline_size =
        (size.inline_size - insets.InlineSum()).ClampNegativeToZero();
  }
  if (size.block_size != kIndefiniteSize) {
    size.block_size =
        (size.block_size - insets.BlockSum()).ClampNegativeToZero();
  }

  return size;
}

LogicalSize CalculateChildAvailableSize(
    const ConstraintSpace& space,
    const BlockNode& node,
    const LogicalSize border_box_size,
    const BoxStrut& border_scrollbar_padding) {
  LogicalSize child_available_size =
      ShrinkLogicalSize(border_box_size, border_scrollbar_padding);

  if (space.IsAnonymous() ||
      (node.IsAnonymousBlock() &&
       child_available_size.block_size == kIndefiniteSize)) {
    child_available_size.block_size = space.AvailableSize().block_size;
  }

  return child_available_size;
}

namespace {

// Implements the common part of the child percentage size calculation. Deals
// with how percentages are propagated from parent to child in quirks mode.
LogicalSize AdjustChildPercentageSize(const ConstraintSpace& space,
                                      const BlockNode node,
                                      LogicalSize child_percentage_size,
                                      LayoutUnit parent_percentage_block_size) {
  // In quirks mode the percentage resolution height is passed from parent to
  // child.
  // https://quirks.spec.whatwg.org/#the-percentage-height-calculation-quirk
  if (child_percentage_size.block_size == kIndefiniteSize &&
      node.UseParentPercentageResolutionBlockSizeForChildren())
    child_percentage_size.block_size = parent_percentage_block_size;

  return child_percentage_size;
}

}  // namespace

LogicalSize CalculateChildPercentageSize(
    const ConstraintSpace& space,
    const BlockNode node,
    const LogicalSize child_available_size) {
  // Anonymous block or spaces should use the parent percent block-size.
  if (space.IsAnonymous() || node.IsAnonymousBlock()) {
    return {child_available_size.inline_size,
            space.PercentageResolutionBlockSize()};
  }

  // Table cell children don't apply the "percentage-quirk". I.e. if their
  // percentage resolution block-size is indefinite, they don't pass through
  // their parent's percentage resolution block-size.
  if (space.IsTableCellChild())
    return child_available_size;

  return AdjustChildPercentageSize(space, node, child_available_size,
                                   space.PercentageResolutionBlockSize());
}

LogicalSize CalculateReplacedChildPercentageSize(
    const ConstraintSpace& space,
    const BlockNode node,
    const LogicalSize child_available_size,
    const BoxStrut& border_scrollbar_padding,
    const BoxStrut& border_padding) {
  // Anonymous block or spaces should use the parent percent block-size.
  if (space.IsAnonymous() || node.IsAnonymousBlock()) {
    return {child_available_size.inline_size,
            space.PercentageResolutionBlockSize()};
  }

  // Table cell children don't apply the "percentage-quirk". I.e. if their
  // percentage resolution block-size is indefinite, they don't pass through
  // their parent's percentage resolution block-size.
  if (space.IsTableCellChild())
    return child_available_size;

  // Replaced descendants of a table-cell which has a definite block-size,
  // always resolve their percentages against this size (even during the
  // "layout" pass where the fixed block-size may be different).
  //
  // This ensures that between the table-cell "measure" and "layout" passes
  // the replaced descendants remain the same size.
  if (space.IsTableCell() && node.Style().LogicalHeight().IsFixed()) {
    LayoutUnit block_size = ComputeBlockSizeForFragmentInternal(
        space, node, border_padding, kIndefiniteSize /* intrinsic_size */,
        kIndefiniteSize /* inline_size */);
    DCHECK_NE(block_size, kIndefiniteSize);
    return {child_available_size.inline_size,
            (block_size - border_scrollbar_padding.BlockSum())
                .ClampNegativeToZero()};
  }

  return AdjustChildPercentageSize(
      space, node, child_available_size,
      space.ReplacedPercentageResolutionBlockSize());
}

LayoutUnit ClampIntrinsicBlockSize(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BlockBreakToken* break_token,
    const BoxStrut& border_scrollbar_padding,
    LayoutUnit current_intrinsic_block_size,
    std::optional<LayoutUnit> body_margin_block_sum) {
  // Tables don't respect size containment, or apply the "fill viewport" quirk.
  DCHECK(!node.IsTable());
  const ComputedStyle& style = node.Style();

  // Check if the intrinsic size was overridden.
  LayoutUnit override_intrinsic_size = node.OverrideIntrinsicContentBlockSize();
  if (override_intrinsic_size != kIndefiniteSize)
    return override_intrinsic_size + border_scrollbar_padding.BlockSum();

  // Check if we have a "default" block-size (e.g. a <textarea>).
  LayoutUnit default_intrinsic_size = node.DefaultIntrinsicContentBlockSize();
  if (default_intrinsic_size != kIndefiniteSize) {
    // <textarea>'s intrinsic size should ignore scrollbar existence.
    if (node.IsTextArea()) {
      return default_intrinsic_size -
             ComputeScrollbars(space, node).BlockSum() +
             border_scrollbar_padding.BlockSum();
    }
    return default_intrinsic_size + border_scrollbar_padding.BlockSum();
  }

  // If we have size containment, we ignore child contributions to intrinsic
  // sizing.
  if (node.ShouldApplyBlockSizeContainment())
    return border_scrollbar_padding.BlockSum();

  // Apply the "fills viewport" quirk if needed.
  if (!IsBreakInside(break_token) && node.IsQuirkyAndFillsViewport() &&
      style.LogicalHeight().HasAuto() &&
      space.AvailableSize().block_size != kIndefiniteSize) {
    DCHECK_EQ(node.IsBody() && !node.CreatesNewFormattingContext(),
              body_margin_block_sum.has_value());
    LayoutUnit margin_sum = body_margin_block_sum.value_or(
        ComputeMarginsForSelf(space, style).BlockSum());
    current_intrinsic_block_size = std::max(
        current_intrinsic_block_size,
        (space.AvailableSize().block_size - margin_sum).ClampNegativeToZero());
  }

  return current_intrinsic_block_size;
}

std::optional<MinMaxSizesResult> CalculateMinMaxSizesIgnoringChildren(
    const BlockNode& node,
    const BoxStrut& border_scrollbar_padding) {
  MinMaxSizes sizes;
  sizes += border_scrollbar_padding.InlineSum();

  // If intrinsic size was overridden, then use that.
  const LayoutUnit intrinsic_size_override =
      node.OverrideIntrinsicContentInlineSize();
  if (intrinsic_size_override != kIndefiniteSize) {
    sizes += intrinsic_size_override;
    return MinMaxSizesResult{sizes,
                             /* depends_on_block_constraints */ false};
  } else {
    LayoutUnit default_inline_size = node.DefaultIntrinsicContentInlineSize();
    if (default_inline_size != kIndefiniteSize) {
      sizes += default_inline_size;
      // <textarea>'s intrinsic size should ignore scrollbar existence.
      if (node.IsTextArea())
        sizes -= ComputeScrollbarsForNonAnonymous(node).InlineSum();
      return MinMaxSizesResult{sizes,
                               /* depends_on_block_constraints */ false};
    }
  }

  // Size contained elements don't consider children for intrinsic sizing.
  // Also, if we don't have children, we can determine the size immediately.
  if (node.ShouldApplyInlineSizeContainment() || !node.FirstChild()) {
    return MinMaxSizesResult{sizes,
                             /* depends_on_block_constraints */ false};
  }

  return std::nullopt;
}

void AddScrollbarFreeze(const BoxStrut& scrollbars_before,
                        const BoxStrut& scrollbars_after,
                        WritingDirectionMode writing_direction,
                        bool* freeze_horizontal,
                        bool* freeze_vertical) {
  PhysicalBoxStrut physical_before =
      scrollbars_before.ConvertToPhysical(writing_direction);
  PhysicalBoxStrut physical_after =
      scrollbars_after.ConvertToPhysical(writing_direction);
  *freeze_horizontal |= (!physical_before.top && physical_after.top) ||
                        (!physical_before.bottom && physical_after.bottom);
  *freeze_vertical |= (!physical_before.left && physical_after.left) ||
                      (!physical_before.right && physical_after.right);
}

}  // namespace blink
```

这是blink/renderer/core/layout/length_utils.cc文件的第3部分，主要包含了一系列用于计算和处理元素尺寸相关的工具函数。

**功能概括:**

该文件的核心功能是提供各种工具函数，用于在布局过程中计算元素的尺寸，包括：

*   **计算边框、内边距和滚动条的大小**: 考虑了不同类型的元素（如替换元素）以及是否是内部尺寸计算。
*   **计算元素的初始片段几何尺寸**:  确定元素在布局时的初始大小。
*   **收缩尺寸**:  根据给定的内边距值减小元素的逻辑尺寸。
*   **计算子元素的可用空间**:  确定父元素提供给子元素进行布局的空间。
*   **计算子元素的百分比尺寸**:  处理子元素百分比尺寸的计算，包括处理 quirks 模式下的特殊情况以及表格单元格的子元素。
*   **调整元素的固有块级尺寸**:  考虑到尺寸包含、viewport 填充等因素来调整元素的固有高度。
*   **计算忽略子元素的最小/最大尺寸**:  在不考虑子元素的情况下计算元素的最小和最大尺寸。
*   **检测滚动条的冻结状态**:  判断滚动条是否在布局过程中出现或消失。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些函数直接服务于浏览器渲染引擎的布局阶段，该阶段的目标是根据 HTML 结构和 CSS 样式来确定页面上每个元素的位置和大小。

1. **CSS 盒模型 (Box Model):**
    *   `CalculateBorderPaddingAndScrollbar` 函数直接对应了 CSS 盒模型的概念，它计算了 `border`, `padding`, 和 `scrollbar` 的大小，这些都是盒模型的重要组成部分。
    *   **举例:**  当 CSS 样式中设置了 `border: 1px solid black; padding: 10px;` 时，这个函数会被调用来获取这些值。

2. **CSS 尺寸属性 (Width and Height):**
    *   `CalculateInitialFragmentGeometry`, `CalculateChildAvailableSize`, `CalculateChildPercentageSize`, 和 `ClampIntrinsicBlockSize` 等函数都参与计算元素的最终宽度和高度。
    *   **举例:**
        *   对于 `width: 50%;` 的元素，`CalculateChildPercentageSize` 会根据父元素的宽度计算出子元素的实际宽度。
        *   对于 `height: auto;` 的块级元素，`ClampIntrinsicBlockSize` 可能会考虑其内容来确定最终高度。
        *   对于设置了 `box-sizing: border-box;` 的元素，`CalculateBorderPaddingAndScrollbar` 返回的 `border` 和 `padding` 值会被包含在元素的总尺寸计算中。

3. **CSS 布局 (Layout):**
    *   这些函数是布局算法的关键组成部分，它们决定了元素在页面上的排列方式。
    *   **举例:**  在计算浮动元素或绝对定位元素的位置时，需要先确定其尺寸，这些函数会参与到这个尺寸的计算过程中。

4. **HTML 元素特性:**
    *   `node.IsReplaced()` 检查元素是否是替换元素（如 `<img>`, `<iframe>`），这会影响尺寸的计算方式。
    *   **举例:**  对于 `<img>` 标签，其尺寸可能由 `width` 和 `height` 属性或其固有尺寸决定，`CalculateInitialFragmentGeometry` 会根据这些信息进行计算。

5. **JavaScript 获取元素尺寸:**
    *   当 JavaScript 代码使用 `offsetWidth`, `offsetHeight`, `clientWidth`, `clientHeight`, `scrollWidth`, `scrollHeight` 等属性来获取元素尺寸时，浏览器引擎内部会执行类似的计算逻辑，而这些 C++ 函数就是实现这些计算的核心。
    *   **举例:** 当 JavaScript 调用 `element.offsetWidth` 时，浏览器引擎会调用相应的布局计算函数，其中可能就包含此文件中定义的函数来获取元素的边框、内边距等信息。

6. **Quirks 模式:**
    *   `AdjustChildPercentageSize` 函数处理了在 quirks 模式下百分比高度计算的特殊规则，这与浏览器对早期网页的兼容性处理有关。
    *   **举例:**  在 quirks 模式下，如果一个元素的 `height` 设置为百分比，其父元素的高度如果没有明确指定，百分比高度可能无法正确计算。这个函数就处理了这种情况。

**逻辑推理的假设输入与输出:**

**示例 1: `ShrinkLogicalSize`**

*   **假设输入:**
    *   `size`: `LogicalSize(100, 200)` (inline_size = 100, block_size = 200)
    *   `insets`: `BoxStrut(10, 20, 5, 15)` (top=10, left=20, bottom=5, right=15)
*   **逻辑:** 从 `size` 中减去 `insets` 的相应值。
*   **预期输出:** `LogicalSize(65, 185)` (inline_size = 100 - (20 + 15) = 65, block_size = 200 - (10 + 5) = 185)

**示例 2: `CalculateChildAvailableSize`**

*   **假设输入:**
    *   `space`: 非匿名 ConstraintSpace， `AvailableSize` 为 `LogicalSize(500, 600)`
    *   `node`: 非匿名 BlockNode
    *   `border_box_size`: `LogicalSize(400, 500)`
    *   `border_scrollbar_padding`: `BoxStrut(5, 5, 5, 5)`
*   **逻辑:**  先用 `ShrinkLogicalSize` 从 `border_box_size` 中减去 `border_scrollbar_padding`，得到初步的可用尺寸。因为 `space` 和 `node` 都不是匿名，所以直接返回结果。
*   **预期输出:** `LogicalSize(390, 490)` (inline_size = 400 - (5 + 5) = 390, block_size = 500 - (5 + 5) = 490)

**用户或编程常见的使用错误及举例说明:**

1. **CSS 样式冲突导致尺寸计算错误:**
    *   **场景:** 用户可能设置了相互冲突的 CSS 属性，例如同时设置了 `width` 和 `max-width`，或者设置了过大的 `border` 和 `padding` 导致内容溢出。
    *   **举例:**  一个 `div` 设置了 `width: 100px; padding: 20px; border: 10px solid black;`。用户可能期望 `offsetWidth` 是 100px，但实际上是 100 + 20\*2 + 10\*2 = 160px。`length_utils.cc` 中的函数会正确计算出 160px，但用户的预期可能与实际不符。

2. **对 Quirks 模式下百分比高度理解不足:**
    *   **场景:** 开发者可能没有意识到在 quirks 模式下，百分比高度的计算依赖于父元素的明确高度。
    *   **举例:**  一个父 `div` 没有设置高度，子 `div` 设置了 `height: 50%;`。在标准模式下，子元素的高度会是 0，但在 quirks 模式下，`AdjustChildPercentageSize` 可能会尝试使用父元素的百分比解析高度（如果存在），否则高度仍然为 0。开发者可能会错误地认为子元素应该占父元素一半的高度。

3. **假设滚动条始终存在或不存在:**
    *   **场景:**  开发者编写 JavaScript 代码时，可能没有考虑到滚动条的出现和消失会影响元素的客户端尺寸 (`clientWidth`, `clientHeight`)。
    *   **举例:**  一个 `div` 元素在内容较少时没有滚动条，JavaScript 代码获取其 `clientWidth` 并进行计算。当内容增多出现滚动条后，`clientWidth` 会减小滚动条的宽度，导致之前的 JavaScript 计算结果出现错误。`AddScrollbarFreeze` 这样的函数用于帮助引擎判断滚动条状态的变化，从而进行更精确的布局和尺寸计算。

**归纳一下它的功能 (第3部分):**

总而言之，这部分 `length_utils.cc` 文件提供了一组底层的、精细的工具函数，用于在 blink 渲染引擎的布局阶段准确计算各种元素的尺寸和相关属性。这些函数考虑了 CSS 盒模型、各种 CSS 尺寸属性、HTML 元素特性以及浏览器兼容性（quirks 模式）等因素，是浏览器正确渲染网页的关键组成部分。它们确保了无论 CSS 如何设置，浏览器都能按照规范计算出元素的最终大小，并为 JavaScript 获取元素尺寸提供了底层的支持。

Prompt: 
```
这是目录为blink/renderer/core/layout/length_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
llbar_padding = border_padding + scrollbar;

  if (node.IsReplaced()) {
    const auto border_box_size = ComputeReplacedSize(
        node, space, border_padding,
        is_intrinsic ? ReplacedSizeMode::kIgnoreInlineLengths
                     : ReplacedSizeMode::kNormal);
    return {border_box_size, border, scrollbar, padding};
  }

  const LayoutUnit inline_size =
      is_intrinsic ? kIndefiniteSize
                   : ComputeInlineSizeForFragment(space, node, border_padding,
                                                  min_max_sizes_func);

  if (inline_size != kIndefiniteSize &&
      inline_size < border_scrollbar_padding.InlineSum() &&
      scrollbar.InlineSum() && !space.IsAnonymous()) [[unlikely]] {
    // Clamp the inline size of the scrollbar, unless it's larger than the
    // inline size of the content box, in which case we'll return that instead.
    // Scrollbar handling is quite bad in such situations, and this method here
    // is just to make sure that left-hand scrollbars don't mess up scrollWidth.
    // For the full story, visit http://crbug.com/724255.
    const auto content_box_inline_size =
        inline_size - border_padding.InlineSum();
    if (scrollbar.InlineSum() > content_box_inline_size) {
      if (scrollbar.inline_end) {
        DCHECK(!scrollbar.inline_start);
        scrollbar.inline_end = content_box_inline_size;
      } else {
        DCHECK(scrollbar.inline_start);
        scrollbar.inline_start = content_box_inline_size;
      }
    }
  }

  const auto default_block_size = CalculateDefaultBlockSize(
      space, node, break_token, border_scrollbar_padding);
  const auto block_size = ComputeInitialBlockSizeForFragment(
      space, node, border_padding, default_block_size, inline_size);

  return {LogicalSize(inline_size, block_size), border, scrollbar, padding};
}

FragmentGeometry CalculateInitialFragmentGeometry(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BlockBreakToken* break_token,
    bool is_intrinsic) {
  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    return node.ComputeMinMaxSizes(space.GetWritingMode(), type, space);
  };

  return CalculateInitialFragmentGeometry(space, node, break_token,
                                          MinMaxSizesFunc, is_intrinsic);
}

LogicalSize ShrinkLogicalSize(LogicalSize size, const BoxStrut& insets) {
  if (size.inline_size != kIndefiniteSize) {
    size.inline_size =
        (size.inline_size - insets.InlineSum()).ClampNegativeToZero();
  }
  if (size.block_size != kIndefiniteSize) {
    size.block_size =
        (size.block_size - insets.BlockSum()).ClampNegativeToZero();
  }

  return size;
}

LogicalSize CalculateChildAvailableSize(
    const ConstraintSpace& space,
    const BlockNode& node,
    const LogicalSize border_box_size,
    const BoxStrut& border_scrollbar_padding) {
  LogicalSize child_available_size =
      ShrinkLogicalSize(border_box_size, border_scrollbar_padding);

  if (space.IsAnonymous() ||
      (node.IsAnonymousBlock() &&
       child_available_size.block_size == kIndefiniteSize)) {
    child_available_size.block_size = space.AvailableSize().block_size;
  }

  return child_available_size;
}

namespace {

// Implements the common part of the child percentage size calculation. Deals
// with how percentages are propagated from parent to child in quirks mode.
LogicalSize AdjustChildPercentageSize(const ConstraintSpace& space,
                                      const BlockNode node,
                                      LogicalSize child_percentage_size,
                                      LayoutUnit parent_percentage_block_size) {
  // In quirks mode the percentage resolution height is passed from parent to
  // child.
  // https://quirks.spec.whatwg.org/#the-percentage-height-calculation-quirk
  if (child_percentage_size.block_size == kIndefiniteSize &&
      node.UseParentPercentageResolutionBlockSizeForChildren())
    child_percentage_size.block_size = parent_percentage_block_size;

  return child_percentage_size;
}

}  // namespace

LogicalSize CalculateChildPercentageSize(
    const ConstraintSpace& space,
    const BlockNode node,
    const LogicalSize child_available_size) {
  // Anonymous block or spaces should use the parent percent block-size.
  if (space.IsAnonymous() || node.IsAnonymousBlock()) {
    return {child_available_size.inline_size,
            space.PercentageResolutionBlockSize()};
  }

  // Table cell children don't apply the "percentage-quirk". I.e. if their
  // percentage resolution block-size is indefinite, they don't pass through
  // their parent's percentage resolution block-size.
  if (space.IsTableCellChild())
    return child_available_size;

  return AdjustChildPercentageSize(space, node, child_available_size,
                                   space.PercentageResolutionBlockSize());
}

LogicalSize CalculateReplacedChildPercentageSize(
    const ConstraintSpace& space,
    const BlockNode node,
    const LogicalSize child_available_size,
    const BoxStrut& border_scrollbar_padding,
    const BoxStrut& border_padding) {
  // Anonymous block or spaces should use the parent percent block-size.
  if (space.IsAnonymous() || node.IsAnonymousBlock()) {
    return {child_available_size.inline_size,
            space.PercentageResolutionBlockSize()};
  }

  // Table cell children don't apply the "percentage-quirk". I.e. if their
  // percentage resolution block-size is indefinite, they don't pass through
  // their parent's percentage resolution block-size.
  if (space.IsTableCellChild())
    return child_available_size;

  // Replaced descendants of a table-cell which has a definite block-size,
  // always resolve their percentages against this size (even during the
  // "layout" pass where the fixed block-size may be different).
  //
  // This ensures that between the table-cell "measure" and "layout" passes
  // the replaced descendants remain the same size.
  if (space.IsTableCell() && node.Style().LogicalHeight().IsFixed()) {
    LayoutUnit block_size = ComputeBlockSizeForFragmentInternal(
        space, node, border_padding, kIndefiniteSize /* intrinsic_size */,
        kIndefiniteSize /* inline_size */);
    DCHECK_NE(block_size, kIndefiniteSize);
    return {child_available_size.inline_size,
            (block_size - border_scrollbar_padding.BlockSum())
                .ClampNegativeToZero()};
  }

  return AdjustChildPercentageSize(
      space, node, child_available_size,
      space.ReplacedPercentageResolutionBlockSize());
}

LayoutUnit ClampIntrinsicBlockSize(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BlockBreakToken* break_token,
    const BoxStrut& border_scrollbar_padding,
    LayoutUnit current_intrinsic_block_size,
    std::optional<LayoutUnit> body_margin_block_sum) {
  // Tables don't respect size containment, or apply the "fill viewport" quirk.
  DCHECK(!node.IsTable());
  const ComputedStyle& style = node.Style();

  // Check if the intrinsic size was overridden.
  LayoutUnit override_intrinsic_size = node.OverrideIntrinsicContentBlockSize();
  if (override_intrinsic_size != kIndefiniteSize)
    return override_intrinsic_size + border_scrollbar_padding.BlockSum();

  // Check if we have a "default" block-size (e.g. a <textarea>).
  LayoutUnit default_intrinsic_size = node.DefaultIntrinsicContentBlockSize();
  if (default_intrinsic_size != kIndefiniteSize) {
    // <textarea>'s intrinsic size should ignore scrollbar existence.
    if (node.IsTextArea()) {
      return default_intrinsic_size -
             ComputeScrollbars(space, node).BlockSum() +
             border_scrollbar_padding.BlockSum();
    }
    return default_intrinsic_size + border_scrollbar_padding.BlockSum();
  }

  // If we have size containment, we ignore child contributions to intrinsic
  // sizing.
  if (node.ShouldApplyBlockSizeContainment())
    return border_scrollbar_padding.BlockSum();

  // Apply the "fills viewport" quirk if needed.
  if (!IsBreakInside(break_token) && node.IsQuirkyAndFillsViewport() &&
      style.LogicalHeight().HasAuto() &&
      space.AvailableSize().block_size != kIndefiniteSize) {
    DCHECK_EQ(node.IsBody() && !node.CreatesNewFormattingContext(),
              body_margin_block_sum.has_value());
    LayoutUnit margin_sum = body_margin_block_sum.value_or(
        ComputeMarginsForSelf(space, style).BlockSum());
    current_intrinsic_block_size = std::max(
        current_intrinsic_block_size,
        (space.AvailableSize().block_size - margin_sum).ClampNegativeToZero());
  }

  return current_intrinsic_block_size;
}

std::optional<MinMaxSizesResult> CalculateMinMaxSizesIgnoringChildren(
    const BlockNode& node,
    const BoxStrut& border_scrollbar_padding) {
  MinMaxSizes sizes;
  sizes += border_scrollbar_padding.InlineSum();

  // If intrinsic size was overridden, then use that.
  const LayoutUnit intrinsic_size_override =
      node.OverrideIntrinsicContentInlineSize();
  if (intrinsic_size_override != kIndefiniteSize) {
    sizes += intrinsic_size_override;
    return MinMaxSizesResult{sizes,
                             /* depends_on_block_constraints */ false};
  } else {
    LayoutUnit default_inline_size = node.DefaultIntrinsicContentInlineSize();
    if (default_inline_size != kIndefiniteSize) {
      sizes += default_inline_size;
      // <textarea>'s intrinsic size should ignore scrollbar existence.
      if (node.IsTextArea())
        sizes -= ComputeScrollbarsForNonAnonymous(node).InlineSum();
      return MinMaxSizesResult{sizes,
                               /* depends_on_block_constraints */ false};
    }
  }

  // Size contained elements don't consider children for intrinsic sizing.
  // Also, if we don't have children, we can determine the size immediately.
  if (node.ShouldApplyInlineSizeContainment() || !node.FirstChild()) {
    return MinMaxSizesResult{sizes,
                             /* depends_on_block_constraints */ false};
  }

  return std::nullopt;
}

void AddScrollbarFreeze(const BoxStrut& scrollbars_before,
                        const BoxStrut& scrollbars_after,
                        WritingDirectionMode writing_direction,
                        bool* freeze_horizontal,
                        bool* freeze_vertical) {
  PhysicalBoxStrut physical_before =
      scrollbars_before.ConvertToPhysical(writing_direction);
  PhysicalBoxStrut physical_after =
      scrollbars_after.ConvertToPhysical(writing_direction);
  *freeze_horizontal |= (!physical_before.top && physical_after.top) ||
                        (!physical_before.bottom && physical_after.bottom);
  *freeze_vertical |= (!physical_before.left && physical_after.left) ||
                      (!physical_before.right && physical_after.right);
}

}  // namespace blink

"""


```